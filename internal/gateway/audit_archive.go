package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"
)

// ErrArchiveCommitUnknown means the archive exists, but the caller must reopen
// and inspect the authenticated checkpoint before deciding whether pruning committed.
var ErrArchiveCommitUnknown = errors.New("audit archive checkpoint outcome unknown; retain archive and reopen state")

// AuditArchiveResult contains no filesystem paths or credentials. SHA256 names
// the exact durable export, while CoveredCount excludes previously archived rows.
type AuditArchiveResult struct {
	SHA256             string `json:"sha256"`
	CoveredCount       uint64 `json:"covered_count"`
	BaseSequence       uint64 `json:"base_sequence"`
	LastSequence       uint64 `json:"last_sequence"`
	CheckpointSequence uint64 `json:"checkpoint_sequence"`
	ArchivedUnfinished uint64 `json:"archived_unfinished"`
}
type AuditArchiveInfo = AuditArchiveResult

type archiveRow struct {
	Sequence uint64          `json:"sequence"`
	Event    json.RawMessage `json:"event"`
	MAC      string          `json:"mac"`
}
type archiveDocument struct {
	Format                string       `json:"format"`
	BaseSequence          uint64       `json:"base_sequence"`
	BaseHead              string       `json:"base_head"`
	PreviousArchiveSHA256 string       `json:"previous_archive_sha256"`
	LastSequence          uint64       `json:"last_sequence"`
	Head                  string       `json:"head"`
	CoveredCount          uint64       `json:"covered_count"`
	ArchivedUnfinished    uint64       `json:"archived_unfinished"`
	Rows                  []archiveRow `json:"rows"`
}

// ArchiveAudit is an offline owner-only, explicit export-and-retention operation.
// It refuses active operations and stale sequence expectations. Orphaned starts
// from earlier processes remain unknown in the export and checkpoint count. Exact journal
// events and their original MACs are written to a new 0600 file and synced before
// any deletion. Keep every archive and its historical verification key: rotation
// does not rewrite archives, and whole-database rollback remains out of scope.
// Failures never delete the output; a partial file may remain after an I/O error.
func (g *Gateway) ArchiveAudit(path string, expectedSequence uint64) (AuditArchiveResult, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var result AuditArchiveResult
	if g.closed {
		return result, ErrClosed
	}
	if !g.maintenance || g.store == nil {
		return result, ErrDenied
	}
	s := g.store
	if s.version != 4 || g.auditFault {
		return result, ErrStorage
	}
	if expectedSequence != s.auditSequence {
		return result, ErrConflict
	}
	if g.auditPending != 0 || len(g.operations) != 0 {
		return result, ErrDenied
	}
	if s.auditSequence == s.auditBaseSequence || s.auditSequence >= math.MaxInt64 {
		return result, ErrAuditFull
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	doc := archiveDocument{Format: "mcp-entry/audit-archive/v1", BaseSequence: s.auditBaseSequence, BaseHead: s.auditBaseHead, PreviousArchiveSHA256: s.auditArchiveHash, LastSequence: s.auditSequence, Head: s.auditHead, Rows: make([]archiveRow, 0)}
	rows, err := s.conn.QueryContext(ctx, "SELECT sequence,event,mac FROM audit ORDER BY sequence")
	if err != nil {
		return result, ErrStorage
	}
	count, previous := s.auditBaseSequence, s.auditBaseHead
	for rows.Next() {
		var sequence int64
		var raw, mac string
		if err := rows.Scan(&sequence, &raw, &mac); err != nil {
			rows.Close()
			return result, ErrStorage
		}
		count++
		var event AuditEvent
		if sequence < 1 || uint64(sequence) != count || count > s.auditSequence || count-s.auditBaseSequence > uint64(g.auditCapacity) || len(raw) > 2048 || json.Unmarshal([]byte(raw), &event) != nil || event.Sequence != count || VerifyAuditMAC(s.auditKey, previous, event, mac) != nil {
			rows.Close()
			return result, ErrStorage
		}
		canonical, _ := json.Marshal(event)
		if string(canonical) != raw {
			rows.Close()
			return result, ErrStorage
		}
		doc.Rows = append(doc.Rows, archiveRow{count, json.RawMessage(raw), mac})
		previous = mac
	}
	err = rows.Err()
	rows.Close()
	if err != nil || count != s.auditSequence || previous != s.auditHead {
		return result, ErrStorage
	}
	doc.CoveredCount = count - s.auditBaseSequence
	if g.auditArchivedUnfinished > s.auditSequence || uint64(len(g.auditUnfinished)) > s.auditSequence-g.auditArchivedUnfinished {
		return result, ErrStorage
	}
	doc.ArchivedUnfinished = g.auditArchivedUnfinished + uint64(len(g.auditUnfinished))
	// Bind the complete export envelope under the current audit key; its SHA256 is
	// also committed into the independently authenticated live-state manifest.
	body, err := json.Marshal(doc)
	if err != nil || len(body) > 160<<20 {
		return result, ErrStorage
	}
	auth := hmac.New(sha256.New, s.auditKey)
	auth.Write([]byte("mcp-entry/audit-archive/v1\x00"))
	auth.Write(body)
	export, err := json.Marshal(struct {
		Archive json.RawMessage `json:"archive"`
		MAC     string          `json:"mac"`
	}{body, hex.EncodeToString(auth.Sum(nil))})
	if err != nil {
		return result, ErrStorage
	}
	export = append(export, '\n')
	digest := sha256.Sum256(export)
	result = AuditArchiveResult{SHA256: hex.EncodeToString(digest[:]), CoveredCount: doc.CoveredCount, BaseSequence: doc.BaseSequence, LastSequence: doc.LastSequence, CheckpointSequence: doc.LastSequence + 1, ArchivedUnfinished: doc.ArchivedUnfinished}
	if err = writeAuditArchive(path, export); err != nil {
		return result, ErrStorage
	}
	candidate := *s
	candidate.auditBaseSequence = s.auditSequence
	candidate.auditBaseHead = s.auditHead
	candidate.auditArchiveHash = result.SHA256
	event := g.maintenanceAuditEvent(AuditActionStorageArchive)
	event.ArchivedUnfinished = doc.ArchivedUnfinished
	ring, err := NewAuditRing(g.auditCapacity)
	if err != nil {
		return result, ErrStorage
	}
	ring.sequence = s.auditSequence
	ring.dropped = s.auditSequence
	if err = ring.Append(event); err != nil {
		return result, ErrStorage
	}
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return result, ErrStorage
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) && !g.closed {
			g.auditFailureLocked()
		}
	}()
	if _, err = tx.ExecContext(ctx, "DELETE FROM audit"); err != nil {
		return result, ErrStorage
	}
	sequence, head, err := candidate.writeAudit(ctx, tx, event)
	if err != nil {
		return result, ErrStorage
	}
	if err = candidate.updateAuditManifest(ctx, tx, candidate.records, sequence, head); err != nil {
		return result, ErrStorage
	}
	if err = tx.Commit(); err != nil {
		g.auditFailureLocked()
		return result, ErrArchiveCommitUnknown
	}
	candidate.auditSequence = sequence
	candidate.auditHead = head
	*s = candidate
	g.auditRing = ring
	g.auditArchivedUnfinished = doc.ArchivedUnfinished
	g.auditUnfinished = make(map[string]bool)
	return result, nil
}

func writeAuditArchive(path string, data []byte) error {
	if path == "" {
		return ErrStorage
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrStorage
	}
	// No cleanup: failed writes can leave partial evidence, never overwrite it.
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	n, err := f.Write(data)
	if err != nil || n != len(data) {
		return ErrStorage
	}
	created, err := f.Stat()
	if err != nil || !created.Mode().IsRegular() {
		return ErrStorage
	}
	if err = f.Sync(); err != nil {
		return ErrStorage
	}
	if err = f.Close(); err != nil {
		return ErrStorage
	}
	ok = true
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return ErrStorage
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return ErrStorage
	}
	// Refuse a missing or replaced pathname before the database transaction.
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || !os.SameFile(created, st) || st.Mode().Perm()&0077 != 0 || st.Size() != int64(len(data)) {
		return ErrStorage
	}
	verify, err := os.Open(path)
	if err != nil {
		return ErrStorage
	}
	defer verify.Close()
	opened, err := verify.Stat()
	if err != nil || !os.SameFile(created, opened) {
		return ErrStorage
	}
	read, err := io.ReadAll(io.LimitReader(verify, int64(len(data))+1))
	if err != nil || !hmac.Equal(read, data) {
		return ErrStorage
	}
	return nil
}
