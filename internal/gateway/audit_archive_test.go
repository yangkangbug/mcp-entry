package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func archiveFixture(t *testing.T, capacity int) (*Gateway, Config, PersistenceOptions) {
	t.Helper()
	cfg := maintenanceConfig()
	cfg.Audit.Capacity = capacity
	opts := maintenanceOptions(t)
	maintenanceSeed(t, cfg, opts)
	opts.Initialize = false
	g, err := OpenMaintenance(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	return g, cfg, opts
}
func archiveFill(t *testing.T, g *Gateway, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := g.appendAuditLocked(g.maintenanceAuditEvent(AuditActionStorageRotate)); err != nil {
			t.Fatal(err)
		}
	}
}
func TestArchiveFullJournalReopenAndContinue(t *testing.T) {
	g, cfg, opts := archiveFixture(t, 3)
	archiveFill(t, g, 3)
	if g.auditRoomLocked(1) {
		t.Fatal("full journal admitted write")
	}
	path := filepath.Join(t.TempDir(), "archive.json")
	result, err := g.ArchiveAudit(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	if result.CoveredCount != 3 || result.CheckpointSequence != 4 || !g.auditRoomLocked(1) {
		t.Fatalf("result %+v", result)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != result.SHA256 || result.SHA256 != g.store.auditArchiveHash {
		t.Fatal("archive digest not bound")
	}
	if bytes.Contains(raw, []byte("synthetic-maintenance-binding")) || bytes.Contains(raw, []byte(maintenanceToken(1))) || bytes.Contains(raw, []byte(path)) {
		t.Fatal("sensitive archive data")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("not private")
	}
	var envelope struct {
		Archive archiveDocument `json:"archive"`
		MAC     string          `json:"mac"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Archive.Rows) != 3 || envelope.Archive.Rows[0].Sequence != 1 {
		t.Fatal("bad archive")
	}
	if err = g.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenMaintenance(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	page, err := reopened.AuditAll(0, 10)
	if err != nil || len(page.Events) != 1 || page.Events[0].Sequence != 4 || page.Events[0].Action != AuditActionStorageArchive || page.Dropped != 3 {
		t.Fatalf("page %+v err %v", page, err)
	}
	archiveFill(t, reopened, 1)
	second, err := reopened.ArchiveAudit(filepath.Join(t.TempDir(), "next.json"), 5)
	if err != nil || second.BaseSequence != 3 || second.CoveredCount != 2 || second.CheckpointSequence != 6 {
		t.Fatalf("second %+v %v", second, err)
	}
}
func TestArchiveRefusesStaleExistingAndActive(t *testing.T) {
	g, _, _ := archiveFixture(t, 3)
	archiveFill(t, g, 2)
	path := filepath.Join(t.TempDir(), "archive.json")
	if _, err := g.ArchiveAudit(path, 1); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale archive wrote file")
	}
	os.WriteFile(path, []byte("existing"), 0600)
	if _, err := g.ArchiveAudit(path, 2); err == nil {
		t.Fatal("overwrote output")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "existing" || g.store.auditSequence != 2 || g.store.auditBaseSequence != 0 {
		t.Fatal("changed on output failure")
	}
	g.auditPending = 1
	if _, err := g.ArchiveAudit(filepath.Join(t.TempDir(), "unfinished"), 2); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
}
func TestArchiveDBFailureKeepsExportAndOldJournal(t *testing.T) {
	g, _, _ := archiveFixture(t, 3)
	archiveFill(t, g, 2)
	_, err := g.store.conn.ExecContext(context.Background(), "CREATE TRIGGER stop_archive BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "archive.json")
	result, err := g.ArchiveAudit(path, 2)
	if err == nil || result.SHA256 == "" {
		t.Fatal("expected failed DB mutation with artifact")
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("archive removed")
	}
	var count int
	if err = g.store.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM audit").Scan(&count); err != nil || count != 2 || g.store.auditBaseSequence != 0 {
		t.Fatalf("old journal changed %d %v", count, err)
	}
}

func TestArchiveLostCommitAckRequiresReopen(t *testing.T) {
	g, cfg, opts := archiveFixture(t, 3)
	archiveFill(t, g, 2)
	maintenanceLoseCommitAck(t, g, opts.Path)
	path := filepath.Join(t.TempDir(), "archive.json")
	result, err := g.ArchiveAudit(path, 2)
	if !errors.Is(err, ErrArchiveCommitUnknown) || !g.closed {
		t.Fatalf("expected explicit ambiguity/closed, got %v", err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenMaintenance(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.store.auditArchiveHash != result.SHA256 || reopened.store.auditBaseSequence != 2 || reopened.store.auditSequence != 3 {
		t.Fatal("committed checkpoint not recovered")
	}
}

func TestArchiveRejectsMissingAuthenticatedRows(t *testing.T) {
	g, _, _ := archiveFixture(t, 3)
	archiveFill(t, g, 2)
	if _, err := g.store.conn.ExecContext(context.Background(), "DELETE FROM audit WHERE sequence=1"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "archive.json")
	if _, err := g.ArchiveAudit(path, 2); err == nil {
		t.Fatal("archived missing evidence")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrote invalid evidence")
	}
}

func TestArchivePreservesOrphanUnknownAcrossReopenAndNextArchive(t *testing.T) {
	g, cfg, opts := archiveFixture(t, 3)
	event := g.maintenanceAuditEvent(AuditActionDiscovery)
	event.SystemID = AuditIdentifier(g.auditIDKey, "system", "shared")
	event.Phase = AuditPhaseStart
	event.Result = AuditResultPending
	if err := g.appendAuditLocked(event); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	m, err := OpenMaintenance(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	first, err := m.ArchiveAudit(filepath.Join(t.TempDir(), "one.json"), 1)
	if err != nil || first.ArchivedUnfinished != 1 || len(m.auditUnfinished) != 0 {
		t.Fatalf("first %+v %v", first, err)
	}
	m.Close()
	m, err = OpenMaintenance(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if m.AuditStatus().Unfinished != 1 {
		t.Fatal("orphan history hidden after reopen")
	}
	second, err := m.ArchiveAudit(filepath.Join(t.TempDir(), "two.json"), 2)
	if err != nil || second.ArchivedUnfinished != 1 || m.AuditStatus().Unfinished != 1 {
		t.Fatalf("second %+v %v", second, err)
	}
}
