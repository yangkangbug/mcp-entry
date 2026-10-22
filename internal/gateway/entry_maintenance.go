package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
	"time"
)

// EntryInfo contains no credential or verification digest.
type EntryInfo struct {
	Generation uint64
	ExpiresAt  time.Time
	Revoked    bool
}

func (g *Gateway) Entry(identity Identity) (EntryInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, p, err := g.principalLocked(identity)
	if err != nil {
		return EntryInfo{}, err
	}
	return p.entry, nil
}
func (g *Gateway) ReplaceEntry(identity Identity, expected uint64, token string, expiry time.Time) (EntryInfo, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token || !validExpiryDate(expiry) || expiry.IsZero() || !expiry.After(time.Now()) {
		return EntryInfo{}, ErrDenied
	}
	digest := entryTokenDigest(token)
	return g.mutateEntry(identity, expected, &digest, expiry.UTC())
}
func (g *Gateway) RevokeEntry(identity Identity, expected uint64) (EntryInfo, error) {
	return g.mutateEntry(identity, expected, nil, time.Time{})
}
func (g *Gateway) mutateEntry(identity Identity, expected uint64, digest *[32]byte, expiry time.Time) (EntryInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.maintenance || g.store == nil {
		return EntryInfo{}, ErrDenied
	}
	id, p, err := g.principalLocked(identity)
	if err != nil {
		return EntryInfo{}, err
	}
	if p.disabled {
		return EntryInfo{}, ErrDenied
	}
	if p.entry.Generation != expected || expected == 0 || expected >= math.MaxInt64 {
		return EntryInfo{}, ErrConflict
	}
	if digest != nil {
		for _, old := range g.entryTokens {
			if old == *digest {
				return EntryInfo{}, ErrDenied
			}
		}
	}
	if !g.auditRoomLocked(1) {
		return EntryInfo{}, ErrAuditFull
	}
	candidate := *p
	candidate.entry.Generation++
	candidate.entry.Revoked = digest == nil
	action := AuditActionEntryRevoke
	if digest != nil {
		candidate.entry.ExpiresAt = expiry
		action = AuditActionEntryRotate
	}
	r, err := g.store.record(g, id, &candidate)
	if err != nil {
		return EntryInfo{}, ErrStorage
	}
	if digest != nil {
		r.TokenHash = append([]byte(nil), digest[:]...)
		r.TokenExpiresAt = expiry
		r.EntryStrong = true
	}
	event := g.auditEventLocked(id, "", "", &candidate, action, AuditPhaseCommit, AuditResultSuccess, AuditActorOperator)
	if err = g.store.persistEntry(g, id, r, event); err != nil {
		g.auditFailureLocked()
		return EntryInfo{}, ErrStorage
	}
	if err = g.auditRing.Append(event); err != nil {
		g.auditFailureLocked()
		return EntryInfo{}, ErrStorage
	}
	g.principals[id] = &candidate
	if digest != nil {
		g.entryTokens[id] = *digest
		g.entryStrong[id] = true
		u := g.users[id]
		u.TokenExpiresAt = expiry
		g.users[id] = u
	}
	return candidate.entry, nil
}
func (s *sqliteStore) persistEntry(g *Gateway, id string, r storedPrincipal, event AuditEvent) error {
	next := make(map[string]storedPrincipal, len(s.records))
	for k, v := range s.records {
		next[k] = v
	}
	next[id] = r
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = writePrincipal(ctx, tx, r, false); err != nil {
		return err
	}
	seq, head, err := s.writeAudit(ctx, tx, event)
	if err != nil {
		return err
	}
	if err = s.updateAuditManifest(ctx, tx, next, seq, head); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.records = next
	s.auditSequence = seq
	s.auditHead = head
	return nil
}

// Frozen canonical legacy layout: changing field order would break authenticated upgrades.
type legacyStoredPrincipal struct {
	UserID, Tenant, Principal string
	TokenHash                 []byte
	TokenExpiresAt            time.Time
	Version                   uint64
	Disabled                  bool
	Allowed                   []string
	Bindings                  []storedBinding
}

func (s *sqliteStore) canonicalState(records []storedPrincipal, sequence uint64, head string) []byte {
	var encoded []byte
	if s.version < 4 {
		old := make([]legacyStoredPrincipal, 0, len(records))
		for _, r := range records {
			old = append(old, legacyStoredPrincipal{r.UserID, r.Tenant, r.Principal, r.TokenHash, r.TokenExpiresAt, r.Version, r.Disabled, r.Allowed, r.Bindings})
		}
		if s.version == 2 {
			encoded, _ = json.Marshal(struct {
				Version  int
				Topology []byte
				Records  []legacyStoredPrincipal
			}{2, s.topology, old})
		} else {
			encoded, _ = json.Marshal(struct {
				Version       int
				Topology      []byte
				Records       []legacyStoredPrincipal
				AuditSequence uint64
				AuditHead     string
				AuditIDKey    []byte
			}{3, s.topology, old, sequence, head, s.auditIDCipher})
		}
	} else {
		encoded, _ = json.Marshal(struct {
			Version           int
			Topology          []byte
			Records           []storedPrincipal
			AuditSequence     uint64
			AuditHead         string
			AuditIDKey        []byte
			AuditBaseSequence uint64
			AuditBaseHead     string
			AuditArchiveHash  string
		}{4, s.topology, records, sequence, head, s.auditIDCipher, s.auditBaseSequence, s.auditBaseHead, s.auditArchiveHash})
	}
	return encoded
}
func (s *sqliteStore) loadLegacyOrCurrentAudit(ctx context.Context, g *Gateway) error {
	if s.version == 2 {
		s.auditIDCipher = s.aead.Seal(nil, nil, g.auditIDKey, s.auditIDAAD())
		return nil
	}
	return s.loadAudit(ctx, g)
}
