package gateway

import (
	"bytes"
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func managedStoreFixture(t *testing.T) (Config, PersistenceOptions, *Gateway) {
	t.Helper()
	cfg := Config{Systems: []System{{Name: "svc", Endpoint: "http://127.0.0.1:1/mcp"}}, Users: map[string]User{"seed": {Tenant: "seed", Principal: "seed", Token: "synthetic-seed-only"}}}
	opts := PersistenceOptions{Path: filepath.Join(t.TempDir(), "state.sqlite"), Key: bytes.Repeat([]byte{7}, 32), Initialize: true}
	g, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	return cfg, opts, g
}

// Persist only synthetic revoked records; this fixture never issues a usable token.
func insertManagedFixture(t *testing.T, g *Gateway, identity Identity, transform func(*storedPrincipal)) string {
	t.Helper()
	id := managedUserID(identity)
	p := &principalState{identity: identity, version: 1, entry: EntryInfo{Generation: 1, Revoked: true}, bindings: map[string]*bindingRecord{}}
	for name := range g.systems {
		p.bindings[name] = &bindingRecord{info: BindingInfo{ID: id + "-" + name, Tenant: identity.Tenant, Principal: identity.Principal, System: name, Generation: 1, State: BindingUnbound}}
	}
	r, err := g.store.record(g, id, p)
	if err != nil {
		t.Fatal(err)
	}
	hash := entryTokenDigest("synthetic-placeholder:" + id)
	r.TokenHash = hash[:]
	if transform != nil {
		transform(&r)
	}
	event := g.auditEventLocked(id, "", "", p, AuditActionEntryRevoke, AuditPhaseCommit, AuditResultSuccess, AuditActorOperator)
	if err = g.store.persistEntry(g, id, r, event); err != nil {
		t.Fatal(err)
	}
	if err = g.auditRing.Append(event); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestManagedPersistenceRestoresWithoutConfigTopologyChange(t *testing.T) {
	cfg, opts, g := managedStoreFixture(t)
	identity := Identity{"new-tenant", "new-principal"}
	id := insertManagedFixture(t, g, identity, nil)
	before := append([]byte(nil), g.store.topology...)
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Initialize = false
	reopened, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !bytes.Equal(before, reopened.store.topology) {
		t.Fatal("bootstrap topology changed")
	}
	if reopened.identities[identity] != id || reopened.users[id].Tenant != identity.Tenant {
		t.Fatal("identity not restored")
	}
	p := reopened.principals[id]
	if !p.entry.Revoked || p.disabled || len(p.allowed) != 0 || p.bindings["svc"].credential != "" || p.bindings["svc"].info.State != BindingUnbound {
		t.Fatal("restoration granted authority")
	}
	if reopened.state.Load().handlers[id] == nil {
		t.Fatal("missing handler")
	}
	if release, ok := reopened.ingress.acquire(reopened.ingress.principalBucket(identity)); !ok {
		t.Fatal("missing ingress scope")
	} else {
		release()
	}
	permit, err := reopened.limiter.acquire(context.Background(), identity, "svc")
	if err != nil {
		t.Fatal("missing outbound scope:", err)
	}
	permit.Release()
}

func TestManagedPersistenceRejectsInvalidAuthenticatedRows(t *testing.T) {
	for _, kind := range []string{"wrong_id", "duplicate_digest", "unbounded_strong", "unissued_active"} {
		t.Run(kind, func(t *testing.T) {
			cfg, opts, g := managedStoreFixture(t)
			identity := Identity{"tenant", "person"}
			insertManagedFixture(t, g, identity, func(r *storedPrincipal) {
				switch kind {
				case "wrong_id":
					r.UserID = "not-managed"
				case "duplicate_identity":
					r.Tenant = "seed"
					r.Principal = "seed"
				case "duplicate_digest":
					r.TokenHash = append([]byte(nil), g.store.records["seed"].TokenHash...)
				case "unbounded_strong":
					r.EntryStrong = true
				case "unissued_active":
					r.EntryRevoked = false
				}
			})
			g.Close()
			opts.Initialize = false
			bad, err := NewPersistent(cfg, opts)
			if bad != nil {
				bad.Close()
			}
			if err == nil {
				t.Fatal("invalid managed state accepted")
			}
		})
	}
}

func TestManagedIdentityLimiterRegistrationPreservesExistingBuckets(t *testing.T) {
	old := Identity{"tenant", "old"}
	next := Identity{"tenant", "new"}
	l, err := newAdmissionLimiter(LimitsConfig{}, []Identity{old}, map[string]string{"svc": ""})
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := newIngressLimiter(IngressConfig{}, []Identity{old})
	if err != nil {
		t.Fatal(err)
	}
	original := l.tenants[old.Tenant]
	existing := ingress.principalBucket(old)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); l.addIdentity(next); ingress.addIdentity(next); ingress.principalBucket(next) }()
	}
	wg.Wait()
	if l.tenants[old.Tenant] != original || ingress.principalBucket(old) != existing {
		t.Fatal("quota reset")
	}
	if len(l.principals) != 2 || len(ingress.principals) != 2 {
		t.Fatal("duplicate scope")
	}
}

func TestManagedPersistenceExpiredStrongEntryDoesNotBreakStartup(t *testing.T) {
	cfg, opts, g := managedStoreFixture(t)
	id := insertManagedFixture(t, g, Identity{"tenant", "expired"}, func(r *storedPrincipal) {
		r.EntryStrong = true
		r.EntryRevoked = false
		r.TokenExpiresAt = time.Now().UTC().Add(-time.Hour)
	})
	g.Close()
	opts.Initialize = false
	restored, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if restored.principalUsableLocked(id) {
		t.Fatal("expired entry usable")
	}
}

func TestManagedPersistenceInsertAndAuditAreAtomic(t *testing.T) {
	_, _, g := managedStoreFixture(t)
	identity := Identity{"transaction", "candidate"}
	id := managedUserID(identity)
	p := &principalState{identity: identity, version: 1, entry: EntryInfo{Generation: 1, Revoked: true}, bindings: map[string]*bindingRecord{}}
	r, err := g.store.record(g, id, p)
	if err != nil {
		t.Fatal(err)
	}
	event := g.auditEventLocked(id, "", "", p, AuditActionEntryRevoke, AuditPhaseCommit, AuditResultSuccess, AuditActorOperator)
	if _, err = g.store.conn.ExecContext(context.Background(), "CREATE TRIGGER reject_managed_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END"); err != nil {
		t.Fatal(err)
	}
	if err = g.store.persistEntry(g, id, r, event); err == nil {
		t.Fatal("expected audit failure")
	}
	if _, exists := g.store.records[id]; exists {
		t.Fatal("failed write published store cache")
	}
	var count int
	if err = g.store.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM principals WHERE user_id=?", id).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial principal persisted: %d %v", count, err)
	}
	if g.store.auditSequence != 0 {
		t.Fatal("failed write advanced sequence")
	}
}
