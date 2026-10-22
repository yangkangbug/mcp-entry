package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func maintenanceFixture(t *testing.T) (Config, PersistenceOptions, *Gateway) {
	t.Helper()
	cfg := Config{Systems: []System{{Name: "synthetic", Endpoint: "http://127.0.0.1:1/mcp"}}, Users: map[string]User{"test": {Tenant: "tenant", Principal: "principal", Token: "synthetic-maintenance-entry", Allowed: []string{"synthetic__read"}, Credentials: map[string]string{"synthetic": "synthetic-only-secret"}}}}
	opts := PersistenceOptions{Path: filepath.Join(t.TempDir(), "state.sqlite"), Key: bytes.Repeat([]byte{0x31}, 32), Initialize: true}
	g, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	return cfg, opts, g
}
func TestMaintenanceRotationPreservesAuthorityAndHistory(t *testing.T) {
	cfg, opts, g := maintenanceFixture(t)
	identity := Identity{"tenant", "principal"}
	if _, err := g.SetPolicy(identity, 1, nil); err != nil {
		t.Fatal(err)
	}
	oldID := append([]byte(nil), g.auditIDKey...)
	oldRecord := g.store.records["test"]
	oldEvent, _ := g.auditRing.Read(AuditFilter{Limit: 100})
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Initialize = false
	g, err := OpenMaintenance(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	newKey := bytes.Repeat([]byte{0x42}, 32)
	if err = g.RotateKey(newKey); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(g.auditIDKey, oldID) {
		t.Fatal("audit identity key changed")
	}
	record := g.store.records["test"]
	if record.Version != oldRecord.Version || !reflect.DeepEqual(record.Allowed, oldRecord.Allowed) || record.EntryGeneration != oldRecord.EntryGeneration {
		t.Fatal("authority changed")
	}
	if bytes.Equal(record.Bindings[0].Credential, oldRecord.Bindings[0].Credential) {
		t.Fatal("credential was not re-encrypted")
	}
	events, _ := g.auditRing.Read(AuditFilter{Limit: 100})
	if len(events.Events) != len(oldEvent.Events)+1 || !reflect.DeepEqual(events.Events[:len(oldEvent.Events)], oldEvent.Events) || events.Events[len(events.Events)-1].Action != AuditActionStorageRotate {
		t.Fatal("audit history/provenance changed")
	}
	if err = g.Close(); err != nil {
		t.Fatal(err)
	}
	if rejected, e := NewPersistent(cfg, opts); e == nil {
		rejected.Close()
		t.Fatal("old key accepted")
	}
	opts.Key = newKey
	g, err = NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if !bytes.Equal(g.auditIDKey, oldID) || g.principals["test"].bindings["synthetic"].credential != "synthetic-only-secret" {
		t.Fatal("rotation recovery failed")
	}
	if g.store.auditSequence != uint64(len(events.Events)) {
		t.Fatal("manifest sequence not committed")
	}
}
func TestMaintenanceRotationGatesAndFullCapacity(t *testing.T) {
	cfg, opts, g := maintenanceFixture(t)
	key := bytes.Repeat([]byte{0x42}, 32)
	if !errors.Is(g.RotateKey(key), ErrDenied) {
		t.Fatal("online rotation accepted")
	}
	if !errors.Is(g.migrateStorage(context.Background()), ErrDenied) {
		t.Fatal("online migration accepted")
	}
	g.Close()
	opts.Initialize = false
	g, err := OpenMaintenance(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if !errors.Is(g.RotateKey(opts.Key), ErrDenied) {
		t.Fatal("same-key rotation accepted")
	}
	if !errors.Is(g.RotateKey(key[:31]), ErrStorage) {
		t.Fatal("short key accepted")
	}
	before := g.store.stateMAC(g.store.records)
	g.auditCapacity = 0
	if !errors.Is(g.RotateKey(key), ErrAuditFull) {
		t.Fatal("full audit rotation accepted")
	}
	if !bytes.Equal(before, g.store.stateMAC(g.store.records)) || g.closed {
		t.Fatal("failed preflight changed state")
	}
}

func TestMaintenanceRotationRollbackRetainsOldKey(t *testing.T) {
	cfg, opts, g := maintenanceFixture(t)
	g.Close()
	opts.Initialize = false
	g, err := OpenMaintenance(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	before := g.store.stateMAC(g.store.records)
	if _, err = g.store.conn.ExecContext(context.Background(), "CREATE TRIGGER reject_rotation BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT, 'synthetic fault'); END"); err != nil {
		t.Fatal(err)
	}
	if err = g.RotateKey(bytes.Repeat([]byte{0x42}, 32)); !errors.Is(err, ErrStorage) {
		t.Fatalf("expected rollback error, got %v", err)
	}
	if !bytes.Equal(before, g.store.stateMAC(g.store.records)) {
		t.Fatal("candidate state published before commit")
	}
	if !g.closed {
		t.Fatal("storage failure did not fence maintenance")
	}
	db, err := sql.Open("sqlite", opts.Path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("DROP TRIGGER reject_rotation"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	g, err = NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if g.store.auditSequence != 0 {
		t.Fatal("failed rotation left audit provenance")
	}
}
