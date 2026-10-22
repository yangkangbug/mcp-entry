package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	sqlite "modernc.org/sqlite"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// Independent tests use synthetic tokens and keys, temporary SQLite databases,
// and no downstream network. Legacy fixtures below are frozen authenticated SQL,
// not new-format records stamped with an old version.
func maintenanceToken(n byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32))
}
func maintenanceIdentity(id string) Identity {
	return Identity{Tenant: "tenant-" + id, Principal: "principal-" + id}
}
func maintenanceConfig() Config {
	c := Config{Systems: []System{{Name: "shared", Endpoint: "http://127.0.0.1:1/mcp"}}, Users: map[string]User{}}
	for i, id := range []string{"active", "expired", "disabled"} {
		expiry := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
		if id == "expired" {
			expiry = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		c.Users[id] = User{Tenant: "tenant-" + id, Principal: "principal-" + id, Token: maintenanceToken(byte(i + 1)), TokenExpiresAt: expiry, Allowed: []string{"shared__echo"}, Credentials: map[string]string{"shared": "synthetic-maintenance-binding"}}
	}
	return c
}
func maintenanceOptions(t *testing.T) PersistenceOptions {
	t.Helper()
	return PersistenceOptions{Path: filepath.Join(t.TempDir(), "state.sqlite"), Key: bytes.Repeat([]byte{0x67}, 32), Initialize: true}
}
func maintenanceSeed(t *testing.T, cfg Config, opts PersistenceOptions) {
	t.Helper()
	g, e := NewPersistent(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	if e = g.Close(); e != nil {
		t.Fatal(e)
	}
}
func maintenanceOpenGateway(t *testing.T, cfg Config, opts PersistenceOptions) *Gateway {
	t.Helper()
	opts.Initialize = false
	g, e := NewPersistent(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}
func maintenanceAuthenticate(t *testing.T, g *Gateway, token, user string, want bool) {
	t.Helper()
	r := httptest.NewRequest("GET", "http://gateway.invalid/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	identity, ok := g.authenticateEntry(r)
	if ok != want || (ok && identity != maintenanceIdentity(user)) {
		t.Fatalf("entry auth = %+v,%v; want user=%s accepted=%v", identity, ok, user, want)
	}
}
func maintenanceSQL(t *testing.T, path, statement string) {
	t.Helper()
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec(statement); e != nil {
		t.Fatal(e)
	}
}
func maintenanceLegacy(t *testing.T, fixture string) PersistenceOptions {
	t.Helper()
	opts := maintenanceOptions(t)
	opts.Initialize = false
	if e := os.WriteFile(opts.Path, nil, 0600); e != nil {
		t.Fatal(e)
	}
	maintenanceSQL(t, opts.Path, fixture)
	return opts
}

func TestMaintenanceReplaceRevokeRestartAndCAS(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	maintenanceSeed(t, cfg, opts)
	opts.Initialize = false
	m, e := OpenMaintenance(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	identity := maintenanceIdentity("active")
	old, e := m.Entry(identity)
	if e != nil {
		t.Fatal(e)
	}
	expiry := time.Now().UTC().Add(time.Hour)
	replacement := maintenanceToken(21)
	next, e := m.ReplaceEntry(identity, old.Generation, replacement, expiry)
	if e != nil {
		t.Fatal(e)
	}
	if next.Generation != old.Generation+1 || next.Revoked || !next.ExpiresAt.Equal(expiry) {
		t.Fatalf("incorrect replacement status: %+v", next)
	}
	if _, e = m.ReplaceEntry(identity, old.Generation, maintenanceToken(22), expiry); !errors.Is(e, ErrConflict) {
		t.Fatalf("stale replacement: %v", e)
	}
	if _, e = m.RevokeEntry(identity, old.Generation); !errors.Is(e, ErrConflict) {
		t.Fatalf("stale revoke: %v", e)
	}
	if e = m.Close(); e != nil {
		t.Fatal(e)
	}
	// Stale seeds must not remain an authority after a durable replacement.
	g := maintenanceOpenGateway(t, cfg, opts)
	maintenanceAuthenticate(t, g, maintenanceToken(1), "active", false)
	maintenanceAuthenticate(t, g, replacement, "active", true)
	originalBinding, e := g.Binding(identity, "shared")
	if e != nil {
		t.Fatal(e)
	}
	originalPolicy, e := g.Policy(identity)
	if e != nil {
		t.Fatal(e)
	}
	if e = g.Close(); e != nil {
		t.Fatal(e)
	}
	m, e = OpenMaintenance(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	revoked, e := m.RevokeEntry(identity, next.Generation)
	if e != nil {
		t.Fatal(e)
	}
	if !revoked.Revoked || revoked.Generation != next.Generation+1 {
		t.Fatalf("incorrect revoke: %+v", revoked)
	}
	_ = m.Close()
	user := cfg.Users["active"]
	user.Token = replacement
	user.TokenExpiresAt = time.Now().UTC().Add(365 * 24 * time.Hour)
	cfg.Users["active"] = user
	g = maintenanceOpenGateway(t, cfg, opts)
	maintenanceAuthenticate(t, g, replacement, "active", false)
	binding, _ := g.Binding(identity, "shared")
	policy, _ := g.Policy(identity)
	if binding != originalBinding || !reflect.DeepEqual(policy, originalPolicy) {
		t.Fatal("entry revoke mutated downstream binding or policy")
	}
}

func TestMaintenanceRenewalPreservesRevocationAndDisabled(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	g := maintenanceOpenGatewaySeed(t, cfg, opts)
	expired := maintenanceIdentity("expired")
	disabled := maintenanceIdentity("disabled")
	revoked, e := g.RevokeBinding(expired, "shared", 1)
	if e != nil {
		t.Fatal(e)
	}
	_, e = g.DisablePrincipal(disabled, 1)
	if e != nil {
		t.Fatal(e)
	}
	disabledBinding, _ := g.Binding(disabled, "shared")
	disabledPolicy, _ := g.Policy(disabled)
	_ = g.Close()
	opts.Initialize = false
	m, e := OpenMaintenance(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	expiredStatus, _ := m.Entry(expired)
	disabledStatus, _ := m.Entry(disabled)
	if _, e = m.ReplaceEntry(disabled, disabledStatus.Generation, maintenanceToken(41), time.Now().UTC().Add(time.Hour)); !errors.Is(e, ErrDenied) {
		t.Fatalf("disabled entry renewed: %v", e)
	}
	if _, e = m.ReplaceEntry(expired, expiredStatus.Generation, maintenanceToken(42), time.Now().UTC().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	_ = m.Close()
	g = maintenanceOpenGateway(t, cfg, opts)
	maintenanceAuthenticate(t, g, maintenanceToken(42), "expired", true)
	maintenanceAuthenticate(t, g, maintenanceToken(41), "disabled", false)
	got, _ := g.Binding(expired, "shared")
	gotDisabled, _ := g.Binding(disabled, "shared")
	policy, _ := g.Policy(disabled)
	if got != revoked || gotDisabled != disabledBinding || !reflect.DeepEqual(policy, disabledPolicy) {
		t.Fatal("renewal revived downstream authorization")
	}
}
func maintenanceOpenGatewaySeed(t *testing.T, cfg Config, opts PersistenceOptions) *Gateway {
	t.Helper()
	g, e := NewPersistent(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func TestMaintenanceInvalidReplacementHasNoEffects(t *testing.T) {
	for _, tc := range []struct {
		name, token string
		expiry      time.Time
		identity    Identity
	}{
		{"same", maintenanceToken(1), time.Now().UTC().Add(time.Hour), maintenanceIdentity("active")},
		{"duplicate", maintenanceToken(3), time.Now().UTC().Add(time.Hour), maintenanceIdentity("active")},
		{"weak", "synthetic-weak", time.Now().UTC().Add(time.Hour), maintenanceIdentity("active")},
		{"newline", maintenanceToken(24) + "\n", time.Now().UTC().Add(time.Hour), maintenanceIdentity("active")},
		{"zero-expiry", maintenanceToken(24), time.Time{}, maintenanceIdentity("active")},
		{"past-expiry", maintenanceToken(24), time.Now().UTC().Add(-time.Hour), maintenanceIdentity("active")},
		{"invalid-year", maintenanceToken(24), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), maintenanceIdentity("active")},
		{"wrong-identity", maintenanceToken(24), time.Now().UTC().Add(time.Hour), Identity{Tenant: "tenant-active", Principal: "principal-disabled"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := maintenanceConfig()
			opts := maintenanceOptions(t)
			maintenanceSeed(t, cfg, opts)
			opts.Initialize = false
			m, e := OpenMaintenance(cfg, opts)
			if e != nil {
				t.Fatal(e)
			}
			before, e := m.Entry(maintenanceIdentity("active"))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = m.ReplaceEntry(tc.identity, before.Generation, tc.token, tc.expiry); e == nil {
				t.Fatal("invalid replacement accepted")
			}
			after, e := m.Entry(maintenanceIdentity("active"))
			if e != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("rejection changed status: before=%+v after=%+v err=%v", before, after, e)
			}
			_ = m.Close()
			g := maintenanceOpenGateway(t, cfg, opts)
			maintenanceAuthenticate(t, g, maintenanceToken(1), "active", true)
		})
	}
}

func TestMaintenanceStoredAuthorityWithoutSeed(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	maintenanceSeed(t, cfg, opts)
	opts.Initialize = false
	m, e := OpenMaintenance(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	status, _ := m.Entry(maintenanceIdentity("active"))
	expiry := time.Now().UTC().Add(time.Hour)
	_, e = m.ReplaceEntry(maintenanceIdentity("active"), status.Generation, maintenanceToken(31), expiry)
	if e != nil {
		t.Fatal(e)
	}
	_ = m.Close()
	for id, u := range cfg.Users {
		u.Token = ""
		u.TokenExpiresAt = time.Time{}
		cfg.Users[id] = u
	}
	g := maintenanceOpenGateway(t, cfg, opts)
	maintenanceAuthenticate(t, g, maintenanceToken(31), "active", true)
	if !g.users["active"].TokenExpiresAt.Equal(expiry) || !g.entryStrong["active"] {
		t.Fatal("stored finite/strong entry authority lost without config seed")
	}
	if e = g.validateAccountAuth(); e != nil {
		t.Fatalf("account security incorrectly derived from absent seeds: %v", e)
	}
}

func TestMaintenanceFailedWriteIsAtomicAndFenced(t *testing.T) {
	for _, operation := range []string{"replace", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			cfg := maintenanceConfig()
			opts := maintenanceOptions(t)
			maintenanceSeed(t, cfg, opts)
			opts.Initialize = false
			maintenanceSQL(t, opts.Path, "CREATE TRIGGER maintenance_fail_final BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT, 'synthetic maintenance failure'); END")
			m, e := OpenMaintenance(cfg, opts)
			if e != nil {
				t.Fatal(e)
			}
			before, _ := m.Entry(maintenanceIdentity("active"))
			if operation == "replace" {
				_, e = m.ReplaceEntry(maintenanceIdentity("active"), before.Generation, maintenanceToken(51), time.Now().UTC().Add(time.Hour))
			} else {
				_, e = m.RevokeEntry(maintenanceIdentity("active"), before.Generation)
			}
			if !errors.Is(e, ErrStorage) {
				t.Fatalf("failed write acknowledged: %v", e)
			}
			if _, e = m.RevokeEntry(maintenanceIdentity("active"), before.Generation); e == nil {
				t.Fatal("poisoned maintenance reused without explicit reopen")
			}
			_ = m.Close()
			maintenanceSQL(t, opts.Path, "DROP TRIGGER maintenance_fail_final")
			m, e = OpenMaintenance(cfg, opts)
			if e != nil {
				t.Fatal(e)
			}
			after, e := m.Entry(maintenanceIdentity("active"))
			if e != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("partial state survived: %+v, %v", after, e)
			}
			_ = m.Close()
			g := maintenanceOpenGateway(t, cfg, opts)
			maintenanceAuthenticate(t, g, maintenanceToken(1), "active", true)
			maintenanceAuthenticate(t, g, maintenanceToken(51), "active", false)
			if g.AuditStatus().LastSequence != 0 {
				t.Fatal("failed transaction appended audit history")
			}
		})
	}
}

func TestMaintenanceReplacementTTLAndRevokedRenewal(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	maintenanceSeed(t, cfg, opts)
	opts.Initialize = false
	m, e := OpenMaintenance(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	identity := maintenanceIdentity("active")
	status, _ := m.Entry(identity)
	revoked, e := m.RevokeEntry(identity, status.Generation)
	if e != nil {
		t.Fatal(e)
	}
	expiry := time.Now().UTC().Add(300 * time.Millisecond)
	replacement, e := m.ReplaceEntry(identity, revoked.Generation, maintenanceToken(61), expiry)
	if e != nil {
		t.Fatal(e)
	}
	if replacement.Revoked || replacement.Generation != revoked.Generation+1 {
		t.Fatal("revoked entry renewal did not advance generation")
	}
	_ = m.Close()
	g := maintenanceOpenGateway(t, cfg, opts)
	maintenanceAuthenticate(t, g, maintenanceToken(61), "active", true)
	maintenanceAuthenticate(t, g, maintenanceToken(1), "active", false)
	time.Sleep(time.Until(expiry) + time.Millisecond)
	maintenanceAuthenticate(t, g, maintenanceToken(61), "active", false)
	_ = g.Close()
	// A stale config with later expiry must not renew a stored expired credential.
	u := cfg.Users["active"]
	u.Token = maintenanceToken(61)
	u.TokenExpiresAt = time.Now().UTC().Add(time.Hour)
	cfg.Users["active"] = u
	g = maintenanceOpenGateway(t, cfg, opts)
	maintenanceAuthenticate(t, g, maintenanceToken(61), "active", false)
}

func TestMaintenanceExclusiveOwnerAndNoServing(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	maintenanceSeed(t, cfg, opts)
	opts.Initialize = false
	m, e := OpenMaintenance(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	if other, e := NewPersistent(cfg, opts); e == nil {
		_ = other.Close()
		t.Fatal("server opened during offline maintenance")
	}
	if other, e := OpenMaintenance(cfg, opts); e == nil {
		_ = other.Close()
		t.Fatal("second maintenance owner opened")
	}
	maintenanceAuthenticate(t, m, maintenanceToken(1), "active", false)
	r := httptest.NewRequest("GET", "http://gateway.invalid/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+maintenanceToken(1))
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, r)
	if w.Code < 400 {
		t.Fatal("maintenance instance served authenticated HTTP")
	}
	if _, e = m.ReplaceEntry(maintenanceIdentity("active"), 1, maintenanceToken(62), time.Now().UTC().Add(time.Hour)); e != nil {
		t.Fatalf("offline owner unable to maintain: %v", e)
	}
}

func TestMaintenanceNoPlaintextCredentialPersistence(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	maintenanceSeed(t, cfg, opts)
	opts.Initialize = false
	m, e := OpenMaintenance(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	token := maintenanceToken(69)
	if _, e = m.ReplaceEntry(maintenanceIdentity("active"), 1, token, time.Now().UTC().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	_ = m.Close()
	data, e := os.ReadFile(opts.Path)
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{token, maintenanceToken(1), maintenanceToken(2), maintenanceToken(3), "synthetic-maintenance-binding"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatal("synthetic credential persisted in plaintext")
		}
	}
	g := maintenanceOpenGateway(t, cfg, opts)
	page, e := g.Audit(maintenanceIdentity("active"), 0, 100)
	if e != nil {
		t.Fatal(e)
	}
	if len(page.Events) != 1 || page.Events[0].Action != AuditActionEntryRotate || page.Events[0].Phase != AuditPhaseCommit {
		t.Fatalf("missing entry mutation audit: %+v", page)
	}
}

func maintenanceLegacyConfig() Config {
	c := maintenanceConfig()
	for i, id := range []string{"indefinite", "expired-binding"} {
		expiry := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
		if id == "indefinite" {
			expiry = time.Time{}
		}
		c.Users[id] = User{Tenant: "tenant-" + id, Principal: "principal-" + id, Token: maintenanceToken(byte(i + 4)), TokenExpiresAt: expiry, Allowed: []string{"shared__echo"}, Credentials: map[string]string{"shared": "synthetic-maintenance-binding"}}
	}
	return c
}

func TestMaintenanceAuthenticatedLegacyMigration(t *testing.T) {
	for _, fixture := range []struct {
		name, sql string
		oldEvents uint64
	}{{"v2", maintenanceFixtureV2, 0}, {"v3", maintenanceFixtureV3, 5}} {
		t.Run(fixture.name, func(t *testing.T) {
			cfg := maintenanceLegacyConfig()
			opts := maintenanceLegacy(t, fixture.sql)
			if g, e := NewPersistent(cfg, opts); e == nil {
				_ = g.Close()
				t.Fatal("normal server silently migrated legacy DB")
			}
			opts.Migrate = true
			m, e := OpenMaintenance(cfg, opts)
			if e != nil {
				t.Fatal(e)
			}
			if m.AuditStatus().LastSequence <= fixture.oldEvents {
				t.Fatal("migration provenance absent")
			}
			for _, id := range []string{"active", "expired", "disabled", "indefinite", "expired-binding"} {
				entry, e := m.Entry(maintenanceIdentity(id))
				if e != nil || entry.Generation != 1 || entry.Revoked {
					t.Fatalf("legacy entry conversion %s: %+v %v", id, entry, e)
				}
			}
			revoked, e := m.Binding(maintenanceIdentity("expired"), "shared")
			if e != nil || revoked.State != BindingRevoked || revoked.Generation != 2 {
				t.Fatalf("revoked binding resurrected: %+v %v", revoked, e)
			}
			disabled, e := m.Policy(maintenanceIdentity("disabled"))
			if e != nil || !disabled.Disabled || disabled.Version != 2 {
				t.Fatalf("disabled state lost: %+v %v", disabled, e)
			}
			policy, e := m.Policy(maintenanceIdentity("active"))
			if e != nil || policy.Version != 2 || len(policy.Allowed) != 0 {
				t.Fatalf("policy migration widened access: %+v %v", policy, e)
			}
			expiredBinding, e := m.Binding(maintenanceIdentity("expired-binding"), "shared")
			if e != nil || expiredBinding.Generation != 2 || expiredBinding.State != BindingActive || expiredBinding.ExpiresAt.IsZero() || !expiredBinding.ExpiresAt.Before(time.Now()) {
				t.Fatalf("expired binding lease extended: %+v %v", expiredBinding, e)
			}
			indefinite, e := m.Entry(maintenanceIdentity("indefinite"))
			if e != nil || !indefinite.ExpiresAt.IsZero() {
				t.Fatalf("legacy indefinite entry invented lease: %+v %v", indefinite, e)
			}
			_ = m.Close()
			opts.Migrate = false
			// Old seed data is explicitly not an authority for stored strength after migration.
			for id, u := range cfg.Users {
				u.Token = maintenanceToken(88)
				u.TokenExpiresAt = time.Now().UTC().Add(time.Hour)
				cfg.Users[id] = u
			}
			g := maintenanceOpenGateway(t, cfg, opts)
			maintenanceAuthenticate(t, g, maintenanceToken(1), "active", true)
			maintenanceAuthenticate(t, g, maintenanceToken(2), "expired", false)
			maintenanceAuthenticate(t, g, maintenanceToken(3), "disabled", false)
			maintenanceAuthenticate(t, g, maintenanceToken(4), "indefinite", true)
			maintenanceAuthenticate(t, g, maintenanceToken(88), "active", false)
			if e = g.validateAccountAuth(); e == nil {
				t.Fatal("legacy indefinite entry gained finite account authority")
			}
		})
	}
}

func TestMaintenanceLegacyCorruptionNeverResets(t *testing.T) {
	for _, fixture := range []struct{ name, sql string }{{"v2", maintenanceFixtureV2}, {"v3", maintenanceFixtureV3}} {
		for _, damage := range []string{"wrong-key", "mac", "ciphertext", "missing-binding", "unknown-version"} {
			t.Run(fixture.name+"/"+damage, func(t *testing.T) {
				cfg := maintenanceLegacyConfig()
				opts := maintenanceLegacy(t, fixture.sql)
				opts.Migrate = true
				switch damage {
				case "wrong-key":
					opts.Key = bytes.Repeat([]byte{0x68}, 32)
				case "mac":
					maintenanceSQL(t, opts.Path, "UPDATE meta SET state_mac=zeroblob(32)")
				case "ciphertext":
					maintenanceSQL(t, opts.Path, "UPDATE bindings SET credential=zeroblob(length(credential)) WHERE user_id='active'")
				case "missing-binding":
					maintenanceSQL(t, opts.Path, "DELETE FROM bindings WHERE user_id='active'")
				case "unknown-version":
					maintenanceSQL(t, opts.Path, "UPDATE meta SET version=999")
				}
				before, e := os.ReadFile(opts.Path)
				if e != nil {
					t.Fatal(e)
				}
				if m, e := OpenMaintenance(cfg, opts); e == nil {
					_ = m.Close()
					t.Fatal("corrupt or wrong-key source was migrated")
				}
				after, e := os.ReadFile(opts.Path)
				if e != nil {
					t.Fatal(e)
				}
				if !bytes.Equal(before, after) {
					t.Fatal("failed authentication changed source DB instead of failing closed")
				}
			})
		}
	}
}

const maintenanceFixtureV2 = `BEGIN TRANSACTION;
CREATE TABLE bindings(user_id TEXT NOT NULL REFERENCES principals(user_id),system TEXT NOT NULL,binding_id TEXT NOT NULL UNIQUE,generation INTEGER NOT NULL,state TEXT NOT NULL,expires_at TEXT NOT NULL,credential BLOB NOT NULL,PRIMARY KEY(user_id,system));
INSERT INTO "bindings" VALUES('indefinite','shared','binding-4',1,'active','',X'97D7C57F93766AF020812FEB88CFE22B22344E6F48FAEA00E77AFCB9C1A7AE732F23989D3F72391A35493CB9C71C6F9553AA2AA59BB425B46C');
INSERT INTO "bindings" VALUES('expired','shared','binding-2',2,'revoked','',X'5A6F2980AEFF5C1041DF713CA30DE702E0786A7DCCFA8DE6901A6B27');
INSERT INTO "bindings" VALUES('disabled','shared','binding-3',2,'revoked','',X'FC4F035D6E05890E3D2BCAA1D0F8B7F93E2D36BE676DA1F0505A98D9');
INSERT INTO "bindings" VALUES('active','shared','binding-1',1,'active','',X'204101986E060E901C3D6B81DC4CE9D36455F6D1EB2D85BA1A7D93F4D6D0AA717601ED39E8253FCA9532689042A26F86F75B223582C707EC72');
INSERT INTO "bindings" VALUES('expired-binding','shared','binding-5',2,'active','2026-10-22T11:20:35.58781621Z',X'BEFAB2DD03C40F94739DFE41C445DFEB6AB4CA397A8735F4DE9D47F9C3DC6E0DC70C18B481BE102C69ED400BABEFBDC8CD9E03FA2D288B193A');
CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,topology BLOB NOT NULL,key_check BLOB NOT NULL,state_mac BLOB NOT NULL);
INSERT INTO "meta" VALUES(1,2,X'C1CA1B91EBA05C348C8C7EEC4DAB9A622B62690E0D02FC9433FB96CE8DA045C5',X'A6E011FAB7FA29AFF21FD887D09EA6FCFD680E3F257447A359D8766BEBBF59F893019F409EDB314BFE46BFC81044',X'FE5ECC244AD45AE407146A2310FB78901B82478C2600C91D22A582F050E0364D');
CREATE TABLE principals(user_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,principal TEXT NOT NULL,token_hash BLOB NOT NULL,token_expires_at TEXT NOT NULL,policy_version INTEGER NOT NULL,disabled INTEGER NOT NULL,allowed TEXT NOT NULL,UNIQUE(tenant,principal));
INSERT INTO "principals" VALUES('active','tenant-active','principal-active',X'C7DB84EEBF04465A5419655DAC63E350B5FCAAAEC150437C996EFADF9688F26C','2035-01-01T00:00:00Z',2,0,'null');
INSERT INTO "principals" VALUES('expired','tenant-expired','principal-expired',X'31EB909D9430BC6F0B336BF9C9EF0D862144B33E1DA3DAE30444243BABDC22D2','2020-01-01T00:00:00Z',1,0,'["shared__echo"]');
INSERT INTO "principals" VALUES('disabled','tenant-disabled','principal-disabled',X'3EA604F5B0699B9BCF6EBCB797BAB26FAE501E609EC23801B786C185F5D94641','2035-01-01T00:00:00Z',2,1,'["shared__echo"]');
INSERT INTO "principals" VALUES('indefinite','tenant-indefinite','principal-indefinite',X'5DA4EDA65E2D1F5F470CD60BC471BCB4F7D9D8CFBCFD4F0244124A4CCA15A7EE','',1,0,'["shared__echo"]');
INSERT INTO "principals" VALUES('expired-binding','tenant-expired-binding','principal-expired-binding',X'FCEEB9897EC8E42D1BB0808A83CC9CA38ED5F8B8EE1488074FBDB4CDE3BAACC4','2035-01-01T00:00:00Z',1,0,'["shared__echo"]');
COMMIT;`

const maintenanceFixtureV3 = `BEGIN TRANSACTION;
CREATE TABLE audit(sequence INTEGER PRIMARY KEY,event TEXT NOT NULL,mac TEXT NOT NULL);
INSERT INTO "audit" VALUES(1,'{"actor":"operator","sequence":1,"identity_id":"23c832ee44c3389f18366db11fc349a72818c56ab1c127a099552562c24dc376","tenant_id":"0d1c48bfc67e51ce18f74846989c4c56950d4c1757f44b0da6e377e8e214c9ef","system_id":"926fa08e251c0a79e5efd30ae1940f5ce39f6a82e9b42a0f2cef012b70c5bd0a","request_id":"a398995590e7acea5389ed024bfab848d01097ab54c02706f0eee1b5746117cc","binding_version":2,"policy_version":1,"action":"binding_revoke","phase":"commit","result_class":"success","time":"2026-10-22T11:20:34.582332715Z","duration_ms":0}','709c10ed0d5b22a158781b2744a9890b29c1b8063acad0f7cbc921783da4c774');
INSERT INTO "audit" VALUES(2,'{"actor":"operator","sequence":2,"identity_id":"9dc75b59bc8cef2c5ab5d39b4f81caebffba1859b9aaa0dce90c13f1d6368baf","tenant_id":"2e305185691dd7d5ef56d4c59d66a432ef0c75c6ee41f5da23a4d0e152ec7815","request_id":"6ea3e7c224e90088dbe859a65251dfdcfef8acef03864a4872ef5236d02d7226","binding_version":0,"policy_version":2,"action":"principal_disable","phase":"commit","result_class":"success","time":"2026-10-22T11:20:34.585389312Z","duration_ms":0}','5e0c8890b2a9490010ae72709ba66ab980ac4c89dc2bd7e1821f8bfc16dc5f4b');
INSERT INTO "audit" VALUES(3,'{"actor":"operator","sequence":3,"identity_id":"4b7f843d284c995a4b0f7f5fa7609e0ab4d4587ef9602526d0e6ddb27d6f9aef","tenant_id":"293a8c66e84ab64b03ca8aa0448b062ab4b464351eff36ad0a7d96754ab8a014","request_id":"27afc02dba3575366a3c79f658328f0a0d0836464bdb54d2d872fa56b69625ad","binding_version":0,"policy_version":2,"action":"policy_update","phase":"commit","result_class":"success","time":"2026-10-22T11:20:34.586735024Z","duration_ms":0}','b25df3dbccdf94135b4ec4c60ee918a28d47a247070f910be490123abd14134f');
INSERT INTO "audit" VALUES(4,'{"actor":"operator","sequence":4,"identity_id":"4dcdc20a9cd74a23098f3b1f2a828afed34f0f7dcc3624dc313a5ed04a6a5735","tenant_id":"39f5989cce7d726fcff2745911d1fc55bd60bc471e976378ed9aa6de5b9abbee","system_id":"926fa08e251c0a79e5efd30ae1940f5ce39f6a82e9b42a0f2cef012b70c5bd0a","request_id":"453520a9c964b724c449863bd2dd2ccf2b30660adb7e172612bb717a1ebe7b02","binding_version":2,"policy_version":1,"action":"binding_replace","phase":"commit","result_class":"success","time":"2026-10-22T11:20:34.588156487Z","duration_ms":0}','3c4b99d012361506d57537700880cf05da1789fccbb2cf376140acd8314a9949');
INSERT INTO "audit" VALUES(5,'{"actor":"operator","sequence":5,"identity_id":"23c832ee44c3389f18366db11fc349a72818c56ab1c127a099552562c24dc376","tenant_id":"0d1c48bfc67e51ce18f74846989c4c56950d4c1757f44b0da6e377e8e214c9ef","system_id":"926fa08e251c0a79e5efd30ae1940f5ce39f6a82e9b42a0f2cef012b70c5bd0a","request_id":"a398995590e7acea5389ed024bfab848d01097ab54c02706f0eee1b5746117cc","binding_version":2,"policy_version":1,"action":"discovery","phase":"start","result_class":"pending","time":"2026-10-22T11:20:34.582332715Z","duration_ms":0}','d5597d689027440a8d25c863015cd6e7b73c1bdeeadc8db52e76e8eef3b8be17');
CREATE TABLE bindings(user_id TEXT NOT NULL REFERENCES principals(user_id),system TEXT NOT NULL,binding_id TEXT NOT NULL UNIQUE,generation INTEGER NOT NULL,state TEXT NOT NULL,expires_at TEXT NOT NULL,credential BLOB NOT NULL,PRIMARY KEY(user_id,system));
INSERT INTO "bindings" VALUES('indefinite','shared','binding-4',1,'active','',X'97D7C57F93766AF020812FEB88CFE22B22344E6F48FAEA00E77AFCB9C1A7AE732F23989D3F72391A35493CB9C71C6F9553AA2AA59BB425B46C');
INSERT INTO "bindings" VALUES('expired','shared','binding-2',2,'revoked','',X'5A6F2980AEFF5C1041DF713CA30DE702E0786A7DCCFA8DE6901A6B27');
INSERT INTO "bindings" VALUES('disabled','shared','binding-3',2,'revoked','',X'FC4F035D6E05890E3D2BCAA1D0F8B7F93E2D36BE676DA1F0505A98D9');
INSERT INTO "bindings" VALUES('active','shared','binding-1',1,'active','',X'204101986E060E901C3D6B81DC4CE9D36455F6D1EB2D85BA1A7D93F4D6D0AA717601ED39E8253FCA9532689042A26F86F75B223582C707EC72');
INSERT INTO "bindings" VALUES('expired-binding','shared','binding-5',2,'active','2026-10-22T11:20:35.58781621Z',X'BEFAB2DD03C40F94739DFE41C445DFEB6AB4CA397A8735F4DE9D47F9C3DC6E0DC70C18B481BE102C69ED400BABEFBDC8CD9E03FA2D288B193A');
CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,topology BLOB NOT NULL,key_check BLOB NOT NULL,state_mac BLOB NOT NULL,audit_sequence INTEGER NOT NULL,audit_head TEXT NOT NULL,audit_id_key BLOB NOT NULL);
INSERT INTO "meta" VALUES(1,3,X'C1CA1B91EBA05C348C8C7EEC4DAB9A622B62690E0D02FC9433FB96CE8DA045C5',X'D55B908E63AF7854576E1E3842CA0E48B552218A0533298FE14418C57E411D27D0FFF1A9F441A99ED1CAA2787E84',X'42FFF7B8AA2D2164C008700490614D0A4C536D9171456326C48F7E4F51D29B41',5,'d5597d689027440a8d25c863015cd6e7b73c1bdeeadc8db52e76e8eef3b8be17',X'032AB77467D4C5D8A731C9D08AAAA94964E1165BE75572092EF3F477495113F9A1B8AD0323C6ABB96C9C7FDD1AA28028BD76F6339997E5848936E77A');
CREATE TABLE principals(user_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,principal TEXT NOT NULL,token_hash BLOB NOT NULL,token_expires_at TEXT NOT NULL,policy_version INTEGER NOT NULL,disabled INTEGER NOT NULL,allowed TEXT NOT NULL,UNIQUE(tenant,principal));
INSERT INTO "principals" VALUES('active','tenant-active','principal-active',X'C7DB84EEBF04465A5419655DAC63E350B5FCAAAEC150437C996EFADF9688F26C','2035-01-01T00:00:00Z',2,0,'null');
INSERT INTO "principals" VALUES('expired','tenant-expired','principal-expired',X'31EB909D9430BC6F0B336BF9C9EF0D862144B33E1DA3DAE30444243BABDC22D2','2020-01-01T00:00:00Z',1,0,'["shared__echo"]');
INSERT INTO "principals" VALUES('disabled','tenant-disabled','principal-disabled',X'3EA604F5B0699B9BCF6EBCB797BAB26FAE501E609EC23801B786C185F5D94641','2035-01-01T00:00:00Z',2,1,'["shared__echo"]');
INSERT INTO "principals" VALUES('indefinite','tenant-indefinite','principal-indefinite',X'5DA4EDA65E2D1F5F470CD60BC471BCB4F7D9D8CFBCFD4F0244124A4CCA15A7EE','',1,0,'["shared__echo"]');
INSERT INTO "principals" VALUES('expired-binding','tenant-expired-binding','principal-expired-binding',X'FCEEB9897EC8E42D1BB0808A83CC9CA38ED5F8B8EE1488074FBDB4CDE3BAACC4','2035-01-01T00:00:00Z',1,0,'["shared__echo"]');
COMMIT;`

func maintenanceSemanticRecords(records map[string]storedPrincipal) map[string]storedPrincipal {
	result := map[string]storedPrincipal{}
	for id, r := range records {
		r.Bindings = append([]storedBinding(nil), r.Bindings...)
		for i := range r.Bindings {
			r.Bindings[i].Credential = nil
		}
		result[id] = r
	}
	return result
}
func TestMaintenanceRootRotationPreservesAuthenticatedState(t *testing.T) {
	cfg := maintenanceLegacyConfig()
	opts := maintenanceLegacy(t, maintenanceFixtureV3)
	opts.Migrate = true
	m, e := OpenMaintenance(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	before := maintenanceSemanticRecords(m.store.records)
	auditBefore, e := m.auditRing.Read(AuditFilter{})
	if e != nil {
		t.Fatal(e)
	}
	idkey := append([]byte(nil), m.auditIDKey...)
	oldCiphers := map[string][]byte{}
	for id, r := range m.store.records {
		for _, b := range r.Bindings {
			oldCiphers[id+"/"+b.System] = append([]byte(nil), b.Credential...)
		}
	}
	newKey := bytes.Repeat([]byte{0x71}, 32)
	if e = m.RotateKey(newKey); e != nil {
		t.Fatal(e)
	}
	_ = m.Close()
	opts.Migrate = false
	if g, e := NewPersistent(cfg, opts); e == nil {
		_ = g.Close()
		t.Fatal("old key remained usable after rotation")
	}
	opts.Key = newKey
	g := maintenanceOpenGateway(t, cfg, opts)
	if !reflect.DeepEqual(before, maintenanceSemanticRecords(g.store.records)) {
		t.Fatal("rotation changed policies, generations, credentials metadata or revocations")
	}
	if !bytes.Equal(idkey, g.auditIDKey) {
		t.Fatal("rotation changed historical audit pseudonyms")
	}
	page, e := g.auditRing.Read(AuditFilter{})
	if e != nil {
		t.Fatal(e)
	}
	if len(page.Events) != len(auditBefore.Events)+1 || !reflect.DeepEqual(page.Events[:len(auditBefore.Events)], auditBefore.Events) {
		t.Fatal("rotation changed or lost historical audit records")
	}
	if page.Events[len(page.Events)-1].Action != AuditActionStorageRotate {
		t.Fatal("rotation audit provenance missing")
	}
	seen := map[string]bool{}
	for id, r := range g.store.records {
		for _, b := range r.Bindings {
			if bytes.Equal(oldCiphers[id+"/"+b.System], b.Credential) {
				t.Fatal("credential not reencrypted")
			}
			if seen[string(b.Credential)] {
				t.Fatal("repeated plaintext reused a ciphertext nonce")
			}
			seen[string(b.Credential)] = true
		}
	}
	maintenanceAuthenticate(t, g, maintenanceToken(1), "active", true)
	maintenanceAuthenticate(t, g, maintenanceToken(2), "expired", false)
	maintenanceAuthenticate(t, g, maintenanceToken(3), "disabled", false)
}

func TestMaintenanceRootRotationInvalidKeyNoEffect(t *testing.T) {
	for _, key := range [][]byte{nil, bytes.Repeat([]byte{1}, 31), bytes.Repeat([]byte{1}, 33), bytes.Repeat([]byte{0x67}, 32)} {
		t.Run(base64.RawURLEncoding.EncodeToString(key), func(t *testing.T) {
			cfg := maintenanceConfig()
			opts := maintenanceOptions(t)
			maintenanceSeed(t, cfg, opts)
			opts.Initialize = false
			m, e := OpenMaintenance(cfg, opts)
			if e != nil {
				t.Fatal(e)
			}
			before := maintenanceSemanticRecords(m.store.records)
			seq := m.store.auditSequence
			if e = m.RotateKey(key); e == nil {
				t.Fatal("invalid or identical new key accepted")
			}
			if !reflect.DeepEqual(before, maintenanceSemanticRecords(m.store.records)) || m.store.auditSequence != seq {
				t.Fatal("invalid key changed in-memory state")
			}
			_ = m.Close()
			g := maintenanceOpenGateway(t, cfg, opts)
			maintenanceAuthenticate(t, g, maintenanceToken(1), "active", true)
			if g.AuditStatus().LastSequence != seq {
				t.Fatal("invalid rotation changed audit")
			}
		})
	}
}

func TestMaintenanceRootRotationFailedWriteReopensExactlyOldState(t *testing.T) {
	for _, point := range []string{"audit", "binding", "manifest"} {
		t.Run(point, func(t *testing.T) {
			cfg := maintenanceLegacyConfig()
			opts := maintenanceLegacy(t, maintenanceFixtureV3)
			opts.Migrate = true
			m, e := OpenMaintenance(cfg, opts)
			if e != nil {
				t.Fatal(e)
			}
			before := maintenanceSemanticRecords(m.store.records)
			auditBefore, _ := m.auditRing.Read(AuditFilter{})
			_ = m.Close()
			opts.Migrate = false
			target := "BEFORE UPDATE ON meta"
			if point == "audit" {
				target = "BEFORE UPDATE ON audit"
			}
			if point == "binding" {
				target = "BEFORE INSERT ON bindings WHEN NEW.user_id='expired-binding'"
			}
			maintenanceSQL(t, opts.Path, "CREATE TRIGGER maintenance_fail_rotation "+target+" BEGIN SELECT RAISE(ABORT, 'synthetic rotation failure'); END")
			m, e = OpenMaintenance(cfg, opts)
			if e != nil {
				t.Fatal(e)
			}
			newKey := bytes.Repeat([]byte{0x72}, 32)
			if e = m.RotateKey(newKey); !errors.Is(e, ErrStorage) {
				t.Fatalf("failed rotation acknowledged: %v", e)
			}
			// Any storage fault must force explicit reopen instead of guessing whether a commit happened.
			if _, e = m.RevokeEntry(maintenanceIdentity("active"), 1); e == nil {
				t.Error("storage-failed rotation owner remained reusable")
			}
			_ = m.Close()
			maintenanceSQL(t, opts.Path, "DROP TRIGGER maintenance_fail_rotation")
			wrong := opts
			wrong.Key = newKey
			if g, e := NewPersistent(cfg, wrong); e == nil {
				_ = g.Close()
				t.Fatal("new key accepted after aborted rotation")
			}
			g := maintenanceOpenGateway(t, cfg, opts)
			if !reflect.DeepEqual(before, maintenanceSemanticRecords(g.store.records)) {
				t.Fatal("partial rotation changed semantic state")
			}
			auditAfter, _ := g.auditRing.Read(AuditFilter{})
			if !reflect.DeepEqual(auditBefore.Events, auditAfter.Events) {
				t.Fatal("partial rotation changed audit records")
			}
		})
	}
}

// Test-only SQL driver loses the acknowledgement after a real successful commit.
// It never changes production hooks or external files and establishes uncertainty
// by authenticating a fresh owner with each retained key afterward.
var maintenanceDriverCounter atomic.Uint64

type maintenanceLostAckDriver struct{ inner driver.Driver }

func (d maintenanceLostAckDriver) Open(name string) (driver.Conn, error) {
	c, e := d.inner.Open(name)
	if e != nil {
		return nil, e
	}
	return maintenanceLostAckConn{c}, nil
}

type maintenanceLostAckConn struct{ driver.Conn }

func (c maintenanceLostAckConn) Begin() (driver.Tx, error) {
	tx, e := c.Conn.Begin()
	if e != nil {
		return nil, e
	}
	return maintenanceLostAckTx{tx}, nil
}

type maintenanceLostAckTx struct{ driver.Tx }

func (tx maintenanceLostAckTx) Commit() error {
	if e := tx.Tx.Commit(); e != nil {
		return e
	}
	return errors.New("synthetic commit acknowledgement lost")
}
func maintenanceLoseCommitAck(t *testing.T, g *Gateway, path string) {
	t.Helper()
	if e := g.store.conn.Close(); e != nil {
		t.Fatal(e)
	}
	if e := g.store.db.Close(); e != nil {
		t.Fatal(e)
	}
	name := fmt.Sprintf("maintenance-lost-ack-%d", maintenanceDriverCounter.Add(1))
	sql.Register(name, maintenanceLostAckDriver{&sqlite.Driver{}})
	db, e := sql.Open(name, path)
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	conn, e := db.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	for _, q := range []string{"PRAGMA busy_timeout=0", "PRAGMA locking_mode=EXCLUSIVE", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON"} {
		if _, e = conn.ExecContext(context.Background(), q); e != nil {
			t.Fatal(e)
		}
	}
	g.store.db = db
	g.store.conn = conn
}
func TestMaintenanceLostCommitAcknowledgementRequiresExplicitReopen(t *testing.T) {
	for _, operation := range []string{"entry", "root-key"} {
		t.Run(operation, func(t *testing.T) {
			cfg := maintenanceConfig()
			opts := maintenanceOptions(t)
			maintenanceSeed(t, cfg, opts)
			opts.Initialize = false
			m, e := OpenMaintenance(cfg, opts)
			if e != nil {
				t.Fatal(e)
			}
			maintenanceLoseCommitAck(t, m, opts.Path)
			newKey := bytes.Repeat([]byte{0x74}, 32)
			if operation == "entry" {
				_, e = m.ReplaceEntry(maintenanceIdentity("active"), 1, maintenanceToken(75), time.Now().UTC().Add(time.Hour))
			} else {
				e = m.RotateKey(newKey)
			}
			if !errors.Is(e, ErrStorage) {
				t.Fatalf("lost acknowledgement not reported as storage uncertainty: %v", e)
			}
			if _, e = m.RevokeEntry(maintenanceIdentity("active"), 1); e == nil {
				t.Fatal("uncertain owner allowed further mutation")
			}
			_ = m.Close()
			if operation == "root-key" {
				if old, e := NewPersistent(cfg, opts); e == nil {
					_ = old.Close()
					t.Fatal("old key accepted after durable rotation")
				}
				opts.Key = newKey
			}
			g := maintenanceOpenGateway(t, cfg, opts)
			if operation == "entry" {
				status, e := g.Entry(maintenanceIdentity("active"))
				if e != nil || status.Generation != 2 {
					t.Fatalf("actual committed entry state missing: %+v %v", status, e)
				}
				maintenanceAuthenticate(t, g, maintenanceToken(75), "active", true)
				maintenanceAuthenticate(t, g, maintenanceToken(1), "active", false)
			} else {
				maintenanceAuthenticate(t, g, maintenanceToken(1), "active", true)
			}
		})
	}
}

func TestMaintenanceLegacyMigrationDDLFailureRestoresSource(t *testing.T) {
	for _, fixture := range []struct{ name, sql string }{{"v2", maintenanceFixtureV2}, {"v3", maintenanceFixtureV3}} {
		t.Run(fixture.name, func(t *testing.T) {
			cfg := maintenanceLegacyConfig()
			opts := maintenanceLegacy(t, fixture.sql)
			opts.Migrate = true
			maintenanceSQL(t, opts.Path, "CREATE TRIGGER maintenance_fail_migration BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT, 'synthetic migration final-write failure'); END")
			before, e := os.ReadFile(opts.Path)
			if e != nil {
				t.Fatal(e)
			}
			if m, e := OpenMaintenance(cfg, opts); e == nil {
				_ = m.Close()
				t.Fatal("migration final-write failure acknowledged")
			}
			after, e := os.ReadFile(opts.Path)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("failed migration left modified source DDL or records")
			}
			db, e := sql.Open("sqlite", opts.Path)
			if e != nil {
				t.Fatal(e)
			}
			var columns int
			e = db.QueryRow("SELECT count(*) FROM pragma_table_info('principals') WHERE name IN ('entry_generation','entry_revoked','entry_strong')").Scan(&columns)
			_ = db.Close()
			if e != nil || columns != 0 {
				t.Fatalf("transactional ALTER TABLE escaped rollback: %d %v", columns, e)
			}
			maintenanceSQL(t, opts.Path, "DROP TRIGGER maintenance_fail_migration")
			m, e := OpenMaintenance(cfg, opts)
			if e != nil {
				t.Fatalf("original authenticated source no longer migrates after rollback: %v", e)
			}
			_ = m.Close()
			opts.Migrate = false
			g := maintenanceOpenGateway(t, cfg, opts)
			p, e := g.Policy(maintenanceIdentity("disabled"))
			if e != nil || !p.Disabled {
				t.Fatal("retry widened disabled policy")
			}
		})
	}
}

func TestMaintenanceAuthenticatedOldSnapshotIsNotFreshnessProtected(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	maintenanceSeed(t, cfg, opts)
	opts.Initialize = false
	old, e := os.ReadFile(opts.Path)
	if e != nil {
		t.Fatal(e)
	}
	m, e := OpenMaintenance(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.RevokeEntry(maintenanceIdentity("active"), 1); e != nil {
		t.Fatal(e)
	}
	_ = m.Close()
	g := maintenanceOpenGateway(t, cfg, opts)
	maintenanceAuthenticate(t, g, maintenanceToken(1), "active", false)
	_ = g.Close()
	// Deliberately quarantined second synthetic file: authentication proves integrity,
	// not freshness. This is not an authorized production backup restore workflow.
	replay := opts
	replay.Path = filepath.Join(t.TempDir(), "quarantined-old-snapshot.sqlite")
	if e = os.WriteFile(replay.Path, old, 0600); e != nil {
		t.Fatal(e)
	}
	g = maintenanceOpenGateway(t, cfg, replay)
	maintenanceAuthenticate(t, g, maintenanceToken(1), "active", true)
}

func TestMaintenanceEntryGenerationOverflowFailsClosed(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	maintenanceSeed(t, cfg, opts)
	opts.Initialize = false
	m, e := OpenMaintenance(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	// Manufacture an authenticated synthetic boundary state, without ever letting
	// a public mutation API wrap the SQLite signed integer generation.
	r := m.store.records["active"]
	r.EntryGeneration = math.MaxInt64
	m.store.records["active"] = r
	m.principals["active"].entry.Generation = math.MaxInt64
	if _, e = m.store.conn.ExecContext(context.Background(), "UPDATE principals SET entry_generation=? WHERE user_id='active'", int64(math.MaxInt64)); e != nil {
		t.Fatal(e)
	}
	if _, e = m.store.conn.ExecContext(context.Background(), "UPDATE meta SET state_mac=?", m.store.stateMAC(m.store.records)); e != nil {
		t.Fatal(e)
	}
	_ = m.Close()
	m, e = OpenMaintenance(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	if _, e = m.RevokeEntry(maintenanceIdentity("active"), math.MaxInt64); !errors.Is(e, ErrConflict) {
		t.Fatalf("generation overflow revoke accepted: %v", e)
	}
	if _, e = m.ReplaceEntry(maintenanceIdentity("active"), math.MaxInt64, maintenanceToken(79), time.Now().UTC().Add(time.Hour)); !errors.Is(e, ErrConflict) {
		t.Fatalf("generation overflow replacement accepted: %v", e)
	}
	status, e := m.Entry(maintenanceIdentity("active"))
	if e != nil || status.Generation != math.MaxInt64 || status.Revoked {
		t.Fatalf("overflow changed durable authority: %+v %v", status, e)
	}
}

func TestMaintenanceArchiveRotateReopenArchivePreservesAnchorAndOrphan(t *testing.T) {
	cfg := maintenanceLegacyConfig()
	opts := maintenanceLegacy(t, maintenanceFixtureV3)
	opts.Migrate = true
	m, e := OpenMaintenance(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	opts.Migrate = false
	if m.AuditStatus().Unfinished != 1 {
		t.Fatal("legacy unfinished discovery not recovered")
	}
	firstPath := filepath.Join(t.TempDir(), "first-archive.json")
	first, e := m.ArchiveAudit(firstPath, m.AuditStatus().LastSequence)
	if e != nil {
		t.Fatal(e)
	}
	if first.ArchivedUnfinished != 1 {
		t.Fatal("archive lost orphan accounting")
	}
	firstBytes, e := os.ReadFile(firstPath)
	if e != nil {
		t.Fatal(e)
	}
	base := m.store.auditBaseSequence
	anchor := m.store.auditArchiveHash
	newKey := bytes.Repeat([]byte{0x78}, 32)
	if e = m.RotateKey(newKey); e != nil {
		t.Fatal(e)
	}
	_ = m.Close()
	opts.Key = newKey
	m, e = OpenMaintenance(cfg, opts)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	if m.store.auditBaseSequence != base || m.store.auditArchiveHash != anchor || m.AuditStatus().Unfinished != 1 || m.AuditStatus().ArchivedUnfinished != 1 {
		t.Fatal("rotation/reopen changed archive anchor or orphan accounting")
	}
	secondPath := filepath.Join(t.TempDir(), "second-archive.json")
	second, e := m.ArchiveAudit(secondPath, m.AuditStatus().LastSequence)
	if e != nil {
		t.Fatal(e)
	}
	if second.ArchivedUnfinished != 1 {
		t.Fatal("second archive lost historical orphan")
	}
	secondBytes, e := os.ReadFile(secondPath)
	if e != nil {
		t.Fatal(e)
	}
	var envelope struct {
		Archive struct {
			PreviousArchiveSHA256 string `json:"previous_archive_sha256"`
		} `json:"archive"`
	}
	if e = json.Unmarshal(secondBytes, &envelope); e != nil {
		t.Fatal(e)
	}
	if envelope.Archive.PreviousArchiveSHA256 != first.SHA256 {
		t.Fatal("new-key archive no longer links old-key historical archive")
	}
	unchanged, e := os.ReadFile(firstPath)
	if e != nil || !bytes.Equal(firstBytes, unchanged) {
		t.Fatal("rotation rewrote external historical archive")
	}
}
