package gateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// All runtime-registry fixtures use synthetic credentials and non-listening
// loopback endpoints. Preview and apply must never require network access.
func registryPost(h http.Handler, path string, in map[string]any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(in)
	return adminRequest(h, "POST", "/admin/api/config/"+path, string(b), maintenanceToken(99), nil)
}
func registryCurrent(t *testing.T, h http.Handler) map[string]any {
	t.Helper()
	w := adminRequest(h, "GET", "/admin/api/config/current", "", maintenanceToken(99), nil)
	if w.Code != 200 {
		t.Fatalf("current %d %s", w.Code, w.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func registryPreview(t *testing.T, h http.Handler, revision uint64, systems []System) map[string]any {
	t.Helper()
	in := map[string]any{"expected_revision": revision, "systems": systems}
	w := registryPost(h, "preview", in)
	if w.Code != 200 {
		t.Fatalf("preview %d %s", w.Code, w.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["confirmation_id"] == nil || out["candidate_digest"] == nil {
		t.Fatalf("incomplete preview %s", w.Body)
	}
	in["confirmation_id"] = out["confirmation_id"]
	in["candidate_digest"] = out["candidate_digest"]
	return in
}
func registryApply(t *testing.T, h http.Handler, revision uint64, systems []System) map[string]any {
	t.Helper()
	w := registryPost(h, "apply", registryPreview(t, h, revision, systems))
	if w.Code != 200 {
		t.Fatalf("apply %d %s", w.Code, w.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["applied"] != true || out["persistent"] != true {
		t.Fatalf("not durable applied %s", w.Body)
	}
	return out
}
func registryAdded(cfg Config) []System {
	out := append([]System(nil), cfg.Systems...)
	return append(out, System{Name: "added", Endpoint: "http://127.0.0.1:2/mcp", QuotaSubject: "synthetic-shared"})
}
func registryGateway(t *testing.T, cfg Config) (*Gateway, PersistenceOptions, http.Handler) {
	t.Helper()
	opts := maintenanceOptions(t)
	g, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g, opts, adminTestHandler(t, g)
}
func TestRuntimeRegistryAddPreservesRevocationAndReopensSeed(t *testing.T) {
	cfg := maintenanceConfig()
	g, opts, h := registryGateway(t, cfg)
	if _, err := g.DisablePrincipal(maintenanceIdentity("disabled"), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := g.RevokeBinding(maintenanceIdentity("active"), "shared", 1); err != nil {
		t.Fatal(err)
	}
	before, _ := g.Policy(maintenanceIdentity("active"))
	registryApply(t, h, 0, registryAdded(cfg))
	for id, p := range g.principals {
		b := p.bindings["added"]
		if b == nil || b.credential != "" || b.info.Generation != 1 {
			t.Fatalf("bad empty binding %s %+v", id, b)
		}
		want := BindingUnbound
		if p.disabled {
			want = BindingRevoked
		}
		if b.info.State != want {
			t.Fatalf("state %s %s", id, b.info.State)
		}
		for _, name := range p.allowed {
			if strings.HasPrefix(name, "added__") {
				t.Fatal("granted new authority")
			}
		}
	}
	after, _ := g.Policy(maintenanceIdentity("active"))
	if !reflect.DeepEqual(before, after) {
		t.Fatal("policy changed by service addition")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Initialize = false
	reopened, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, ok := reopened.systems["added"]; !ok {
		t.Fatal("runtime service lost on seed reopen")
	}
	b, _ := reopened.Binding(maintenanceIdentity("active"), "shared")
	if b.State != BindingRevoked {
		t.Fatal("seed credential revived")
	}
	p, _ := reopened.Policy(maintenanceIdentity("disabled"))
	if !p.Disabled {
		t.Fatal("disabled seed revived")
	}
	current := registryCurrent(t, adminTestHandler(t, reopened))
	if current["revision"] != float64(1) {
		t.Fatalf("revision %+v", current)
	}
}
func TestRuntimeRegistryTimeoutOnlyAndOldV4MACRejected(t *testing.T) {
	cfg := maintenanceConfig()
	cfg.Users = map[string]User{}
	g, opts, h := registryGateway(t, cfg)
	systems := append([]System(nil), cfg.Systems...)
	systems[0].Timeouts = &TimeoutConfig{DiscoveryMS: 700, CallMS: 900, ResponseHeaderMS: 400}
	registryApply(t, h, 0, systems)
	// Freeze the old v4 input instead of calling the new canonicalState helper.
	s := g.store
	ids := make([]string, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	records := make([]storedPrincipal, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.records[id])
	}
	encoded, _ := json.Marshal(struct {
		Version           int
		Topology          []byte
		Records           []storedPrincipal
		AuditSequence     uint64
		AuditHead         string
		AuditIDKey        []byte
		AuditBaseSequence uint64
		AuditBaseHead     string
		AuditArchiveHash  string
	}{4, s.topology, records, s.auditSequence, s.auditHead, s.auditIDCipher, s.auditBaseSequence, s.auditBaseHead, s.auditArchiveHash})
	old := hmac.New(sha256.New, s.macKey)
	old.Write(encoded)
	var stored []byte
	if err := s.conn.QueryRowContext(context.Background(), "SELECT state_mac FROM meta WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if hmac.Equal(old.Sum(nil), stored) {
		t.Fatal("old binary could silently ignore timeout manifest")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Initialize = false
	r, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !reflect.DeepEqual(r.systems["shared"].Timeouts, systems[0].Timeouts) {
		t.Fatal("timeout was not durably restored")
	}
}
func TestRuntimeRegistryRejectsDestructiveChanges(t *testing.T) {
	cfg := maintenanceConfig()
	g, _, h := registryGateway(t, cfg)
	cases := map[string]func([]System) []System{
		"endpoint": func(s []System) []System { s[0].Endpoint = "http://127.0.0.1:3/mcp"; return s },
		"auth":     func(s []System) []System { s[0].Auth = AuthConfig{Mode: "raw"}; return s },
		"network": func(s []System) []System {
			s[0].Network = &NetworkPolicy{AllowedIPs: []string{"127.0.0.1"}, AllowInsecureHTTP: true}
			return s
		},
		"quota":  func(s []System) []System { s[0].QuotaSubject = "changed"; return s },
		"delete": func(s []System) []System { return []System{} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			w := registryPost(h, "preview", map[string]any{"expected_revision": 0, "systems": change(append([]System(nil), cfg.Systems...))})
			if w.Code != 400 || !strings.Contains(w.Body.String(), "unsupported_destructive_change") {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
	if len(g.systems) != 1 || registryCurrent(t, h)["revision"] != float64(0) {
		t.Fatal("rejected change mutated state")
	}
}
func TestRuntimeRegistryConfirmationCASAndRequestBinding(t *testing.T) {
	cfg := maintenanceConfig()
	_, _, h := registryGateway(t, cfg)
	a := registryPreview(t, h, 0, registryAdded(cfg))
	b := registryPreview(t, h, 0, registryAdded(cfg))
	if w := registryPost(h, "apply", a); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for _, in := range []map[string]any{a, b} {
		if w := registryPost(h, "apply", in); w.Code != 409 {
			t.Fatalf("stale/replay %d %s", w.Code, w.Body)
		}
	}
	currentSystems := registryAdded(cfg)
	currentSystems[0].Timeouts = &TimeoutConfig{700, 900, 400}
	c := registryPreview(t, h, 1, currentSystems)
	altered := append([]System(nil), currentSystems...)
	altered[0].Timeouts = &TimeoutConfig{800, 900, 400}
	c["systems"] = altered
	if w := registryPost(h, "apply", c); w.Code != 409 {
		t.Fatalf("ticket mismatch %d %s", w.Code, w.Body)
	}
	if registryCurrent(t, h)["revision"] != float64(1) {
		t.Fatal("mismatched preview committed")
	}
}
func TestRuntimeRegistryMemoryModeDoesNotPretendDurability(t *testing.T) {
	cfg := maintenanceConfig()
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h := adminTestHandler(t, g)
	if registryCurrent(t, h)["apply_supported"] != false {
		t.Fatal("memory apply advertised")
	}
	if w := registryPost(h, "preview", map[string]any{"expected_revision": 0, "systems": registryAdded(cfg)}); w.Code != 403 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
func TestRuntimeRegistryManifestTamperingFailsClosed(t *testing.T) {
	for name, sql := range map[string]string{"revision": "UPDATE runtime_config SET revision=revision+1", "systems": "UPDATE runtime_config SET systems_json='[]'", "format": "PRAGMA ignore_check_constraints=ON; UPDATE runtime_config SET format=2", "row_removed": "DELETE FROM runtime_config", "table_removed": "DROP TABLE runtime_config"} {
		t.Run(name, func(t *testing.T) {
			cfg := maintenanceConfig()
			g, opts, h := registryGateway(t, cfg)
			registryApply(t, h, 0, registryAdded(cfg))
			if err := g.Close(); err != nil {
				t.Fatal(err)
			}
			maintenanceSQL(t, opts.Path, sql)
			opts.Initialize = false
			r, err := NewPersistent(cfg, opts)
			if err == nil {
				r.Close()
				t.Fatal("tampered registry opened")
			}
		})
	}
}
func TestRuntimeRegistryPreservesLimiterAndManagedUser(t *testing.T) {
	cfg := maintenanceConfig()
	g, opts, h := registryGateway(t, cfg)
	permit, err := g.limiter.acquire(context.Background(), maintenanceIdentity("active"), "shared")
	if err != nil {
		t.Fatal(err)
	}
	bucket := g.limiter.systems["shared"]
	global := g.limiter.global
	oldActive, oldTokens := bucket.active, bucket.tokens
	registryApply(t, h, 0, registryAdded(cfg))
	if g.limiter.systems["shared"] != bucket || g.limiter.global != global || bucket.active != oldActive || bucket.tokens != oldTokens {
		t.Fatal("apply reset live limiter")
	}
	permit.Release()
	create := lifecyclePreview(t, h, lifecycleRequest{Action: "create_user", Tenant: "new-tenant", Principal: "new-principal"})
	if w := lifecyclePost(h, create); w.Code != 200 {
		t.Fatalf("create %d %s", w.Code, w.Body)
	}
	id := g.identities[Identity{"new-tenant", "new-principal"}]
	if len(g.principals[id].bindings) != 2 {
		t.Fatal("managed user missed runtime service")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Initialize = false
	r, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(r.principals[id].bindings) != 2 || len(r.systems) != 2 {
		t.Fatal("managed runtime state lost")
	}
}
func TestRuntimeRegistryConcurrentCreateAndApply(t *testing.T) {
	cfg := maintenanceConfig()
	g, _, h := registryGateway(t, cfg)
	apply := registryPreview(t, h, 0, registryAdded(cfg))
	create := lifecyclePreview(t, h, lifecycleRequest{Action: "create_user", Tenant: "race-tenant", Principal: "race-principal"})
	var wg sync.WaitGroup
	wg.Add(2)
	codes := make(chan int, 2)
	go func() { defer wg.Done(); codes <- registryPost(h, "apply", apply).Code }()
	go func() { defer wg.Done(); codes <- lifecyclePost(h, create).Code }()
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != 200 {
			t.Fatalf("concurrent status %d", code)
		}
	}
	for _, p := range g.principals {
		if len(p.bindings) != len(g.systems) {
			t.Fatal("partial runtime topology")
		}
	}
}
func TestRuntimeRegistrySurvivesRotationAndArchive(t *testing.T) {
	cfg := maintenanceConfig()
	g, opts, h := registryGateway(t, cfg)
	registryApply(t, h, 0, registryAdded(cfg))
	originalAuditID := append([]byte(nil), g.auditIDKey...)
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Initialize = false
	m, err := OpenMaintenance(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x78}, 32)
	if err = m.RotateKey(key); err != nil {
		t.Fatal(err)
	}
	if _, err = m.ArchiveAudit(filepath.Join(t.TempDir(), "registry-audit.json"), m.store.auditSequence); err != nil {
		t.Fatal(err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Key = key
	r, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(r.systems) != 2 || !bytes.Equal(r.auditIDKey, originalAuditID) {
		t.Fatal("rotation/archive reset registry or audit identity")
	}
	if registryCurrent(t, adminTestHandler(t, r))["revision"] != float64(1) {
		t.Fatal("revision lost")
	}
}
func TestRuntimeRegistryTransactionFailureDoesNotPartiallyPublish(t *testing.T) {
	cfg := maintenanceConfig()
	g, opts, h := registryGateway(t, cfg)
	if _, err := g.store.conn.ExecContext(context.Background(), "CREATE TRIGGER stop_runtime_binding BEFORE INSERT ON bindings WHEN NEW.system='added' BEGIN SELECT RAISE(ABORT,'synthetic failure'); END"); err != nil {
		t.Fatal(err)
	}
	w := registryPost(h, "apply", registryPreview(t, h, 0, registryAdded(cfg)))
	if w.Code != 503 {
		t.Fatalf("failed commit %d %s", w.Code, w.Body)
	}
	if len(g.systems) != 1 {
		t.Fatal("failed apply published service")
	}
	for _, p := range g.principals {
		if len(p.bindings) != 1 {
			t.Fatal("failed apply published binding")
		}
	}
	_ = g.Close()
	opts.Initialize = false
	r, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(r.systems) != 1 || registryCurrent(t, adminTestHandler(t, r))["revision"] != float64(0) {
		t.Fatal("failed apply persisted partial registry")
	}
}

func TestRuntimeRegistryLostCommitAcknowledgementRecoversCommittedRevision(t *testing.T) {
	cfg := maintenanceConfig()
	g, opts, h := registryGateway(t, cfg)
	in := registryPreview(t, h, 0, registryAdded(cfg))
	maintenanceLoseCommitAck(t, g, opts.Path)
	w := registryPost(h, "apply", in)
	if w.Code != 503 {
		t.Fatalf("lost acknowledgment %d %s", w.Code, w.Body)
	}
	if !g.auditFault && !g.closed {
		t.Fatal("uncertain commit kept serving")
	}
	if w = adminRequest(h, "GET", "/admin/api/config/current", "", maintenanceToken(99), nil); w.Code != 503 {
		t.Fatalf("uncertain state exposed as authoritative %d", w.Code)
	}
	_ = g.Close()
	opts.Initialize = false
	r, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(r.systems) != 2 || registryCurrent(t, adminTestHandler(t, r))["revision"] != float64(1) {
		t.Fatal("durable commit not recovered")
	}
	for _, p := range r.principals {
		if len(p.bindings) != 2 {
			t.Fatal("durable commit partial bindings")
		}
	}
}
