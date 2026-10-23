package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const adminTestOrigin = "http://127.0.0.1:8088"

func adminTestHandler(t *testing.T, g *Gateway) http.Handler {
	t.Helper()
	h, err := g.AdminHandler(adminTestOrigin, maintenanceToken(99))
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func adminRequest(h http.Handler, method, path, body, token string, change func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, adminTestOrigin+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:2345"
	r.Header.Set("Authorization", "Bearer "+token)
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-MCP-Admin", "1")
		r.Header.Set("Origin", adminTestOrigin)
	}
	if change != nil {
		change(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestAdminAuthorityAndBoundaries(t *testing.T) {
	g, err := New(maintenanceConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	for _, token := range []string{"", "weak", maintenanceToken(1)} {
		if _, err := g.AdminHandler(adminTestOrigin, token); err == nil {
			t.Fatal("accepted unsafe admin authority")
		}
	}
	for _, origin := range []string{"http://example.com:80", "http://0.0.0.0:80", "https://127.0.0.1:80", "http://127.0.0.1:80/?secret=x"} {
		if _, err := g.AdminHandler(origin, maintenanceToken(99)); err == nil {
			t.Fatal("accepted origin")
		}
	}
	h := adminTestHandler(t, g)
	tests := []struct {
		name, token, path string
		change            func(*http.Request)
		status            int
	}{
		{"entry_is_not_admin", maintenanceToken(1), "/admin/api/snapshot", nil, 401},
		{"valid", maintenanceToken(99), "/admin/api/snapshot", nil, 200},
		{"remote", maintenanceToken(99), "/admin/api/snapshot", func(r *http.Request) { r.RemoteAddr = "203.0.113.1:2" }, 403},
		{"origin", maintenanceToken(99), "/admin/api/snapshot", func(r *http.Request) { r.Header.Set("Origin", "http://evil.invalid") }, 403},
		{"host", maintenanceToken(99), "/admin/api/snapshot", func(r *http.Request) { r.Host = "evil.invalid" }, 403},
		{"query", maintenanceToken(99), "/admin/api/snapshot?token=synthetic-secret", nil, 403},
		{"duplicate_auth", maintenanceToken(99), "/admin/api/snapshot", func(r *http.Request) { r.Header.Add("Authorization", "Bearer synthetic-secret") }, 403},
		{"spoof_role", maintenanceToken(1), "/admin/api/snapshot", func(r *http.Request) { r.Header.Set("X-Role", "admin") }, 401},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := adminRequest(h, "GET", tt.path, "", tt.token, tt.change)
			if w.Code != tt.status {
				t.Fatalf("%d: %s", w.Code, w.Body)
			}
			for _, secret := range []string{maintenanceToken(1), maintenanceToken(99), "synthetic-maintenance-binding", "synthetic-secret"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Fatal("secret echoed")
				}
			}
		})
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+maintenanceToken(99))
	if _, ok := g.authenticateEntry(r); ok {
		t.Fatal("admin became entry")
	}
}
func TestAdminMutationPersistenceAndCAS(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	g, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	h := adminTestHandler(t, g)
	body := `{"action":"set_policy","tenant":"tenant-active","principal":"principal-active","expected_version":1,"allowed":[],"preview":true}`
	w := adminRequest(h, "POST", "/admin/api/mutate", body, maintenanceToken(99), nil)
	if w.Code != 200 {
		t.Fatalf("preview %d %s", w.Code, w.Body)
	}
	before, _ := g.Policy(maintenanceIdentity("active"))
	if before.Version != 1 {
		t.Fatal("preview mutated")
	}
	body = strings.Replace(body, `"preview":true`, `"confirm":true`, 1)
	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- adminRequest(h, "POST", "/admin/api/mutate", body, maintenanceToken(99), nil).Code
		}()
	}
	wg.Wait()
	close(codes)
	successes := 0
	for code := range codes {
		if code == 200 {
			successes++
		} else if code != 409 && code != 429 {
			t.Fatalf("unexpected status %d", code)
		}
	}
	if successes != 1 {
		t.Fatalf("commits %d", successes)
	}
	revoke := `{"action":"revoke_binding","tenant":"tenant-active","principal":"principal-active","system":"shared","expected_version":1,"confirm":true}`
	if w = adminRequest(h, "POST", "/admin/api/mutate", revoke, maintenanceToken(99), nil); w.Code != 200 {
		t.Fatalf("revoke %d %s", w.Code, w.Body)
	}
	if err = g.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Initialize = false
	g, err = NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h = adminTestHandler(t, g)
	p, _ := g.Policy(maintenanceIdentity("active"))
	b, _ := g.Binding(maintenanceIdentity("active"), "shared")
	if p.Version != 2 || len(p.Allowed) != 0 || b.Generation != 2 || b.State != BindingRevoked {
		t.Fatalf("restart lost state: %+v %+v", p, b)
	}
	w = adminRequest(h, "POST", "/admin/api/audit", `{"after":0,"limit":100}`, maintenanceToken(99), nil)
	if w.Code != 200 {
		t.Fatal(w.Body)
	}
	var page AuditPage
	if err = json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	actions := map[AuditAction]int{}
	for _, e := range page.Events {
		actions[e.Action]++
	}
	if actions[AuditActionPolicyUpdate] != 1 || actions[AuditActionBindingRevoke] != 1 {
		t.Fatalf("audit %+v", actions)
	}
}
func TestAdminDraftNeverAppliesAndValidation(t *testing.T) {
	g, err := New(maintenanceConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h := adminTestHandler(t, g)
	before := adminRequest(h, "GET", "/admin/api/snapshot", "", maintenanceToken(99), nil).Body.Bytes()
	draft := `{"systems":[{"name":"other","endpoint":"http://127.0.0.1:9/mcp"}]}`
	w := adminRequest(h, "POST", "/admin/api/config/validate", draft, maintenanceToken(99), nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"applied":false`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	after := adminRequest(h, "GET", "/admin/api/snapshot", "", maintenanceToken(99), nil).Body.Bytes()
	if !bytes.Equal(before, after) {
		t.Fatal("draft changed state")
	}
	for _, body := range []string{`{"systems":[{"name":"x","endpoint":"http://127.0.0.1:9/mcp?api_key=synthetic-secret"}]}`, `{"systems":[{"name":"x","endpoint":"http://example.com/mcp"}]}`, `{"systems":[],"systems":[]}`, `{"systems":[{"name":"x","name":"y","endpoint":"http://127.0.0.1:9"}]}`, `{"systems":[],"token":"synthetic-secret"}`} {
		w = adminRequest(h, "POST", "/admin/api/config/validate", body, maintenanceToken(99), nil)
		if w.Code != 400 || strings.Contains(w.Body.String(), "synthetic-secret") {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	}
}
func TestAdminRequestLimitsAndUnsupported(t *testing.T) {
	g, err := New(maintenanceConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h := adminTestHandler(t, g)
	cases := []struct {
		body   string
		change func(*http.Request)
		status int
	}{
		{`{}`, func(r *http.Request) { r.Header.Del("X-MCP-Admin") }, 403},
		{`{}`, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		{strings.Repeat("x", (64<<10)+1), nil, 413},
		{`{"action":"create_user","confirm":true}`, nil, 501},
		{`{"action":"set_policy","tenant":"tenant-active","principal":"principal-active","expected_version":1}`, nil, 400},
		{`{"action":"set_policy","tenant":"tenant-active","principal":"principal-active","expected_version":1,"confirm":true,"preview":true}`, nil, 400},
	}
	for _, tt := range cases {
		w := adminRequest(h, "POST", "/admin/api/mutate", tt.body, maintenanceToken(99), tt.change)
		if w.Code != tt.status {
			t.Fatalf("want %d got %d %s", tt.status, w.Code, w.Body)
		}
	}
	g.Close()
	w := adminRequest(h, "GET", "/admin/api/snapshot", "", maintenanceToken(99), nil)
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}

func TestAdminDisableAndDraftPersistentTopology(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	g, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	h := adminTestHandler(t, g)
	w := adminRequest(h, "POST", "/admin/api/config/validate", `{"systems":[{"name":"changed","endpoint":"http://127.0.0.1:2/mcp"}]}`, maintenanceToken(99), nil)
	if w.Code != 200 {
		t.Fatal(w.Body)
	}
	w = adminRequest(h, "POST", "/admin/api/mutate", `{"action":"disable_principal","tenant":"tenant-active","principal":"principal-active","expected_version":1,"confirm":true}`, maintenanceToken(99), nil)
	if w.Code != 200 {
		t.Fatalf("disable %d %s", w.Code, w.Body)
	}
	if err = g.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Initialize = false
	changed := maintenanceConfig()
	changed.Systems[0].Endpoint = "http://127.0.0.1:2/mcp"
	if other, err := NewPersistent(changed, opts); err == nil {
		other.Close()
		t.Fatal("draft bypassed topology authentication")
	}
	g, err = NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	p, _ := g.Policy(maintenanceIdentity("active"))
	b, _ := g.Binding(maintenanceIdentity("active"), "shared")
	if !p.Disabled || p.Version != 2 || b.State != BindingRevoked || b.Generation != 2 {
		t.Fatalf("disable lost: %+v %+v", p, b)
	}
}

func TestAdminStorageFailureClosesWithoutSecretEcho(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	maintenanceSeed(t, cfg, opts)
	maintenanceSQL(t, opts.Path, "CREATE TRIGGER admin_synthetic_fail BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT, 'synthetic-secret-storage'); END")
	opts.Initialize = false
	g, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	h := adminTestHandler(t, g)
	w := adminRequest(h, "POST", "/admin/api/mutate", `{"action":"set_policy","tenant":"tenant-active","principal":"principal-active","expected_version":1,"allowed":[],"confirm":true}`, maintenanceToken(99), nil)
	if w.Code != 503 || strings.Contains(w.Body.String(), "synthetic-secret") {
		t.Fatalf("unsafe error %d %s", w.Code, w.Body)
	}
	if w = adminRequest(h, "GET", "/admin/api/snapshot", "", maintenanceToken(99), nil); w.Code != 503 {
		t.Fatal("faulted gateway still serving admin state")
	}
	_ = g.Close()
	maintenanceSQL(t, opts.Path, "DROP TRIGGER admin_synthetic_fail")
	g, err = NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	p, _ := g.Policy(maintenanceIdentity("active"))
	if p.Version != 1 || len(p.Allowed) != 1 {
		t.Fatal("failed mutation published")
	}
}

func TestAdminPersistentAuditCapacityPreventsUnloggedMutation(t *testing.T) {
	cfg := maintenanceConfig()
	cfg.Audit.Capacity = 1
	opts := maintenanceOptions(t)
	g, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h := adminTestHandler(t, g)
	body := `{"action":"set_policy","tenant":"tenant-active","principal":"principal-active","expected_version":1,"allowed":[],"confirm":true}`
	w := adminRequest(h, "POST", "/admin/api/mutate", body, maintenanceToken(99), nil)
	if w.Code != 200 {
		t.Fatalf("first %d %s", w.Code, w.Body)
	}
	body = strings.Replace(body, `"expected_version":1`, `"expected_version":2`, 1)
	w = adminRequest(h, "POST", "/admin/api/mutate", body, maintenanceToken(99), nil)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "audit_capacity_exhausted") {
		t.Fatalf("capacity %d %s", w.Code, w.Body)
	}
	p, _ := g.Policy(maintenanceIdentity("active"))
	if p.Version != 2 {
		t.Fatal("unlogged mutation published")
	}
}
