package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func lifecyclePost(h http.Handler, in lifecycleRequest) *httptest.ResponseRecorder {
	data, _ := json.Marshal(in)
	return adminRequest(h, "POST", "/admin/api/lifecycle", string(data), maintenanceToken(99), nil)
}
func lifecyclePreview(t *testing.T, h http.Handler, in lifecycleRequest) lifecycleRequest {
	t.Helper()
	in.Preview = true
	w := lifecyclePost(h, in)
	if w.Code != 200 {
		t.Fatalf("preview %d %s", w.Code, w.Body)
	}
	var out struct {
		ConfirmationID string `json:"confirmation_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.ConfirmationID == "" {
		t.Fatal("missing confirmation")
	}
	if strings.Contains(w.Body.String(), `"token"`) {
		t.Fatal("preview returned token")
	}
	in.Preview = false
	in.Confirm = true
	in.ConfirmationID = out.ConfirmationID
	return in
}
func TestAdminLifecycleCreateIssueRotateRevokeRecovery(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	g, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	h := adminTestHandler(t, g)
	identity := Identity{"managed-tenant", "managed-principal"}
	create := lifecyclePreview(t, h, lifecycleRequest{Action: "create_user", Tenant: identity.Tenant, Principal: identity.Principal})
	w := lifecyclePost(h, create)
	if w.Code != 200 {
		t.Fatalf("create %d %s", w.Code, w.Body)
	}
	p, _ := g.Policy(identity)
	if p.Version != 1 || len(p.Allowed) != 0 || p.Disabled {
		t.Fatal(p)
	}
	e, _ := g.Entry(identity)
	if e.Generation != 1 || !e.Revoked {
		t.Fatal(e)
	}
	for _, b := range g.principals[g.identities[identity]].bindings {
		if b.credential != "" || b.info.State != BindingUnbound {
			t.Fatal("seeded credential")
		}
	}
	if w = lifecyclePost(h, create); w.Code != 409 {
		t.Fatalf("replay %d", w.Code)
	}
	issue := lifecyclePreview(t, h, lifecycleRequest{Action: "issue_entry", Tenant: identity.Tenant, Principal: identity.Principal, Expected: 1, ExpiresAt: time.Now().Add(time.Hour).UTC()})
	w = lifecyclePost(h, issue)
	if w.Code != 200 {
		t.Fatalf("issue %d %s", w.Code, w.Body)
	}
	var out struct {
		Token string `json:"token"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	oldToken := out.Token
	if len(oldToken) != 43 {
		t.Fatal("missing strong token")
	}
	auth := func(token string) bool {
		r := httptest.NewRequest("POST", "http://localhost/mcp", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		_, ok := g.authenticateEntry(r)
		return ok
	}
	if !auth(oldToken) {
		t.Fatal("new entry rejected")
	}
	rotate := lifecyclePreview(t, h, lifecycleRequest{Action: "rotate_entry", Tenant: identity.Tenant, Principal: identity.Principal, Expected: 2, ExpiresAt: time.Now().Add(2 * time.Hour).UTC()})
	w = lifecyclePost(h, rotate)
	if w.Code != 200 {
		t.Fatalf("rotate %d %s", w.Code, w.Body)
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if auth(oldToken) || !auth(out.Token) {
		t.Fatal("rotation auth")
	}
	snapshot := adminRequest(h, "GET", "/admin/api/snapshot", "", maintenanceToken(99), nil)
	audit := adminRequest(h, "POST", "/admin/api/audit", `{"after":0,"limit":100}`, maintenanceToken(99), nil)
	for _, secret := range []string{oldToken, out.Token} {
		if strings.Contains(snapshot.Body.String(), secret) || strings.Contains(audit.Body.String(), secret) {
			t.Fatal("secret leaked")
		}
	}
	g.Close()
	opts.Initialize = false
	g, err = NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h = adminTestHandler(t, g)
	if auth(oldToken) || !auth(out.Token) {
		t.Fatal("recovery auth")
	}
	revoke := lifecyclePreview(t, h, lifecycleRequest{Action: "revoke_entry", Tenant: identity.Tenant, Principal: identity.Principal, Expected: 3})
	if w = lifecyclePost(h, revoke); w.Code != 200 {
		t.Fatalf("revoke %d %s", w.Code, w.Body)
	}
	if auth(out.Token) {
		t.Fatal("revoked accepted")
	}
	g.Close()
	g, err = NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if auth(out.Token) {
		t.Fatal("revoked resurrected")
	}
}
func TestAdminLifecycleConfirmationBoundaries(t *testing.T) {
	g, err := NewPersistent(maintenanceConfig(), maintenanceOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h := adminTestHandler(t, g)
	h2 := adminTestHandler(t, g)
	in := lifecyclePreview(t, h, lifecycleRequest{Action: "rotate_entry", Tenant: "tenant-active", Principal: "principal-active", Expected: 1, ExpiresAt: time.Now().Add(time.Hour).UTC()})
	if w := lifecyclePost(h2, in); w.Code != 409 {
		t.Fatal("cross-handler ticket accepted")
	}
	modified := in
	modified.ExpiresAt = modified.ExpiresAt.Add(time.Hour)
	if w := lifecyclePost(h, modified); w.Code != 409 {
		t.Fatal("modified ticket accepted")
	}
	if w := lifecyclePost(h, in); w.Code != 409 {
		t.Fatal("consumed ticket reused")
	}
	in = lifecyclePreview(t, h, lifecycleRequest{Action: "rotate_entry", Tenant: "tenant-active", Principal: "principal-active", Expected: 1, ExpiresAt: time.Now().Add(time.Hour).UTC()})
	var wg sync.WaitGroup
	codes := make(chan int, 4)
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- lifecyclePost(h, in).Code }()
	}
	wg.Wait()
	close(codes)
	successes := 0
	for code := range codes {
		if code == 200 {
			successes++
		} else if code != 409 {
			t.Fatalf("unexpected %d", code)
		}
	}
	if successes != 1 {
		t.Fatal(successes)
	}
	disabled := lifecycleRequest{Action: "rotate_entry", Tenant: "tenant-active", Principal: "principal-active", Expected: 2, ExpiresAt: time.Now().Add(time.Hour).UTC(), Preview: true}
	policy, _ := g.Policy(maintenanceIdentity("active"))
	g.DisablePrincipal(maintenanceIdentity("active"), policy.Version)
	if w := lifecyclePost(h, disabled); w.Code != 403 {
		t.Fatalf("disabled %d", w.Code)
	}
}

func TestAdminLifecycleRejectInvalidInputsAndVolatileStore(t *testing.T) {
	g, err := NewPersistent(maintenanceConfig(), maintenanceOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h := adminTestHandler(t, g)
	base := lifecycleRequest{Action: "rotate_entry", Tenant: "tenant-active", Principal: "principal-active", Expected: 1, ExpiresAt: time.Now().Add(time.Hour).UTC(), Preview: true}
	cases := []lifecycleRequest{}
	for _, expiry := range []time.Time{{}, time.Now().Add(-time.Second)} {
		in := base
		in.ExpiresAt = expiry
		cases = append(cases, in)
	}
	in := base
	in.Confirm = true
	cases = append(cases, in)
	in = base
	in.Preview = false
	in.Confirm = true
	cases = append(cases, in)
	in = base
	in.Tenant = "bad\nidentity"
	cases = append(cases, in)
	in = base
	in.Action = "create_user"
	cases = append(cases, in)
	in = base
	in.Action = "revoke_entry"
	cases = append(cases, in)
	for _, in = range cases {
		if w := lifecyclePost(h, in); w.Code != 400 {
			t.Fatalf("invalid input accepted %d", w.Code)
		}
	}
	e, _ := g.Entry(maintenanceIdentity("active"))
	if e.Generation != 1 {
		t.Fatal("invalid input mutated")
	}
	volatile, err := New(maintenanceConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer volatile.Close()
	if w := lifecyclePost(adminTestHandler(t, volatile), base); w.Code != 403 {
		t.Fatal("volatile lifecycle enabled")
	}
}
func TestAdminAuthorityCannotBecomeMaintenanceEntry(t *testing.T) {
	cfg := maintenanceConfig()
	opts := maintenanceOptions(t)
	g, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	g.Close()
	opts.Initialize = false
	g, err = OpenMaintenance(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	_ = adminTestHandler(t, g)
	if _, err := g.ReplaceEntry(maintenanceIdentity("active"), 1, maintenanceToken(99), time.Now().Add(time.Hour)); err == nil {
		t.Fatal("registered admin accepted as entry")
	}
}
