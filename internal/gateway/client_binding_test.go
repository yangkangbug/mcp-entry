package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/mock"
)

func clientRequest(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func clientFixture(t *testing.T) (*Gateway, http.Handler, string) {
	t.Helper()
	g, _, a, _ := accountFixture(t)
	h, err := g.ClientBindingHandler("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	return g, h, a
}
func TestClientBindingStrictBoundary(t *testing.T) {
	g, h, token := clientFixture(t)
	valid := `{"service_id":"crm","expected_generation":1,"credential":"a-replacement"}`
	for _, body := range []string{`{"service_id":"crm","expected_generation":1,"credential":"a-replacement","principal":"bob"}`, `{"service_id":"crm","expected_generation":1,"credential":"a-replacement","tenant":"demo"}`, `{"service_id":"crm","expected_generation":1,"credential":"a-replacement","endpoint":"http://other"}`, `{"service_id":"crm","service_id":"other","expected_generation":1,"credential":"a-replacement"}`, valid + `{}`, `null`, strings.Repeat("x", 9000)} {
		w := clientRequest(h, "POST", "/binding/api/credentials", token, body)
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "a-replacement") {
			t.Fatal("secret echo")
		}
	}
	for k, v := range map[string]string{"Origin": "http://127.0.0.1:8080", "Cookie": "x=y", "Sec-Fetch-Site": "none", "Host": "other"} {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080/binding/api/credentials", strings.NewReader(valid))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		if k == "Host" {
			r.Host = v
		} else {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(k, w.Code)
		}
	}
	for _, path := range []string{"/binding/api/credentials?credential=secret", "/binding/api/%63redentials"} {
		if w := clientRequest(h, "POST", path, token, valid); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	if w := clientRequest(h, "GET", "/binding/api/credentials", token, ""); w.Code != 405 {
		t.Fatal(w.Code)
	}
	b, _ := g.Binding(integratedIdentity, "crm")
	if b.Generation != 1 {
		t.Fatal("rejected request mutated")
	}
	w := clientRequest(h, "POST", "/binding/api/credentials", token, valid)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"binding_saved":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := clientRequest(h, "POST", "/binding/api/credentials", token, valid); w.Code != 409 {
		t.Fatal("replay", w.Code)
	}
	if _, err := g.Call(context.Background(), "alice", "crm__admin", map[string]any{}); !errors.Is(err, ErrDenied) {
		t.Fatal("binding granted policy", err)
	}
}
func TestClientBindingAuthorizedMetadataAndNoMutation(t *testing.T) {
	g, h, token := clientFixture(t)
	before, _ := g.Binding(integratedIdentity, "crm")
	if _, err := g.RevokeBinding(integratedIdentity, "crm", before.Generation); err != nil {
		t.Fatal(err)
	}
	w := clientRequest(h, "GET", "/binding/api/services", token, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"revoked"`) {
		t.Fatal(w.Body.String())
	}
	for _, secret := range []string{token, "a-secret", "b-secret", "credential\"", "principal\"", "tenant\""} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("metadata leak", secret)
		}
	}
	p, _ := g.Policy(integratedIdentity)
	if _, err := g.SetPolicy(integratedIdentity, p.Version, nil); err != nil {
		t.Fatal(err)
	}
	w = clientRequest(h, "GET", "/binding/api/services", token, "")
	if !strings.Contains(w.Body.String(), `"services":[]`) {
		t.Fatal(w.Body.String())
	}
	if w := clientRequest(h, "POST", "/binding/api/credentials", token, `{"service_id":"crm","expected_generation":2,"credential":"a-replacement"}`); w.Code != 403 {
		t.Fatal(w.Code)
	}
	after, _ := g.Binding(integratedIdentity, "crm")
	if after.Generation != 2 || after.State != BindingRevoked {
		t.Fatal(after)
	}
}
func TestClientBindingControlDiscoverableWithoutCredential(t *testing.T) {
	g, h, _ := clientFixture(t)
	_ = h
	b, _ := g.Binding(integratedIdentity, "crm")
	g.RevokeBinding(integratedIdentity, "crm", b.Generation)
	// Direct captured SDK handler exercises the control tool list/call without
	// involving another ingress limiter. External Handler separately authenticates.
	srv := httptest.NewServer(g.state.Load().handlers["alice"])
	defer srv.Close()
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	sess, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: srv.URL, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	list, err := sess.ListTools(context.Background(), nil)
	if err != nil || len(list.Tools) != 3 {
		t.Fatal(list, err)
	}
	for i := 0; i < 2; i++ {
		r, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: clientConnectionsTool, Arguments: map[string]any{}})
		if err != nil || r.IsError {
			t.Fatal(r, err)
		}
	}
	r, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: clientConnectionsTool, Arguments: map[string]any{"credential": "secret"}})
	if err == nil && !r.IsError {
		t.Fatal("control accepted secret")
	}
	after, _ := g.Binding(integratedIdentity, "crm")
	if after.Generation != 2 {
		t.Fatal("read mutated")
	}
	p, _ := g.Policy(integratedIdentity)
	g.DisablePrincipal(integratedIdentity, p.Version)
	r, err = sess.CallTool(context.Background(), &mcp.CallToolParams{Name: clientConnectionsTool, Arguments: map[string]any{}})
	if err == nil && !r.IsError {
		t.Fatal("stale handler bypass")
	}
}
func TestClientBindingSavedDespiteDiscoveryFailure(t *testing.T) {
	g, _, token, _ := accountFixtureHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }), false)
	h, err := g.ClientBindingHandler("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	w := clientRequest(h, "POST", "/binding/api/credentials", token, `{"service_id":"crm","expected_generation":1,"credential":"a-replacement"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"binding_saved":true`) || !strings.Contains(w.Body.String(), `"discovery_status":"unavailable"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	w = clientRequest(h, "GET", "/binding/api/services", token, "")
	if strings.Contains(w.Body.String(), `"state":"expired"`) || strings.Contains(w.Body.String(), `"state":"revoked"`) {
		t.Fatal("guessed provider state")
	}
}
func TestClientBindingCASConcurrentAndEntryGeneration(t *testing.T) {
	g, _, _ := clientFixture(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := g.replaceClientBinding(integratedIdentity, "crm", 1, 1, "a-replacement", time.Time{})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				success++
			} else if !errors.Is(err, ErrConflict) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatal(success)
	}
	if _, err := g.replaceClientBinding(integratedIdentity, "crm", 2, 99, "a-replacement", time.Time{}); !errors.Is(err, ErrDenied) {
		t.Fatal("entry mismatch accepted", err)
	}
	p, _ := g.Policy(integratedIdentity)
	g.SetPolicy(integratedIdentity, p.Version, nil)
	if _, err := g.replaceClientBinding(integratedIdentity, "crm", 2, 1, "a-replacement", time.Time{}); !errors.Is(err, ErrDenied) {
		t.Fatal("policy bypass", err)
	}
}
func TestClientBindingPersistentCommitAndCancel(t *testing.T) {
	srv := httptest.NewServer(mock.Handler("crm", map[string]string{"a-replacement": "alice"}))
	defer srv.Close()
	cfg := integratedConfig(srv.URL)
	opts := PersistenceOptions{Path: filepath.Join(t.TempDir(), "state.sqlite"), Key: bytes.Repeat([]byte{7}, 32), Initialize: true}
	g, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	h, err := g.ClientBindingHandler("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "http://127.0.0.1:8080/binding/api/credentials", strings.NewReader(`{"service_id":"crm","expected_generation":1,"credential":"a-replacement"}`))
	req.Header.Set("Authorization", "Bearer "+cfg.Users["alice"].Token)
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req.WithContext(ctx))
	b, _ := g.Binding(integratedIdentity, "crm")
	if b.Generation != 1 {
		t.Fatal("canceled before mutation changed state")
	}
	w = clientRequest(h, "POST", "/binding/api/credentials", cfg.Users["alice"].Token, `{"service_id":"crm","expected_generation":1,"credential":"a-replacement"}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var out struct {
		Saved bool `json:"binding_saved"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if !out.Saved {
		t.Fatal("no receipt")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Initialize = false
	g, err = NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	b, _ = g.Binding(integratedIdentity, "crm")
	if b.Generation != 2 {
		t.Fatal("commit lost", b)
	}
}

func TestClientBindingMissingExpiredAndSavedRefreshRevocation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(503)
	}))
	defer downstream.Close()
	cfg := integratedConfig(downstream.URL)
	u := cfg.Users["alice"]
	u.Credentials = nil
	cfg.Users["alice"] = u
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h, err := g.ClientBindingHandler("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	w := clientRequest(h, "GET", "/binding/api/services", u.Token, "")
	if !strings.Contains(w.Body.String(), `"state":"missing"`) {
		t.Fatal(w.Body.String())
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- clientRequest(h, "POST", "/binding/api/credentials", u.Token, `{"service_id":"crm","expected_generation":1,"credential":"a-replacement"}`)
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("no refresh")
	}
	b, err := g.RevokeBinding(integratedIdentity, "crm", 2)
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case w = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("refresh did not finish")
	}
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"binding_saved":true`) || !strings.Contains(w.Body.String(), `"discovery_status":"not_completed"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	b2, _ := g.Binding(integratedIdentity, "crm")
	if b2.Generation != b.Generation || b2.State != BindingRevoked {
		t.Fatal("stale refresh revived binding")
	}
	// Local expiry metadata is derived solely from a known timestamp, not HTTP status.
	g.mu.Lock()
	g.principals["alice"].bindings["crm"].info.State = BindingActive
	g.principals["alice"].bindings["crm"].info.ExpiresAt = time.Now().Add(-time.Second)
	g.mu.Unlock()
	w = clientRequest(h, "GET", "/binding/api/services", u.Token, "")
	if !strings.Contains(w.Body.String(), `"state":"expired"`) {
		t.Fatal(w.Body.String())
	}
}
