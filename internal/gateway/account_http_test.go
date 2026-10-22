package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangkangbug/mcp-entry/internal/mock"
)

func accountFixture(t *testing.T) (*Gateway, http.Handler, string, string) {
	return accountFixtureHandler(t, mock.Handler("crm", map[string]string{"a-secret": "alice", "b-secret": "bob", "a-replacement": "alice"}), true)
}
func accountFixtureHandler(t *testing.T, downstreamHandler http.Handler, refresh bool) (*Gateway, http.Handler, string, string) {
	t.Helper()
	token := func() string {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw[:])
	}
	alice, bob := token(), token()
	downstream := httptest.NewServer(downstreamHandler)
	t.Cleanup(downstream.Close)
	g, err := New(Config{Systems: []System{{Name: "crm", Endpoint: downstream.URL}}, Users: map[string]User{
		"alice": {Token: alice, TokenExpiresAt: time.Now().Add(time.Hour), Allowed: []string{"crm__echo"}, Credentials: map[string]string{"crm": "a-secret"}},
		"bob":   {Token: bob, TokenExpiresAt: time.Now().Add(time.Hour), Allowed: []string{"crm__echo"}, Credentials: map[string]string{"crm": "b-secret"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	if issues := g.Refresh(context.Background()); refresh && len(issues) != 0 {
		t.Fatal(issues)
	}
	h, err := g.AccountHandler("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	return g, h, alice, bob
}
func accountRequest(h http.Handler, method, path, token, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://127.0.0.1:8080")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestAccountOwnershipAndLifecycle(t *testing.T) {
	g, h, alice, bob := accountFixture(t)
	status := accountRequest(h, "GET", "/account/api/bindings", alice, "", nil)
	if status.Code != 200 {
		t.Fatal(status.Code, status.Body.String())
	}
	for _, secret := range []string{alice, bob, "a-secret", "b-secret", `"token_hash"`, `"credential"`} {
		if strings.Contains(status.Body.String(), secret) {
			t.Fatal("status leaked secret")
		}
	}
	var view struct {
		Principal string           `json:"principal"`
		Bindings  []accountBinding `json:"bindings"`
	}
	if err := json.Unmarshal(status.Body.Bytes(), &view); err != nil || view.Principal != "alice" || len(view.Bindings) != 1 {
		t.Fatal("bad status", err)
	}
	for _, body := range []string{`{"expected_generation":1,"credential":"a-replacement","principal":"bob"}`, `{"expected_generation":1,"credential":"a-replacement","tenant":"other"}`} {
		w := accountRequest(h, "POST", "/account/api/bindings/crm", alice, body, nil)
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	body := `{"expected_generation":1,"credential":"a-replacement","expires_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`
	w := accountRequest(h, "POST", "/account/api/bindings/crm", alice, body, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "a-replacement") {
		t.Fatal("credential returned")
	}
	a, _ := g.Binding(Identity{"demo", "alice"}, "crm")
	b, _ := g.Binding(Identity{"demo", "bob"}, "crm")
	if a.Generation != 2 || a.ExpiresAt.IsZero() || b.Generation != 1 {
		t.Fatalf("scope or expiry mismatch: %#v %#v", a, b)
	}
	if names := g.Names("alice"); len(names) != 1 {
		t.Fatal("replacement did not refresh", names)
	}
	w = accountRequest(h, "POST", "/account/api/bindings/crm", alice, body, nil)
	if w.Code != 409 {
		t.Fatal(w.Code)
	}
	w = accountRequest(h, "POST", "/account/api/bindings/crm/revoke", alice, `{"expected_generation":2}`, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if len(g.Names("alice")) != 0 || len(g.Names("bob")) != 1 {
		t.Fatal("revocation crossed users or kept old catalog")
	}
	bs := accountRequest(h, "GET", "/account/api/bindings", bob, "", nil)
	if !strings.Contains(bs.Body.String(), `"principal":"bob"`) {
		t.Fatal("wrong owner")
	}
}
func TestAccountRequestGuards(t *testing.T) {
	_, h, alice, _ := accountFixture(t)
	for _, tc := range []struct {
		name, method, path, body string
		headers                  map[string]string
		code                     int
	}{
		{"foreign origin", "GET", "/account/api/bindings", "", map[string]string{"Origin": "http://evil.example"}, 403},
		{"null origin", "GET", "/account/api/bindings", "", map[string]string{"Origin": "null"}, 403},
		{"cross site", "GET", "/account", "", map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"query", "GET", "/account/api/bindings?principal=bob", "", nil, 403},
		{"form", "POST", "/account/api/bindings/crm", "credential=x", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, 415},
		{"method", "DELETE", "/account/api/bindings/crm", "", nil, 405},
		{"unknown field", "POST", "/account/api/bindings/crm", `{"expected_generation":1,"credential":"x","endpoint":"http://evil"}`, nil, 400},
		{"duplicate field", "POST", "/account/api/bindings/crm", `{"expected_generation":1,"expected_generation":2,"credential":"x"}`, nil, 400},
		{"trailing", "POST", "/account/api/bindings/crm", `{"expected_generation":1,"credential":"x"} {}`, nil, 400},
		{"past expiry", "POST", "/account/api/bindings/crm", `{"expected_generation":1,"credential":"x","expires_at":"2000-01-01T00:00:00Z"}`, nil, 400},
		{"null expiry", "POST", "/account/api/bindings/crm", `{"expected_generation":1,"credential":"x","expires_at":null}`, nil, 400},
		{"huge body", "POST", "/account/api/bindings/crm", `{"expected_generation":1,"credential":"` + strings.Repeat("x", 9000) + `"}`, nil, 400},
		{"unknown system", "POST", "/account/api/bindings/unknown", `{"expected_generation":1,"credential":"x"}`, nil, 403},
		{"encoded path", "GET", "/account/api/%62indings", "", nil, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := accountRequest(h, tc.method, tc.path, alice, tc.body, tc.headers)
			if w.Code != tc.code {
				t.Fatal(w.Code, w.Body.String())
			}
			if w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("CORS enabled")
			}
		})
	}
	for _, token := range []string{"", "wrong"} {
		if w := accountRequest(h, "GET", "/account/api/bindings", token, "", nil); w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	for _, duplicate := range []string{"Authorization", "Origin"} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:8080/account/api/bindings", nil)
		r.Header.Set("Authorization", "Bearer "+alice)
		r.Header.Set("Origin", "http://127.0.0.1:8080")
		r.Header.Add(duplicate, "extra")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("duplicate header", w.Code)
		}
	}
	r := httptest.NewRequest("GET", "http://evil.example/account", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("host", w.Code)
	}
}
func TestAccountAssetsAndMCPSeparation(t *testing.T) {
	g, h, alice, _ := accountFixture(t)
	for _, path := range []string{"/account", "/account/assets/account.js", "/account/assets/account.css"} {
		w := accountRequest(h, "GET", path, "", "", nil)
		if w.Code != 200 {
			t.Fatal(path, w.Code)
		}
		for key, want := range map[string]string{"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"} {
			if w.Header().Get(key) != want {
				t.Fatal(key)
			}
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatal("missing CSP")
		}
	}
	js, _ := accountAssets.ReadFile("account_assets/account.js")
	for _, forbidden := range []string{"localStorage", "sessionStorage", "document.cookie", "innerHTML", "window.location", "console.log", "https://"} {
		if strings.Contains(string(js), forbidden) {
			t.Fatal("unsafe asset operation", forbidden)
		}
	}
	w := accountRequest(g.Handler(), "POST", "/mcp", alice, "{}", map[string]string{"Origin": "http://127.0.0.1:8080"})
	if w.Code != 403 {
		t.Fatal("MCP browser guard weakened", w.Code)
	}
	for _, origin := range []string{"http://evil.example:8080", "https://127.0.0.1:8080", "http://127.0.0.1:0", "http://127.0.0.1:8080/", "http://127.0.0.1:8080?x"} {
		if _, err := g.AccountHandler(origin); err == nil {
			t.Fatal("accepted unsafe origin", origin)
		}
	}
}
func TestAccountExpiredView(t *testing.T) {
	b := BindingInfo{System: "crm", Generation: 2, State: BindingActive, ExpiresAt: time.Now().Add(-time.Second)}
	view := accountBindingView(b)
	if view.State != "expired" || !strings.Contains(view.Hint, "fresh") {
		t.Fatal(view)
	}
}

func TestAccountRejectsWeakOrUnboundedEntryAuth(t *testing.T) {
	for _, user := range []User{
		{Token: "demo-only", TokenExpiresAt: time.Now().Add(time.Hour)},
		{Token: base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
	} {
		g, err := New(Config{Users: map[string]User{"alice": user}})
		if err != nil {
			continue
		} // Rejecting at construction also fails closed.
		if _, err := g.AccountHandler("http://127.0.0.1:8080"); err == nil {
			t.Fatal("unsafe entry authentication enabled")
		}
		g.Close()
	}
}

func TestAccountDownstreamFailureDoesNotRevoke(t *testing.T) {
	for _, status := range []int{401, 403, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			g, h, alice, _ := accountFixtureHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("raw-downstream-secret"))
			}), false)
			w := accountRequest(h, "POST", "/account/api/bindings/crm", alice, `{"expected_generation":1,"credential":"a-replacement"}`, nil)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			var out struct {
				Hint    string             `json:"hint"`
				Failure *DownstreamFailure `json:"discovery_failure"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Failure == nil {
				t.Fatal("missing sanitized failure", err, w.Body.String())
			}
			expected := map[int]FailureCode{401: FailureAuthentication, 403: FailurePermission, 500: FailureService}[status]
			if out.Failure.Code != expected {
				t.Fatal(out.Failure)
			}
			if strings.Contains(w.Body.String(), "raw-downstream-secret") || strings.Contains(w.Body.String(), "a-replacement") {
				t.Fatal("failure leaked credential or body")
			}
			b, _ := g.Binding(Identity{"demo", "alice"}, "crm")
			if b.State != BindingActive || b.Generation != 2 {
				t.Fatal("failure changed binding state", b)
			}
			if len(g.Names("alice")) != 0 {
				t.Fatal("failed refresh retained stale tools")
			}
			if status == 401 && !strings.Contains(out.Hint, "does not prove") {
				t.Fatal("auth failure inference")
			}
			if status == 403 && !strings.Contains(out.Hint, "denied permission") {
				t.Fatal("permission failure confused with reauthorization")
			}
		})
	}
}

type accountBarrierBody struct {
	reader           io.Reader
	entered, release chan struct{}
	once             sync.Once
}

func (b *accountBarrierBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.release })
	return b.reader.Read(p)
}
func (b *accountBarrierBody) Close() error { return nil }
func TestAccountMutationRechecksEntryAtAdmission(t *testing.T) {
	for _, operation := range []string{"replace", "revoke"} {
		for _, change := range []string{"expiry", "disable"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				g, h, alice, _ := accountFixture(t)
				path, body := "/account/api/bindings/crm", `{"expected_generation":1,"credential":"a-replacement"}`
				if operation == "revoke" {
					path += "/revoke"
					body = `{"expected_generation":1}`
				}
				barrier := &accountBarrierBody{reader: strings.NewReader(body), entered: make(chan struct{}), release: make(chan struct{})}
				request := httptest.NewRequest("POST", "http://127.0.0.1:8080"+path, nil)
				request.Body = barrier
				request.Header.Set("Authorization", "Bearer "+alice)
				request.Header.Set("Origin", "http://127.0.0.1:8080")
				request.Header.Set("Content-Type", "application/json")
				result := httptest.NewRecorder()
				done := make(chan struct{})
				go func() { defer close(done); h.ServeHTTP(result, request) }()
				select {
				case <-barrier.entered:
				case <-time.After(time.Second):
					close(barrier.release)
					t.Fatal("request did not reach body read after authentication")
				}
				if change == "expiry" {
					g.mu.Lock()
					user := g.users["alice"]
					user.TokenExpiresAt = time.Now().Add(-time.Second)
					g.users["alice"] = user
					g.mu.Unlock()
				} else {
					if _, err := g.DisablePrincipal(Identity{"demo", "alice"}, 1); err != nil {
						close(barrier.release)
						t.Fatal(err)
					}
				}
				close(barrier.release)
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("request remained blocked")
				}
				if result.Code != 403 {
					t.Fatal("late authority loss not rejected", result.Code, result.Body.String())
				}
				binding, err := g.Binding(Identity{"demo", "alice"}, "crm")
				if err != nil {
					t.Fatal(err)
				}
				if change == "expiry" && (binding.Generation != 1 || binding.State != BindingActive) {
					t.Fatal("expired entry mutated binding", binding)
				}
				if change == "disable" && (binding.Generation != 2 || binding.State != BindingRevoked) {
					t.Fatal("disabled entry mutated binding", binding)
				}
			})
		}
	}
}
