package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func connectionParts(t *testing.T, out map[string]any) (string, string) {
	t.Helper()
	u, err := url.Parse(out["authorization_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "http" || u.Host != "127.0.0.1:8080" || u.RawQuery != "" || u.Path != "/binding/" {
		t.Fatal(u)
	}
	a, b, ok := strings.Cut(u.Fragment, ".")
	if !ok || !validConnectionID(a) || !validConnectionID(b) {
		t.Fatal("invalid capability")
	}
	return a, b
}
func connectionPost(h http.Handler, token, action string, fields map[string]any) *httptest.ResponseRecorder {
	data, _ := json.Marshal(fields)
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/binding/api/session/"+action, strings.NewReader(string(data)))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestConnectionSessionBrowserVertical(t *testing.T) {
	g, h, token := clientFixture(t)
	b, _ := g.Binding(integratedIdentity, "crm")
	g.RevokeBinding(integratedIdentity, "crm", b.Generation)
	srv := httptest.NewServer(g.state.Load().handlers["alice"])
	defer srv.Close()
	c := mcp.NewClient(&mcp.Implementation{Name: "neutral-client", Version: "1"}, nil)
	sess, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: srv.URL, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	r, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "crm__echo", Arguments: map[string]any{"message": "not dispatched"}})
	if err != nil || !r.IsError || !strings.Contains(r.Content[0].(*mcp.TextContent).Text, "connection_required") {
		t.Fatal(r, err)
	}
	r, err = sess.CallTool(context.Background(), &mcp.CallToolParams{Name: connectionBeginTool, Arguments: map[string]any{"service_id": "crm", "expected_generation": 2}})
	if err != nil || r.IsError {
		t.Fatal(r, err)
	}
	var out map[string]any
	if json.Unmarshal([]byte(r.Content[0].(*mcp.TextContent).Text), &out) != nil {
		t.Fatal(r)
	}
	locator, capability := connectionParts(t, out)
	fields := map[string]any{"session_locator": locator, "capability": capability}
	w := connectionPost(h, token, "inspect", fields)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"principal":"alice"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	fields["credential"] = "a-replacement"
	fields["confirm"] = true
	w = connectionPost(h, token, "confirm", fields)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"binding_saved":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "a-replacement") || strings.Contains(w.Body.String(), capability) {
		t.Fatal("secret echo")
	}
	if w = connectionPost(h, token, "confirm", fields); w.Code != 403 {
		t.Fatal("replay", w.Code)
	}
	status, err := g.connectionStatus(context.Background(), "alice", locator)
	if err != nil || status["binding_saved"] != true || status["state"] != "saved" || status["saved_generation"] != uint64(3) {
		t.Fatal(status, err)
	}
	if _, err = g.connectionStatus(context.Background(), "bob", locator); err == nil {
		t.Fatal("cross user status")
	}
}
func TestConnectionSessionSingleConcurrentCommit(t *testing.T) {
	g, h, token := clientFixture(t)
	out, err := g.beginConnection(context.Background(), "alice", "crm", 1)
	if err != nil {
		t.Fatal(err)
	}
	locator, capability := connectionParts(t, out)
	fields := map[string]any{"session_locator": locator, "capability": capability, "credential": "a-replacement", "confirm": true}
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := connectionPost(h, token, "confirm", fields)
			mu.Lock()
			defer mu.Unlock()
			if w.Code == 200 {
				success++
			} else if w.Code != 403 {
				t.Error(w.Code, w.Body.String())
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatal(success)
	}
	b, _ := g.Binding(integratedIdentity, "crm")
	if b.Generation != 2 {
		t.Fatal(b)
	}
}
func TestConnectionSessionScopeAndExpiry(t *testing.T) {
	for _, kind := range []string{"expiry", "policy", "binding", "system", "entry"} {
		t.Run(kind, func(t *testing.T) {
			g, h, token := clientFixture(t)
			out, _ := g.beginConnection(context.Background(), "alice", "crm", 1)
			locator, capability := connectionParts(t, out)
			g.mu.Lock()
			s := g.connectionSessions[locator]
			switch kind {
			case "expiry":
				s.expires = time.Now().Add(-time.Second)
			case "policy":
				s.policy++
			case "binding":
				s.binding++
			case "system":
				s.revision++
			case "entry":
				s.entry++
			}
			g.mu.Unlock()
			w := connectionPost(h, token, "confirm", map[string]any{"session_locator": locator, "capability": capability, "credential": "a-replacement", "confirm": true})
			if w.Code != 403 {
				t.Fatal(w.Code, w.Body.String())
			}
			b, _ := g.Binding(integratedIdentity, "crm")
			if b.Generation != 1 {
				t.Fatal("stale mutation")
			}
		})
	}
}
func TestConnectionSessionMetadataBoundaries(t *testing.T) {
	g, h, token := clientFixture(t)
	for i := 0; i < 4; i++ {
		if _, err := g.beginConnection(context.Background(), "alice", "crm", 1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.beginConnection(context.Background(), "alice", "crm", 1); err == nil {
		t.Fatal("unbounded")
	}
	if _, err := g.beginConnection(context.Background(), "alice", "unknown", 1); err == nil {
		t.Fatal("unknown service")
	}
	if _, err := g.ClientBindingHandler("http://127.0.0.1:8081"); err == nil {
		t.Fatal("origin moved")
	}
	for _, raw := range []string{`{"service_id":"crm","service_id":"crm"}`, `{"x":"SECRET`, `{} {}`} {
		_, err := decodeConnectionArgs(json.RawMessage(raw))
		if err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Fatal(err)
		}
	}
	w := clientRequest(h, "GET", "/binding/", token, "")
	if w.Code != 200 || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal(w.Code)
	}
	if r := g.connectionRequired(context.Background(), "alice", "crm__admin"); r != nil {
		t.Fatal("unauthorized hint")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	n := len(g.connectionSessions)
	g.mu.Unlock()
	if n != 0 {
		t.Fatal("close did not clear")
	}
}
