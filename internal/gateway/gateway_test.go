package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
	"github.com/yangkangbug/mcp-entry/internal/mock"
)

func fixture(t *testing.T) (*gateway.Gateway, *httptest.Server) {
	t.Helper()
	crm := httptest.NewServer(mock.Handler("crm", map[string]string{"a-crm": "alice", "b-crm": "bob"}))
	t.Cleanup(crm.Close)
	docs := httptest.NewServer(mock.Handler("docs", map[string]string{"a-docs": "alice"}))
	t.Cleanup(docs.Close)
	g, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "crm", Endpoint: crm.URL}, {Name: "docs", Endpoint: docs.URL}}, Users: map[string]gateway.User{
		"alice": {Token: "alice-token", Allowed: []string{"crm__echo", "docs__echo"}, Credentials: map[string]string{"crm": "a-crm", "docs": "a-docs"}},
		"bob":   {Token: "bob-token", Allowed: []string{"crm__echo"}, Credentials: map[string]string{"crm": "b-crm"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if issues := g.Refresh(context.Background()); len(issues) != 0 {
		t.Fatal(issues)
	}
	server := httptest.NewServer(g.Handler())
	t.Cleanup(server.Close)
	return g, server
}

func connect(t *testing.T, url, token string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	s, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: url, HTTPClient: gateway.CredentialClient(token), MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestDiscoveryAndCalls(t *testing.T) {
	_, server := fixture(t)
	for _, tc := range []struct {
		user  string
		names []string
	}{{"alice", []string{"crm__echo", "docs__echo"}}, {"bob", []string{"crm__echo"}}} {
		t.Run(tc.user, func(t *testing.T) {
			s := connect(t, server.URL, tc.user+"-token")
			tools, err := s.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, tool := range tools.Tools {
				names = append(names, tool.Name)
			}
			if !reflect.DeepEqual(names, tc.names) {
				t.Fatalf("tools=%v want %v", names, tc.names)
			}
			for _, name := range names {
				result, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{"message": "hello"}})
				if err != nil || result.IsError {
					t.Fatalf("call result=%v err=%v", result, err)
				}
				encoded, _ := json.Marshal(result.StructuredContent)
				var out mock.Output
				if err := json.Unmarshal(encoded, &out); err != nil {
					t.Fatal(err)
				}
				if out.User != tc.user || out.Message != "hello" || !strings.HasPrefix(name, out.System+"__") {
					t.Fatalf("identity/routing leak: %+v", out)
				}
			}
		})
	}
}

func TestIndependentAuthorizationAndSpoofing(t *testing.T) {
	g, server := fixture(t)
	for _, tc := range []struct{ user, name string }{{"bob", "docs__echo"}, {"unknown", "crm__echo"}, {"alice", "echo"}, {"alice", "crm__docs__echo"}, {"alice", "http://evil/echo"}} {
		if _, err := g.Call(context.Background(), tc.user, tc.name, map[string]any{"message": "x"}); !errors.Is(err, gateway.ErrDenied) {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
	bob := connect(t, server.URL, "bob-token")
	if result, err := bob.CallTool(context.Background(), &mcp.CallToolParams{Name: "docs__echo", Arguments: map[string]any{"message": "x"}}); err == nil && !result.IsError {
		t.Fatal("hidden tool callable")
	}
	for _, token := range []string{"", "alice", "invalid"} {
		req, _ := http.NewRequest("POST", server.URL, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 401 {
			t.Fatalf("wrong token status %d", res.StatusCode)
		}
	}
	req, _ := http.NewRequest("POST", server.URL, strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer alice-token")
	req.Header.Set("Origin", "https://evil.example")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("origin accepted")
	}
}

func TestConcurrentCredentialIsolation(t *testing.T) {
	g, _ := fixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		user := "alice"
		if i%2 == 1 {
			user = "bob"
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := g.Call(context.Background(), user, "crm__echo", map[string]any{"message": "parallel"})
			if err != nil {
				t.Error(err)
				return
			}
			b, _ := json.Marshal(result.StructuredContent)
			var out mock.Output
			_ = json.Unmarshal(b, &out)
			if out.User != user {
				t.Errorf("wanted %s got %s", user, out.User)
			}
		}()
	}
	wg.Wait()
}

func TestDownstreamInitializationFailure(t *testing.T) {
	var calls atomic.Int32
	var toolCalls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		var msg struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &msg)
		if msg.Method == "tools/call" {
			toolCalls.Add(1)
		}
		http.Error(w, "secret-internal-error", 503)
	}))
	defer s.Close()
	g, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "crm", Endpoint: s.URL}}, Users: map[string]gateway.User{"alice": {Token: "a", Allowed: []string{"crm__echo"}, Credentials: map[string]string{"crm": "synthetic"}}}})
	if err != nil {
		t.Fatal(err)
	}
	g.Refresh(context.Background())
	_, err = g.Call(context.Background(), "alice", "crm__echo", map[string]any{"message": "x"})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe error: %v", err)
	}
	// SDK may perform protocol discovery and a legacy initialization fallback.
	if calls.Load() == 0 {
		t.Fatal("downstream was never contacted")
	}
	if toolCalls.Load() != 0 {
		t.Fatal("tool called despite failed initialization")
	}
}

func TestRejectAmbiguousOrRemoteRoutes(t *testing.T) {
	for _, system := range []gateway.System{{Name: "crm", Endpoint: "https://example.com"}, {Name: "a__b", Endpoint: "http://127.0.0.1:9000"}} {
		if _, err := gateway.New(gateway.Config{Systems: []gateway.System{system}}); err == nil {
			t.Fatalf("accepted %+v", system)
		}
	}
	system := gateway.System{Name: "crm", Endpoint: "http://127.0.0.1:9000"}
	if _, err := gateway.New(gateway.Config{Systems: []gateway.System{system, system}}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := gateway.New(gateway.Config{Systems: []gateway.System{system}, Users: map[string]gateway.User{"alice": {Token: "a", Allowed: []string{"wrong"}}}}); err == nil {
		t.Fatal("ambiguous policy accepted")
	}
}

func TestRedirectDoesNotLeakCredential(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer source.Close()
	res, err := gateway.CredentialClient("synthetic-secret").Get(source.URL)
	if res != nil {
		res.Body.Close()
	}
	if err == nil || hits.Load() != 0 {
		t.Fatalf("redirect followed: hits=%d err=%v", hits.Load(), err)
	}
}

func TestToolCallTransportFailureNotRetried(t *testing.T) {
	var calls atomic.Int32
	downstream := mock.Handler("crm", map[string]string{"synthetic": "alice"})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad body", 400)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var msg struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &msg)
		if msg.Method == "tools/call" {
			calls.Add(1)
			http.Error(w, "secret-internal-error", 503)
			return
		}
		downstream.ServeHTTP(w, r)
	}))
	defer s.Close()
	g, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "crm", Endpoint: s.URL}}, Users: map[string]gateway.User{"alice": {Token: "a", Allowed: []string{"crm__echo"}, Credentials: map[string]string{"crm": "synthetic"}}}})
	if err != nil {
		t.Fatal(err)
	}
	g.Refresh(context.Background())
	_, err = g.Call(context.Background(), "alice", "crm__echo", map[string]any{"message": "x"})
	if err == nil || strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unsafe/incorrect error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("tool call retried: %d", calls.Load())
	}
}

func TestSpoofedArgumentsRejected(t *testing.T) {
	_, server := fixture(t)
	s := connect(t, server.URL, "bob-token")
	result, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: "crm__echo", Arguments: map[string]any{"message": "x", "user": "alice", "endpoint": "http://evil"}})
	if err == nil && !result.IsError {
		t.Fatal("additional routing/identity arguments accepted")
	}
}

func TestMissingCredentialFailsClosed(t *testing.T) {
	var hits atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer s.Close()
	g, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "crm", Endpoint: s.URL}}, Users: map[string]gateway.User{"alice": {Token: "a", Allowed: []string{"crm__echo"}}}})
	if err != nil {
		t.Fatal(err)
	}
	g.Refresh(context.Background())
	if _, err := g.Call(context.Background(), "alice", "crm__echo", map[string]any{"message": "x"}); !errors.Is(err, gateway.ErrDenied) {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Fatal("attempted downstream without credential")
	}
}

func TestConfigurationCopied(t *testing.T) {
	downstream := httptest.NewServer(mock.Handler("crm", map[string]string{"original-credential": "bob"}))
	defer downstream.Close()
	users := map[string]gateway.User{"bob": {Token: "original", Allowed: []string{"crm__echo"}, Credentials: map[string]string{"crm": "original-credential"}}}
	systems := []gateway.System{{Name: "crm", Endpoint: downstream.URL}, {Name: "docs", Endpoint: downstream.URL}}
	g, err := gateway.New(gateway.Config{Systems: systems, Users: users})
	if err != nil {
		t.Fatal(err)
	}
	users["bob"].Allowed[0] = "docs__echo"
	users["bob"].Credentials["crm"] = "mutated"
	systems[0].Name = "mutated"
	if issues := g.Refresh(context.Background()); len(issues) != 0 {
		t.Fatal(issues)
	}
	if got := g.Names("bob"); !reflect.DeepEqual(got, []string{"crm__echo"}) {
		t.Fatalf("configuration mutation: %v", got)
	}
	result, err := g.Call(context.Background(), "bob", "crm__echo", map[string]any{"message": "copy"})
	if err != nil || result.IsError {
		t.Fatalf("credential copy failed: %v %v", result, err)
	}
}

func TestRejectInvalidToolNames(t *testing.T) {
	for _, system := range []string{"has space", "路径", strings.Repeat("a", 123)} {
		if _, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: system, Endpoint: "http://127.0.0.1:9000"}}}); err == nil {
			t.Fatalf("invalid name accepted: %q", system)
		}
	}
}

func TestResponseSizeBound(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, strings.Repeat("x", (1<<20)+1)) }))
	defer s.Close()
	response, err := gateway.CredentialClient("synthetic").Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	var sizeError *http.MaxBytesError
	if !errors.As(err, &sizeError) || len(body) > 1<<20 {
		t.Fatalf("response unbounded: bytes=%d error=%v", len(body), err)
	}
}
