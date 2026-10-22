package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

// An independent legacy wire fixture forces initialize/session/DELETE rather
// than allowing the SDK's newer sessionless negotiation to skip cleanup.
type authCleanupFixture struct {
	mu       sync.Mutex
	sessions map[string]string
	seen     map[string]map[string]int
	next     int
	block    *cleanupBlock
	teardown chan struct{}
	stopOnce sync.Once
}

func newAuthCleanupFixture(t *testing.T, mode string, users ...string) (*authCleanupFixture, *gateway.Gateway) {
	t.Helper()
	f := &authCleanupFixture{sessions: map[string]string{}, seen: map[string]map[string]int{}, block: newCleanupBlock(), teardown: make(chan struct{})}
	header := "Authorization"
	auth := gateway.AuthConfig{Mode: mode}
	if mode == "api_key" {
		header = "X-Cleanup-API-Key"
		auth.Header = header
	}
	identities := map[string]string{}
	cfg := gateway.Config{Users: map[string]gateway.User{}}
	for _, user := range users {
		credential := "Token synthetic-cleanup-" + user + " exact suffix"
		identities[credential] = user
		f.seen[user] = map[string]int{}
		cfg.Users[user] = gateway.User{Token: "entry-" + user, Allowed: []string{"test__whoami"}, Credentials: map[string]string{"test": credential}}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values(header)
		if len(values) != 1 || identities[values[0]] == "" {
			t.Errorf("%s: expected exactly one unmodified credential", mode)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		user := identities[values[0]]
		alternate := "X-Cleanup-API-Key"
		if mode == "api_key" {
			alternate = "Authorization"
		}
		if len(r.Header.Values(alternate)) != 0 || len(r.Header.Values("Proxy-Authorization")) != 0 {
			t.Error("alternate credential header leaked")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		for secret := range identities {
			if bytes.Contains(body, []byte(secret)) || bytes.Contains([]byte(r.URL.String()), []byte(secret)) {
				t.Error("credential leaked outside auth header")
			}
		}
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		method := r.Method
		if r.Method == http.MethodPost {
			if err := json.Unmarshal(body, &request); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			method = request.Method
		}
		f.mu.Lock()
		f.seen[user][method]++
		session := r.Header.Get("Mcp-Session-Id")
		valid := session != "" && f.sessions[session] == user
		f.mu.Unlock()
		if r.Method == http.MethodDelete {
			if !valid {
				t.Error("DELETE used missing or another identity's session")
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if f.block.enabled.Load() {
				f.block.wait(r.Context(), f.teardown)
			}
			f.mu.Lock()
			delete(f.sessions, session)
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if method != "initialize" && method != "server/discover" && !valid {
			t.Errorf("%s used missing or another identity's session", method)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if len(request.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if method == "server/discover" {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
			return
		}
		var result any
		switch method {
		case "initialize":
			f.mu.Lock()
			f.next++
			session = fmt.Sprintf("session-%d", f.next)
			f.sessions[session] = user
			f.mu.Unlock()
			w.Header().Set("Mcp-Session-Id", session)
			result = map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "auth-cleanup", "version": "1"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "whoami", "inputSchema": map[string]any{"type": "object"}}}}
		case "tools/call":
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": user}}}
		default:
			t.Errorf("unexpected method %s", method)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}))
	t.Cleanup(func() { f.stop(); server.CloseClientConnections(); server.Close() })
	cfg.Systems = []gateway.System{{Name: "test", Endpoint: server.URL, Auth: auth}}
	g, err := gateway.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return f, g
}

func (f *authCleanupFixture) stop() { f.stopOnce.Do(func() { close(f.teardown) }) }

func authCleanupStart[T any](t *testing.T, f *authCleanupFixture, operation func() T) <-chan T {
	t.Helper()
	result := make(chan T, 1)
	done := make(chan struct{})
	go func() { defer close(done); result <- operation() }()
	t.Cleanup(func() { f.stop(); cleanupReceive(t, done, time.Second, "auth cleanup operation teardown") })
	return result
}

func authCleanupResult(t *testing.T, got cleanupCallResult, user string) {
	t.Helper()
	if got.err != nil || got.result == nil || got.result.IsError || len(got.result.Content) != 1 {
		t.Fatalf("confirmed result lost: %+v, %v", got.result, got.err)
	}
	text, ok := got.result.Content[0].(*mcp.TextContent)
	if !ok || text.Text != user {
		t.Fatalf("wrong identity result: %+v", got.result)
	}
}

func TestAuthModesStatefulCleanupIsolation(t *testing.T) {
	for _, mode := range []string{"raw", "api_key"} {
		t.Run(mode, func(t *testing.T) {
			f, g := newAuthCleanupFixture(t, mode, "alice", "bob")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if issues := g.Refresh(ctx); len(issues) != 0 {
				t.Fatal(issues)
			}
			results := map[string]<-chan cleanupCallResult{}
			for _, user := range []string{"alice", "bob"} {
				results[user] = authCleanupStart(t, f, func() cleanupCallResult {
					result, err := g.Call(ctx, user, "test__whoami", map[string]any{"Authorization": "attacker", "X-Cleanup-API-Key": "attacker"})
					return cleanupCallResult{result, err}
				})
			}
			for user, result := range results {
				authCleanupResult(t, cleanupReceive(t, result, 5*time.Second, "identity call"), user)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, user := range []string{"alice", "bob"} {
				for method, want := range map[string]int{"initialize": 2, "notifications/initialized": 2, "tools/list": 1, "tools/call": 1, "DELETE": 2} {
					if got := f.seen[user][method]; got != want {
						t.Errorf("%s %s=%d, want %d", user, method, got, want)
					}
				}
			}
			if len(f.sessions) != 0 {
				t.Errorf("sessions remain after cleanup: %d", len(f.sessions))
			}
		})
	}
}

func TestAuthModesStatefulCleanupPreservesConfirmedCall(t *testing.T) {
	for _, mode := range []string{"raw", "api_key"} {
		t.Run(mode, func(t *testing.T) {
			f, g := newAuthCleanupFixture(t, mode, "alice")
			if issues := g.Refresh(context.Background()); len(issues) != 0 {
				t.Fatal(issues)
			}
			f.block.enabled.Store(true)
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			completed := make(chan time.Time, 1)
			result := authCleanupStart(t, f, func() cleanupCallResult {
				value, err := g.Call(ctx, "alice", "test__whoami", map[string]any{})
				completed <- time.Now()
				return cleanupCallResult{value, err}
			})
			requestCtx := cleanupReceive(t, f.block.started, time.Second, "authenticated DELETE")
			got := cleanupReceive(t, result, 2*time.Second, "caller deadline cleanup")
			deadline, _ := ctx.Deadline()
			if finished := <-completed; finished.Before(deadline) {
				t.Fatalf("cleanup returned %v before caller deadline", deadline.Sub(finished))
			}
			// The transport and parent context share a deadline, but their
			// timer callbacks need not run in parent-first order. Assert the
			// real completion boundary, then require parent cancellation too.
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("parent deadline did not cancel")
			}
			if ctx.Err() != context.DeadlineExceeded {
				t.Fatalf("unexpected parent cancellation: %v", ctx.Err())
			}
			authCleanupResult(t, got, "alice")
			cleanupAssertReleased(t, f.block, requestCtx)
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.seen["alice"]["tools/call"] != 1 || f.seen["alice"]["DELETE"] != 2 {
				t.Fatalf("unexpected retry or skipped cleanup: %v", f.seen["alice"])
			}
		})
	}
}

func TestAuthModesStatefulCleanupPreservesDiscoveryAtInternalDeadline(t *testing.T) {
	for _, mode := range []string{"raw", "api_key"} {
		t.Run(mode, func(t *testing.T) {
			f, g := newAuthCleanupFixture(t, mode, "alice")
			f.block.enabled.Store(true)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			start := time.Now()
			result := authCleanupStart(t, f, func() []gateway.DiscoveryIssue { return g.Refresh(ctx) })
			requestCtx := cleanupReceive(t, f.block.started, time.Second, "discovery authenticated DELETE")
			issues := cleanupReceive(t, result, 7*time.Second, "fixed discovery deadline")
			if elapsed := time.Since(start); elapsed < 4*time.Second || elapsed >= 7*time.Second || ctx.Err() != nil {
				t.Fatalf("internal deadline not respected: elapsed=%s caller=%v", elapsed, ctx.Err())
			}
			if names := g.Names("alice"); len(issues) != 0 || len(names) != 1 || names[0] != "test__whoami" {
				t.Fatalf("confirmed catalog lost: issues=%v names=%v", issues, names)
			}
			cleanupAssertReleased(t, f.block, requestCtx)
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, method := range []string{"initialize", "tools/list", "DELETE"} {
				if f.seen["alice"][method] != 1 {
					t.Errorf("%s count=%d", method, f.seen["alice"][method])
				}
			}
		})
	}
}
