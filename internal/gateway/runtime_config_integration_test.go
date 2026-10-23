package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuntimeRegistryLiveAddBindingDiscoveryCallAndTimeoutFence(t *testing.T) {
	var calls atomic.Int32
	var blockList atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-service" {
			http.Error(w, "denied", 401)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"synthetic","version":"1"}}}`, req.ID)
		case "notifications/initialized", "notifications/cancelled":
			w.WriteHeader(202)
		case "tools/list":
			if blockList.Load() {
				enteredOnce.Do(func() { close(entered) })
				<-release
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"ping","inputSchema":{"type":"object"}}]}}`, req.ID)
		case "tools/call":
			calls.Add(1)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"synthetic-ok"}]}}`, req.ID)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	// Cleanup must unblock the synthetic provider before server.Close can wait.
	defer unblock()
	cfg := Config{Systems: []System{}, Users: map[string]User{"u": {Tenant: "tenant", Principal: "principal", Token: maintenanceToken(1)}}}
	g, opts, h := registryGateway(t, cfg)
	systems := []System{{Name: "live", Endpoint: server.URL}}
	registryApply(t, h, 0, systems)
	identity := Identity{"tenant", "principal"}
	b, err := g.Binding(identity, "live")
	if err != nil || b.State != BindingUnbound {
		t.Fatal(b, err)
	}
	if _, err = g.ReplaceBinding(identity, "live", b.Generation, "synthetic-service"); err != nil {
		t.Fatal(err)
	}
	policy, err := g.Policy(identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.SetPolicy(identity, policy.Version, []string{"live__ping"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if issues := g.Refresh(ctx); len(issues) > 0 {
		t.Fatal(issues)
	}
	if result, err := g.Call(ctx, "u", "live__ping", nil); err != nil || result == nil {
		t.Fatal(result, err)
	}
	if calls.Load() != 1 {
		t.Fatal("call not dispatched exactly once")
	}
	g.mu.Lock()
	old := g.state.Load().catalogs["u"]["live__ping"]
	g.mu.Unlock()
	g.mu.Lock()
	capturedHandler := g.state.Load().handlers["u"]
	g.mu.Unlock()
	capturedServer := httptest.NewServer(capturedHandler)
	defer capturedServer.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "runtime-fence", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: capturedServer.URL, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	blockList.Store(true)
	done := make(chan []DiscoveryIssue, 1)
	go func() { done <- g.RefreshBinding(ctx, identity, "live") }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("discovery barrier missing")
	}
	systems[0].Timeouts = &TimeoutConfig{DiscoveryMS: 4000, CallMS: 4500, ResponseHeaderMS: 3000}
	registryApply(t, h, 1, systems)
	g.mu.Lock()
	staleAllowed := g.entryAllowedLocked("u", "live__ping", old)
	g.mu.Unlock()
	if staleAllowed {
		t.Fatal("old SDK catalog entry survived service revision")
	}
	if len(g.Names("u")) != 0 {
		t.Fatal("updated service kept stale tools")
	}
	unblock()
	select {
	case issues := <-done:
		if len(issues) == 0 {
			t.Fatal("old discovery accepted")
		}
	case <-ctx.Done():
		t.Fatal("old discovery stuck")
	}
	if len(g.Names("u")) != 0 {
		t.Fatal("late discovery republished old configuration")
	}
	blockList.Store(false)
	if issues := g.Refresh(ctx); len(issues) > 0 {
		t.Fatal(issues)
	}
	g.mu.Lock()
	current := g.state.Load().catalogs["u"]["live__ping"]
	g.mu.Unlock()
	if current.system.revision != 2 || current.system.timeoutBudgets().call != 4500*time.Millisecond {
		t.Fatal("fresh discovery not using committed timeout")
	}
	if list, err := session.ListTools(ctx, nil); err != nil || len(list.Tools) != 0 {
		t.Fatal("captured handler exposed new catalog", list, err)
	}
	if result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "live__ping", Arguments: map[string]any{}}); err == nil && (result == nil || !result.IsError) {
		t.Fatal("captured SDK session called new revision", result)
	}
	staleContext := context.WithValue(ctx, runtimeServiceRevisionKey{}, runtimeServiceRevision{old.system.Name, old.system.revision})
	if _, err := g.Call(staleContext, "u", "live__ping", nil); !errors.Is(err, ErrDenied) {
		t.Fatal("old handler context called new revision", err)
	}
	if calls.Load() != 1 {
		t.Fatal("stale handler dispatched")
	}
	if err = g.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Initialize = false
	reopened, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(reopened.systems) != 1 || reopened.systems["live"].Timeouts.CallMS != 4500 {
		t.Fatal("live config not recovered")
	}
	if issues := reopened.Refresh(ctx); len(issues) > 0 {
		t.Fatal(issues)
	}
	if result, err := reopened.Call(ctx, "u", "live__ping", nil); err != nil || result == nil {
		t.Fatal(result, err)
	}
	if calls.Load() != 2 {
		t.Fatal("unexpected business replay")
	}
}
