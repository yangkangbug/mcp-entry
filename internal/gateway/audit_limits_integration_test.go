package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

// Independent end-to-end coverage uses synthetic loopback traffic exclusively.
// The barrier is inside a real tools/call handler, not around limiter internals.
type auditLimitFixture struct {
	server   *httptest.Server
	calls    atomic.Int32
	requests atomic.Int32
	gate     *revocationBarrier
	block    atomic.Bool
}

func newAuditLimitFixture(t *testing.T) *auditLimitFixture {
	t.Helper()
	f := &auditLimitFixture{}
	server := mcp.NewServer(&mcp.Implementation{Name: "audit-limit-fixture", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.calls.Add(1)
		if f.block.Load() {
			f.gate.block(ctx)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "synthetic-result-canary-927416"}}}, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.requests.Add(1); handler.ServeHTTP(w, r) }))
	t.Cleanup(f.server.Close)
	f.gate = newRevocationBarrier(t)
	return f
}

func auditLimitConfig(f *auditLimitFixture) gateway.Config {
	return gateway.Config{Systems: []gateway.System{{Name: "alpha", Endpoint: f.server.URL}, {Name: "beta", Endpoint: f.server.URL}}, Users: map[string]gateway.User{
		"east": {Tenant: "tenant-east", Principal: "principal-east", Token: "synthetic-entry-canary-east-927416", Allowed: []string{"alpha__echo", "beta__echo"}, Credentials: map[string]string{"alpha": "synthetic-credential-canary-927416", "beta": "synthetic-credential-canary-927416"}},
		"peer": {Tenant: "tenant-east", Principal: "principal-peer", Token: "synthetic-entry-canary-peer-927416", Allowed: []string{"alpha__echo", "beta__echo"}, Credentials: map[string]string{"alpha": "synthetic-credential-canary-927416", "beta": "synthetic-credential-canary-927416"}},
		"west": {Tenant: "tenant-west", Principal: "principal-west", Token: "synthetic-entry-canary-west-927416", Allowed: []string{"alpha__echo", "beta__echo"}, Credentials: map[string]string{"alpha": "synthetic-credential-canary-927416", "beta": "synthetic-credential-canary-927416"}},
	}}
}

func auditLimitSeed(t *testing.T, g *gateway.Gateway) {
	t.Helper()
	if issues := g.Refresh(discoveryContext(t)); len(issues) != 0 {
		t.Fatal(issues)
	}
}

func TestAuditLimitsIntegrationScopeBarriers(t *testing.T) {
	for _, scope := range []string{"principal", "tenant", "system", "shared_quota", "global"} {
		t.Run(scope, func(t *testing.T) {
			f := newAuditLimitFixture(t)
			cfg := auditLimitConfig(f)
			user, tool := "west", "beta__echo"
			switch scope {
			case "principal":
				cfg.Limits.Principal.MaxConcurrent = 1
				user = "east"
			case "tenant":
				cfg.Limits.Tenant.MaxConcurrent = 1
				user = "peer"
			case "system":
				cfg.Limits.System.MaxConcurrent = 1
				tool = "alpha__echo"
			case "shared_quota":
				cfg.Limits.SharedQuota.MaxConcurrent = 1
				cfg.Systems[0].QuotaSubject = "synthetic-shared"
				cfg.Systems[1].QuotaSubject = "synthetic-shared"
			case "global":
				cfg.Limits.Global.MaxConcurrent = 1
			}
			g, err := gateway.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = g.Close() })
			auditLimitSeed(t, g)
			f.block.Store(true)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := g.Call(ctx, "east", "alpha__echo", map[string]any{}); done <- err }()
			f.gate.wait(t, ctx)
			before := f.requests.Load()
			_, err = g.Call(ctx, user, tool, map[string]any{})
			var denied *gateway.AdmissionFailure
			if !errors.As(err, &denied) || denied.Scope != scope || denied.Reason != "concurrency" {
				t.Errorf("scope %s: %v (%+v)", scope, err, denied)
			}
			if f.requests.Load() != before || f.calls.Load() != 1 {
				t.Error("rejected operation reached downstream")
			}
			f.block.Store(false)
			f.gate.open()
			if err := cleanupReceive(t, done, 5*time.Second, "first tool completion"); err != nil {
				t.Fatal(err)
			}
			if _, err := g.Call(ctx, user, tool, map[string]any{}); err != nil {
				t.Fatal("permit leaked:", err)
			}
			if f.calls.Load() != 2 {
				t.Fatal("tool replay or unexpected dispatch", f.calls.Load())
			}
		})
	}
}

func TestAuditLimitsIntegrationDiscoverySharesCallQuota(t *testing.T) {
	f := newAuditLimitFixture(t)
	cfg := auditLimitConfig(f)
	cfg.Limits.SharedQuota.MaxConcurrent = 1
	for i := range cfg.Systems {
		cfg.Systems[i].QuotaSubject = "synthetic-shared"
	}
	g, err := gateway.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	auditLimitSeed(t, g)
	f.block.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := g.Call(ctx, "east", "alpha__echo", map[string]any{}); done <- err }()
	f.gate.wait(t, ctx)
	before := f.requests.Load()
	issues := g.RefreshBinding(ctx, gateway.Identity{Tenant: "tenant-west", Principal: "principal-west"}, "beta")
	if len(issues) == 0 {
		t.Error("targeted refresh bypassed quota")
	}
	if issues = g.Refresh(ctx); len(issues) == 0 {
		t.Error("full discovery bypassed quota")
	}
	if f.requests.Load() != before {
		t.Error("discovery reached downstream despite occupied shared quota")
	}
	f.block.Store(false)
	f.gate.open()
	_ = cleanupReceive(t, done, 5*time.Second, "call cancellation after refresh")
}

func TestAuditLimitsIntegrationPermitHeldThroughCleanup(t *testing.T) {
	f, _ := newCleanupFixture(t)
	cfg := gateway.Config{Systems: []gateway.System{{Name: "test", Endpoint: f.server.URL}}, Users: map[string]gateway.User{"u": {Token: "synthetic", Allowed: []string{"test__echo"}, Credentials: map[string]string{"test": "synthetic-downstream"}}}, Limits: gateway.LimitsConfig{Global: gateway.AdmissionLimit{MaxConcurrent: 1}}}
	g, err := gateway.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	cleanupSeedCatalog(t, g)
	f.deleteBlock.enabled.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := cleanupStart(t, f, func() error { _, err := g.Call(ctx, "u", "test__echo", map[string]any{}); return err })
	_ = cleanupReceive(t, f.deleteBlock.started, time.Second, "session DELETE barrier")
	before := f.requests.Load()
	_, err = g.Call(context.Background(), "u", "test__echo", map[string]any{})
	var denied *gateway.AdmissionFailure
	if !errors.As(err, &denied) || denied.Scope != "global" {
		t.Errorf("permit released before cleanup: %v", err)
	}
	if f.requests.Load() != before {
		t.Error("cleanup overlap reached downstream")
	}
	cancel()
	if err = cleanupReceive(t, done, 5*time.Second, "bounded cleanup completion"); err != nil {
		t.Fatal(err)
	}
	f.deleteBlock.enabled.Store(false)
	if _, err = g.Call(context.Background(), "u", "test__echo", map[string]any{}); err != nil {
		t.Fatal("cleanup leaked permit:", err)
	}
	if f.calls.Load() != 2 {
		t.Fatal("unexpected tool replay", f.calls.Load())
	}
}

func TestAuditLimitsIntegrationDurableMetadataAndIsolation(t *testing.T) {
	f := newAuditLimitFixture(t)
	cfg := auditLimitConfig(f)
	opts := recoveryOptions(t)
	g := recoveryOpen(t, cfg, opts)
	auditLimitSeed(t, g)
	east := gateway.Identity{Tenant: "tenant-east", Principal: "principal-east"}
	west := gateway.Identity{Tenant: "tenant-west", Principal: "principal-west"}
	original, _ := g.Binding(east, "alpha")
	changed, err := g.ReplaceBinding(east, "alpha", original.Generation, "synthetic-new-credential-canary-927416")
	if err != nil {
		t.Fatal(err)
	}
	if issues := g.RefreshBinding(discoveryContext(t), east, "alpha"); len(issues) != 0 {
		t.Fatal(issues)
	}
	if _, err := g.Call(discoveryContext(t), "east", "alpha__echo", map[string]any{"message": "synthetic-args-canary-927416"}); err != nil {
		t.Fatal(err)
	}
	page, err := g.Audit(east, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	other, err := g.Audit(west, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) == 0 || len(other.Events) == 0 {
		t.Fatal("missing audit events")
	}
	own := page.Events[0].IdentityID
	for _, e := range page.Events {
		if e.IdentityID != own {
			t.Error("cross-principal audit disclosure")
		}
	}
	for _, e := range other.Events {
		if e.IdentityID == own {
			t.Error("own audit visible to different principal")
		}
	}
	b, _ := json.Marshal(page)
	for _, canary := range []string{"synthetic-", "principal-east", "tenant-east", "alpha__echo", "127.0.0.1"} {
		if strings.Contains(string(b), canary) {
			t.Errorf("raw metadata leaked: %s", canary)
		}
	}
	commits := 0
	for _, e := range page.Events {
		if e.Action == gateway.AuditActionBindingReplace && e.Phase == gateway.AuditPhaseCommit {
			commits++
			if e.BindingVersion != changed.Generation {
				t.Error("commit version mismatch")
			}
		}
	}
	if commits != 1 {
		t.Fatal("missing atomic commit event", commits)
	}
	recoveryClose(t, g)
	opts.Initialize = false
	g = recoveryOpen(t, cfg, opts)
	persisted, err := g.Audit(east, 0, 1000)
	if err != nil || !reflect.DeepEqual(page, persisted) {
		t.Fatalf("audit changed across restart: %v", err)
	}
	got, _ := g.Binding(east, "alpha")
	if got != changed {
		t.Fatal("mutation missing after restart")
	}
	oldRequests := map[string]bool{}
	for _, event := range page.Events {
		oldRequests[event.RequestID] = true
	}
	if issues := g.RefreshBinding(discoveryContext(t), east, "alpha"); len(issues) != 0 {
		t.Fatal(issues)
	}
	appended, err := g.Audit(east, page.LastSequence, 1000)
	if err != nil || len(appended.Events) == 0 {
		t.Fatalf("missing post-restart audit: %v", err)
	}
	for _, event := range appended.Events {
		if oldRequests[event.RequestID] {
			t.Error("request identity reused across restart")
		}
	}
}

func TestAuditLimitsIntegrationAuditFailureAtomicity(t *testing.T) {
	for _, phase := range []string{"commit", "start", "terminal"} {
		t.Run(phase, func(t *testing.T) {
			f := newAuditLimitFixture(t)
			cfg := auditLimitConfig(f)
			opts := recoveryOptions(t)
			g := recoveryOpen(t, cfg, opts)
			auditLimitSeed(t, g)
			east := gateway.Identity{Tenant: "tenant-east", Principal: "principal-east"}
			original, _ := g.Binding(east, "alpha")
			recoveryClose(t, g)
			action := "call"
			if phase == "commit" {
				action = "binding_replace"
			}
			recoverySQL(t, opts.Path, "CREATE TRIGGER synthetic_fail_audit BEFORE INSERT ON audit WHEN json_extract(NEW.event,'$.action')='"+action+"' AND json_extract(NEW.event,'$.phase')='"+phase+"' BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END")
			opts.Initialize = false
			g = recoveryOpen(t, cfg, opts)
			auditLimitSeed(t, g)
			before := f.requests.Load()
			if phase == "commit" {
				_, err := g.ReplaceBinding(east, "alpha", original.Generation, "synthetic-rejected-canary-927416")
				if err == nil {
					t.Fatal("audit failure acknowledged mutation")
				}
			} else {
				result, err := g.Call(discoveryContext(t), "east", "alpha__echo", map[string]any{})
				if phase == "start" && err == nil {
					t.Error("failed start acknowledged call")
				}
				if phase == "terminal" && (err != nil || result == nil || result.IsError) {
					t.Fatalf("confirmed result lost: %+v %v", result, err)
				}
			}
			if phase != "terminal" && f.requests.Load() != before {
				t.Error("failed audit reached downstream")
			}
			before = f.requests.Load()
			_, _ = g.Call(discoveryContext(t), "east", "alpha__echo", map[string]any{})
			if f.requests.Load() != before {
				t.Error("audit failure did not disable new admission")
			}
			recoveryClose(t, g)
			recoverySQL(t, opts.Path, "DROP TRIGGER synthetic_fail_audit")
			opts.Initialize = false
			g = recoveryOpen(t, cfg, opts)
			if phase == "commit" {
				got, _ := g.Binding(east, "alpha")
				if got != original {
					t.Fatal("failed audit mutation committed")
				}
			}
		})
	}
}

func TestAuditLimitsIntegrationCapacityAndTamper(t *testing.T) {
	t.Run("reserved terminal capacity", func(t *testing.T) {
		f := newAuditLimitFixture(t)
		cfg := auditLimitConfig(f)
		cfg.Systems = cfg.Systems[:1]
		cfg.Users = map[string]gateway.User{"east": cfg.Users["east"]}
		u := cfg.Users["east"]
		u.Credentials = map[string]string{"alpha": "synthetic"}
		u.Allowed = []string{"alpha__echo"}
		cfg.Users["east"] = u
		cfg.Audit.Capacity = 4
		opts := recoveryOptions(t)
		g := recoveryOpen(t, cfg, opts)
		auditLimitSeed(t, g)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		f.block.Store(true)
		done := make(chan error, 1)
		go func() { _, err := g.Call(ctx, "east", "alpha__echo", map[string]any{}); done <- err }()
		f.gate.wait(t, ctx)
		east := gateway.Identity{Tenant: "tenant-east", Principal: "principal-east"}
		original, _ := g.Binding(east, "alpha")
		if _, err := g.ReplaceBinding(east, "alpha", original.Generation, "synthetic-other"); err == nil {
			t.Error("mutation stole reserved terminal capacity")
		}
		f.block.Store(false)
		f.gate.open()
		if err := cleanupReceive(t, done, 5*time.Second, "terminal event"); err != nil {
			t.Fatal(err)
		}
		before := f.requests.Load()
		_, _ = g.Call(ctx, "east", "alpha__echo", map[string]any{})
		if f.requests.Load() != before {
			t.Error("full durable audit dispatched work")
		}
		recoveryClose(t, g)
		opts.Initialize = false
		g = recoveryOpen(t, cfg, opts)
		before = f.requests.Load()
		_ = g.Refresh(ctx)
		if f.requests.Load() != before {
			t.Error("restart bypassed capacity")
		}
	})
	t.Run("tampered metadata", func(t *testing.T) {
		f := newAuditLimitFixture(t)
		cfg := auditLimitConfig(f)
		opts := recoveryOptions(t)
		g := recoveryOpen(t, cfg, opts)
		auditLimitSeed(t, g)
		recoveryClose(t, g)
		recoverySQL(t, opts.Path, "UPDATE audit SET event=json_set(event,'$.duration_ms',12345) WHERE sequence=1")
		opts.Initialize = false
		recoveryReject(t, cfg, opts)
	})
}

func TestAuditLimitsIntegrationCancellationReleasesPermit(t *testing.T) {
	f := newAuditLimitFixture(t)
	cfg := auditLimitConfig(f)
	cfg.Limits.Global.MaxConcurrent = 1
	g, err := gateway.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	auditLimitSeed(t, g)
	f.block.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := g.Call(ctx, "east", "alpha__echo", map[string]any{}); done <- err }()
	watch, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	f.gate.wait(t, watch)
	cancel()
	if err := cleanupReceive(t, done, 5*time.Second, "canceled call completion"); err == nil {
		t.Error("canceled call unexpectedly succeeded")
	}
	f.block.Store(false)
	f.gate.open()
	if _, err := g.Call(watch, "west", "beta__echo", map[string]any{}); err != nil {
		t.Fatal("canceled call leaked permit:", err)
	}
	if f.calls.Load() != 2 {
		t.Fatal("cancellation replayed call", f.calls.Load())
	}
}

func TestAuditLimitsIntegrationDiscoverySpendsSameRateBudget(t *testing.T) {
	f := newAuditLimitFixture(t)
	cfg := auditLimitConfig(f)
	cfg.Limits.Principal = gateway.AdmissionLimit{MaxConcurrent: 8, RatePerSecond: 0.000001, Burst: 3}
	g, err := gateway.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	auditLimitSeed(t, g)
	if _, err := g.Call(discoveryContext(t), "east", "alpha__echo", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	before := f.requests.Load()
	_, err = g.Call(discoveryContext(t), "east", "alpha__echo", map[string]any{})
	var denied *gateway.AdmissionFailure
	if !errors.As(err, &denied) || denied.Scope != "principal" || denied.Reason != "rate" {
		t.Fatalf("discovery/call rate budget not shared: %v", err)
	}
	if f.requests.Load() != before || f.calls.Load() != 1 {
		t.Error("rate-rejected operation reached provider")
	}
}

func TestAuditLimitsIntegrationCloseDrainsTerminal(t *testing.T) {
	f := newAuditLimitFixture(t)
	cfg := auditLimitConfig(f)
	opts := recoveryOptions(t)
	g := recoveryOpen(t, cfg, opts)
	auditLimitSeed(t, g)
	east := gateway.Identity{Tenant: "tenant-east", Principal: "principal-east"}
	before, err := g.Audit(east, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f.block.Store(true)
	done := make(chan error, 1)
	go func() { _, err := g.Call(ctx, "east", "alpha__echo", map[string]any{}); done <- err }()
	f.gate.wait(t, ctx)
	closed := make(chan error, 1)
	go func() { closed <- g.Close() }()
	if err := cleanupReceive(t, closed, 5*time.Second, "Close draining terminal audit"); err != nil {
		t.Fatal(err)
	}
	_ = cleanupReceive(t, done, 5*time.Second, "call exiting Close")
	opts.Initialize = false
	g = recoveryOpen(t, cfg, opts)
	page, err := g.Audit(east, before.LastSequence, 1000)
	if err != nil {
		t.Fatal(err)
	}
	start, terminal := 0, 0
	for _, event := range page.Events {
		if event.Action == gateway.AuditActionCall {
			switch event.Phase {
			case gateway.AuditPhaseStart:
				start++
			case gateway.AuditPhaseTerminal:
				terminal++
			}
		}
	}
	if start != 1 || terminal != 1 {
		t.Fatalf("Close left incomplete audit: start=%d terminal=%d", start, terminal)
	}
	if f.calls.Load() != 1 {
		t.Error("Close replayed call")
	}
}
