package gateway_test

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

// These tests use only synthetic credentials, temporary databases and loopback.
func recoveryConfig(f *revocationFixture) gateway.Config {
	return gateway.Config{Systems: []gateway.System{{Name: "shared", Endpoint: f.server.URL}}, Users: map[string]gateway.User{
		"east-user": {Tenant: revocationEast.Tenant, Principal: revocationEast.Principal, Token: "recovery-entry-canary-east-09472", Allowed: []string{"shared__whoami"}, Credentials: map[string]string{"shared": "synthetic-east"}},
		"west-user": {Tenant: revocationWest.Tenant, Principal: revocationWest.Principal, Token: "recovery-entry-canary-west-09472", Allowed: []string{"shared__whoami"}, Credentials: map[string]string{"shared": "synthetic-west"}},
	}}
}
func recoveryOptions(t *testing.T) gateway.PersistenceOptions {
	t.Helper()
	return gateway.PersistenceOptions{Path: filepath.Join(t.TempDir(), "authority.sqlite"), Key: bytes.Repeat([]byte{0x53}, 32), Initialize: true}
}
func recoveryOpen(t *testing.T, cfg gateway.Config, opts gateway.PersistenceOptions) *gateway.Gateway {
	t.Helper()
	g, err := gateway.NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}
func recoveryClose(t *testing.T, g *gateway.Gateway) {
	t.Helper()
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
}
func recoveryReject(t *testing.T, cfg gateway.Config, opts gateway.PersistenceOptions) {
	t.Helper()
	g, err := gateway.NewPersistent(cfg, opts)
	if g != nil {
		_ = g.Close()
	}
	if err == nil {
		t.Fatal("unsafe persistent startup succeeded")
	}
}

func TestPersistenceRecoveryRevocationAndStableVersions(t *testing.T) {
	f := newRevocationFixture(t)
	cfg := recoveryConfig(f)
	opts := recoveryOptions(t)
	g := recoveryOpen(t, cfg, opts)
	east, _ := g.Binding(revocationEast, "shared")
	west, _ := g.Binding(revocationWest, "shared")
	revoked, err := g.RevokeBinding(revocationEast, "shared", east.Generation)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := g.SetPolicy(revocationEast, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := g.DisablePrincipal(revocationWest, 1)
	if err != nil {
		t.Fatal(err)
	}
	disabledBinding, _ := g.Binding(revocationWest, "shared")
	recoveryClose(t, g)
	opts.Initialize = false
	g = recoveryOpen(t, cfg, opts) // Config deliberately still grants both users.
	gotEast, err := g.Binding(revocationEast, "shared")
	if err != nil || gotEast != revoked {
		t.Fatalf("revocation not durable: %+v, %v", gotEast, err)
	}
	gotWest, err := g.Binding(revocationWest, "shared")
	if err != nil || gotWest != disabledBinding || gotWest.ID != west.ID {
		t.Fatalf("disabled binding not durable: %+v, %v", gotWest, err)
	}
	gotPolicy, err := g.Policy(revocationEast)
	if err != nil || !reflect.DeepEqual(gotPolicy, policy) {
		t.Fatalf("policy not durable: %+v, %v", gotPolicy, err)
	}
	gotDisabled, err := g.Policy(revocationWest)
	if err != nil || !reflect.DeepEqual(gotDisabled, disabled) {
		t.Fatalf("disabled principal not durable: %+v, %v", gotDisabled, err)
	}
	before := f.requests.Load()
	_ = g.Refresh(discoveryContext(t))
	assertRevocationDenied(t, discoveryContext(t), g, f, "east-user")
	assertRevocationDenied(t, discoveryContext(t), g, f, "west-user")
	if f.requests.Load() != before {
		t.Fatal("revoked configuration caused discovery traffic")
	}
	if _, err := g.ReplaceBinding(revocationEast, "shared", east.Generation, "synthetic-east"); !errors.Is(err, gateway.ErrConflict) {
		t.Fatalf("old generation accepted: %v", err)
	}
	if _, err := g.SetPolicy(revocationEast, 1, []string{"shared__whoami"}); !errors.Is(err, gateway.ErrConflict) {
		t.Fatalf("old policy version accepted: %v", err)
	}
	if _, err := g.ReplaceBinding(revocationWest, "shared", gotWest.Generation, "synthetic-west"); !errors.Is(err, gateway.ErrDenied) {
		t.Fatalf("disabled principal restored: %v", err)
	}
}

func TestPersistenceRecoveryReplacementOverridesStaleConfig(t *testing.T) {
	f := newRevocationFixture(t)
	cfg := recoveryConfig(f)
	opts := recoveryOptions(t)
	g := recoveryOpen(t, cfg, opts)
	original, _ := g.Binding(revocationEast, "shared")
	replaced, err := g.ReplaceBinding(revocationEast, "shared", original.Generation, "synthetic-west")
	if err != nil {
		t.Fatal(err)
	}
	recoveryClose(t, g)
	opts.Initialize = false
	g = recoveryOpen(t, cfg, opts)
	got, err := g.Binding(revocationEast, "shared")
	if err != nil || got != replaced || got.ID != original.ID {
		t.Fatalf("replacement changed across restart: %+v, %v", got, err)
	}
	if len(g.Names("east-user")) != 0 {
		t.Fatal("restart restored stale catalog")
	}
	if issues := g.Refresh(discoveryContext(t)); len(issues) != 0 {
		t.Fatal(issues)
	}
	assertRevocationIdentity(t, discoveryContext(t), g, "east-user", "west")
}

func TestPersistenceRecoveryRejectsUnsafeStartup(t *testing.T) {
	f := newRevocationFixture(t)
	t.Run("missing must not initialize", func(t *testing.T) {
		opts := recoveryOptions(t)
		opts.Initialize = false
		recoveryReject(t, recoveryConfig(f), opts)
	})
	t.Run("corrupt must not initialize", func(t *testing.T) {
		opts := recoveryOptions(t)
		if err := os.WriteFile(opts.Path, []byte("synthetic-not-a-database"), 0600); err != nil {
			t.Fatal(err)
		}
		opts.Initialize = false
		recoveryReject(t, recoveryConfig(f), opts)
		opts.Initialize = true
		recoveryReject(t, recoveryConfig(f), opts)
	})
	t.Run("invalid key", func(t *testing.T) {
		for _, size := range []int{0, 16, 31, 33} {
			opts := recoveryOptions(t)
			opts.Key = make([]byte, size)
			recoveryReject(t, recoveryConfig(f), opts)
		}
	})
	t.Run("wrong key without active secrets", func(t *testing.T) {
		cfg := recoveryConfig(f)
		for id, u := range cfg.Users {
			u.Credentials = nil
			cfg.Users[id] = u
		}
		opts := recoveryOptions(t)
		g := recoveryOpen(t, cfg, opts)
		recoveryClose(t, g)
		opts.Initialize = false
		opts.Key = bytes.Repeat([]byte{0x54}, 32)
		recoveryReject(t, cfg, opts)
	})
	t.Run("existing cannot reinitialize", func(t *testing.T) {
		cfg := recoveryConfig(f)
		opts := recoveryOptions(t)
		g := recoveryOpen(t, cfg, opts)
		recoveryClose(t, g)
		recoveryReject(t, cfg, opts)
	})
	for _, kind := range []string{"endpoint", "scope", "user removed", "user added", "auth mode"} {
		t.Run(kind, func(t *testing.T) {
			cfg := recoveryConfig(f)
			opts := recoveryOptions(t)
			g := recoveryOpen(t, cfg, opts)
			recoveryClose(t, g)
			opts.Initialize = false
			switch kind {
			case "endpoint":
				cfg.Systems[0].Endpoint = "http://127.0.0.1:1"
			case "scope":
				u := cfg.Users["east-user"]
				u.Tenant = "changed"
				cfg.Users["east-user"] = u
			case "user removed":
				delete(cfg.Users, "east-user")
			case "user added":
				cfg.Users["new-user"] = gateway.User{Token: "synthetic-new-token"}
			case "auth mode":
				cfg.Systems[0].Auth = gateway.AuthConfig{Mode: "raw"}
			}
			recoveryReject(t, cfg, opts)
		})
	}
}

func TestPersistenceRecoveryConcurrentCAS(t *testing.T) {
	f := newRevocationFixture(t)
	cfg := recoveryConfig(f)
	opts := recoveryOptions(t)
	g := recoveryOpen(t, cfg, opts)
	original, _ := g.Binding(revocationEast, "shared")
	const count = 16
	start := make(chan struct{})
	out := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := g.ReplaceBinding(revocationEast, "shared", original.Generation, "synthetic-west")
			out <- err
		}()
	}
	close(start)
	wg.Wait()
	close(out)
	wins := 0
	for err := range out {
		if err == nil {
			wins++
		} else if !errors.Is(err, gateway.ErrConflict) {
			t.Fatalf("unexpected CAS error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("CAS winners=%d", wins)
	}
	current, _ := g.Binding(revocationEast, "shared")
	if current.Generation != original.Generation+1 || current.ID != original.ID {
		t.Fatalf("bad committed revision: %+v", current)
	}
	recoveryClose(t, g)
	opts.Initialize = false
	g = recoveryOpen(t, cfg, opts)
	got, _ := g.Binding(revocationEast, "shared")
	if got != current {
		t.Fatalf("CAS not durable: %+v vs %+v", got, current)
	}
}

func TestPersistenceRecoveryExclusiveOwnerAndClosedDenial(t *testing.T) {
	f := newRevocationFixture(t)
	cfg := recoveryConfig(f)
	opts := recoveryOptions(t)
	g := recoveryOpen(t, cfg, opts)
	if issues := g.Refresh(discoveryContext(t)); len(issues) != 0 {
		t.Fatal(issues)
	}
	opts.Initialize = false
	recoveryReject(t, cfg, opts)
	recoveryClose(t, g)
	recoveryClose(t, g)
	before := f.requests.Load()
	_ = g.Refresh(context.Background())
	if len(g.Names("east-user")) != 0 {
		t.Fatal("closed instance exposed tools")
	}
	if result, err := g.Call(discoveryContext(t), "east-user", "shared__whoami", map[string]any{}); err == nil || result != nil {
		t.Fatalf("closed call succeeded: %v, %v", result, err)
	}
	if _, err := g.ReplaceBinding(revocationEast, "shared", 1, "synthetic-west"); err == nil {
		t.Fatal("closed mutation succeeded")
	}
	if f.requests.Load() != before {
		t.Fatal("closed instance contacted downstream")
	}
	reopened := recoveryOpen(t, cfg, opts)
	if issues := reopened.Refresh(discoveryContext(t)); len(issues) != 0 {
		t.Fatal(issues)
	}
	assertRevocationIdentity(t, discoveryContext(t), reopened, "east-user", "east")
}

func recoveryAssertNoPlaintext(t *testing.T, path string, canaries ...string) {
	t.Helper()
	err := filepath.Walk(filepath.Dir(path), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, canary := range canaries {
			if bytes.Contains(data, []byte(canary)) {
				t.Errorf("plaintext synthetic secret found in %s", filepath.Base(path))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestPersistenceRecoveryNoPlaintextSecretsOnDisk(t *testing.T) {
	f := newRevocationFixture(t)
	cfg := recoveryConfig(f)
	opts := recoveryOptions(t)
	g := recoveryOpen(t, cfg, opts)
	canaries := []string{cfg.Users["east-user"].Token, cfg.Users["west-user"].Token, "synthetic-east", "synthetic-west", "replacement-downstream-canary-784129"}
	recoveryAssertNoPlaintext(t, opts.Path, canaries...)
	if _, err := g.ReplaceBinding(revocationEast, "shared", 1, canaries[4]); err != nil {
		t.Fatal(err)
	}
	recoveryAssertNoPlaintext(t, opts.Path, canaries...)
	recoveryClose(t, g)
	recoveryAssertNoPlaintext(t, opts.Path, canaries...)
}

// The trigger is test-only fault injection, not a production escape hatch.
func recoverySQL(t *testing.T, path, statement string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(statement); err != nil {
		t.Fatal(err)
	}
}
func TestPersistenceRecoveryFailedCommitPoisonsWithoutAcknowledgement(t *testing.T) {
	for _, kind := range []string{"grant policy", "replace binding", "revoke binding", "disable principal"} {
		t.Run(kind, func(t *testing.T) {
			f := newRevocationFixture(t)
			cfg := recoveryConfig(f)
			opts := recoveryOptions(t)
			g := recoveryOpen(t, cfg, opts)
			if kind == "grant policy" {
				if _, err := g.SetPolicy(revocationEast, 1, nil); err != nil {
					t.Fatal(err)
				}
			}
			oldPolicy, _ := g.Policy(revocationEast)
			oldBinding, _ := g.Binding(revocationEast, "shared")
			recoveryClose(t, g)
			recoverySQL(t, opts.Path, "CREATE TRIGGER recovery_fail_final_update BEFORE UPDATE ON meta WHEN EXISTS (SELECT 1 FROM audit WHERE sequence=NEW.audit_sequence AND json_extract(event, '$.phase')='commit') BEGIN SELECT RAISE(ABORT, 'synthetic persistence failure'); END")
			opts.Initialize = false
			g = recoveryOpen(t, cfg, opts)
			_ = g.Refresh(discoveryContext(t))
			var err error
			switch kind {
			case "grant policy":
				_, err = g.SetPolicy(revocationEast, oldPolicy.Version, []string{"shared__whoami"})
			case "replace binding":
				_, err = g.ReplaceBinding(revocationEast, "shared", oldBinding.Generation, "synthetic-west")
			case "revoke binding":
				_, err = g.RevokeBinding(revocationEast, "shared", oldBinding.Generation)
			case "disable principal":
				_, err = g.DisablePrincipal(revocationEast, oldPolicy.Version)
			}
			if !errors.Is(err, gateway.ErrStorage) {
				t.Fatalf("failed persistence acknowledged or wrong error: %v", err)
			}
			before := f.requests.Load()
			if len(g.Names("east-user")) != 0 {
				t.Fatal("failed storage left an authorizing catalog")
			}
			if result, err := g.Call(discoveryContext(t), "east-user", "shared__whoami", map[string]any{}); err == nil || result != nil {
				t.Fatalf("poisoned call succeeded: %v, %v", result, err)
			}
			_ = g.Refresh(context.Background())
			if f.requests.Load() != before {
				t.Fatal("poisoned instance contacted downstream")
			}
			recoveryClose(t, g)
			recoverySQL(t, opts.Path, "DROP TRIGGER recovery_fail_final_update")
			g = recoveryOpen(t, cfg, opts)
			gotPolicy, _ := g.Policy(revocationEast)
			gotBinding, _ := g.Binding(revocationEast, "shared")
			if !reflect.DeepEqual(gotPolicy, oldPolicy) || gotBinding != oldBinding {
				t.Fatalf("failed transaction changed durable state: policy=%+v binding=%+v", gotPolicy, gotBinding)
			}
		})
	}
}

func TestPersistenceRecoveryRejectsTamperedAuthority(t *testing.T) {
	// Whole-state integrity and AEAD must not treat missing authority rows as fresh
	// configuration. These tests intentionally make no anti-backup-rollback claim.
	cases := map[string]string{
		"missing principal":                "DELETE FROM principals WHERE user_id = 'east-user'",
		"missing binding":                  "DELETE FROM bindings WHERE user_id = 'east-user'",
		"missing metadata":                 "DELETE FROM meta",
		"policy version":                   "UPDATE principals SET policy_version = policy_version + 1 WHERE user_id = 'east-user'",
		"policy grant":                     "UPDATE principals SET allowed = '[\"shared__whoami\",\"shared__admin\"]' WHERE user_id = 'east-user'",
		"binding generation":               "UPDATE bindings SET generation = generation + 1 WHERE user_id = 'east-user'",
		"binding ID":                       "UPDATE bindings SET binding_id = 'forged-binding' WHERE user_id = 'east-user'",
		"ciphertext identity substitution": "UPDATE bindings SET credential = (SELECT credential FROM bindings WHERE user_id = 'west-user' AND system = 'shared') WHERE user_id = 'east-user' AND system = 'shared'",
		"corrupt ciphertext":               "UPDATE bindings SET credential = X'01020304' WHERE user_id = 'east-user'",
	}
	for name, statement := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRevocationFixture(t)
			cfg := recoveryConfig(f)
			opts := recoveryOptions(t)
			g := recoveryOpen(t, cfg, opts)
			recoveryClose(t, g)
			recoverySQL(t, opts.Path, statement)
			opts.Initialize = false
			recoveryReject(t, cfg, opts)
		})
	}
}

func TestPersistenceRecoveryCloseCancelsDiscovery(t *testing.T) {
	f := newRevocationFixture(t)
	cfg := recoveryConfig(f)
	opts := recoveryOptions(t)
	g := recoveryOpen(t, cfg, opts)
	ctx := discoveryContext(t)
	barrier := newRevocationBarrier(t)
	f.block("tools/list", barrier, false)
	done := make(chan struct{})
	go func() { _ = g.Refresh(ctx); close(done) }()
	barrier.wait(t, ctx)
	recoveryClose(t, g)
	barrier.open()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("Close did not terminate pending discovery")
	}
	before := f.requests.Load()
	_ = g.Refresh(ctx)
	if len(g.Names("east-user")) != 0 || len(g.Names("west-user")) != 0 {
		t.Fatal("discovery republished after Close")
	}
	if result, err := g.Call(ctx, "east-user", "shared__whoami", map[string]any{}); err == nil || result != nil {
		t.Fatalf("closed call: %v, %v", result, err)
	}
	if f.requests.Load() != before {
		t.Fatal("closed gateway initiated new downstream work")
	}
	opts.Initialize = false
	_ = recoveryOpen(t, cfg, opts)
}

func TestPersistenceRecoveryCloseRacesMutations(t *testing.T) {
	f := newRevocationFixture(t)
	cfg := recoveryConfig(f)
	opts := recoveryOptions(t)
	g := recoveryOpen(t, cfg, opts)
	start := make(chan struct{})
	successes := make(chan int, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			var err error
			if i%2 == 0 {
				_, err = g.ReplaceBinding(revocationEast, "shared", 1, "synthetic-west")
			} else {
				_, err = g.SetPolicy(revocationEast, 1, nil)
			}
			if err == nil {
				successes <- i % 2
			}
			if err != nil && !errors.Is(err, gateway.ErrConflict) && !errors.Is(err, gateway.ErrClosed) {
				t.Errorf("mutation racing Close: %v", err)
			}
		}(i)
	}
	close(start)
	recoveryClose(t, g)
	wg.Wait()
	close(successes)
	expectedPolicy, expectedBinding := uint64(1), uint64(1)
	for kind := range successes {
		if kind == 0 {
			expectedBinding++
		} else {
			expectedPolicy++
		}
	}
	if len(g.Names("east-user")) != 0 {
		t.Fatal("closed gateway retained tools")
	}
	opts.Initialize = false
	g = recoveryOpen(t, cfg, opts)
	// Either lock order is legal; every acknowledged update must leave a complete,
	// readable state, never a half-written principal or binding transaction.
	policy, err := g.Policy(revocationEast)
	if err != nil || policy.Version != expectedPolicy {
		t.Fatalf("invalid recovered policy: %+v, %v", policy, err)
	}
	binding, err := g.Binding(revocationEast, "shared")
	if err != nil || binding.Generation != expectedBinding {
		t.Fatalf("invalid recovered binding: %+v, %v", binding, err)
	}
}

func TestPersistenceRecoveryProcessOwnerCrash(t *testing.T) {
	if os.Getenv("MCP_RECOVERY_CHILD") == "1" {
		var cfg gateway.Config
		if err := json.Unmarshal([]byte(os.Getenv("MCP_RECOVERY_CONFIG")), &cfg); err != nil {
			t.Fatal(err)
		}
		g, err := gateway.NewPersistent(cfg, gateway.PersistenceOptions{Path: os.Getenv("MCP_RECOVERY_PATH"), Key: bytes.Repeat([]byte{0x53}, 32)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.RevokeBinding(revocationEast, "shared", 1); err != nil {
			t.Fatal(err)
		}
		fmt.Println("synthetic-owner-ready")
		_, _ = bufio.NewReader(os.Stdin).ReadByte()
		os.Exit(0) // Parent normally kills the process without graceful Close.
	}
	f := newRevocationFixture(t)
	cfg := recoveryConfig(f)
	opts := recoveryOptions(t)
	g := recoveryOpen(t, cfg, opts)
	original, _ := g.Binding(revocationEast, "shared")
	recoveryClose(t, g)
	opts.Initialize = false
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestPersistenceRecoveryProcessOwnerCrash$")
	cmd.Env = append(os.Environ(), "MCP_RECOVERY_CHILD=1", "MCP_RECOVERY_PATH="+opts.Path, "MCP_RECOVERY_CONFIG="+string(encoded))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "synthetic-owner-ready" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	ctx := discoveryContext(t)
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child failed before ownership ready")
		}
	case <-ctx.Done():
		t.Fatal("child ownership did not become ready")
	}
	recoveryReject(t, cfg, opts)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	waited = true
	g = recoveryOpen(t, cfg, opts)
	recovered, err := g.Binding(revocationEast, "shared")
	if err != nil || recovered.ID != original.ID || recovered.Generation != original.Generation+1 || recovered.State != gateway.BindingRevoked {
		t.Fatalf("committed revocation lost after process exit: %+v, %v", recovered, err)
	}
	_ = g.Refresh(ctx)
	assertRevocationDenied(t, ctx, g, f, "east-user")
}

// Defaults retain the historical topology serialization; changing only runtime
// budgets must preserve authenticated state instead of reseeding old grants.
func TestPersistenceServiceTimeoutRestartPreservesRevocation(t *testing.T) {
	f := newRevocationFixture(t)
	cfg := recoveryConfig(f)
	opts := recoveryOptions(t)
	g := recoveryOpen(t, cfg, opts)
	old, _ := g.Binding(revocationEast, "shared")
	revoked, err := g.RevokeBinding(revocationEast, "shared", old.Generation)
	if err != nil {
		t.Fatal(err)
	}
	recoveryClose(t, g)
	opts.Initialize = false
	cfg.Systems[0].Timeouts = &gateway.TimeoutConfig{DiscoveryMS: 5000, CallMS: 30000, ResponseHeaderMS: 25000}
	g = recoveryOpen(t, cfg, opts)
	got, err := g.Binding(revocationEast, "shared")
	if err != nil || got != revoked {
		t.Fatalf("runtime budget reset state: %+v %v", got, err)
	}
	recoveryClose(t, g)
	cfg.Systems[0].Auth = gateway.AuthConfig{Mode: "raw"}
	recoveryReject(t, cfg, opts) // The timeout exception must not weaken auth topology.
	cfg.Systems[0].Auth = gateway.AuthConfig{}
	cfg.Systems[0].Endpoint = "http://127.0.0.1:1"
	recoveryReject(t, cfg, opts)
}
