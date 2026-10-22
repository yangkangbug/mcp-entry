package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
	"github.com/yangkangbug/mcp-entry/internal/mock"
)

// This is an actual executable/HTTP integration test using the official Go SDK.
// It does not assert compatibility with the Codex GUI or MCP Inspector.
type cliE2ELog struct {
	sync.Mutex
	b bytes.Buffer
}

func (b *cliE2ELog) Write(p []byte) (int, error) { b.Lock(); defer b.Unlock(); return b.b.Write(p) }
func (b *cliE2ELog) String() string              { b.Lock(); defer b.Unlock(); return b.b.String() }

type cliE2EProcess struct {
	cmd     *exec.Cmd
	done    chan error
	log     *cliE2ELog
	stopped bool
}

func cliE2EStart(t *testing.T, binary string, args ...string) *cliE2EProcess {
	t.Helper()
	p := &cliE2EProcess{cmd: exec.Command(binary, args...), done: make(chan error, 1), log: new(cliE2ELog)}
	p.cmd.Stdout = p.log
	p.cmd.Stderr = p.log
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- p.cmd.Wait() }()
	t.Cleanup(func() {
		if !p.stopped {
			_ = p.cmd.Process.Kill()
			<-p.done
			p.stopped = true
		}
	})
	return p
}
func (p *cliE2EProcess) stop(t *testing.T) {
	t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-p.done:
		p.stopped = true
		if err != nil {
			t.Fatalf("SIGTERM was not orderly: %v; %s", err, p.log.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SIGTERM did not stop executable")
	}
}
func cliE2EAddress(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := l.Addr().String()
	_ = l.Close()
	return a
}
func cliE2EReady(t *testing.T, p *cliE2EProcess, address string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-p.done:
			p.stopped = true
			t.Fatalf("executable exited before serving: %v; %s", err, p.log.String())
		default:
		}
		c, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			if strings.Contains(p.log.String(), "NONPRODUCTION SYNTHETIC GATEWAY:") {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("executable did not listen: %s", p.log.String())
}

type cliE2EBearer string

func (token cliE2EBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	c := r.Clone(r.Context())
	c.Header = r.Header.Clone()
	c.Header.Set("Authorization", "Bearer "+string(token))
	return http.DefaultTransport.RoundTrip(c)
}
func cliE2EConnect(t *testing.T, address, token string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := mcp.NewClient(&mcp.Implementation{Name: "subprocess-e2e-official-sdk", Version: "1"}, nil)
	s, e := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: "http://" + address + "/mcp", HTTPClient: &http.Client{Transport: cliE2EBearer(token)}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func cliE2ETools(t *testing.T, s *mcp.ClientSession, want ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, e := s.ListTools(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	got := []string{}
	for _, tool := range r.Tools {
		got = append(got, tool.Name)
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) || len(got) > 0 && !reflect.DeepEqual(got, want) {
		t.Fatalf("tools=%v want=%v", got, want)
	}
}
func cliE2ECall(t *testing.T, s *mcp.ClientSession, name, user string, allowed bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, e := s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]any{"message": "synthetic-payload-canary-73492"}})
	if !allowed {
		if e == nil && r != nil && !r.IsError {
			t.Fatalf("forbidden tool %s succeeded", name)
		}
		return
	}
	if e != nil || r == nil || r.IsError {
		t.Fatalf("call %s: %v / %+v", name, e, r)
	}
	data, _ := json.Marshal(r.StructuredContent)
	var out mock.Output
	if e = json.Unmarshal(data, &out); e != nil {
		t.Fatal(e)
	}
	if out.User != user || out.System != strings.Split(name, "__")[0] || out.Message != "synthetic-payload-canary-73492" {
		t.Fatalf("identity/route/payload isolation failed: %+v", out)
	}
}

func TestGatewayExecutablePersistentLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM lifecycle test requires Unix")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	binary := filepath.Join(temp, "gateway")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-buildvcs=false", "-o", binary, "./cmd/gateway")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build executable: %v\n%s", err, output)
	}
	var downstreamRequests atomic.Int64
	downstream := func(system string, tokens map[string]string) *httptest.Server {
		h := mock.Handler(system, tokens)
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { downstreamRequests.Add(1); h.ServeHTTP(w, r) }))
		t.Cleanup(s.Close)
		return s
	}
	crm := downstream("crm", map[string]string{"synthetic-crm-alice-canary-73492": "alice", "synthetic-crm-bob-canary-73492": "bob"})
	docs := downstream("docs", map[string]string{"synthetic-docs-alice-canary-73492": "alice"})
	cfg := gateway.Config{Systems: []gateway.System{{Name: "crm", Endpoint: crm.URL}, {Name: "docs", Endpoint: docs.URL}}, Users: map[string]gateway.User{
		"alice": {Tenant: "east", Principal: "same-principal", Token: "synthetic-entry-alice-canary-73492", Allowed: []string{"crm__echo", "docs__echo"}, Credentials: map[string]string{"crm": "synthetic-crm-alice-canary-73492", "docs": "synthetic-docs-alice-canary-73492"}},
		"bob":   {Tenant: "west", Principal: "same-principal", Token: "synthetic-entry-bob-canary-73492", Allowed: []string{"crm__echo"}, Credentials: map[string]string{"crm": "synthetic-crm-bob-canary-73492"}},
	}}
	config := filepath.Join(temp, "config.json")
	data, _ := json.Marshal(cfg)
	if err = os.WriteFile(config, data, 0600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(temp, "key")
	keyBytes := []byte("synthetic-key-canary-73492-abcde")
	if len(keyBytes) != 32 {
		t.Fatal("fixture key must be raw32")
	}
	if err = os.WriteFile(key, keyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(temp, "authority.sqlite")
	base := []string{"-config", config, "-db", db, "-key-file", key}
	logs := []*cliE2ELog{}
	start := func(t *testing.T, args ...string) *cliE2EProcess {
		p := cliE2EStart(t, binary, args...)
		logs = append(logs, p.log)
		return p
	}
	runControl := func(t *testing.T, success bool, args ...string) string {
		t.Helper()
		before := downstreamRequests.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, append(append([]string{}, base...), args...)...)
		log := new(cliE2ELog)
		logs = append(logs, log)
		cmd.Stdout = log
		cmd.Stderr = log
		err := cmd.Run()
		if ctx.Err() != nil {
			t.Fatalf("offline control did not terminate: %s", log.String())
		}
		if (err == nil) != success {
			t.Fatalf("control expected success=%v: %v; %s", success, err, log.String())
		}
		if downstreamRequests.Load() != before {
			t.Fatal("offline control contacted downstream")
		}
		return log.String()
	}
	rejectServe := func(t *testing.T, args ...string) {
		t.Helper()
		address := cliE2EAddress(t)
		before := downstreamRequests.Load()
		p := start(t, append(args, "-listen", address)...)
		deadline := time.After(8 * time.Second)
		for {
			select {
			case err := <-p.done:
				p.stopped = true
				if err == nil {
					t.Fatal("unsafe startup exited successfully")
				}
				if downstreamRequests.Load() != before {
					t.Fatal("unsafe startup contacted downstream")
				}
				return
			case <-deadline:
				t.Fatalf("unsafe startup failed to terminate: %s", p.log.String())
			default:
			}
			c, e := net.DialTimeout("tcp", address, 10*time.Millisecond)
			if e == nil {
				_ = c.Close()
				t.Fatal("unsafe startup opened network listener")
			}
			time.Sleep(time.Millisecond)
		}
	}
	t.Run("reject_missing_state_and_key", func(t *testing.T) {
		rejectServe(t, base...)
		rejectServe(t, "-config", config, "-db", db)
		rejectServe(t, "-config", config, "-db", db, "-key-file", filepath.Join(temp, "absent-key"), "-init-db")
		if _, e := os.Stat(db); !os.IsNotExist(e) {
			t.Fatalf("invalid startup created database: %v", e)
		}
	})
	address := cliE2EAddress(t)
	p := start(t, append(append([]string{}, base...), "-init-db", "-listen", address)...)
	cliE2EReady(t, p, address)
	t.Run("two_user_two_downstream_sdk_isolation", func(t *testing.T) {
		alice := cliE2EConnect(t, address, cfg.Users["alice"].Token)
		bob := cliE2EConnect(t, address, cfg.Users["bob"].Token)
		cliE2ETools(t, alice, "crm__echo", "docs__echo")
		cliE2ETools(t, bob, "crm__echo")
		cliE2ECall(t, alice, "crm__echo", "alice", true)
		cliE2ECall(t, alice, "docs__echo", "alice", true)
		cliE2ECall(t, bob, "crm__echo", "bob", true)
		cliE2ECall(t, bob, "docs__echo", "bob", false)
	})
	t.Run("exclusive_owner", func(t *testing.T) {
		rejectServe(t, base...)
		runControl(t, false, "-operation", "revoke-binding", "-tenant", "east", "-principal", "same-principal", "-system", "docs", "-expected-version", "1")
	})
	p.stop(t)
	t.Run("init_never_overwrites", func(t *testing.T) {
		before, e := os.ReadFile(db)
		if e != nil {
			t.Fatal(e)
		}
		rejectServe(t, append(append([]string{}, base...), "-init-db")...)
		after, e := os.ReadFile(db)
		if e != nil || !bytes.Equal(before, after) {
			t.Fatal("explicit reinitialization changed existing database")
		}
	})
	t.Run("reject_unsafe_key_files_and_options", func(t *testing.T) {
		public := filepath.Join(temp, "public-key")
		if e := os.WriteFile(public, keyBytes, 0644); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(public, 0644); e != nil {
			t.Fatal(e)
		}
		rejectServe(t, "-config", config, "-db", db, "-key-file", public)
		link := filepath.Join(temp, "key-symlink")
		if e := os.Symlink(key, link); e != nil {
			t.Fatal(e)
		}
		rejectServe(t, "-config", config, "-db", db, "-key-file", link)
		short := filepath.Join(temp, "short-key")
		if e := os.WriteFile(short, []byte("short"), 0600); e != nil {
			t.Fatal(e)
		}
		rejectServe(t, "-config", config, "-db", db, "-key-file", short)
		rejectServe(t, append(append([]string{}, base...), "-unexpected", cfg.Users["alice"].Token)...)
	})
	t.Run("wrong_key_and_corrupt_database", func(t *testing.T) {
		wrong := filepath.Join(temp, "wrong-key")
		if e := os.WriteFile(wrong, bytes.Repeat([]byte{0x71}, 32), 0600); e != nil {
			t.Fatal(e)
		}
		rejectServe(t, "-config", config, "-db", db, "-key-file", wrong)
		corrupt := filepath.Join(temp, "corrupt.sqlite")
		if e := os.WriteFile(corrupt, []byte("not-a-database"), 0600); e != nil {
			t.Fatal(e)
		}
		rejectServe(t, "-config", config, "-db", corrupt, "-key-file", key)
	})
	address = cliE2EAddress(t)
	p = start(t, append(append([]string{}, base...), "-listen", address)...)
	cliE2EReady(t, p, address)
	t.Run("reopen_retains_authority", func(t *testing.T) {
		alice := cliE2EConnect(t, address, cfg.Users["alice"].Token)
		bob := cliE2EConnect(t, address, cfg.Users["bob"].Token)
		cliE2ETools(t, alice, "crm__echo", "docs__echo")
		cliE2ETools(t, bob, "crm__echo")
		cliE2ECall(t, bob, "crm__echo", "bob", true)
	})
	p.stop(t)
	t.Run("offline_scoped_revoke_and_disable", func(t *testing.T) {
		runControl(t, true, "-operation", "status", "-tenant", "east", "-principal", "same-principal")
		runControl(t, true, "-operation", "revoke-binding", "-tenant", "east", "-principal", "same-principal", "-system", "docs", "-expected-version", "1")
		runControl(t, false, "-operation", "revoke-binding", "-tenant", "east", "-principal", "same-principal", "-system", "docs", "-expected-version", "1")
		runControl(t, true, "-operation", "disable-principal", "-tenant", "west", "-principal", "same-principal", "-expected-version", "1")
	})
	address = cliE2EAddress(t)
	p = start(t, append(append([]string{}, base...), "-listen", address)...)
	cliE2EReady(t, p, address)
	t.Run("restart_does_not_restore_revoked_credentials", func(t *testing.T) {
		alice := cliE2EConnect(t, address, cfg.Users["alice"].Token)
		cliE2ETools(t, alice, "crm__echo")
		cliE2ECall(t, alice, "crm__echo", "alice", true)
		before := downstreamRequests.Load()
		cliE2ECall(t, alice, "docs__echo", "alice", false)
		if downstreamRequests.Load() != before {
			t.Fatal("revoked binding dispatched downstream")
		}
		req, _ := http.NewRequest(http.MethodPost, "http://"+address+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"disabled-auth-check","version":"1"}}}`))
		req.Header.Set("Authorization", "Bearer "+cfg.Users["bob"].Token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		client := &http.Client{Timeout: 5 * time.Second}
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("disabled old entry token status=%d want 401", resp.StatusCode)
		}
	})
	p.stop(t)
	t.Run("no_synthetic_secrets_or_payload_in_logs", func(t *testing.T) {
		canaries := []string{string(keyBytes), "synthetic-payload-canary-73492"}
		for _, u := range cfg.Users {
			canaries = append(canaries, u.Token)
			for _, v := range u.Credentials {
				canaries = append(canaries, v)
			}
		}
		for i, log := range logs {
			for _, canary := range canaries {
				if strings.Contains(log.String(), canary) {
					t.Errorf("process %d leaked synthetic canary", i)
				}
			}
		}
	})
	t.Log("subprocess E2E: official Go SDK HTTP, 2 users, 2 simulated downstreams; not a GUI-client verification")
}
