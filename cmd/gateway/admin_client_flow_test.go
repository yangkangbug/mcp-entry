package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
	"github.com/yangkangbug/mcp-entry/internal/mock"
)

// Exercises the shipped executables together, not a mock binding endpoint:
// missing provider credential -> MCP control tool -> private-file CLI bind ->
// real SDK business call -> separate admin CAS revoke -> persisted denial.
func TestAdminClientExecutableBindingLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM lifecycle requires Unix")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	build := func(name string) string {
		t.Helper()
		binary := filepath.Join(temp, name)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-p=1", "-buildvcs=false", "-o", binary, "./cmd/"+name)
		cmd.Dir = root
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v %s", name, err, output)
		}
		return binary
	}
	gatewayBinary, connectBinary := build("gateway"), build("connect")
	entry := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x35}, 32))
	admin := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x76}, 32))
	const provider = "synthetic-executable-provider-canary-46183"
	secrets := []string{entry, admin, provider}
	assertSafe := func(data []byte) {
		t.Helper()
		for _, secret := range secrets {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatal("credential leaked into response or executable output")
			}
		}
	}
	processes := []*cliE2EProcess{}
	// Registered before process cleanup, so this reads complete logs after exit.
	t.Cleanup(func() {
		for _, p := range processes {
			assertSafe([]byte(p.log.String()))
		}
	})
	upstream := httptest.NewServer(mock.Handler("crm", map[string]string{provider: "alice"}))
	defer upstream.Close()
	cfg := gateway.Config{Systems: []gateway.System{{Name: "crm", Endpoint: upstream.URL}}, Users: map[string]gateway.User{"alice": {Tenant: "demo", Principal: "alice", Token: entry, TokenExpiresAt: time.Now().Add(time.Hour).UTC(), Allowed: []string{"crm__echo"}, Credentials: map[string]string{}}}}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	config := writeOnboardingFile(t, "config.json", data)
	entryFile := writeOnboardingFile(t, "entry.private", []byte(entry))
	adminFile := writeOnboardingFile(t, "admin.private", []byte(admin))
	providerFile := writeOnboardingFile(t, "provider.private", []byte(provider))
	keyFile := writeOnboardingFile(t, "root.private", bytes.Repeat([]byte{0x51}, 32))
	address := cliE2EAddress(t)
	origin := "http://" + address
	base := []string{"-config", config, "-db", filepath.Join(temp, "state.db"), "-key-file", keyFile, "-listen", address, "-admin-token-file", adminFile, "-client-binding"}
	start := func(initialize bool) *cliE2EProcess {
		t.Helper()
		args := append([]string{}, base...)
		if initialize {
			args = append(args, "-init-db")
		}
		p := cliE2EStart(t, gatewayBinary, args...)
		processes = append(processes, p)
		cliE2EReady(t, p, address)
		return p
	}
	cli := func(extra ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		args := append([]string{"-gateway", origin, "-entry-file", entryFile}, extra...)
		output, err := exec.CommandContext(ctx, connectBinary, args...).CombinedOutput()
		assertSafe(output)
		if err != nil {
			t.Fatalf("connect executable failed: %v %s", err, output)
		}
		return output
	}
	adminCall := func(method, path, token, body string, want int) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, method, origin+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if method == "POST" {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-MCP-Admin", "1")
			req.Header.Set("Origin", origin)
		}
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		bodyBytes, err := io.ReadAll(io.LimitReader(response.Body, 128<<10))
		if err != nil {
			t.Fatal(err)
		}
		assertSafe(bodyBytes)
		if response.StatusCode != want {
			t.Fatalf("admin status %d want %d: %s", response.StatusCode, want, bodyBytes)
		}
		return bodyBytes
	}
	status := func(wantState string, wantGeneration uint64) {
		t.Helper()
		output := cli("-status")
		var view struct {
			Services []struct {
				System     string `json:"system"`
				State      string `json:"state"`
				Generation uint64 `json:"generation"`
			} `json:"services"`
		}
		if err := json.Unmarshal(output, &view); err != nil {
			t.Fatal(err)
		}
		if len(view.Services) != 1 || view.Services[0].System != "crm" || view.Services[0].State != wantState || view.Services[0].Generation != wantGeneration {
			t.Fatalf("unexpected safe service state: %s", output)
		}
	}
	process := start(true)
	session := cliE2EConnect(t, address, entry)
	cliE2ETools(t, session, "mcp_entry_connections", "mcp_entry_connection_begin", "mcp_entry_connection_status")
	cliE2ECall(t, session, "crm__echo", "alice", false)
	// The SDK closes its transport after an unknown-tool protocol rejection.
	// Use a fresh authenticated session for the independent control flow.
	_ = session.Close()
	session = cliE2EConnect(t, address, entry)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	control, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "mcp_entry_connections", Arguments: map[string]any{}})
	cancel()
	if err != nil || control == nil || control.IsError {
		details, _ := json.Marshal(control)
		assertSafe(details)
		if err != nil {
			assertSafe([]byte(err.Error()))
		}
		t.Fatalf("missing-credential control tool unavailable: %v %s", err, details)
	}
	controlJSON, err := json.Marshal(control)
	if err != nil {
		t.Fatal(err)
	}
	assertSafe(controlJSON)
	if !bytes.Contains(controlJSON, []byte("private_file_cli")) || !bytes.Contains(controlJSON, []byte("missing")) {
		t.Fatal("control tool did not describe missing connection and secure submission")
	}
	status("missing", 1)
	adminCall("GET", "/admin/api/snapshot", entry, "", 401)
	snapshot := adminCall("GET", "/admin/api/snapshot", admin, "", 200)
	if !bytes.Contains(snapshot, []byte(`"persistent":true`)) {
		t.Fatal("admin snapshot missing actual persistent state")
	}
	bound := cli("-service", "crm", "-generation", "1", "-credential-file", providerFile)
	if !bytes.Contains(bound, []byte(`"binding_saved":true`)) || !bytes.Contains(bound, []byte(`"discovery_status":"ready"`)) {
		t.Fatalf("binding/discovery not completed: %s", bound)
	}
	status("active", 2)
	cliE2ETools(t, session, "crm__echo", "mcp_entry_connections", "mcp_entry_connection_begin", "mcp_entry_connection_status")
	cliE2ECall(t, session, "crm__echo", "alice", true)
	preview := `{"action":"revoke_binding","tenant":"demo","principal":"alice","system":"crm","expected_version":2,"preview":true}`
	adminCall("POST", "/admin/api/mutate", admin, preview, 200)
	// Preview is not a write and cannot revoke the existing business session.
	cliE2ECall(t, session, "crm__echo", "alice", true)
	confirmed := strings.Replace(preview, `"preview":true`, `"confirm":true`, 1)
	adminCall("POST", "/admin/api/mutate", admin, confirmed, 200)
	adminCall("POST", "/admin/api/mutate", admin, confirmed, 409)
	status("revoked", 3)
	cliE2ETools(t, session, "mcp_entry_connections", "mcp_entry_connection_begin", "mcp_entry_connection_status")
	cliE2ECall(t, session, "crm__echo", "alice", false)
	_ = session.Close()
	process.stop(t)
	process = start(false)
	session = cliE2EConnect(t, address, entry)
	status("revoked", 3)
	cliE2ETools(t, session, "mcp_entry_connections", "mcp_entry_connection_begin", "mcp_entry_connection_status")
	cliE2ECall(t, session, "crm__echo", "alice", false)
	audit := adminCall("POST", "/admin/api/audit", admin, `{"after":0,"limit":100}`, 200)
	var page gateway.AuditPage
	if err := json.Unmarshal(audit, &page); err != nil {
		t.Fatal(err)
	}
	revocations := 0
	for _, event := range page.Events {
		if event.Action == gateway.AuditActionBindingRevoke {
			revocations++
			if event.Actor != gateway.AuditActorOperator || event.BindingVersion != 3 {
				t.Fatal("incorrect persisted operator revocation audit")
			}
		}
	}
	if revocations != 1 {
		t.Fatalf("revocation audit count %d", revocations)
	}
	_ = session.Close()
	process.stop(t)
}
