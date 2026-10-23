package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangkangbug/mcp-entry/internal/gateway"
	"github.com/yangkangbug/mcp-entry/internal/mock"
)

func onboardingConfig() gateway.Config {
	return gateway.Config{Systems: []gateway.System{{Name: "crm", Endpoint: "http://127.0.0.1:1/mcp"}}, Users: map[string]gateway.User{"alice": {Allowed: []string{"crm__echo"}}}}
}
func writeOnboardingFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestCredentialsFileSupplementAndIsolation(t *testing.T) {
	cfg := onboardingConfig()
	path := writeOnboardingFile(t, "credentials.json", []byte(`{"users":{"alice":{"token":"demo-alice","credentials":{"crm":"mock-crm-alice"}}}}`))
	got, err := loadCredentials(cfg, path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Users["alice"].Token != "demo-alice" || got.Users["alice"].Credentials["crm"] != "mock-crm-alice" {
		t.Fatal("missing supplement")
	}
	if cfg.Users["alice"].Token != "" || len(cfg.Users["alice"].Credentials) != 0 {
		t.Fatal("input mutated")
	}
	g, err := gateway.New(got)
	if err != nil {
		t.Fatal(err)
	}
	g.Close()
}
func TestCredentialsFileRejectsUnsafeInputs(t *testing.T) {
	canary := "secret-canary"
	cases := []string{
		`{"Users":{"alice":{"token":"secret-canary"}}}`, `{"users":{"alice":{"Token":"secret-canary"}}}`, `{"users":{"alice":{"token":null,"credentials":{"crm":"x"}}}}`, `null`, `[]`, `{}`, `{"users":{}}`, `{"users":{"alice":{}}}`,
		`{"users":{"unknown":{"token":"secret-canary"}}}`,
		`{"users":{"alice":{"token":""}}}`,
		`{"users":{"alice":{"credentials":{"unknown":"secret-canary"}}}}`,
		`{"users":{"alice":{"credentials":{"crm":""}}}}`,
		`{"users":{"alice":{"allowed":["crm__echo"],"token":"secret-canary"}}}`,
		`{"users":{"alice":{"token":"secret-canary","token":"second"}}}`,
		`{"users":{"alice":{"token":"secret-canary"},"alice":{"token":"second"}}}`,
		`{"users":{"alice":{"token":"secret-canary"}}} {}`,
		strings.Repeat("x", (256<<10)+1),
	}
	for _, data := range cases {
		path := writeOnboardingFile(t, "secret-path-canary", []byte(data))
		_, err := loadCredentials(onboardingConfig(), path)
		if err == nil || strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), path) {
			t.Fatalf("unsafe input accepted or leaked: %.100s %v", data, err)
		}
	}
	path := writeOnboardingFile(t, "credentials.json", []byte(`{"users":{"alice":{"token":"demo-alice"}}}`))
	for _, mode := range []os.FileMode{0644, 0620, 0604} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCredentials(onboardingConfig(), path); err == nil {
			t.Fatal("public file accepted")
		}
	}
	os.Chmod(path, 0600)
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{link, filepath.Dir(path), path + ".missing"} {
		if _, err := loadCredentials(onboardingConfig(), bad); err == nil {
			t.Fatal("unsafe file accepted")
		}
	}
}
func TestCredentialsFileNeverOverrides(t *testing.T) {
	for _, inline := range []gateway.User{{Token: "inline"}, {Credentials: map[string]string{"crm": "inline"}}, {Credentials: map[string]string{"crm": ""}}} {
		cfg := onboardingConfig()
		cfg.Users["alice"] = inline
		path := writeOnboardingFile(t, "credentials.json", []byte(`{"users":{"alice":{"token":"file","credentials":{"crm":"file"}}}}`))
		if _, err := loadCredentials(cfg, path); err == nil {
			t.Fatal("override accepted")
		}
	}
}
func TestCheckConfigOfflineAndScoped(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	cfg := onboardingConfig()
	cfg.Systems[0].Endpoint = server.URL + "/mcp"
	data, _ := json.Marshal(cfg)
	path := writeOnboardingFile(t, "config.json", data)
	credentials := writeOnboardingFile(t, "credentials.json", []byte(`{"users":{"alice":{"token":"secret-canary","credentials":{"crm":"mock-crm-alice"}}}}`))
	var output bytes.Buffer
	reader := &countingReader{}
	if err := run([]string{"-operation", "check-config", "-config", path, "-credentials-file", credentials}, reader, &output, &output); err != nil {
		t.Fatal(err)
	}
	want := "{\"valid\":true,\"scope\":\"bootstrap-config\",\"systems\":1,\"users\":1,\"discovery_checked\":false,\"storage_checked\":false}\n"
	if output.String() != want || calls.Load() != 0 || reader.count != 0 {
		t.Fatalf("preflight side effect or wrong report: %q", output.String())
	}
}
func TestCheckConfigAndCredentialOptions(t *testing.T) {
	for _, extra := range [][]string{{"-db", "x"}, {"-init-db=false"}, {"-key-stdin"}, {"-listen", "127.0.0.1:0"}, {"-account=false"}, {"-allow-remote-test=false"}, {"-tenant", "demo"}, {"-credentials-file", ""}} {
		args := append([]string{"-operation", "check-config"}, extra...)
		if _, err := parseOptions(args, io.Discard); !errors.Is(err, errOptions) {
			t.Fatalf("accepted %v", args)
		}
	}
	for _, args := range [][]string{
		{"-credentials-file", "x", "-db", "x", "-key-file", "x"},
		{"-credentials-file", "x", "-db", "x", "-key-file", "x", "-operation", "migrate"},
		{"-credentials-file", ""},
	} {
		if _, err := parseOptions(args, io.Discard); !errors.Is(err, errOptions) {
			t.Fatalf("accepted %v", args)
		}
	}
	for _, args := range [][]string{{"-operation", "check-config"}, {"-credentials-file", "x"}, {"-credentials-file", "x", "-db", "x", "-key-file", "x", "-init-db"}} {
		if _, err := parseOptions(args, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
}
func TestCheckConfigUsesExistingValidators(t *testing.T) {
	cases := []string{
		`{"systems":[],"users":{"alice":{"token":"secret-canary","allowed":["missing__echo"]}}}`,
		`{"systems":[{"name":"crm","endpoint":"http://example.com/mcp"}],"users":{}}`,
		`{"systems":[],"users":{},"unknown":"secret-canary"}`,
	}
	for _, data := range cases {
		path := writeOnboardingFile(t, "config.json", []byte(data))
		var output bytes.Buffer
		err := run([]string{"-operation", "check-config", "-config", path}, nil, &output, &output)
		if err == nil || output.Len() != 0 || strings.Contains(err.Error(), "secret-canary") {
			t.Fatalf("invalid config accepted or leaked: %v", err)
		}
	}
}
func TestCredentialsExecutablePersistentBootstrap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM lifecycle requires Unix")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "gateway")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-buildvcs=false", "-o", binary, "./cmd/gateway")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	server := httptest.NewServer(mock.Handler("crm", map[string]string{"mock-crm-alice": "alice"}))
	defer server.Close()
	cfg := onboardingConfig()
	cfg.Systems[0].Endpoint = server.URL
	data, _ := json.Marshal(cfg)
	config := writeOnboardingFile(t, "config.json", data)
	credentials := writeOnboardingFile(t, "credentials.json", []byte(`{"users":{"alice":{"token":"demo-alice","credentials":{"crm":"mock-crm-alice"}}}}`))
	key := writeOnboardingFile(t, "root.key", bytes.Repeat([]byte{'k'}, 32))
	db := filepath.Join(t.TempDir(), "state.db")
	base := []string{"-config", config, "-db", db, "-key-file", key}
	address := cliE2EAddress(t)
	start := append(append([]string{}, base...), "-init-db", "-credentials-file", credentials, "-listen", address)
	process := cliE2EStart(t, binary, start...)
	cliE2EReady(t, process, address)
	session := cliE2EConnect(t, address, "demo-alice")
	cliE2ETools(t, session, "crm__echo")
	cliE2ECall(t, session, "crm__echo", "alice", true)
	session.Close()
	process.stop(t)
	revoke := append(append([]string{}, base...), "-operation", "revoke-binding", "-tenant", "demo", "-principal", "alice", "-system", "crm", "-expected-version", "1")
	if out, err := exec.Command(binary, revoke...).CombinedOutput(); err != nil {
		t.Fatalf("revoke: %v %s", err, out)
	}
	// Bootstrap files are unnecessary at reopen, and cannot restore revoked access.
	if err := os.Remove(credentials); err != nil {
		t.Fatal(err)
	}
	reopen := append(append([]string{}, base...), "-listen", address)
	process = cliE2EStart(t, binary, reopen...)
	cliE2EReady(t, process, address)
	session = cliE2EConnect(t, address, "demo-alice")
	cliE2ETools(t, session)
	cliE2ECall(t, session, "crm__echo", "alice", false)
	session.Close()
	process.stop(t)
}
