package gateway_test

import (
	"context"
	"strings"
	"testing"

	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

func TestConfigLoading(t *testing.T) {
	valid := `{"systems":[{"name":"crm","endpoint":"http://127.0.0.1:9001/mcp"}],"users":{"alice":{"token":"demo","allowed":["crm__echo"],"credentials":{"crm":"synthetic"}}}}`
	cfg, err := gateway.LoadConfig(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.New(cfg); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{valid + ` {}`, `{"unknown":true}`, `null`, strings.Repeat(" ", 256<<10) + valid} {
		cfg, err := gateway.LoadConfig(strings.NewReader(bad))
		if err == nil {
			_, err = gateway.New(cfg)
		}
		if err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}

func TestEmptyCatalogBeforeDiscovery(t *testing.T) {
	g, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "crm", Endpoint: "http://127.0.0.1:9001"}}, Users: map[string]gateway.User{"alice": {Token: "demo", Allowed: []string{"crm__echo"}, Credentials: map[string]string{"crm": "synthetic"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Names("alice")) != 0 {
		t.Fatal("undiscovered tool was published")
	}
	if _, err := g.Call(context.Background(), "alice", "crm__echo", map[string]any{"message": "x"}); err == nil {
		t.Fatal("undiscovered tool callable")
	}
}

func TestOnlyToolCapabilitiesAdvertised(t *testing.T) {
	_, server := fixture(t)
	session := connect(t, server.URL, "alice-token")
	caps := session.InitializeResult().Capabilities
	if caps.Prompts != nil || caps.Resources != nil || caps.Completions != nil {
		t.Fatalf("unsupported capabilities advertised: %+v", caps)
	}
	if caps.Tools == nil {
		t.Fatal("tool capability missing")
	}
}
