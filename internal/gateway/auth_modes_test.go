package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yangkangbug/mcp-entry/internal/gateway"
)

// This fixture deliberately does not use gateway.CredentialClient or mock.Handler:
// it independently verifies the exact wire representation for every SDK request.
func TestAuthModesDiscoveryCallsAndIsolation(t *testing.T) {
	ctx := discoveryContext(t)
	cfg := gateway.Config{Users: map[string]gateway.User{}}
	secrets := []string{}
	allowed := []string{}
	credentials := map[string]map[string]string{"alice": {}, "bob": {}}
	type observation struct{ system, user, method string }
	var mu sync.Mutex
	seen := map[observation]int{}
	for _, mode := range []string{"", "bearer", "raw", "api_key"} {
		name := mode
		if name == "" {
			name = "default"
		}
		auth := gateway.AuthConfig{Mode: mode}
		header := "Authorization"
		if mode == "api_key" {
			header = "X-Integration-API-Key"
			auth.Header = header
		}
		handlers := map[string]http.Handler{}
		identities := map[string]string{}
		for _, user := range []string{"alice", "bob"} {
			secret := "synthetic-" + name + "-" + user
			if mode == "raw" {
				secret = "Token " + secret
			}
			if mode == "api_key" {
				secret += " exact suffix"
			}
			credentials[user][name] = secret
			secrets = append(secrets, secret)
			wire := secret
			if mode == "" || mode == "bearer" {
				wire = "Bearer " + secret
			}
			identities[wire] = user
			srv := mcp.NewServer(&mcp.Implementation{Name: "auth-fixture", Version: "1"}, nil)
			srv.AddTool(&mcp.Tool{Name: "whoami", InputSchema: json.RawMessage(`{"type":"object","additionalProperties":true}`)}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				// All arguments are returned so accidental credential injection is visible.
				var args any
				if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
					return nil, err
				}
				return discoveryResult(map[string]any{"system": name, "user": user, "arguments": args}), nil
			})
			srv.AddTool(&mcp.Tool{Name: user, InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return discoveryResult("private catalog"), nil
			})
			handlers[wire] = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
		}
		down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			values := r.Header.Values(header)
			if len(values) != 1 {
				t.Errorf("%s: expected exactly one auth header, got %d", name, len(values))
				http.Error(w, "unauthorized", 401)
				return
			}
			h, ok := handlers[values[0]]
			if !ok {
				t.Errorf("%s: unexpected auth value", name)
				http.Error(w, "unauthorized", 401)
				return
			}
			if mode == "api_key" && r.Header.Get("Authorization") != "" {
				t.Error("API-key mode also sent Authorization")
			}
			if r.Header.Get("X-Caller-Spoof") != "" {
				t.Error("caller header propagated")
			}
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
			for _, secret := range credentials[identities[values[0]]] {
				if bytes.Contains(data, []byte(secret)) {
					t.Error("credential leaked into downstream RPC body")
				}
			}
			var message struct{ Method string }
			_ = json.Unmarshal(data, &message)
			mu.Lock()
			seen[observation{name, identities[values[0]], message.Method}]++
			mu.Unlock()
			h.ServeHTTP(w, r)
		}))
		t.Cleanup(down.Close)
		cfg.Systems = append(cfg.Systems, gateway.System{Name: name, Endpoint: down.URL, Auth: auth})
		allowed = append(allowed, name+"__whoami", name+"__alice", name+"__bob")
	}
	for _, user := range []string{"alice", "bob"} {
		cfg.Users[user] = gateway.User{Token: "gateway-" + user, Allowed: allowed, Credentials: credentials[user]}
	}
	cfg.Users["missing"] = gateway.User{Token: "gateway-missing", Allowed: allowed, Credentials: map[string]string{}}
	g, err := gateway.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	issues := g.Refresh(ctx)
	if len(issues) != 4 {
		t.Fatalf("expected only missing-user issues: %+v", issues)
	}
	for _, issue := range issues {
		if issue.User != "missing" {
			t.Fatalf("discovery failed: %+v", issue)
		}
	}
	if len(g.Names("missing")) != 0 {
		t.Fatal("missing credentials borrowed another user's catalog")
	}
	for _, system := range cfg.Systems {
		if _, err := g.Call(ctx, "missing", system.Name+"__whoami", map[string]any{}); !errors.Is(err, gateway.ErrDenied) {
			t.Fatalf("missing credentials call: %v", err)
		}
	}
	front := httptest.NewServer(g.Handler())
	t.Cleanup(front.Close)
	for _, user := range []string{"alice", "bob"} {
		client := mcp.NewClient(&mcp.Implementation{Name: "spoof-client", Version: "1"}, nil)
		session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: front.URL, HTTPClient: &http.Client{Transport: authModeCallerTransport{token: "gateway-" + user}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = session.Close() })
		list, err := session.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(list.Tools) != 8 {
			t.Fatalf("%s catalog length=%d", user, len(list.Tools))
		}
		for _, tool := range list.Tools {
			if !strings.HasSuffix(tool.Name, "__whoami") && !strings.HasSuffix(tool.Name, "__"+user) {
				t.Fatalf("cross-user catalog: %s", tool.Name)
			}
		}
		args := map[string]any{"Authorization": "attacker-value", "X-Integration-API-Key": "attacker-key", "headers": map[string]any{"Authorization": "attacker-nested"}, "credential": "attacker-credential", "system": "attacker-system", "user": "attacker-user"}
		for _, system := range cfg.Systems {
			result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: system.Name + "__whoami", Arguments: args})
			if err != nil || result.IsError {
				t.Fatalf("%s/%s: result=%v err=%v", user, system.Name, result, err)
			}
			want := map[string]any{"system": system.Name, "user": user, "arguments": args}
			if !reflect.DeepEqual(discoveryJSON(t, result.StructuredContent), want) {
				t.Fatalf("identity or argument corruption: %+v", result.StructuredContent)
			}
			encoded, _ := json.Marshal(result)
			for _, secret := range secrets {
				if bytes.Contains(encoded, []byte(secret)) {
					t.Fatal("credential leaked into result")
				}
			}
		}
	}
	// Overlap all users and systems to catch transport state accidentally shared
	// between identities, rather than merely overwritten correctly in serial use.
	var calls sync.WaitGroup
	for _, user := range []string{"alice", "bob"} {
		for _, system := range cfg.Systems {
			calls.Add(1)
			go func() {
				defer calls.Done()
				result, err := g.Call(ctx, user, system.Name+"__whoami", map[string]any{})
				if err != nil {
					t.Error(err)
					return
				}
				encoded, err := json.Marshal(result.StructuredContent)
				if err != nil {
					t.Error(err)
					return
				}
				var got struct{ User, System string }
				if err := json.Unmarshal(encoded, &got); err != nil {
					t.Error(err)
					return
				}
				if got.User != user || got.System != system.Name {
					t.Errorf("parallel identity mixup: %+v", got)
				}
			}()
		}
	}
	calls.Wait()

	mu.Lock()
	defer mu.Unlock()
	for _, system := range cfg.Systems {
		for _, user := range []string{"alice", "bob"} {
			for _, method := range []string{"tools/list", "tools/call"} {
				if seen[observation{system.Name, user, method}] == 0 {
					t.Errorf("missing authenticated %s/%s/%s", system.Name, user, method)
				}
			}
		}
	}
}

type authModeCallerTransport struct{ token string }

func (a authModeCallerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.Header.Set("Authorization", "Bearer "+a.token)
	copy.Header.Set("X-Integration-API-Key", "caller-spoof-key")
	copy.Header.Set("X-Caller-Spoof", "do-not-forward")
	return http.DefaultTransport.RoundTrip(copy)
}

func TestAuthModesRejectInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth gateway.AuthConfig
	}{
		{"unknown", gateway.AuthConfig{Mode: "basic"}},
		{"wrong-case", gateway.AuthConfig{Mode: "RAW"}},
		{"default-with-header", gateway.AuthConfig{Header: "X-API-Key"}},
		{"bearer-with-header", gateway.AuthConfig{Mode: "bearer", Header: "X-API-Key"}},
		{"raw-with-header", gateway.AuthConfig{Mode: "raw", Header: "X-API-Key"}},
		{"key-without-header", gateway.AuthConfig{Mode: "api_key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "svc", Endpoint: "http://127.0.0.1:1", Auth: tc.auth}}}); err == nil {
				t.Fatal("invalid auth config accepted")
			}
		})
	}
	for _, header := range []string{"Authorization", "authorization", "Proxy-Authorization", "Host", "Cookie", "Set-Cookie", "Connection", "Transfer-Encoding", "Content-Length", "Content-Type", "Accept", "Origin", "Forwarded", "X-Forwarded-For", "Mcp-Session-Id", "MCP-Protocol-Version", "Last-Event-ID", "Upgrade", "Trailer", "TE", " X-API-Key", "X API Key", "X_API_Key", "X-Key:", "X-Key\r\nInjected", "1-API-Key", strings.Repeat("X", 65)} {
		t.Run("header/"+header, func(t *testing.T) {
			_, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "svc", Endpoint: "http://127.0.0.1:1", Auth: gateway.AuthConfig{Mode: "api_key", Header: header}}}})
			if err == nil {
				t.Fatal("unsafe custom header accepted")
			}
		})
	}
	for _, mode := range []string{"", "bearer", "raw", "api_key"} {
		for i, value := range []string{" secret", "secret ", "secret\r\ninjected", "secret\tvalue", "secret\x00value", "secret\x1fvalue", "secret\x7fvalue", "secreté", strings.Repeat("x", 4097)} {
			t.Run(fmt.Sprintf("credential/%s/%d", mode, i), func(t *testing.T) {
				auth := gateway.AuthConfig{Mode: mode}
				if mode == "api_key" {
					auth.Header = "X-API-Key"
				}
				_, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "svc", Endpoint: "http://127.0.0.1:1", Auth: auth}}, Users: map[string]gateway.User{"alice": {Token: "entry", Credentials: map[string]string{"svc": value}}}})
				if err == nil {
					t.Fatal("malformed credential accepted")
				}
				if err != nil && strings.Contains(err.Error(), value) {
					t.Fatal("credential echoed in configuration error")
				}
			})
		}
	}
	for _, value := range []string{"two words", "key:secret", "abc=def", "=abc", "abc,def"} {
		_, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "svc", Endpoint: "http://127.0.0.1:1"}}, Users: map[string]gateway.User{"alice": {Token: "entry", Credentials: map[string]string{"svc": value}}}})
		if err == nil {
			t.Errorf("invalid bearer token accepted: %q", value)
		}
	}
}

func TestAuthModesFailureDoesNotLeakOrFallback(t *testing.T) {
	for _, mode := range []string{"bearer", "raw", "api_key"} {
		t.Run(mode, func(t *testing.T) {
			ctx := discoveryContext(t)
			secret := "synthetic-error-credential"
			var fail atomic.Bool
			var requests atomic.Int32
			server := mcp.NewServer(&mcp.Implementation{Name: "failure-fixture", Version: "1"}, nil)
			server.AddTool(&mcp.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return discoveryResult("ok"), nil
			})
			handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
			down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if fail.Load() {
					http.Error(w, secret, http.StatusUnauthorized)
					return
				}
				handler.ServeHTTP(w, r)
			}))
			t.Cleanup(down.Close)
			auth := gateway.AuthConfig{Mode: mode}
			if mode == "api_key" {
				auth.Header = "X-API-Key"
			}
			g, err := gateway.New(gateway.Config{Systems: []gateway.System{{Name: "svc", Endpoint: down.URL, Auth: auth}}, Users: map[string]gateway.User{"alice": {Token: "entry", Allowed: []string{"svc__echo"}, Credentials: map[string]string{"svc": secret}}}})
			if err != nil {
				t.Fatal(err)
			}
			if issues := g.Refresh(ctx); len(issues) != 0 {
				t.Fatal(issues)
			}
			fail.Store(true)
			result, err := g.Call(ctx, "alice", "svc__echo", map[string]any{})
			if err == nil || result != nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("unsafe failed call: result=%v err=%v", result, err)
			}
			issues := g.Refresh(ctx)
			encoded, _ := json.Marshal(issues)
			if len(issues) != 1 || bytes.Contains(encoded, []byte(secret)) {
				t.Fatalf("unsafe discovery issues: %s", encoded)
			}
			if len(g.Names("alice")) != 0 {
				t.Fatal("failed auth left stale catalog")
			}
			before := requests.Load()
			if _, err := g.Call(ctx, "alice", "svc__echo", map[string]any{}); !errors.Is(err, gateway.ErrDenied) {
				t.Fatalf("stale call: %v", err)
			}
			if requests.Load() != before {
				t.Fatal("denied call contacted downstream")
			}
		})
	}
}

func TestAuthModesStrictJSONConfiguration(t *testing.T) {
	for _, auth := range []string{`{"mode":"bearer"}`, `{"mode":"raw"}`, `{"mode":"api_key","header":"x-api-key"}`} {
		input := `{"systems":[{"name":"svc","endpoint":"http://127.0.0.1:1","auth":` + auth + `}],"users":{"alice":{"token":"entry","credentials":{"svc":"synthetic-key"}}}}`
		cfg, err := gateway.LoadConfig(strings.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gateway.New(cfg); err != nil {
			t.Fatal(err)
		}
	}
	for _, auth := range []string{`{"mode":"raw","headers":{"Authorization":"secret"}}`, `{"mode":7}`, `{"mode":"api_key","header":["X-Key"]}`, `"raw"`, `[]`, `{"mode":"raw","credential":"shared-identity"}`} {
		input := `{"systems":[{"name":"svc","endpoint":"http://127.0.0.1:1","auth":` + auth + `}]}`
		if _, err := gateway.LoadConfig(strings.NewReader(input)); err == nil {
			t.Fatalf("malformed auth JSON accepted: %s", auth)
		}
	}
}
