package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangkangbug/mcp-entry/internal/mock"
)

func integratedConfig(endpoint string) Config {
	return Config{Systems: []System{{Name: "crm", Endpoint: endpoint}}, Users: map[string]User{"alice": {Token: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)), TokenExpiresAt: time.Now().Add(time.Hour).UTC(), Allowed: []string{"crm__echo"}, Credentials: map[string]string{"crm": "synthetic-original"}}}}
}

var integratedIdentity = Identity{"demo", "alice"}

func TestIntegratedControlledHTTPS(t *testing.T) {
	downstream := httptest.NewTLSServer(mock.Handler("crm", map[string]string{"synthetic-original": "alice"}))
	defer downstream.Close()
	cfg := integratedConfig(downstream.URL)
	cfg.Systems[0].Network = &NetworkPolicy{AllowedIPs: []string{"127.0.0.1"}, TrustedCAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: downstream.Certificate().Raw}))}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	// Both serialized policy and compiled authority must be independent of callers.
	cfg.Systems[0].Network.AllowedIPs[0] = "192.0.2.1"
	cfg.Systems[0].Network.TrustedCAPEM = "invalid"
	cfg.Systems[0].Endpoint = "https://unrelated.invalid/mcp"
	if g.systems["crm"].Network.AllowedIPs[0] != "127.0.0.1" {
		t.Fatal("mutable policy retained")
	}
	if issues := g.RefreshBinding(context.Background(), integratedIdentity, "crm"); len(issues) != 0 {
		t.Fatal(issues)
	}
	result, err := g.Call(context.Background(), "alice", "crm__echo", map[string]any{"message": "tls"})
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	data, _ := json.Marshal(result.StructuredContent)
	var output mock.Output
	if json.Unmarshal(data, &output) != nil || output.User != "alice" || output.Message != "tls" {
		t.Fatal(string(data))
	}
}
func TestIntegratedPersistentExpiry(t *testing.T) {
	var requests atomic.Int64
	mockHandler := mock.Handler("crm", map[string]string{"synthetic-original": "alice", "synthetic-replacement": "alice"})
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); mockHandler.ServeHTTP(w, r) }))
	defer downstream.Close()
	cfg := integratedConfig(downstream.URL)
	opts := PersistenceOptions{Path: filepath.Join(t.TempDir(), "state.sqlite"), Key: bytes.Repeat([]byte{41}, 32), Initialize: true}
	g, err := NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := g.Binding(integratedIdentity, "crm")
	expiry := time.Now().Add(time.Second).UTC()
	saved, err := g.ReplaceBindingExpiring(integratedIdentity, "crm", before.Generation, "synthetic-replacement", expiry)
	if err != nil {
		g.Close()
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Initialize = false
	g, err = NewPersistent(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	restored, err := g.Binding(integratedIdentity, "crm")
	if err != nil || !reflect.DeepEqual(saved, restored) {
		t.Fatal(saved, restored, err)
	}
	<-time.After(time.Until(expiry) + time.Millisecond)
	requests.Store(0)
	if issues := g.RefreshBinding(context.Background(), integratedIdentity, "crm"); len(issues) != 1 {
		t.Fatal(issues)
	}
	if len(g.Names("alice")) != 0 {
		t.Fatal("expired binding visible")
	}
	if _, err := g.Call(context.Background(), "alice", "crm__echo", nil); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("expired credential dispatched")
	}
	g.Close()
	// A config edit must not extend an already persisted entry credential lifetime.
	changed := cfg
	changed.Users = map[string]User{}
	user := cfg.Users["alice"]
	user.TokenExpiresAt = user.TokenExpiresAt.Add(time.Hour)
	changed.Users["alice"] = user
	if reopened, err := NewPersistent(changed, opts); err == nil {
		reopened.Close()
		t.Fatal("entry expiry changed on reopen")
	}
}
func TestIntegratedPersistentExpiryIntegrityAndVersion(t *testing.T) {
	for _, tt := range []struct {
		name, statement string
		version         bool
	}{
		{"binding expiry", "UPDATE bindings SET expires_at='2099-01-01T00:00:00Z'", false},
		{"entry expiry", "UPDATE principals SET token_expires_at='2099-01-01T00:00:00Z'", false},
		{"old version", "UPDATE meta SET version=1", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := integratedConfig("http://127.0.0.1:1/mcp")
			opts := PersistenceOptions{Path: filepath.Join(t.TempDir(), "state.sqlite"), Key: bytes.Repeat([]byte{42}, 32), Initialize: true}
			g, err := NewPersistent(cfg, opts)
			if err != nil {
				t.Fatal(err)
			}
			g.Close()
			db, err := sql.Open("sqlite", opts.Path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(tt.statement); err != nil {
				db.Close()
				t.Fatal(err)
			}
			db.Close()
			opts.Initialize = false
			reopened, err := NewPersistent(cfg, opts)
			if err == nil {
				reopened.Close()
				t.Fatal("invalid store opened")
			}
			if !errors.Is(err, ErrStorage) {
				t.Fatal(err)
			}
			if tt.version && !errors.Is(err, ErrStorageVersion) {
				t.Fatal(err)
			}
		})
	}
}
func TestIntegratedExpiredEntryRecovery(t *testing.T) {
	cfg := integratedConfig("http://127.0.0.1:1/mcp")
	user := cfg.Users["alice"]
	user.TokenExpiresAt = time.Now().Add(-time.Hour)
	cfg.Users["alice"] = user
	opts := PersistenceOptions{Path: filepath.Join(t.TempDir(), "state.sqlite"), Key: bytes.Repeat([]byte{43}, 32), Initialize: true}
	for i := 0; i < 2; i++ {
		g, err := NewPersistent(cfg, opts)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest("POST", "http://127.0.0.1/mcp", nil)
		request.Header.Set("Authorization", "Bearer "+user.Token)
		response := httptest.NewRecorder()
		g.Handler().ServeHTTP(response, request)
		if response.Code != 401 {
			t.Fatal(response.Code)
		}
		if issues := g.Refresh(context.Background()); len(issues) != 0 {
			t.Fatal(issues)
		}
		if len(g.Names("alice")) != 0 {
			t.Fatal("expired entry visible")
		}
		if _, err := g.replaceOwnBinding(integratedIdentity, "crm", 1, "replacement", time.Time{}); !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
		// Trusted offline control remains independent of an end-user entry TTL.
		binding, _ := g.Binding(integratedIdentity, "crm")
		if _, err := g.RevokeBinding(integratedIdentity, "crm", binding.Generation); err != nil {
			t.Fatal(err)
		}
		g.Close()
		opts.Initialize = false
	}
}
func TestIntegratedTargetedRefreshSupersession(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "same generation", true: "new generation"}[replace], func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var block atomic.Bool
			handler := mock.Handler("crm", map[string]string{"synthetic-original": "alice", "synthetic-replacement": "alice"})
			downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Body != nil {
					raw, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(raw))
					var rpc struct{ Method string }
					json.Unmarshal(raw, &rpc)
					if rpc.Method == "tools/list" && block.CompareAndSwap(true, false) {
						close(entered)
						<-release
					}
				}
				handler.ServeHTTP(w, r)
			}))
			defer downstream.Close()
			defer close(release)
			g, err := New(integratedConfig(downstream.URL))
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			if issues := g.Refresh(context.Background()); len(issues) != 0 {
				t.Fatal(issues)
			}
			block.Store(true)
			done := make(chan []DiscoveryIssue, 1)
			go func() { done <- g.RefreshBinding(context.Background(), integratedIdentity, "crm") }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("discovery did not enter")
			}
			if replace {
				if _, err := g.ReplaceBinding(integratedIdentity, "crm", 1, "synthetic-replacement"); err != nil {
					t.Fatal(err)
				}
			}
			if issues := g.RefreshBinding(context.Background(), integratedIdentity, "crm"); len(issues) != 0 {
				t.Fatal(issues)
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("superseded discovery not canceled")
			}
			if !reflect.DeepEqual(g.Names("alice"), []string{"crm__echo"}) {
				t.Fatal(g.Names("alice"))
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if issues := g.RefreshBinding(ctx, integratedIdentity, "crm"); len(issues) != 1 {
				t.Fatal(issues)
			}
			if !reflect.DeepEqual(g.Names("alice"), []string{"crm__echo"}) {
				t.Fatal("pre-canceled refresh cleared current catalog")
			}
		})
	}
}
