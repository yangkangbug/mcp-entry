// Package gateway implements a demo-only, stateless MCP tool gateway.
package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

var ErrDenied = errors.New("tool unavailable or access denied")

type Route struct {
	Name     string
	System   string
	Tool     string
	Endpoint string
}

type User struct {
	Token   string
	Allowed []string
	// Credentials maps a configured system to a synthetic downstream token.
	Credentials map[string]string
}

type Gateway struct {
	routes map[string]Route
	users  map[string]User
}

// New copies configuration, rejects ambiguous routes, and accepts loopback demo endpoints only.
func New(routes []Route, users map[string]User) (*Gateway, error) {
	g := &Gateway{routes: map[string]Route{}, users: map[string]User{}}
	for _, r := range routes {
		u, err := url.Parse(r.Endpoint)
		if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
			return nil, errors.New("demo endpoints must be literal loopback HTTP URLs")
		}
		if !toolNamePattern.MatchString(r.Name) || r.System == "" || r.Tool == "" || strings.Contains(r.System, "__") || strings.Contains(r.Tool, "__") || r.Name != r.System+"__"+r.Tool {
			return nil, errors.New("invalid stable tool name")
		}
		if _, exists := g.routes[r.Name]; exists {
			return nil, errors.New("duplicate tool name")
		}
		g.routes[r.Name] = r
	}
	tokens := map[string]bool{}
	for id, u := range users {
		if id == "" || u.Token == "" || tokens[u.Token] {
			return nil, errors.New("invalid demo identity")
		}
		tokens[u.Token] = true
		clone := User{Token: u.Token, Allowed: append([]string(nil), u.Allowed...), Credentials: map[string]string{}}
		for system, token := range u.Credentials {
			clone.Credentials[system] = token
		}
		for _, name := range u.Allowed {
			if _, ok := g.routes[name]; !ok {
				return nil, errors.New("unknown policy tool")
			}
		}
		g.users[id] = clone
	}
	return g, nil
}

func (g *Gateway) allowed(id, name string) bool {
	u, ok := g.users[id]
	if !ok {
		return false
	}
	for _, n := range u.Allowed {
		if n == name {
			return true
		}
	}
	return false
}

func (g *Gateway) Names(id string) []string {
	names := []string{}
	for name := range g.routes {
		if g.allowed(id, name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// Call authorizes independently of discovery. Caller cannot select endpoint, system or credentials.
func (g *Gateway) Call(ctx context.Context, id, name string, args any) (*mcp.CallToolResult, error) {
	r, exists := g.routes[name]
	if !exists || !g.allowed(id, name) {
		return nil, ErrDenied
	}
	token := g.users[id].Credentials[r.System]
	if token == "" {
		return nil, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-entry", Version: "0.1.0-demo"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: r.Endpoint, HTTPClient: CredentialClient(token), MaxRetries: -1, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		return nil, errors.New("downstream unavailable")
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: r.Tool, Arguments: args})
	if err != nil {
		return nil, errors.New("downstream call failed; outcome may be unknown; not retried")
	}
	return result, nil
}

type credentialTransport struct {
	token string
	base  http.RoundTripper
}

func (t credentialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.Header.Set("Authorization", "Bearer "+t.token)
	response, err := t.base.RoundTrip(copy)
	if err != nil {
		return nil, err
	}
	response.Body = http.MaxBytesReader(nil, response.Body, 1<<20)
	return response, nil
}

// CredentialClient never follows redirects, so downstream credentials cannot cross origins.
func CredentialClient(token string) *http.Client {
	return &http.Client{Transport: credentialTransport{token, http.DefaultTransport}, Timeout: 12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
}

// Handler uses a fixed per-user server and stateless transport; no cross-user session reuse.
// Static bearer tokens are deliberately NOT production authentication or OAuth.
func (g *Gateway) Handler() http.Handler {
	handlers := map[string]http.Handler{}
	for id := range g.users {
		server := mcp.NewServer(&mcp.Implementation{Name: "mcp-entry", Version: "0.1.0-demo"}, nil)
		for _, name := range g.Names(id) {
			mcp.AddTool(server, &mcp.Tool{Name: name, Description: "Synthetic demo echo tool", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"message": map[string]any{"type": "string"}}, "required": []string{"message"}, "additionalProperties": false}}, func(ctx context.Context, _ *mcp.CallToolRequest, in map[string]any) (*mcp.CallToolResult, any, error) {
				result, err := g.Call(ctx, id, name, in)
				return result, nil, err
			})
		}
		handlers[id] = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 64 << 10})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This demo has no browser-facing flow. Reject all browser Origin headers.
		if r.Header.Get("Origin") != "" {
			http.Error(w, "browser access disabled", http.StatusForbidden)
			return
		}
		auth := r.Header.Get("Authorization")
		for id, u := range g.users {
			if auth == "Bearer "+u.Token {
				handlers[id].ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}
