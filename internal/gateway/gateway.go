// Package gateway implements a demo-only, stateless MCP tool gateway.
package gateway

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var ErrDenied = errors.New("tool unavailable or access denied")

const (
	MaxToolsPerSystem = 128
	MaxPagesPerSystem = 16
)

type entry struct {
	system        System
	original      string
	tool          *mcp.Tool
	input         *boundedSchema
	generation    uint64
	policyVersion uint64
}
type snapshot struct {
	catalogs map[string]map[string]entry
	handlers map[string]http.Handler
}
type Gateway struct {
	closed        bool
	store         *sqliteStore
	entryTokens   map[string][32]byte
	mu            sync.Mutex
	principals    map[string]*principalState
	identities    map[Identity]string
	operations    map[uint64]admittedOperation
	nextOperation uint64
	systems       map[string]System
	users         map[string]User
	refreshMu     sync.Mutex
	state         atomic.Pointer[snapshot]
}

// DiscoveryIssue contains no credentials, raw downstream errors or tool descriptions.
type DiscoveryIssue struct {
	User   string
	System string
	Reason string
}

// New copies configuration. Nothing is published until Refresh discovers authorized tools.
func New(cfg Config) (*Gateway, error) {
	if len(cfg.Systems) > 16 || len(cfg.Users) > 64 {
		return nil, errors.New("demo configuration exceeds system/user limit")
	}
	g := &Gateway{systems: map[string]System{}, users: map[string]User{}}
	for _, system := range cfg.Systems {
		if !validPart(system.Name) || len(system.Name) > 64 || !validateEndpoint(system.Endpoint) {
			return nil, errors.New("invalid system name or non-loopback endpoint")
		}
		if _, exists := g.systems[system.Name]; exists {
			return nil, errors.New("duplicate system")
		}
		auth, err := normalizeAuth(system.Auth)
		if err != nil {
			return nil, err
		}
		system.Auth = auth
		g.systems[system.Name] = system
	}
	tokens := map[string]bool{}
	for id, user := range cfg.Users {
		if id == "" || len(id) > 128 || user.Token == "" || len(user.Token) > 4096 || strings.ContainsAny(user.Token, "\r\n") || tokens[user.Token] {
			return nil, errors.New("invalid demo identity")
		}
		tokens[user.Token] = true
		clone := User{Tenant: user.Tenant, Principal: user.Principal, Token: user.Token, Allowed: append([]string(nil), user.Allowed...), Credentials: map[string]string{}}
		if len(clone.Allowed) > 2048 {
			return nil, errors.New("too many policy tools")
		}
		for _, name := range clone.Allowed {
			if !validNamespaced(name, g.systems) {
				return nil, errors.New("invalid policy tool")
			}
		}
		for system, token := range user.Credentials {
			if connection, ok := g.systems[system]; !ok || !validCredential(token, connection.Auth) {
				return nil, errors.New("invalid system credential configuration")
			}
			clone.Credentials[system] = token
		}
		g.users[id] = clone
	}
	if err := g.initializeIdentities(); err != nil {
		return nil, err
	}
	g.entryTokens = map[string][32]byte{}
	for id, user := range g.users {
		g.entryTokens[id] = entryTokenDigest(user.Token)
		user.Token = ""
		g.users[id] = user
	}
	g.state.Store(g.makeSnapshot(map[string]map[string]entry{}))
	return g, nil
}

func (g *Gateway) Names(id string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	names := []string{}
	for name := range g.state.Load().catalogs[id] {
		if _, ok := g.evaluateLocked(id, name); ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// Refresh captures authorization revisions per discovery and rechecks at atomic
// publication. Network operations never hold the authorization lock.
func (g *Gateway) Refresh(ctx context.Context) []DiscoveryIssue {
	g.refreshMu.Lock()
	defer g.refreshMu.Unlock()
	catalogs := map[string]map[string]entry{}
	issues := []DiscoveryIssue{}
	ids := make([]string, 0, len(g.users))
	for id := range g.users {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	systems := make([]string, 0, len(g.systems))
	for name := range g.systems {
		systems = append(systems, name)
	}
	sort.Strings(systems)
	for _, id := range ids {
		catalogs[id] = map[string]entry{}
		for _, name := range systems {
			g.mu.Lock()
			p := g.principals[id]
			if g.closed {
				g.mu.Unlock()
				issues = append(issues, DiscoveryIssue{id, name, "gateway closed"})
				continue
			}
			needed := false
			if !p.disabled {
				for _, allowed := range p.allowed {
					if strings.HasPrefix(allowed, name+"__") {
						needed = true
						break
					}
				}
			}
			if !needed {
				g.mu.Unlock()
				continue
			}
			b := p.bindings[name]
			if b.info.State != BindingActive || b.credential == "" {
				g.mu.Unlock()
				issues = append(issues, DiscoveryIssue{id, name, "credential unavailable"})
				continue
			}
			generation, version, token := b.info.Generation, p.version, b.credential
			opCtx, cancel := context.WithCancel(ctx)
			g.nextOperation++
			opID := g.nextOperation
			g.operations[opID] = admittedOperation{id, name, cancel}
			g.mu.Unlock()
			entries, err := g.discover(opCtx, g.systems[name], token)
			g.mu.Lock()
			delete(g.operations, opID)
			cancel()
			if err != nil {
				issues = append(issues, DiscoveryIssue{id, name, "discovery failed; system catalog unavailable"})
			} else {
				for tool, e := range entries {
					e.generation, e.policyVersion = generation, version
					if g.entryAllowedLocked(id, tool, e) {
						catalogs[id][tool] = e
					}
				}
			}
			g.mu.Unlock()
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, cat := range catalogs {
		for name, e := range cat {
			if !g.entryAllowedLocked(id, name, e) {
				delete(cat, name)
			}
		}
	}
	g.state.Store(g.makeSnapshot(catalogs))
	return issues
}

func connect(ctx context.Context, system System, token string) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-entry", Version: "0.2.0-demo"}, &mcp.ClientOptions{MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true}})
	// Validate before SDK ListTools filters malformed header annotations or dereferences
	// nil entries. A malformed catalog must fail as a whole, not become a partial list.
	client.AddSendingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			result, err := next(ctx, method, req)
			if err != nil {
				return nil, err
			}
			if method == "tools/list" {
				list, ok := result.(*mcp.ListToolsResult)
				if !ok || list == nil {
					return nil, errors.New("invalid catalog")
				}
				if len(list.Tools) > MaxToolsPerSystem {
					return nil, errors.New("tool count limit")
				}
				pageBytes := 0
				for _, tool := range list.Tools {
					if tool == nil {
						return nil, errors.New("null tool")
					}
					data, err := json.Marshal(tool)
					pageBytes += len(data)
					if err != nil || len(data) > 64<<10 || pageBytes > 1<<20 {
						return nil, errors.New("catalog byte limit")
					}
				}
				for _, tool := range list.Tools {
					schemas := []any{tool.InputSchema}
					if tool.OutputSchema != nil {
						schemas = append(schemas, tool.OutputSchema)
					}
					for _, schema := range schemas {
						if _, err := analyzeSchema(schema); err != nil {
							return nil, err
						}
						if err := validateSchemaTypes(schema); err != nil {
							return nil, err
						}
					}
				}
			}
			return result, nil
		}
	})

	return client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: system.Endpoint, HTTPClient: systemOperationClient(ctx, token, system.Auth), MaxRetries: -1, DisableStandaloneSSE: true}, nil)
}

func (g *Gateway) discover(ctx context.Context, system System, token string) (map[string]entry, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	session, err := connect(ctx, system, token)
	if err != nil {
		return nil, err
	}
	// Cleanup is synchronous and shares ctx. A cleanup error must not replace a
	// complete discovery result or a confirmed tool outcome.
	defer session.Close()
	entries := map[string]entry{}
	seen := map[string]bool{}
	cursor := ""
	total := 0
	totalBytes := 0
	for page := 0; page < MaxPagesPerSystem; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, err
		}
		total += len(result.Tools)
		if total > MaxToolsPerSystem {
			return nil, errors.New("tool count limit")
		}
		for _, tool := range result.Tools {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if tool == nil || !validPart(tool.Name) || !toolNamePattern.MatchString(system.Name+"__"+tool.Name) {
				return nil, errors.New("invalid downstream tool name")
			}
			name := system.Name + "__" + tool.Name
			if _, exists := entries[name]; exists {
				return nil, errors.New("duplicate downstream tool")
			}
			data, err := json.Marshal(tool)
			if err != nil {
				return nil, err
			}
			totalBytes += len(data)
			if len(data) > 64<<10 || totalBytes > 1<<20 {
				return nil, errors.New("catalog byte limit")
			}
			var copy mcp.Tool
			if err := json.Unmarshal(data, &copy); err != nil {
				return nil, err
			}
			resolved, err := resolveSchema(copy.InputSchema, true)
			if err != nil {
				return nil, err
			}
			if copy.OutputSchema != nil {
				if _, err := resolveSchema(copy.OutputSchema, false); err != nil {
					return nil, err
				}
			}

			original := copy.Name
			copy.Name = name
			entries[name] = entry{system: system, original: original, tool: &copy, input: resolved}
		}
		if result.NextCursor == "" {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return entries, nil
		}
		if len(result.NextCursor) > 4096 || seen[result.NextCursor] {
			return nil, errors.New("invalid pagination cursor")
		}
		seen[result.NextCursor] = true
		cursor = result.NextCursor
	}
	return nil, errors.New("pagination limit")
}

// boundedSchema retains the validator's dialect semantics without rewriting the
// advertised schema. Admission limits are not a wall-clock CPU interruption.
type boundedSchema struct {
	resolved *jsonschema.Resolved
	work     int
}

func (s *boundedSchema) Validate(value any) error {
	if err := validateInstanceBudget(value, s.work); err != nil {
		return err
	}
	return s.resolved.Validate(value)
}

func resolveSchema(value any, input bool) (*boundedSchema, error) {
	work, err := analyzeSchema(value)
	if err != nil {
		return nil, err
	}
	if err := validateSchemaTypes(value); err != nil {
		return nil, err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, err
	}
	if input && schema.Type != "object" {
		return nil, errors.New("input schema must describe object")
	}
	switch schema.Schema {
	case "", "https://json-schema.org/draft/2020-12/schema", "http://json-schema.org/draft-07/schema#", "https://json-schema.org/draft-07/schema#":
	default:
		return nil, errors.New("unsupported schema draft")
	}
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{
		Loader: func(*url.URL) (*jsonschema.Schema, error) {
			return nil, errors.New("external schema loading disabled")
		},
	})
	if err != nil {
		return nil, err
	}
	return &boundedSchema{resolved: resolved, work: work}, nil
}

// The validator resolves references but does not reject unknown type names.
// Check type declarations at schema positions, not arbitrary example/data objects.
func validateSchemaTypes(value any) error {
	schema, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	for _, key := range []string{"$dynamicRef", "x-mcp-header"} {
		if _, exists := schema[key]; exists {
			return errors.New("dynamic references and header mappings unsupported")
		}
	}
	if typ, exists := schema["type"]; exists {
		valid := func(v any) bool {
			s, ok := v.(string)
			if !ok {
				return false
			}
			switch s {
			case "object", "array", "string", "number", "integer", "boolean", "null":
				return true
			}
			return false
		}
		switch typ := typ.(type) {
		case string:
			if !valid(typ) {
				return errors.New("invalid schema type")
			}
		case []any:
			seen := map[any]bool{}
			if len(typ) == 0 {
				return errors.New("empty schema type")
			}
			for _, v := range typ {
				if !valid(v) {
					return errors.New("invalid schema type")
				}
				if seen[v] {
					return errors.New("duplicate schema type")
				}
				seen[v] = true
			}
		default:
			return errors.New("invalid schema type")
		}
	}
	for key, child := range schema {
		switch key {
		case "properties", "patternProperties", "$defs", "definitions", "dependentSchemas", "dependencies":
			if children, ok := child.(map[string]any); ok {
				for _, c := range children {
					if err := validateSchemaTypes(c); err != nil {
						return err
					}
				}
			}
		case "allOf", "anyOf", "oneOf", "prefixItems":
			if children, ok := child.([]any); ok {
				for _, c := range children {
					if err := validateSchemaTypes(c); err != nil {
						return err
					}
				}
			}
		case "items":
			if children, ok := child.([]any); ok {
				for _, c := range children {
					if err := validateSchemaTypes(c); err != nil {
						return err
					}
				}
			} else if err := validateSchemaTypes(child); err != nil {
				return err
			}
		case "additionalProperties", "additionalItems", "propertyNames", "contains", "not", "if", "then", "else", "unevaluatedProperties", "unevaluatedItems", "contentSchema":
			if err := validateSchemaTypes(child); err != nil {
				return err
			}
		}
	}
	return nil
}

// Call authorizes independently of discovery and validates the discovered input schema.
// Neither caller arguments nor downstream names can choose an endpoint or credential.
func (g *Gateway) Call(ctx context.Context, id, name string, args any) (*mcp.CallToolResult, error) {
	g.mu.Lock()
	e, exists := g.evaluateLocked(id, name)
	g.mu.Unlock()
	if !exists {
		return nil, ErrDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if args == nil {
		args = map[string]any{}
	}
	if raw, ok := args.(json.RawMessage); ok && len(raw) == 0 {
		args = map[string]any{}
	}
	data, err := json.Marshal(args)
	if err != nil || len(data) > 64<<10 {
		return nil, errors.New("invalid tool arguments")
	}
	var input any
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, errors.New("invalid tool arguments")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := e.input.Validate(input); err != nil {
		return nil, errors.New("arguments do not match discovered schema")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Final dispatch admission and revocation share this lock. A request admitted
	// first is in flight even if its first network byte is sent later.
	g.mu.Lock()
	current, ok := g.evaluateLocked(id, name)
	if !ok || current.tool != e.tool || current.generation != e.generation || current.policyVersion != e.policyVersion {
		g.mu.Unlock()
		return nil, ErrDenied
	}
	if err := ctx.Err(); err != nil {
		g.mu.Unlock()
		return nil, err
	}
	token := g.principals[id].bindings[e.system.Name].credential
	g.nextOperation++
	opID := g.nextOperation
	g.operations[opID] = admittedOperation{id, e.system.Name, cancel}
	g.mu.Unlock()
	defer func() { g.mu.Lock(); delete(g.operations, opID); g.mu.Unlock() }()
	session, err := connect(ctx, e.system, token)
	if err != nil {
		return nil, errors.New("downstream unavailable")
	}
	// Cleanup is synchronous and shares ctx. A cleanup error must not replace a
	// complete discovery result or a confirmed tool outcome.
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: e.original, Arguments: json.RawMessage(data)})
	if err != nil {
		return nil, errors.New("downstream call failed; outcome may be unknown; not retried")
	}
	return result, nil
}

func (g *Gateway) makeSnapshot(catalogs map[string]map[string]entry) *snapshot {
	state := &snapshot{catalogs: catalogs, handlers: map[string]http.Handler{}}
	for id := range g.users {
		state.handlers[id] = g.toolHandler(id, catalogs[id])
	}
	return state
}

func (g *Gateway) toolHandler(id string, catalog map[string]entry) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "mcp-entry", Version: "0.2.0-demo"}, nil)
	for name, e := range catalog {
		server.AddTool(e.tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			result, err := g.Call(ctx, id, name, req.Params.Arguments)
			if err != nil {
				result = &mcp.CallToolResult{}
				result.SetError(err)
			}
			return result, nil
		})
	}
	// Even a previously captured SDK handler rechecks list eligibility and its
	// catalog revision. It can never expose an old binding's schema as a new one.
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			result, err := next(ctx, method, req)
			if err != nil || method != "tools/list" {
				return result, err
			}
			list, ok := result.(*mcp.ListToolsResult)
			if !ok {
				return result, nil
			}
			g.mu.Lock()
			defer g.mu.Unlock()
			filtered := make([]*mcp.Tool, 0, len(list.Tools))
			for _, tool := range list.Tools {
				e, exists := catalog[tool.Name]
				current, allowed := g.evaluateLocked(id, tool.Name)
				if exists && allowed && current.tool == e.tool && g.entryAllowedLocked(id, tool.Name, e) {
					filtered = append(filtered, tool)
				}
			}
			copy := *list
			copy.Tools = filtered
			return &copy, nil
		}
	})
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 64 << 10})
}

// Handler reauthenticates every request, never using session IDs as identities.
func (g *Gateway) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			http.Error(w, "browser access disabled", http.StatusForbidden)
			return
		}
		auth := r.Header.Get("Authorization")
		digest := entryTokenDigest(strings.TrimPrefix(auth, "Bearer "))
		for id, expected := range g.entryTokens {
			if strings.HasPrefix(auth, "Bearer ") && subtle.ConstantTimeCompare(digest[:], expected[:]) == 1 {
				g.mu.Lock()
				active := !g.closed && !g.principals[id].disabled
				handler := g.state.Load().handlers[id]
				g.mu.Unlock()
				if !active {
					break
				}
				handler.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// credentialTransport binds the SDK's detached connection/cleanup requests to the
// original operation budget, while retaining cancellation from each request.
type credentialTransport struct {
	auth      AuthConfig
	token     string
	base      http.RoundTripper
	operation context.Context
}

func (t credentialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	operation := t.operation
	if operation == nil {
		operation = context.Background()
	}
	if err := operation.Err(); err != nil {
		return nil, err
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if deadline, ok := operation.Deadline(); ok {
		ctx, cancel = context.WithDeadline(r.Context(), deadline)
	} else {
		ctx, cancel = context.WithCancel(r.Context())
	}
	stop := context.AfterFunc(operation, cancel)
	// AfterFunc may be scheduled asynchronously if cancellation raced registration.
	if err := operation.Err(); err != nil {
		stop()
		cancel()
		return nil, err
	}
	release := func() { stop(); cancel() }
	copy := r.Clone(ctx)
	header, value := "Authorization", t.token
	switch t.auth.Mode {
	case "", "bearer":
		value = "Bearer " + t.token
	case "raw":
	case "api_key":
		header = t.auth.Header
	default:
		release()
		return nil, errors.New("unsupported authentication mode")
	}
	// Clone has its own header map. Remove all casing variants, not just the
	// canonical entry, so an existing header cannot become a second credential.
	for name := range copy.Header {
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, header) {
			delete(copy.Header, name)
		}
	}
	copy.Header.Set(header, value)
	response, err := t.base.RoundTrip(copy)
	if err != nil {
		release()
		return nil, err
	}
	// Do not release at RoundTrip return: the context must also bound body reads.
	response.Body = &operationBody{ReadCloser: http.MaxBytesReader(nil, response.Body, 1<<20), release: release}
	return response, nil
}

type operationBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *operationBody) Close() error {
	b.once.Do(b.release)
	return b.ReadCloser.Close()
}

func systemOperationClient(ctx context.Context, token string, auth AuthConfig) *http.Client {
	return &http.Client{Transport: credentialTransport{auth: auth, token: token, base: http.DefaultTransport, operation: ctx}, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
}

func operationClient(ctx context.Context, token string) *http.Client {
	return systemOperationClient(ctx, token, AuthConfig{Mode: "bearer"})
}

// CredentialClient refuses redirects and bounds each HTTP response to 1 MiB.
// Gateway operations use a separate client bound to their operation context.
func CredentialClient(token string) *http.Client { return operationClient(context.Background(), token) }
