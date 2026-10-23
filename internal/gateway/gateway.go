// Package gateway 实现合成测试用 MCP 工具网关：隔离身份、授权目录与下游凭据。
// MCP 传输使用无状态会话；授权状态可选 SQLite 持久化，不等于整个网关无状态。
package gateway

import (
	"context"
	"encoding/base64"
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

// snapshot 发布后只读；目录与对应 SDK handler 必须成对替换，读者可持有旧快照，
// 但实际列举/调用仍须重新核对当前授权和绑定代次。
type snapshot struct {
	catalogs map[string]map[string]entry
	handlers map[string]http.Handler
}

// Gateway 由固定拓扑、可变身份状态和只读目录快照组成。mu 串行化授权变更、
// 最终准入及审计发布；网络 I/O 在锁外执行，完成后再检查版本是否仍可发布。
type Gateway struct {
	clientBindingEnabled    atomic.Bool
	ingress                 *ingressLimiter
	rejections              rejectionSummary
	auditArchivedUnfinished uint64
	limiter                 *admissionLimiter
	operationWG             sync.WaitGroup
	closingContext          context.Context
	auditRing               *AuditRing
	maintenance             bool
	auditUnfinished         map[string]bool
	auditIDKey              []byte
	auditCapacity           int
	auditPending            uint64
	auditFault              bool
	closed                  bool
	store                   *sqliteStore
	entryTokens             map[string][32]byte
	entryStrong             map[string]bool
	discoveryEpoch          map[discoveryKey]uint64
	mu                      sync.Mutex
	principals              map[string]*principalState
	identities              map[Identity]string
	operations              map[uint64]admittedOperation
	nextOperation           uint64
	systems                 map[string]System
	users                   map[string]User
	refreshMu               sync.Mutex
	state                   atomic.Pointer[snapshot]
}

// DiscoveryIssue contains no credentials, raw downstream errors or tool descriptions.
type DiscoveryIssue struct {
	User    string
	System  string
	Reason  string
	Failure *DownstreamFailure `json:"failure,omitempty"`
}

// New 复制并校验配置，不执行下游发现；业务目录在 Refresh 后才可能有工具。
// 显式启用的本地连接状态工具不属于下游业务目录。
func New(cfg Config) (*Gateway, error) { return newGateway(cfg, true) }
func newGateway(cfg Config, bootstrap bool) (*Gateway, error) {
	if len(cfg.Systems) > 16 || len(cfg.Users) > 64 {
		return nil, errors.New("demo configuration exceeds system/user limit")
	}
	g := &Gateway{systems: map[string]System{}, users: map[string]User{}}
	for _, system := range cfg.Systems {
		if !validPart(system.Name) || len(system.Name) > 64 {
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
		if system.Network != nil {
			copy := *system.Network
			copy.AllowedIPs = append([]string(nil), copy.AllowedIPs...)
			system.Network = &copy
		}
		transport, err := compileNetworkPolicy(system.Endpoint, system.Network)
		if err != nil {
			return nil, err
		}
		system.transport = transport
		g.systems[system.Name] = system
	}
	tokens := map[string]bool{}
	for id, user := range cfg.Users {
		if !bootstrap {
			user.Token = ""
			user.TokenExpiresAt = time.Time{}
			user.Allowed = nil
			user.Credentials = nil
		}
		if !validExpiryDate(user.TokenExpiresAt.UTC()) {
			return nil, errors.New("invalid entry credential expiry")
		}
		if id == "" || len(id) > 128 || (bootstrap && (user.Token == "" || len(user.Token) > 4096 || strings.ContainsAny(user.Token, "\r\n") || tokens[user.Token])) {
			return nil, errors.New("invalid demo identity")
		}
		tokens[user.Token] = true
		clone := User{TokenExpiresAt: user.TokenExpiresAt.UTC(), Tenant: user.Tenant, Principal: user.Principal, Token: user.Token, Allowed: append([]string(nil), user.Allowed...), Credentials: map[string]string{}}
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
	if err := g.initializeAudit(cfg.Audit); err != nil {
		return nil, err
	}
	identities := []Identity{}
	for identity := range g.identities {
		identities = append(identities, identity)
	}
	subjects := map[string]string{}
	for name, system := range g.systems {
		subjects[name] = system.QuotaSubject
	}
	limiter, err := newAdmissionLimiter(cfg.Limits, identities, subjects)
	if err != nil {
		return nil, err
	}
	g.limiter = limiter
	g.ingress, err = newIngressLimiter(cfg.Ingress, identities)
	if err != nil {
		return nil, err
	}
	g.rejections.status.Started = time.Now().UTC()
	g.entryTokens = map[string][32]byte{}
	g.entryStrong = map[string]bool{}
	g.discoveryEpoch = map[discoveryKey]uint64{}
	for id, user := range g.users {
		if bootstrap {
			g.entryTokens[id] = entryTokenDigest(user.Token)
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(user.Token)
		g.entryStrong[id] = err == nil && len(decoded) == 32
		user.Token = ""
		g.users[id] = user
	}
	g.state.Store(g.makeSnapshot(map[string]map[string]entry{}))
	return g, nil
}

// Names 返回当前仍满足授权和绑定状态的业务工具名，按名称排序。
// id 是内部配置用户键，不是外部认证凭据；此方法不列出本地连接状态工具。
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
	issues := []DiscoveryIssue{}
	for _, id := range ids {
		user := g.users[id]
		for _, system := range systems {
			issues = append(issues, g.RefreshBinding(ctx, Identity{user.Tenant, user.Principal}, system)...)
		}
	}
	return issues
}

// catalogAdmission accounts for the entire received catalog before the SDK can
// filter tools or inspect header annotations. Its authorization view is immutable
// and belongs to one discovery attempt, never to the session's later policy.
type catalogAdmission struct {
	system  string
	allowed map[string]bool
	names   map[string]bool
	cursors map[string]bool
	total   int
	bytes   int
	pages   int
}

func (a *catalogAdmission) admit(ctx context.Context, list *mcp.ListToolsResult) error {
	if list == nil || list.Tools == nil {
		return errors.New("invalid catalog")
	}
	a.pages++
	a.total += len(list.Tools)
	if a.pages > MaxPagesPerSystem || a.total > MaxToolsPerSystem {
		return errors.New("catalog count limit")
	}
	if len(list.NextCursor) > 4096 || (list.NextCursor != "" && a.cursors[list.NextCursor]) {
		return errors.New("invalid pagination cursor")
	}
	if list.NextCursor != "" {
		a.cursors[list.NextCursor] = true
	}
	selected := make([]*mcp.Tool, 0, len(list.Tools))
	for _, tool := range list.Tools {
		if err := ctx.Err(); err != nil {
			return err
		}
		if tool == nil || !validPart(tool.Name) || !toolNamePattern.MatchString(a.system+"__"+tool.Name) {
			return errors.New("invalid downstream tool name")
		}
		name := a.system + "__" + tool.Name
		if a.names[name] {
			return errors.New("duplicate downstream tool")
		}
		a.names[name] = true
		data, err := json.Marshal(tool)
		a.bytes += len(data)
		if err != nil || len(data) > 64<<10 || a.bytes > 1<<20 {
			return errors.New("catalog byte limit")
		}
		schemas := []any{tool.InputSchema}
		if tool.OutputSchema != nil {
			schemas = append(schemas, tool.OutputSchema)
		}
		for _, schema := range schemas {
			if err := validateSchemaStructure(schema); err != nil {
				return observeSchemaAdmission(ctx, err)
			}
		}
		if !a.allowed[name] {
			continue
		}
		// Fail selected tools before SDK filterValidTools can silently drop them or
		// log schema-derived errors. Compilation still occurs atomically in discover.
		for _, schema := range schemas {
			if _, err := analyzeSchema(schema); err != nil {
				return observeSchemaAdmission(ctx, err)
			}
			if err := validateSchemaTypes(schema); err != nil {
				return observeSchemaAdmission(ctx, err)
			}
		}
		selected = append(selected, tool)
	}
	list.Tools = selected
	return nil
}

func connect(ctx context.Context, system System, token string, admission *catalogAdmission) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-entry", Version: "0.2.0-demo"}, &mcp.ClientOptions{MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true}})
	client.AddSendingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			result, err := next(ctx, method, req)
			if err != nil {
				return nil, err
			}
			if method == "tools/list" {
				list, ok := result.(*mcp.ListToolsResult)
				if !ok || admission == nil {
					return nil, errors.New("unexpected catalog")
				}
				if err := admission.admit(ctx, list); err != nil {
					return nil, err
				}
			}
			return result, nil
		}
	})
	return client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: system.Endpoint, HTTPClient: downstreamOperationClient(ctx, token, system), MaxRetries: -1, DisableStandaloneSSE: true}, nil)
}

func (g *Gateway) discover(ctx context.Context, system System, token string, allowed map[string]bool) (resultEntries map[string]entry, retErr error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx, observation := withFailureObservation(ctx)
	observation.setPhase(FailureConnect)
	admission := &catalogAdmission{system: system.Name, allowed: allowed, names: map[string]bool{}, cursors: map[string]bool{}}
	session, err := connect(ctx, system, token, admission)
	if err != nil {
		return nil, classifyDownstreamFailure(ctx, FailureConnect, err, false)
	}
	// Cleanup is synchronous and shares ctx. A cleanup error must not replace a
	// complete discovery result or a confirmed tool outcome.
	defer func() { observation.setPhase(FailureCleanup); session.Close() }()
	defer func() {
		if retErr != nil {
			var typed *DownstreamFailure
			if !errors.As(retErr, &typed) {
				retErr = classifyDownstreamFailure(ctx, FailureDiscovery, retErr, false)
			}
		}
	}()
	entries := map[string]entry{}
	cursor := ""
	for page := 0; page < MaxPagesPerSystem; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		observation.setPhase(FailureDiscovery)
		result, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, classifyDownstreamFailure(ctx, FailureDiscovery, err, false)
		}
		for _, tool := range result.Tools {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			name := system.Name + "__" + tool.Name
			data, err := json.Marshal(tool)
			if err != nil {
				return nil, err
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

func resolveSchema(value any, input bool) (result *boundedSchema, retErr error) {
	defer func() {
		if retErr != nil {
			retErr = schemaAdmissionFailure(retErr)
		}
	}()
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
// id 由可信调用方提供；HTTP 路径须先验证入口 token，不能直接采信请求中的用户键。
func (g *Gateway) Call(ctx context.Context, id, name string, args any) (result *mcp.CallToolResult, retErr error) {
	g.mu.Lock()
	e, exists := g.evaluateLocked(id, name)
	g.mu.Unlock()
	if !exists {
		g.rejectOperation(ctx, RejectionOperationAuthorization)
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
		g.rejectOperation(ctx, RejectionOperationArguments)
		return nil, errors.New("invalid tool arguments")
	}
	var input any
	if err := json.Unmarshal(data, &input); err != nil {
		g.rejectOperation(ctx, RejectionOperationArguments)
		return nil, errors.New("invalid tool arguments")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// schema 校验可能耗时，先在锁外完成；下方最终准入会重新确认同一目录版本，
	// 防止校验期间发生的撤权或刷新被这次调用越过。
	if err := e.input.Validate(input); err != nil {
		g.rejectOperation(ctx, RejectionOperationArguments)
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
		g.rejectOperation(ctx, RejectionOperationAuthorization)
		return nil, ErrDenied
	}
	if err := ctx.Err(); err != nil {
		g.mu.Unlock()
		return nil, err
	}
	permit, err := g.limiter.acquire(ctx, g.principals[id].identity, e.system.Name)
	if err != nil {
		g.rejectAdmission(ctx, err)
		g.mu.Unlock()
		return nil, err
	}
	started := time.Now()
	event, err := g.startAuditLocked(id, e.system.Name, name, AuditActionCall)
	if err != nil {
		permit.Release()
		g.mu.Unlock()
		return nil, err
	}
	token := g.principals[id].bindings[e.system.Name].credential
	g.nextOperation++
	opID := g.nextOperation
	g.operations[opID] = admittedOperation{id, e.system.Name, cancel}
	g.operationWG.Add(1)
	g.mu.Unlock()
	defer func() { g.finishOperation(opID, event, started, retErr, result != nil && result.IsError, permit) }()
	ctx, observation := withFailureObservation(ctx)
	observation.setPhase(FailureConnect)
	session, err := connect(ctx, e.system, token, nil)
	if err != nil {
		return nil, classifyDownstreamFailure(ctx, FailureConnect, err, false)
	}
	// Cleanup is synchronous and shares ctx. A cleanup error must not replace a
	// complete discovery result or a confirmed tool outcome.
	defer func() { observation.setPhase(FailureCleanup); session.Close() }()
	observation.setPhase(FailureCall)
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: e.original, Arguments: json.RawMessage(data)})
	if err != nil {
		return nil, classifyDownstreamFailure(ctx, FailureCall, err, true)
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

// toolHandler 将身份绑定在服务端闭包中。业务工具走 Call 的独立准入，
// 本地连接状态工具只读获准服务元数据，不沿业务下游转发路径执行。
func (g *Gateway) toolHandler(id string, catalog map[string]entry) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "mcp-entry", Version: "0.2.0-demo"}, nil)
	g.addClientBindingTool(server, id)
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
			ctx = context.WithValue(ctx, operationRejectionKey{}, &operationRejection{})
			result, err := next(ctx, method, req)
			if err != nil {
				g.rejectOperation(ctx, RejectionOperationProtocol)
			}
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
				if tool.Name == clientConnectionsTool && g.clientBindingEnabled.Load() && g.principalUsableLocked(id) {
					filtered = append(filtered, tool)
					continue
				}
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
// 返回值已包装入口限额；宿主仍负责监听地址、TLS、原始头和连接读取预算。
func (g *Gateway) Handler() http.Handler {
	return g.GuardHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			http.Error(w, "browser access disabled", http.StatusForbidden)
			return
		}
		identity, ok := g.authenticateEntry(r)
		if ok {
			g.mu.Lock()
			id, p, err := g.principalLocked(identity)
			var handler http.Handler
			if err == nil && !p.disabled && g.principalUsableLocked(id) {
				handler = g.state.Load().handlers[id]
			}
			g.mu.Unlock()
			if handler != nil {
				handler.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
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

func downstreamOperationClient(ctx context.Context, token string, system System) *http.Client {
	base := system.transport
	if base == nil {
		var err error
		base, err = compileNetworkPolicy(system.Endpoint, system.Network)
		if err != nil {
			return &http.Client{Transport: deniedTransport{}}
		}
	}
	return &http.Client{Transport: observeFailureTransport(ctx, credentialTransport{auth: system.Auth, token: token, base: base, operation: ctx}), Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
}

type deniedTransport struct{}

func (deniedTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, errNetworkPolicy }

func systemOperationClient(ctx context.Context, token string, auth AuthConfig) *http.Client {
	return &http.Client{Transport: credentialTransport{auth: auth, token: token, base: http.DefaultTransport, operation: ctx}, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
}

func operationClient(ctx context.Context, token string) *http.Client {
	return systemOperationClient(ctx, token, AuthConfig{Mode: "bearer"})
}

// CredentialClient refuses redirects and bounds each HTTP response to 1 MiB.
// Gateway operations use a separate client bound to their operation context.
func CredentialClient(token string) *http.Client { return operationClient(context.Background(), token) }
