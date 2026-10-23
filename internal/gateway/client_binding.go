package gateway

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// No '__': configured business tools always contain that separator.
const clientConnectionsTool = "mcp_entry_connections"
const bindingInstructions = "Use the trusted local connect helper with private owner-only entry and provider credential files. Never paste credentials into chat, tool arguments, elicitation forms, URLs or command-line values. Confirm the gateway address independently. If submission is interrupted, inspect generation before any new explicit attempt. Binding does not grant tools or repeat a business operation."

type clientService struct {
	System     string `json:"system"`
	Generation uint64 `json:"generation"`
	State      string `json:"state"`
	Discovery  string `json:"discovery_status"`
}
type clientServices struct {
	Services     []clientService `json:"services"`
	Submission   string          `json:"submission"`
	Instructions string          `json:"instructions"`
}

// clientServiceAllowedLocked 按本地策略判断服务能否进入本人连接流程，不要求
// 已有可用凭据或发现目录；否则缺凭据的服务将永远无法显示为待连接。
func (g *Gateway) clientServiceAllowedLocked(id, system string) bool {
	if !g.principalUsableLocked(id) {
		return false
	}
	if _, ok := g.systems[system]; !ok {
		return false
	}
	for _, name := range g.principals[id].allowed {
		if strings.HasPrefix(name, system+"__") {
			return true
		}
	}
	return false
}
func (g *Gateway) clientServicesFor(id string) (clientServices, error) {
	return g.clientServicesContext(context.Background(), id)
}
func (g *Gateway) clientServicesContext(ctx context.Context, id string) (clientServices, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := clientServices{Services: []clientService{}, Submission: "private_file_cli", Instructions: bindingInstructions}
	if !g.clientBindingEnabled.Load() || !g.principalUsableLocked(id) || !g.entryRevisionAllowedLocked(ctx, id) {
		return out, ErrDenied
	}
	p := g.principals[id]
	for _, system := range sortedBindingNames(p.bindings) {
		if !g.clientServiceAllowedLocked(id, system) {
			continue
		}
		b := accountBindingView(p.bindings[system].info)
		state := string(b.State)
		if b.State == BindingUnbound {
			state = "missing"
		}
		// 未观察到可用工具不等于提供方故障：尚未刷新、工具为空或已失效均可能如此。
		discovery := "not_observed"
		for name, e := range g.state.Load().catalogs[id] {
			if e.system.Name == system && g.entryAllowedLocked(id, name, e) {
				discovery = "available"
				break
			}
		}
		out.Services = append(out.Services, clientService{system, b.Generation, state, discovery})
	}
	return out, nil
}
func (g *Gateway) addClientBindingTool(server *mcp.Server, id string) {
	if !g.clientBindingEnabled.Load() {
		return
	}
	server.AddTool(&mcp.Tool{Name: clientConnectionsTool, Description: "Read current user's authorized configured service connection metadata and secure local submission instructions. Does not accept credentials, contact providers or change bindings.", InputSchema: map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Do not let arguments become an identity selector or secret-submission path.
		raw := req.Params.Arguments
		var args map[string]json.RawMessage
		if len(raw) > 64 || (len(raw) > 0 && (json.Unmarshal(raw, &args) != nil || args == nil || len(args) != 0)) {
			return nil, errors.New("invalid control arguments")
		}
		out, err := g.clientServicesContext(ctx, id)
		if err != nil {
			return nil, ErrDenied
		}
		data, _ := json.Marshal(out)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(data)}}, StructuredContent: out}, nil
	})
}

// replaceClientBinding 将策略、身份可用性、入口代次、绑定 CAS 及持久发布放在
// 同一锁范围；提交下游凭据不能为原本无权限的服务授权，也不能跨入口轮换写入。
func (g *Gateway) replaceClientBinding(identity Identity, system string, expected uint64, entryGeneration uint64, credential string, expiry time.Time) (BindingInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	id, p, err := g.principalLocked(identity)
	if err != nil {
		return BindingInfo{}, err
	}
	if !g.clientBindingEnabled.Load() || !g.clientServiceAllowedLocked(id, system) || p.entry.Generation != entryGeneration {
		return BindingInfo{}, ErrDenied
	}
	b := p.bindings[system]
	if b == nil {
		return BindingInfo{}, ErrDenied
	}
	if b.info.Generation != expected {
		return BindingInfo{}, ErrConflict
	}
	if credential == "" || len(credential) > 4096 || !validCredential(credential, g.systems[system].Auth) || !validExpiryDate(expiry.UTC()) || (!expiry.IsZero() && !expiry.After(time.Now())) {
		return BindingInfo{}, errors.New("invalid credential")
	}
	p = clonePrincipal(p)
	b = p.bindings[system]
	b.info.Generation++
	b.info.State = BindingActive
	b.info.ExpiresAt = expiry.UTC()
	b.credential = credential
	if err := g.publishPrincipalLocked(id, p, system, AuditActionBindingReplace, true); err != nil {
		return BindingInfo{}, err
	}
	return b.info, nil
}

// ClientBindingHandler is an opt-in non-browser synthetic loopback channel. The
// fixed listener origin is deployment configuration, never supplied by MCP data.
// 成功构造会启用本地只读连接工具并重建 handler；提交凭据走独立 HTTP 路径，
// 不是 MCP 工具参数。宿主必须将返回的 handler 挂到对应的回环监听器。
func (g *Gateway) ClientBindingHandler(expectedOrigin string) (http.Handler, error) {
	u, err := url.Parse(expectedOrigin)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("invalid binding origin")
	}
	host, port, err := net.SplitHostPort(u.Host)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || n < 1 || n > 65535 || (host != "127.0.0.1" && host != "::1") || u.String() != expectedOrigin {
		return nil, errors.New("invalid binding origin")
	}
	if err := g.validateAccountAuth(); err != nil {
		return nil, err
	}
	g.mu.Lock()
	// 同时更新开关和 handler 快照，使已发现业务目录保留并获得本地控制工具。
	g.clientBindingEnabled.Store(true)
	g.state.Store(g.makeSnapshot(g.state.Load().catalogs))
	g.mu.Unlock()
	return g.GuardHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accountHeaders(w)
		if r.Host != u.Host || r.URL.RawQuery != "" || r.URL.ForceQuery || strings.Contains(r.URL.EscapedPath(), "%") || len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Cookie")) != 0 || len(r.Header.Values("Sec-Fetch-Site")) != 0 {
			accountError(w, 403, "request_denied")
			return
		}
		identity, entryGeneration, ok := g.authenticateClientEntry(r)
		if !ok {
			accountError(w, 401, "entry_authentication_rejected")
			return
		}
		r = r.WithContext(withEntryRevision(r.Context(), identity, entryGeneration))
		switch r.URL.Path {
		case "/binding/api/services":
			if r.Method != "GET" {
				accountError(w, 405, "method_not_allowed")
				return
			}
			g.mu.Lock()
			id := g.identities[identity]
			g.mu.Unlock()
			out, err := g.clientServicesContext(r.Context(), id)
			if err != nil {
				clientBindingFailure(w, err)
				return
			}
			accountJSON(w, 200, out)
		case "/binding/api/credentials":
			if r.Method != "POST" {
				accountError(w, 405, "method_not_allowed")
				return
			}
			typ, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || typ != "application/json" || len(r.Header.Values("Content-Type")) != 1 {
				accountError(w, 415, "json_required")
				return
			}
			fields, err := decodeAccountObject(w, r)
			if err != nil {
				accountError(w, 400, "invalid_request")
				return
			}
			for k := range fields {
				if k != "service_id" && k != "expected_generation" && k != "credential" && k != "expires_at" {
					accountError(w, 400, "invalid_request")
					return
				}
			}
			var system, credential string
			var generation uint64
			var expiry time.Time
			if json.Unmarshal(fields["service_id"], &system) != nil || !validPart(system) || len(system) > 64 || json.Unmarshal(fields["expected_generation"], &generation) != nil || generation == 0 || json.Unmarshal(fields["credential"], &credential) != nil || credential == "" || len(credential) > 4096 {
				accountError(w, 400, "invalid_request")
				return
			}
			if raw, ok := fields["expires_at"]; ok {
				var value string
				if json.Unmarshal(raw, &value) != nil || value == "" {
					accountError(w, 400, "invalid_request")
					return
				}
				expiry, err = time.Parse(time.RFC3339Nano, value)
				if err != nil {
					accountError(w, 400, "invalid_request")
					return
				}
			}
			if r.Context().Err() != nil {
				accountError(w, 408, "request_canceled")
				return
			}
			info, err := g.replaceClientBinding(identity, system, generation, entryGeneration, credential, expiry)
			credential = ""
			if err != nil {
				clientBindingFailure(w, err)
				return
			}
			// Save already committed. Discovery failure must never imply save failure.
			ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
			issues := g.RefreshBinding(ctx, identity, system)
			status := "ready"
			if len(issues) > 0 {
				status = "unavailable"
			}
			if ctx.Err() != nil {
				status = "not_completed"
			}
			cancel()
			// Refresh may intentionally skip dispatch after a concurrent revocation.
			// Never turn that nil issue list into a claim of usable discovery.
			g.mu.Lock()
			id := g.identities[identity]
			p := g.principals[id]
			if !g.clientServiceAllowedLocked(id, system) || p.entry.Generation != entryGeneration || p.bindings[system].info.Generation != info.Generation {
				status = "not_completed"
			}
			g.mu.Unlock()
			accountJSON(w, 200, struct {
				Saved     bool           `json:"binding_saved"`
				Binding   accountBinding `json:"binding"`
				Discovery string         `json:"discovery_status"`
			}{true, accountBindingView(info), status})
		default:
			accountError(w, 404, "not_found")
		}
	})), nil
}

// authenticateClientEntry 将入口认证和代次捕获放在同一锁内；解析请求后写入时
// 再核对该代次，阻止已被轮换或撤销的旧 token 继续修改本人绑定。
func (g *Gateway) authenticateClientEntry(r *http.Request) (Identity, uint64, bool) {
	if len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return Identity{}, 0, false
	}
	digest := entryTokenDigest(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, expected := range g.entryTokens {
		if subtle.ConstantTimeCompare(digest[:], expected[:]) == 1 && g.principalUsableLocked(id) {
			p := g.principals[id]
			return p.identity, p.entry.Generation, true
		}
	}
	return Identity{}, 0, false
}

func clientBindingFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrAuditFull) {
		accountError(w, http.StatusServiceUnavailable, "state_unavailable")
		return
	}
	accountFailure(w, err)
}
