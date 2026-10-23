package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const connectionBeginTool = "mcp_entry_connection_begin"
const connectionStatusTool = "mcp_entry_connection_status"
const connectionLifetime = 5 * time.Minute

type connectionSession struct {
	owner, system                    string
	entry, policy, binding, revision uint64
	capability                       [32]byte
	expires                          time.Time
	state                            string
	discovery                        string
	saved                            bool
	generation                       uint64
	timer                            *time.Timer
}

func isConnectionControlTool(name string) bool {
	return name == clientConnectionsTool || name == connectionBeginTool || name == connectionStatusTool
}
func connectionResult(v any) *mcp.CallToolResult {
	data, _ := json.Marshal(v)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(data)}}, StructuredContent: v}
}
func connectionRandom() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
func validConnectionID(v string) bool {
	b, e := base64.RawURLEncoding.DecodeString(v)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == v
}

// 会话只存能力摘要与非秘密版本。每人最多四个、全局最多一百二十八个，
// 定时清除保证无人再次访问时也不会保留过期能力；重启不恢复这些短期会话。
func (g *Gateway) beginConnection(ctx context.Context, id, system string, generation uint64) (map[string]any, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !g.clientBindingEnabled.Load() || !g.clientServiceAllowedLocked(id, system) || !g.entryRevisionAllowedLocked(ctx, id) || g.clientBindingOrigin == "" {
		return nil, ErrDenied
	}
	p := g.principals[id]
	b := p.bindings[system]
	if b == nil {
		return nil, ErrDenied
	}
	if b.info.Generation != generation {
		return nil, ErrConflict
	}
	count := 0
	for _, s := range g.connectionSessions {
		if s.owner == id {
			count++
		}
	}
	if count >= 4 || len(g.connectionSessions) >= 128 {
		return nil, errors.New("connection session limit")
	}
	locator, err := connectionRandom()
	if err != nil {
		return nil, err
	}
	capability, err := connectionRandom()
	if err != nil {
		return nil, err
	}
	s := &connectionSession{owner: id, system: system, entry: p.entry.Generation, policy: p.version, binding: generation, revision: g.systems[system].revision, capability: sha256.Sum256([]byte(capability)), expires: time.Now().Add(connectionLifetime), state: "pending", discovery: "not_observed"}
	g.connectionSessions[locator] = s
	s.timer = time.AfterFunc(connectionLifetime, func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		delete(g.connectionSessions, locator)
		s.capability = [32]byte{}
	})
	return map[string]any{"session_locator": locator, "service_id": system, "expires_at": s.expires.UTC(), "authorization_url": g.clientBindingOrigin + "/binding/#" + locator + "." + capability, "state": "pending", "instructions": "Show this link to the user. The user must independently verify the gateway address and authenticate in the browser with their own current entry credential. Never ask for credentials in chat or tool arguments. Saving does not retry any business operation."}, nil
}
func (g *Gateway) connectionValidLocked(s *connectionSession) bool {
	if !g.clientBindingEnabled.Load() || !g.clientServiceAllowedLocked(s.owner, s.system) || !time.Now().Before(s.expires) {
		return false
	}
	p := g.principals[s.owner]
	b := p.bindings[s.system]
	return b != nil && p.entry.Generation == s.entry && p.version == s.policy && b.info.Generation == s.binding && g.systems[s.system].revision == s.revision
}
func invalidateConnection(s *connectionSession, state string) {
	s.state = state
	s.capability = [32]byte{}
}
func (g *Gateway) connectionStatus(ctx context.Context, id, locator string) (map[string]any, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.clientBindingEnabled.Load() || !g.principalUsableLocked(id) || !g.entryRevisionAllowedLocked(ctx, id) {
		return nil, ErrDenied
	}
	s := g.connectionSessions[locator]
	if s == nil || s.owner != id || !g.clientServiceAllowedLocked(id, s.system) || g.principals[id].entry.Generation != s.entry {
		return nil, ErrDenied
	}
	if s.state == "pending" && !g.connectionValidLocked(s) {
		invalidateConnection(s, "invalidated")
	}
	out := map[string]any{"session_locator": locator, "service_id": s.system, "state": s.state, "current_binding": accountBindingView(g.principals[id].bindings[s.system].info), "save_receipt": "in_memory_session_only", "discovery_status": s.discovery, "expires_at": s.expires.UTC(), "save_outcome": "not_attempted"}
	if s.saved {
		out["binding_saved"] = true
		out["saved_generation"] = s.generation
		out["save_outcome"] = "saved"
	} else if s.state == "consumed" {
		out["save_outcome"] = "unknown"
	}
	out["instructions"] = "Saved generation and discovery describe this session's historical attempt, not current usability. If outcome is unknown, inspect current binding and resolve conflicts; never automatically resubmit or retry the business operation. Receipts disappear on expiry or restart."
	return out, nil
}
func (g *Gateway) addConnectionSessionTools(server *mcp.Server, id string) {
	for _, name := range []string{connectionBeginTool, connectionStatusTool} {
		props := map[string]any{"session_locator": map[string]any{"type": "string", "minLength": 43, "maxLength": 43}}
		required := []string{"session_locator"}
		description := "Read only this user's short-lived connection session status. Never accepts credentials; completion does not retry a business operation."
		if name == connectionBeginTool {
			props = map[string]any{"service_id": map[string]any{"type": "string", "maxLength": 64}, "expected_generation": map[string]any{"type": "integer", "minimum": 1}}
			required = []string{"service_id", "expected_generation"}
			description = "Begin a short-lived one-time browser connection link for an authorized service. Only metadata is accepted. Show the link to the user; never read or request their credentials."
		}
		server.AddTool(&mcp.Tool{Name: name, Description: description, InputSchema: map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// 重用严格对象解码：拒绝重复键、未知身份选择器及可能误传的秘密。
			fields, err := decodeConnectionArgs(req.Params.Arguments)
			if err != nil {
				return nil, err
			}
			var out map[string]any
			if name == connectionBeginTool {
				var service string
				var generation uint64
				if len(fields) != 2 || json.Unmarshal(fields["service_id"], &service) != nil || !validPart(service) || len(service) > 64 || json.Unmarshal(fields["expected_generation"], &generation) != nil || generation == 0 {
					return nil, errors.New("invalid control arguments")
				}
				out, err = g.beginConnection(ctx, id, service, generation)
			} else {
				var locator string
				if len(fields) != 1 || json.Unmarshal(fields["session_locator"], &locator) != nil || !validConnectionID(locator) {
					return nil, errors.New("invalid control arguments")
				}
				out, err = g.connectionStatus(ctx, id, locator)
			}
			if err != nil {
				return nil, err
			}
			return connectionResult(out), nil
		})
	}
}
func decodeConnectionArgs(raw json.RawMessage) (fields map[string]json.RawMessage, retErr error) {
	defer func() {
		if retErr != nil {
			retErr = errors.New("invalid control arguments")
		}
	}()
	if len(raw) > 512 {
		return nil, errors.New("invalid control arguments")
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid control arguments")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return nil, e
		}
		k, ok := key.(string)
		if !ok {
			return nil, errors.New("invalid control arguments")
		}
		if _, ok := out[k]; ok {
			return nil, errors.New("invalid control arguments")
		}
		var v json.RawMessage
		if e = d.Decode(&v); e != nil {
			return nil, e
		}
		out[k] = v
	}
	if _, err = d.Token(); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid control arguments")
	}
	return out, nil
}

// 仅本地策略明确允许的精确工具名可得到连接提示。该分支先于业务派发，
// 不从未知工具、下游错误或工具描述推断服务，也不重放原始业务参数。
func (g *Gateway) connectionRequired(ctx context.Context, id, name string) *mcp.CallToolResult {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.clientBindingEnabled.Load() || !g.principalUsableLocked(id) || !g.entryRevisionAllowedLocked(ctx, id) {
		return nil
	}
	allowed := false
	for _, n := range g.principals[id].allowed {
		if n == name {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil
	}
	system, _, ok := strings.Cut(name, "__")
	if !ok || !g.clientServiceAllowedLocked(id, system) {
		return nil
	}
	b := g.principals[id].bindings[system]
	if b == nil || bindingUsable(b) {
		return nil
	}
	r := connectionResult(map[string]any{"code": "connection_required", "service_id": system, "next_action": map[string]any{"tool": connectionBeginTool, "arguments": map[string]any{"service_id": system, "expected_generation": b.info.Generation}}, "instructions": "Ask the user to open the trusted connection link, or use the private-file helper. Never request secrets in chat. The business operation has not been dispatched and will not be retried automatically."})
	r.IsError = true
	return r
}
