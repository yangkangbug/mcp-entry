package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"mime"
	"net/http"
	"strings"
	"time"
)

//go:embed binding_assets/*
var bindingAssets embed.FS

// 所有资源固定在本站，不使用请求Host构造链接、不接受跳转或查询参数。
// fragment能力只在同源POST正文中出现，不能单独替代用户入口身份验证。
func (g *Gateway) serveConnectionBrowser(w http.ResponseWriter, r *http.Request, host, origin string) bool {
	browser := r.URL.Path == "/binding/" || r.URL.Path == "/binding/binding.js" || r.URL.Path == "/binding/binding.css" || strings.HasPrefix(r.URL.Path, "/binding/api/session/")
	if !browser {
		return false
	}
	if r.Host != host || r.URL.RawQuery != "" || r.URL.ForceQuery || strings.Contains(r.URL.EscapedPath(), "%") || len(r.Header.Values("Cookie")) != 0 {
		accountError(w, 403, "request_denied")
		return true
	}
	if !strings.HasPrefix(r.URL.Path, "/binding/api/session/") {
		if r.Method != "GET" {
			accountError(w, 405, "method_not_allowed")
			return true
		}
		name := "index.html"
		typ := "text/html; charset=utf-8"
		if r.URL.Path == "/binding/binding.js" {
			name = "binding.js"
			typ = "text/javascript; charset=utf-8"
		}
		if r.URL.Path == "/binding/binding.css" {
			name = "binding.css"
			typ = "text/css; charset=utf-8"
		}
		data, err := bindingAssets.ReadFile("binding_assets/" + name)
		if err != nil {
			accountError(w, 404, "not_found")
			return true
		}
		w.Header().Set("Content-Type", typ)
		_, _ = w.Write(data)
		return true
	}
	if r.Method != "POST" {
		accountError(w, 405, "method_not_allowed")
		return true
	}
	if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != origin || len(r.Header.Values("Sec-Fetch-Site")) > 1 || (r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") {
		accountError(w, 403, "request_denied")
		return true
	}
	typ, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" || len(r.Header.Values("Content-Type")) != 1 {
		accountError(w, 415, "json_required")
		return true
	}
	identity, entryGeneration, ok := g.authenticateClientEntry(r)
	if !ok {
		accountError(w, 401, "entry_authentication_rejected")
		return true
	}
	fields, err := decodeAccountObject(w, r)
	if err != nil {
		accountError(w, 400, "invalid_request")
		return true
	}
	action := strings.TrimPrefix(r.URL.Path, "/binding/api/session/")
	if action != "inspect" && action != "confirm" && action != "cancel" {
		accountError(w, 404, "not_found")
		return true
	}
	for k := range fields {
		if k != "session_locator" && k != "capability" && !(action == "confirm" && (k == "credential" || k == "expires_at" || k == "confirm")) {
			accountError(w, 400, "invalid_request")
			return true
		}
	}
	var locator, capability, credential string
	var confirm bool
	var expiry time.Time
	if json.Unmarshal(fields["session_locator"], &locator) != nil || !validConnectionID(locator) || json.Unmarshal(fields["capability"], &capability) != nil || !validConnectionID(capability) {
		accountError(w, 400, "invalid_request")
		return true
	}
	if action == "confirm" {
		if json.Unmarshal(fields["credential"], &credential) != nil || credential == "" || len(credential) > 4096 || json.Unmarshal(fields["confirm"], &confirm) != nil || !confirm {
			accountError(w, 400, "invalid_request")
			return true
		}
		if raw, ok := fields["expires_at"]; ok {
			var value string
			if json.Unmarshal(raw, &value) != nil {
				accountError(w, 400, "invalid_request")
				return true
			}
			expiry, err = time.Parse(time.RFC3339Nano, value)
			if err != nil {
				accountError(w, 400, "invalid_request")
				return true
			}
		}
	}
	digest := sha256.Sum256([]byte(capability))
	capability = ""
	g.mu.Lock()
	id := g.identities[identity]
	s := g.connectionSessions[locator]
	// 不匹配的身份不能读取会话详情，更不能凭泄漏链接替另一人绑定或取消。
	if s == nil || s.owner != id || s.entry != entryGeneration || s.state != "pending" || subtle.ConstantTimeCompare(digest[:], s.capability[:]) != 1 {
		g.mu.Unlock()
		accountError(w, 403, "permission_denied")
		return true
	}
	if !g.connectionValidLocked(s) {
		invalidateConnection(s, "invalidated")
		g.mu.Unlock()
		accountError(w, 403, "permission_denied")
		return true
	}
	if r.Context().Err() != nil {
		g.mu.Unlock()
		accountError(w, 408, "request_canceled")
		return true
	}
	if action == "inspect" {
		out := map[string]any{"service_id": s.system, "identity": map[string]string{"tenant": identity.Tenant, "principal": identity.Principal}, "auth_type": g.systems[s.system].Auth.Mode, "expires_at": s.expires.UTC(), "state": s.state}
		g.mu.Unlock()
		accountJSON(w, 200, out)
		return true
	}
	if action == "cancel" {
		invalidateConnection(s, "canceled")
		g.mu.Unlock()
		accountJSON(w, 200, map[string]string{"state": "canceled"})
		return true
	}
	// 在发布前不可逆地消费能力：即使存储结果不确定也不能用同一链接重试。
	// 会话保存标志只来自本次成功提交，不把外部generation变化猜成自己的回执。
	invalidateConnection(s, "consumed")
	info, err := g.replaceClientBindingLocked(identity, s.system, s.binding, s.entry, credential, expiry)
	credential = ""
	if err == nil {
		s.state = "saved"
		s.saved = true
		s.generation = info.Generation
	}
	g.mu.Unlock()
	if err != nil {
		clientBindingFailure(w, err)
		return true
	}
	// 保存已经确认；后续仅发现工具，绝不派发或重试原业务请求。
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	issues := g.RefreshBinding(ctx, identity, s.system)
	discovery := "ready"
	if len(issues) > 0 {
		discovery = "unavailable"
	}
	if ctx.Err() != nil {
		discovery = "not_completed"
	}
	cancel()
	g.mu.Lock()
	p := g.principals[id]
	if !g.clientServiceAllowedLocked(id, s.system) || p.entry.Generation != s.entry || p.version != s.policy || p.bindings[s.system].info.Generation != info.Generation || g.systems[s.system].revision != s.revision {
		discovery = "not_completed"
	}
	s.discovery = discovery
	g.mu.Unlock()
	accountJSON(w, 200, map[string]any{"binding_saved": true, "binding": accountBindingView(info), "discovery_status": discovery})
	return true
}
