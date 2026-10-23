package gateway

import (
	"bytes"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed admin_assets/*
var adminAssets embed.FS

// AdminHandler is a separately authorized, opt-in loopback control surface.
// token is supplied by the operator, never derived from entry identity or roles.
// Configuration drafts are stateless and never change the live topology.
// 此入口是单一管理员权限，不区分持有同一 token 的自然人；变更记为 operator。
// 宿主仍须提供入口总限额、读取截止和原始 HTTP 头限制，不能只依赖这里的槽位。
func (g *Gateway) AdminHandler(origin, token string) (http.Handler, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" || u.Opaque != "" {
		return nil, errors.New("invalid admin origin")
	}
	host, port, err := net.SplitHostPort(u.Host)
	n, pe := strconv.Atoi(port)
	if err != nil || pe != nil || n < 1 || n > 65535 || (host != "127.0.0.1" && host != "::1") || u.String() != origin {
		return nil, errors.New("invalid admin origin")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return nil, errors.New("invalid admin authority")
	}
	clear(raw)
	digest := entryTokenDigest(token)
	g.mu.Lock()
	for _, d := range g.entryTokens {
		if d == digest {
			g.mu.Unlock()
			return nil, errors.New("admin authority must be separate")
		}
	}
	g.mu.Unlock()
	// 额外的四槽零队列限制只属于此 handler 实例，覆盖静态资源和 API；
	// 它不是按管理员身份隔离的配额，也不能替代宿主入口防护。
	slots := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accountHeaders(w)
		remote, _, re := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(remote)
		if re != nil || ip == nil || !ip.IsLoopback() || r.Host != u.Host || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Origin")) > 1 || len(r.Header.Values("Authorization")) > 1 || strings.Contains(r.URL.EscapedPath(), "%") {
			accountError(w, 403, "request_denied")
			return
		}
		site := r.Header.Get("Sec-Fetch-Site")
		if (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != origin) || (site != "" && site != "same-origin" && site != "none") {
			accountError(w, 403, "request_denied")
			return
		}
		if r.Method == http.MethodPost && (r.Header.Get("X-MCP-Admin") != "1" || (site != "" && r.Header.Get("Origin") != origin)) {
			accountError(w, 403, "request_denied")
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			accountError(w, 429, "admin_busy")
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/admin/api/") {
			files := map[string]string{"/admin": "index.html", "/admin/": "index.html", "/admin/assets/admin.js": "admin.js", "/admin/assets/admin.css": "admin.css"}
			file, ok := files[r.URL.Path]
			if !ok {
				accountError(w, 404, "not_found")
				return
			}
			if r.Method != http.MethodGet {
				accountError(w, 405, "method_not_allowed")
				return
			}
			data, err := adminAssets.ReadFile("admin_assets/" + file)
			if err != nil {
				accountError(w, 503, "state_unavailable")
				return
			}
			ct := "text/html; charset=utf-8"
			if strings.HasSuffix(file, ".js") {
				ct = "text/javascript; charset=utf-8"
			}
			if strings.HasSuffix(file, ".css") {
				ct = "text/css; charset=utf-8"
			}
			w.Header().Set("Content-Type", ct)
			_, _ = w.Write(data)
			return
		}
		supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		got := entryTokenDigest(supplied)
		if r.Header.Get("Authorization") != "Bearer "+supplied || subtle.ConstantTimeCompare(got[:], digest[:]) != 1 {
			accountError(w, 401, "admin_authentication_rejected")
			return
		}
		switch r.URL.Path {
		case "/admin/api/snapshot":
			if r.Method != http.MethodGet {
				accountError(w, 405, "method_not_allowed")
				return
			}
			value, err := g.adminSnapshot()
			if err != nil {
				adminFailure(w, err)
				return
			}
			accountJSON(w, 200, value)
		case "/admin/api/mutate":
			var in adminMutation
			if !adminDecode(w, r, &in) {
				return
			}
			g.adminMutate(w, in)
		case "/admin/api/audit":
			var in struct {
				After uint64 `json:"after"`
				Limit int    `json:"limit"`
			}
			if !adminDecode(w, r, &in) {
				return
			}
			if in.Limit < 1 || in.Limit > MaxAuditReadLimit {
				accountError(w, 400, "invalid_request")
				return
			}
			g.mu.Lock()
			var page AuditPage
			var err error
			if g.closed || g.auditFault {
				err = ErrStorage
			} else {
				page, err = g.auditRing.Read(AuditFilter{After: in.After, Limit: in.Limit})
			}
			g.mu.Unlock()
			if err != nil {
				adminFailure(w, err)
				return
			}
			accountJSON(w, 200, page)
		case "/admin/api/config/validate":
			var in struct {
				Systems []System `json:"systems"`
			}
			if !adminDecode(w, r, &in) {
				return
			}
			// 独立临时网关只做配置语义校验，不发现下游、不打开数据库，也不
			// 修改当前实例；valid 只代表草稿可解析/构造，不代表已应用或连通。
			candidate, err := New(Config{Systems: in.Systems, Users: map[string]User{}})
			if err != nil {
				accountError(w, 400, "invalid_configuration")
				return
			}
			_ = candidate.Close()
			accountJSON(w, 200, map[string]any{"valid": true, "applied": false, "state": "not_applied", "reason": "topology_migration_required", "draft": in})
		default:
			accountError(w, 404, "not_found")
		}
	}), nil
}

// Reject duplicate keys at every nesting depth, then enforce the typed schema.
func adminDecode(w http.ResponseWriter, r *http.Request, out any) bool {
	if r.Method != http.MethodPost {
		accountError(w, 405, "method_not_allowed")
		return false
	}
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/json" {
		accountError(w, 415, "json_required")
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		accountError(w, 413, "request_too_large")
		return false
	}
	data = bytes.TrimSpace(data)
	d := json.NewDecoder(bytes.NewReader(data))
	if err = adminJSONValue(d, 0); err != nil {
		accountError(w, 400, "invalid_request")
		return false
	}
	if _, err = d.Token(); err != io.EOF {
		accountError(w, 400, "invalid_request")
		return false
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(out); err != nil || len(data) == 0 || data[0] != '{' {
		accountError(w, 400, "invalid_request")
		return false
	}
	return true
}
func adminJSONValue(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrDenied
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return ErrDenied
			}
			seen[key] = true
			if err = adminJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	} else if delim == '[' {
		for d.More() {
			if err = adminJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	} else {
		return ErrDenied
	}
	_, err = d.Token()
	return err
}
func adminFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrAuditFull) {
		accountError(w, 503, "audit_capacity_exhausted")
		return
	}
	accountFailure(w, err)
}

type adminMutation struct {
	Action    string   `json:"action"`
	Tenant    string   `json:"tenant"`
	Principal string   `json:"principal"`
	System    string   `json:"system,omitempty"`
	Expected  uint64   `json:"expected_version"`
	Allowed   []string `json:"allowed,omitempty"`
	Preview   bool     `json:"preview,omitempty"`
	Confirm   bool     `json:"confirm,omitempty"`
}

func (g *Gateway) adminMutate(w http.ResponseWriter, in adminMutation) {
	if in.Action != "set_policy" && in.Action != "disable_principal" && in.Action != "revoke_binding" {
		accountError(w, 501, "unsupported_operation")
		return
	}
	if in.Expected == 0 || in.Tenant == "" || in.Principal == "" || (in.Preview == in.Confirm) || (in.Action != "revoke_binding" && in.System != "") || (in.Action != "set_policy" && in.Allowed != nil) {
		accountError(w, 400, "invalid_request")
		return
	}
	id := Identity{in.Tenant, in.Principal}
	// Preview checks current authoritative versions. Commit repeats CAS under the
	// existing transaction lock; a preview is never permission to bypass CAS.
	g.mu.Lock()
	_, p, err := g.principalLocked(id)
	if err == nil {
		expected := p.version
		if in.Action == "revoke_binding" {
			b := p.bindings[in.System]
			if b == nil {
				err = ErrDenied
			} else {
				expected = b.info.Generation
			}
		}
		if err == nil && expected != in.Expected {
			err = ErrConflict
		}
		if in.Action == "set_policy" {
			if len(in.Allowed) > 2048 {
				err = ErrDenied
			}
			for _, n := range in.Allowed {
				if !validNamespaced(n, g.systems) {
					err = ErrDenied
				}
			}
			if p.disabled {
				err = ErrDenied
			}
		}
	}
	g.mu.Unlock()
	if err != nil {
		adminFailure(w, err)
		return
	}
	if in.Preview {
		accountJSON(w, 200, map[string]any{"preview": true, "action": in.Action, "expected_version": in.Expected})
		return
	}
	switch in.Action {
	case "set_policy":
		_, err = g.SetPolicy(id, in.Expected, in.Allowed)
	case "disable_principal":
		_, err = g.DisablePrincipal(id, in.Expected)
	case "revoke_binding":
		_, err = g.RevokeBinding(id, in.System, in.Expected)
	}
	if err != nil {
		adminFailure(w, err)
		return
	}
	accountJSON(w, 200, map[string]any{"applied": true})
}

type adminUser struct {
	Tenant        string           `json:"tenant"`
	Principal     string           `json:"principal"`
	PolicyVersion uint64           `json:"policy_version"`
	Allowed       []string         `json:"allowed"`
	Disabled      bool             `json:"disabled"`
	Entry         adminEntry       `json:"entry"`
	Bindings      []accountBinding `json:"bindings"`
	Tools         []adminTool      `json:"tools"`
}
type adminEntry struct {
	Generation uint64    `json:"generation"`
	ExpiresAt  time.Time `json:"expires_at"`
	Revoked    bool      `json:"revoked"`
}
type adminTool struct {
	Name       string `json:"name"`
	System     string `json:"system"`
	Discovered bool   `json:"discovered"`
	Authorized bool   `json:"authorized"`
}
type adminService struct {
	System
	Configured bool   `json:"configured"`
	Health     string `json:"health"`
}

// adminSnapshot 在 g.mu 内复制身份/目录视图，再分别读取审计和拒绝摘要；
// 整个响应不是跨所有指标的原子快照。服务健康未探测、未实现指标显式留空。
func (g *Gateway) adminSnapshot() (any, error) {
	g.mu.Lock()
	if g.closed || g.auditFault {
		g.mu.Unlock()
		return nil, ErrStorage
	}
	services := []adminService{}
	for _, s := range g.systems {
		services = append(services, adminService{s, true, "not_checked"})
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	users := []adminUser{}
	state := g.state.Load()
	for id, p := range g.principals {
		u := adminUser{Tenant: p.identity.Tenant, Principal: p.identity.Principal, PolicyVersion: p.version, Allowed: append([]string{}, p.allowed...), Disabled: p.disabled, Entry: adminEntry{p.entry.Generation, p.entry.ExpiresAt, p.entry.Revoked}, Bindings: []accountBinding{}, Tools: []adminTool{}}
		for _, b := range p.bindings {
			u.Bindings = append(u.Bindings, accountBindingView(b.info))
		}
		sort.Slice(u.Bindings, func(i, j int) bool { return u.Bindings[i].System < u.Bindings[j].System })
		if state != nil {
			for name, e := range state.catalogs[id] {
				u.Tools = append(u.Tools, adminTool{name, e.system.Name, true, g.entryAllowedLocked(id, name, e)})
			}
		}
		sort.Slice(u.Tools, func(i, j int) bool { return u.Tools[i].Name < u.Tools[j].Name })
		users = append(users, u)
	}
	sort.Slice(users, func(i, j int) bool {
		if users[i].Tenant != users[j].Tenant {
			return users[i].Tenant < users[j].Tenant
		}
		return users[i].Principal < users[j].Principal
	})
	persistent := g.store != nil
	g.mu.Unlock()
	return map[string]any{"capabilities": map[string]bool{"policy_update": true, "principal_disable": true, "binding_revoke": true, "entry_lifecycle": false, "user_create": false, "topology_apply": false, "config_validate": true}, "limitations": map[string]string{"entry_lifecycle": "offline_only", "user_create": "topology_migration_required", "topology_apply": "topology_migration_required"}, "persistent": persistent, "services": services, "users": users, "audit": g.AuditStatus(), "rejections": g.RejectionStatus(), "metrics": map[string]any{"latency_p95": nil, "success_rate": nil}}, nil
}
