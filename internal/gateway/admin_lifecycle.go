package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// lifecycleRequest 将预览与确认绑定到同一动作、身份、入口代次及到期时间。
// 票据仅存于当前 handler 的有界内存中，短期有效、不可恢复，也不包含入口凭据。
type lifecycleRequest struct {
	Action         string    `json:"action"`
	Tenant         string    `json:"tenant"`
	Principal      string    `json:"principal"`
	Expected       uint64    `json:"expected_generation"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	Preview        bool      `json:"preview,omitempty"`
	Confirm        bool      `json:"confirm,omitempty"`
	ConfirmationID string    `json:"confirmation_id,omitempty"`
}

// lifecycleConfirmation 保存归一化请求；访问由 g.mu 保护，不以 HTTP 并发槽替代互斥。
type lifecycleConfirmation struct {
	Request   lifecycleRequest
	ExpiresAt time.Time
}

func lifecycleScope(s string) bool {
	if s == "" || len(s) > 128 || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// checkLifecycleLocked 在 g.mu 内复核实时状态和入口代次 CAS；预览成功不预留变更权。
// 新身份只构造未发布候选，初始入口已撤销、绑定未连接、工具许可为空。
func (g *Gateway) checkLifecycleLocked(in lifecycleRequest) (string, *principalState, error) {
	if g.closed || g.auditFault {
		return "", nil, ErrStorage
	}
	if g.store == nil || g.maintenance {
		return "", nil, ErrDenied
	}
	if (in.Action == "issue_entry" || in.Action == "rotate_entry") && !in.ExpiresAt.After(time.Now()) {
		return "", nil, ErrDenied
	}
	identity := Identity{in.Tenant, in.Principal}
	if in.Action == "create_user" {
		if _, exists := g.identities[identity]; exists {
			return "", nil, ErrConflict
		}
		if len(g.users) >= 64 {
			return "", nil, ErrDenied
		}
		id := managedUserID(identity)
		if _, exists := g.users[id]; exists {
			return "", nil, ErrConflict
		}
		p := &principalState{identity: identity, version: 1, entry: EntryInfo{Generation: 1, Revoked: true}, bindings: map[string]*bindingRecord{}}
		for name := range g.systems {
			p.bindings[name] = &bindingRecord{info: BindingInfo{ID: "managed-" + rand.Text(), Tenant: in.Tenant, Principal: in.Principal, System: name, Generation: 1, State: BindingUnbound}}
		}
		return id, p, nil
	}
	id, p, err := g.principalLocked(identity)
	if err != nil {
		return "", nil, err
	}
	if p.disabled {
		return "", nil, ErrDenied
	}
	if p.entry.Generation != in.Expected || in.Expected == 0 || in.Expected >= math.MaxInt64 || p.version >= math.MaxInt64 {
		return "", nil, ErrConflict
	}
	if (in.Action == "issue_entry" && !p.entry.Revoked) || (in.Action == "rotate_entry" && p.entry.Revoked) || (in.Action == "revoke_entry" && p.entry.Revoked) {
		return "", nil, ErrConflict
	}
	return id, p, nil
}

// adminLifecycle 串行完成票据消费、状态复核、持久提交与内存发布。
// 响应写入一律先解锁，慢客户端不能阻塞撤权及业务最终准入。
func (g *Gateway) adminLifecycle(w http.ResponseWriter, in lifecycleRequest, tickets map[string]lifecycleConfirmation) {
	issuing := in.Action == "issue_entry" || in.Action == "rotate_entry"
	if (in.Action != "create_user" && in.Action != "revoke_entry" && !issuing) || !lifecycleScope(in.Tenant) || !lifecycleScope(in.Principal) || in.Preview == in.Confirm || (in.Action == "create_user" && in.Expected != 0) || (!issuing && !in.ExpiresAt.IsZero()) || (issuing && (in.ExpiresAt.IsZero() || !validExpiryDate(in.ExpiresAt) || !in.ExpiresAt.After(time.Now()))) || (in.Preview && in.ConfirmationID != "") || (in.Confirm && in.ConfirmationID == "") {
		accountError(w, 400, "invalid_request")
		return
	}
	in.ExpiresAt = in.ExpiresAt.UTC()
	normalized := in
	normalized.Preview = false
	normalized.Confirm = false
	normalized.ConfirmationID = ""
	g.mu.Lock()
	locked := true
	unlock := func() {
		if locked {
			locked = false
			g.mu.Unlock()
		}
	}
	defer unlock()
	failure := func(err error) { unlock(); adminFailure(w, err) }
	response := func(code int, value any) { unlock(); accountJSON(w, code, value) }
	requestError := func(code int, value string) { unlock(); accountError(w, code, value) }
	now := time.Now()
	for k, t := range tickets {
		if !now.Before(t.ExpiresAt) {
			delete(tickets, k)
		}
	}
	// 确认先消费票据再校验；冲突或存储失败也不能重放，须重新预览当前状态。
	if in.Confirm {
		ticket, ok := tickets[in.ConfirmationID]
		delete(tickets, in.ConfirmationID)
		if !ok || ticket.Request != normalized {
			failure(ErrConflict)
			return
		}
	}
	id, p, err := g.checkLifecycleLocked(in)
	if err != nil {
		failure(err)
		return
	}
	if in.Preview {
		if len(tickets) >= 64 {
			requestError(429, "admin_busy")
			return
		}
		key := rand.Text()
		expiry := now.Add(2 * time.Minute)
		tickets[key] = lifecycleConfirmation{normalized, expiry}
		response(200, map[string]any{"preview": true, "action": in.Action, "expected_generation": in.Expected, "confirmation_id": key, "confirmation_expires_at": expiry})
		return
	}
	if !g.auditRoomLocked(1) {
		failure(ErrAuditFull)
		return
	}
	candidate := clonePrincipal(p)
	action := AuditActionUserCreate
	digest := sha256.Sum256([]byte("mcp-entry/unissued/v1\x00" + id))
	token := ""
	if in.Action != "create_user" {
		candidate.entry.Generation++
		candidate.version++
		candidate.entry.Revoked = in.Action == "revoke_entry"
		digest = g.entryTokens[id]
		action = AuditActionEntryRevoke
	}
	// 明文 token 只在确认提交这次请求中生成；存储和索引只保留摘要。
	// clear 仅清理随机字节缓冲，不承诺清除 Go 字符串或响应缓冲中的副本。
	if issuing {
		raw := make([]byte, 32)
		if _, err = rand.Read(raw); err != nil {
			failure(ErrStorage)
			return
		}
		token = base64.RawURLEncoding.EncodeToString(raw)
		clear(raw)
		digest = entryTokenDigest(token)
		candidate.entry.ExpiresAt = in.ExpiresAt
		action = AuditActionEntryRotate
		if in.Action == "issue_entry" {
			action = AuditActionEntryIssue
		}
	}
	if in.Action == "create_user" || issuing {
		if g.adminAuthorities[digest] {
			failure(ErrConflict)
			return
		}
		for _, d := range g.entryTokens {
			if d == digest {
				failure(ErrConflict)
				return
			}
		}
	}
	record, err := g.store.record(g, id, candidate)
	if err != nil {
		failure(ErrStorage)
		return
	}
	record.TokenHash = append([]byte(nil), digest[:]...)
	record.TokenExpiresAt = candidate.entry.ExpiresAt
	if issuing {
		record.EntryStrong = true
	}
	if issuing && !in.ExpiresAt.After(time.Now()) {
		failure(ErrDenied)
		return
	}
	event := g.auditEventLocked(id, "", "", candidate, action, AuditPhaseCommit, AuditResultSuccess, AuditActorOperator)
	// 状态、审计和 MAC 同事务提交后才发布。提交报错可能结果未知，关闭实例
	// 而非假定回滚；响应丢失也不能取回本次明文，应查询状态后重新轮换。
	if err = g.store.persistEntry(g, id, record, event); err != nil {
		g.auditFailureLocked()
		failure(ErrStorage)
		return
	}
	if err = g.auditRing.Append(event); err != nil {
		g.auditFailureLocked()
		failure(ErrStorage)
		return
	}
	g.principals[id] = candidate
	g.identities[candidate.identity] = id
	g.entryTokens[id] = digest
	g.entryStrong[id] = record.EntryStrong
	g.users[id] = User{Tenant: in.Tenant, Principal: in.Principal, TokenExpiresAt: candidate.entry.ExpiresAt}
	if in.Action == "create_user" {
		g.limiter.addIdentity(candidate.identity)
		g.ingress.addIdentity(candidate.identity)
	}
	g.invalidateLocked(id, "")
	g.cancelOperationsLocked(id, "")
	result := map[string]any{"applied": true, "entry": adminEntry{candidate.entry.Generation, candidate.entry.ExpiresAt, candidate.entry.Revoked}}
	// 仅成功签发/轮换响应揭示一次 secret；快照、预览及票据均不保存它。
	if issuing {
		result["token"] = token
	}
	response(200, result)
}
