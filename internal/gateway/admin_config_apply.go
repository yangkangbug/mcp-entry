package gateway

import (
	"crypto/rand"
	"errors"
	"net/http"
	"time"
)

// runtimeConfigRequest 用 revision 防止覆盖并发修改，用摘要将确认绑定到预览内容。
type runtimeConfigRequest struct {
	ExpectedRevision uint64   `json:"expected_revision"`
	Systems          []System `json:"systems"`
	CandidateDigest  string   `json:"candidate_digest,omitempty"`
	ConfirmationID   string   `json:"confirmation_id,omitempty"`
}

// runtimeConfigConfirmation 仅在当前 handler 存活，访问与配置变更共用 g.mu。
type runtimeConfigConfirmation struct {
	ExpectedRevision uint64
	Digest           string
	ExpiresAt        time.Time
}

// runtimeConfigViewLocked 要求持有 g.mu；返回运行配置而非启动 seed，且不含用户凭据。
func (g *Gateway) runtimeConfigViewLocked() map[string]any {
	systems := sortedSystems(g.systems)
	return map[string]any{"revision": g.configRevisionLocked(), "digest": systemDigest(systems), "systems": systems, "persistent": g.store != nil, "apply_supported": g.store != nil && !g.maintenance, "supported_changes": []string{"add", "timeouts"}}
}
func (g *Gateway) adminCurrentConfig(w http.ResponseWriter) {
	g.mu.Lock()
	if g.closed || g.auditFault {
		g.mu.Unlock()
		adminFailure(w, ErrStorage)
		return
	}
	result := g.runtimeConfigViewLocked()
	g.mu.Unlock()
	accountJSON(w, 200, result)
}
func runtimeConfigFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errDestructiveConfig):
		accountError(w, 400, "unsupported_destructive_change")
	case errors.Is(err, errInvalidRuntimeConfig):
		accountError(w, 400, "invalid_configuration")
	default:
		adminFailure(w, err)
	}
}

// adminRuntimeConfig 预览不发布配置；确认仍须以当前 revision 重新构造并校验候选。
// 票据短期、一次性且有数量上限，不能当作长期可重试的提交命令。
func (g *Gateway) adminRuntimeConfig(w http.ResponseWriter, in runtimeConfigRequest, apply bool, tickets map[string]runtimeConfigConfirmation) {
	if in.Systems == nil || (!apply && (in.ConfirmationID != "" || in.CandidateDigest != "")) || (apply && (in.ConfirmationID == "" || in.CandidateDigest == "")) {
		accountError(w, 400, "invalid_request")
		return
	}
	// HTTP 响应在锁外写入，避免慢管理员客户端占用业务准入及撤权所需的 g.mu。
	result, err := func() (map[string]any, error) {
		g.mu.Lock()
		defer g.mu.Unlock()
		now := time.Now()
		for id, ticket := range tickets {
			if !now.Before(ticket.ExpiresAt) {
				delete(tickets, id)
			}
		}
		var ticket runtimeConfigConfirmation
		// 无论随后校验或提交是否成功，确认尝试都消费票据，失败后需重新预览。
		if apply {
			var ok bool
			ticket, ok = tickets[in.ConfirmationID]
			delete(tickets, in.ConfirmationID)
			if !ok || ticket.ExpectedRevision != in.ExpectedRevision || ticket.Digest != in.CandidateDigest {
				return nil, ErrConflict
			}
		}
		manifest, systems, added, updated, err := g.runtimeCandidateLocked(in.ExpectedRevision, in.Systems)
		if err != nil {
			return nil, err
		}
		// 摘要取规范排序后的完整候选，防止只复用 revision/票据而偷换请求内容。
		digest := systemDigest(manifest.Systems)
		if apply {
			if digest != ticket.Digest {
				return nil, ErrConflict
			}
			if err = g.applyRuntimeConfigLocked(manifest, systems, added, updated); err != nil {
				return nil, err
			}
			result := g.runtimeConfigViewLocked()
			result["applied"] = true
			required := append(append([]string{}, added...), updated...)
			result["discovery_required"] = required
			return result, nil
		}
		if len(tickets) >= 64 {
			return nil, ErrAuditFull
		}
		id := rand.Text()
		expiry := now.Add(2 * time.Minute)
		tickets[id] = runtimeConfigConfirmation{in.ExpectedRevision, digest, expiry}
		return map[string]any{"preview": true, "revision": in.ExpectedRevision, "candidate_digest": digest, "confirmation_id": id, "confirmation_expires_at": expiry, "added": added, "updated": updated, "applied": false}, nil
	}()
	if err != nil {
		runtimeConfigFailure(w, err)
		return
	}
	accountJSON(w, 200, result)
}
