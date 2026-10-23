package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
	"time"
)

// EntryInfo contains no credential or verification digest.
type EntryInfo struct {
	Generation uint64
	ExpiresAt  time.Time
	Revoked    bool
}

// Entry 返回可信进程内调用方指定身份的入口元数据，不返回 token 或摘要。
// Identity 仅用于查找，不替外部调用方完成认证。
func (g *Gateway) Entry(identity Identity) (EntryInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, p, err := g.principalLocked(identity)
	if err != nil {
		return EntryInfo{}, err
	}
	return p.entry, nil
}

// ReplaceEntry 仅在离线维护模式替换入口 token；expected 必须匹配当前入口代次。
// token 必须是规范编码的 32 字节值，expiry 必须在未来；成功后旧 token 不再有效。
// 此操作不恢复已禁用身份，也不改变工具策略或下游绑定。
func (g *Gateway) ReplaceEntry(identity Identity, expected uint64, token string, expiry time.Time) (EntryInfo, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token || !validExpiryDate(expiry) || expiry.IsZero() || !expiry.After(time.Now()) {
		return EntryInfo{}, ErrDenied
	}
	digest := entryTokenDigest(token)
	return g.mutateEntry(identity, expected, &digest, expiry.UTC())
}

// RevokeEntry 以入口代次作乐观并发检查；撤销只标记入口失效，保留原到期时间。
// 与替换相同，它要求离线维护实例，不是在线自助注销接口。
func (g *Gateway) RevokeEntry(identity Identity, expected uint64) (EntryInfo, error) {
	return g.mutateEntry(identity, expected, nil, time.Time{})
}
func (g *Gateway) mutateEntry(identity Identity, expected uint64, digest *[32]byte, expiry time.Time) (EntryInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.maintenance || g.store == nil {
		return EntryInfo{}, ErrDenied
	}
	id, p, err := g.principalLocked(identity)
	if err != nil {
		return EntryInfo{}, err
	}
	if p.disabled {
		return EntryInfo{}, ErrDenied
	}
	if p.entry.Generation != expected || expected == 0 || expected >= math.MaxInt64 {
		return EntryInfo{}, ErrConflict
	}
	if digest != nil {
		if g.adminAuthorities[*digest] {
			return EntryInfo{}, ErrDenied
		}
		for _, old := range g.entryTokens {
			if old == *digest {
				return EntryInfo{}, ErrDenied
			}
		}
	}
	if !g.auditRoomLocked(1) {
		return EntryInfo{}, ErrAuditFull
	}
	// 这里只替换值类型的入口元数据；共享的策略和绑定容器均不写入。
	// 先构造候选记录，持久事务成功前不发布新的内存身份视图。
	candidate := *p
	candidate.entry.Generation++
	candidate.entry.Revoked = digest == nil
	action := AuditActionEntryRevoke
	if digest != nil {
		candidate.entry.ExpiresAt = expiry
		action = AuditActionEntryRotate
	}
	r, err := g.store.record(g, id, &candidate)
	if err != nil {
		return EntryInfo{}, ErrStorage
	}
	if digest != nil {
		r.TokenHash = append([]byte(nil), digest[:]...)
		r.TokenExpiresAt = expiry
		r.EntryStrong = true
	}
	event := g.auditEventLocked(id, "", "", &candidate, action, AuditPhaseCommit, AuditResultSuccess, AuditActorOperator)
	if err = g.store.persistEntry(g, id, r, event); err != nil {
		g.auditFailureLocked()
		return EntryInfo{}, ErrStorage
	}
	if err = g.auditRing.Append(event); err != nil {
		g.auditFailureLocked()
		return EntryInfo{}, ErrStorage
	}
	g.principals[id] = &candidate
	if digest != nil {
		g.entryTokens[id] = *digest
		g.entryStrong[id] = true
		u := g.users[id]
		u.TokenExpiresAt = expiry
		g.users[id] = u
	}
	return candidate.entry, nil
}

// persistEntry 由持有 g.mu 的在线管理或离线维护路径调用，将身份记录、审计事件及状态 MAC
// 放在同一事务中；提交失败交由调用方关闭实例，不能继续使用旧视图猜测结果。
func (s *sqliteStore) persistEntry(g *Gateway, id string, r storedPrincipal, event AuditEvent) error {
	next := make(map[string]storedPrincipal, len(s.records))
	for k, v := range s.records {
		next[k] = v
	}
	next[id] = r
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// 在线 create_user 使用插入，其余入口变更使用更新；二者共用审计与 MAC 事务。
	_, exists := s.records[id]
	if err = writePrincipal(ctx, tx, r, !exists); err != nil {
		return err
	}
	seq, head, err := s.writeAudit(ctx, tx, event)
	if err != nil {
		return err
	}
	if err = s.updateAuditManifest(ctx, tx, next, seq, head); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.records = next
	s.auditSequence = seq
	s.auditHead = head
	return nil
}

// Frozen canonical legacy layout: changing field order would break authenticated upgrades.
type legacyStoredPrincipal struct {
	UserID, Tenant, Principal string
	TokenHash                 []byte
	TokenExpiresAt            time.Time
	Version                   uint64
	Disabled                  bool
	Allowed                   []string
	Bindings                  []storedBinding
}

// canonicalState 是状态 MAC 的序列化输入，不是可自由调整的展示格式。
// 旧版本保留原字段布局；调用方负责先固定 records 的顺序。
func (s *sqliteStore) canonicalState(records []storedPrincipal, sequence uint64, head string) []byte {
	var encoded []byte
	if s.version < 4 {
		old := make([]legacyStoredPrincipal, 0, len(records))
		for _, r := range records {
			old = append(old, legacyStoredPrincipal{r.UserID, r.Tenant, r.Principal, r.TokenHash, r.TokenExpiresAt, r.Version, r.Disabled, r.Allowed, r.Bindings})
		}
		if s.version == 2 {
			encoded, _ = json.Marshal(struct {
				Version  int
				Topology []byte
				Records  []legacyStoredPrincipal
			}{2, s.topology, old})
		} else {
			encoded, _ = json.Marshal(struct {
				Version       int
				Topology      []byte
				Records       []legacyStoredPrincipal
				AuditSequence uint64
				AuditHead     string
				AuditIDKey    []byte
			}{3, s.topology, old, sequence, head, s.auditIDCipher})
		}
	} else {
		encoded, _ = json.Marshal(struct {
			Version           int
			Topology          []byte
			Records           []storedPrincipal
			AuditSequence     uint64
			AuditHead         string
			AuditIDKey        []byte
			AuditBaseSequence uint64
			AuditBaseHead     string
			AuditArchiveHash  string
		}{4, s.topology, records, sequence, head, s.auditIDCipher, s.auditBaseSequence, s.auditBaseHead, s.auditArchiveHash})
	}
	return encoded
}
func (s *sqliteStore) loadLegacyOrCurrentAudit(ctx context.Context, g *Gateway) error {
	if s.version == 2 {
		s.auditIDCipher = s.aead.Seal(nil, nil, g.auditIDKey, s.auditIDAAD())
		return nil
	}
	return s.loadAudit(ctx, g)
}
