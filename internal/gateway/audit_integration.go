package gateway

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// AuditConfig bounds metadata retention. Persistent journals never prune silently.
type AuditConfig struct {
	Capacity int `json:"capacity,omitempty"`
}

// AuditStatus 区分运行中预留终态槽的 Pending 与缺少终态记录的 Unfinished。
// 后者包含历史崩溃遗留及已归档的未知结果，不等于当前并发操作数。
type AuditStatus struct {
	ArchivedUnfinished uint64 `json:"archived_unfinished"`
	Persistent         bool   `json:"persistent"`
	Healthy            bool   `json:"healthy"`
	Closed             bool   `json:"closed"`
	Pending            uint64 `json:"pending"`
	Unfinished         uint64 `json:"unfinished"`
	LastSequence       uint64 `json:"last_sequence"`
	Dropped            uint64 `json:"dropped"`
	Capacity           int    `json:"capacity"`
}

// AuditStatus 读取可信进程内状态快照；Healthy 仅表示未标记审计故障，
// 不表示下游健康，也不证明历史业务操作均已成功。
func (g *Gateway) AuditStatus() AuditStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	page, _ := g.auditRing.Read(AuditFilter{Limit: 1})
	return AuditStatus{ArchivedUnfinished: g.auditArchivedUnfinished, Persistent: g.store != nil, Healthy: !g.auditFault, Closed: g.closed, Pending: g.auditPending, Unfinished: g.auditArchivedUnfinished + uint64(len(g.auditUnfinished)), LastSequence: page.LastSequence, Dropped: page.Dropped, Capacity: g.auditCapacity}
}

// Audit is a trusted operator API, not an authenticated HTTP audit endpoint.
func (g *Gateway) Audit(identity Identity, after uint64, limit int) (AuditPage, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.auditFault {
		return AuditPage{}, ErrStorage
	}
	if _, ok := g.identities[identity]; !ok {
		return AuditPage{}, ErrDenied
	}
	encoded, _ := json.Marshal(identity)
	return g.auditRing.Read(AuditFilter{IdentityID: AuditIdentifier(g.auditIDKey, "identity", string(encoded)), After: after, Limit: limit})
}
func (g *Gateway) initializeAudit(cfg AuditConfig) error {
	if cfg.Capacity == 0 {
		cfg.Capacity = DefaultAuditCapacity
	}
	ring, err := NewAuditRing(cfg.Capacity)
	if err != nil {
		return err
	}
	g.auditCapacity = cfg.Capacity
	g.auditRing = ring
	g.auditUnfinished = make(map[string]bool)
	g.auditIDKey = make([]byte, 32)
	_, err = rand.Read(g.auditIDKey)
	return err
}
func (g *Gateway) auditEventLocked(id, system, tool string, p *principalState, action AuditAction, phase AuditPhase, result AuditResult, actor AuditActor) AuditEvent {
	identity, _ := json.Marshal(p.identity)
	e := AuditEvent{IdentityID: AuditIdentifier(g.auditIDKey, "identity", string(identity)), TenantID: AuditIdentifier(g.auditIDKey, "tenant", p.identity.Tenant), SystemID: AuditIdentifier(g.auditIDKey, "system", system), RequestID: AuditIdentifier(g.auditIDKey, "request", rand.Text()), PolicyVersion: p.version, Action: action, Phase: phase, Result: result, Actor: actor, Time: time.Now().UTC()}
	if b := p.bindings[system]; b != nil {
		e.BindingVersion = b.info.Generation
	}
	if tool != "" {
		e.ToolID = AuditIdentifier(g.auditIDKey, "tool", system+"\x00"+tool)
	}
	return e
}

// auditRoomLocked 要求持有 g.mu；持久容量同时计入已有日志和已预留的终态槽。
// 内存模式允许日志环淘汰，因而不在这里拒绝新增事件。
func (g *Gateway) auditRoomLocked(extra uint64) bool {
	return g.store == nil || g.store.auditSequence-g.store.auditBaseSequence+g.auditPending+extra <= uint64(g.auditCapacity)
}
func (g *Gateway) auditFailureLocked() { g.auditFault = true; g.closeLocked() }

// appendAuditLocked 有存储时先提交事件和认证链头，再更新内存观察视图。
// 任一步失败均封闭网关，避免在审计状态不确定时继续接纳业务操作。
func (g *Gateway) appendAuditLocked(e AuditEvent) error {
	if g.auditFault {
		return ErrStorage
	}
	if g.store != nil {
		if err := g.store.appendAudit(g, e); err != nil {
			g.auditFailureLocked()
			return ErrStorage
		}
	}
	if err := g.auditRing.Append(e); err != nil {
		g.auditFailureLocked()
		return ErrStorage
	}
	g.trackAuditLocked(e)
	return nil
}
func (g *Gateway) trackAuditLocked(e AuditEvent) {
	if e.Action == AuditActionStorageArchive {
		g.auditArchivedUnfinished = e.ArchivedUnfinished
	}
	if e.Phase == AuditPhaseStart {
		g.auditUnfinished[e.RequestID] = true
	}
	if e.Phase == AuditPhaseTerminal {
		delete(g.auditUnfinished, e.RequestID)
	}
}

// startAuditLocked 在操作开始前一次检查开始/终态两条记录的容量；
// 成功写入开始事件后保留一个终态槽，结束时再释放该预留。
func (g *Gateway) startAuditLocked(id, system, tool string, action AuditAction) (AuditEvent, error) {
	if !g.auditRoomLocked(2) {
		return AuditEvent{}, ErrAuditFull
	}
	e := g.auditEventLocked(id, system, tool, g.principals[id], action, AuditPhaseStart, AuditResultPending, AuditActorGateway)
	if err := g.appendAuditLocked(e); err != nil {
		return AuditEvent{}, err
	}
	g.auditPending++
	return e, nil
}
func auditOutcome(err error) AuditResult {
	if err == nil {
		return AuditResultSuccess
	}
	var failure *DownstreamFailure
	if errors.As(err, &failure) {
		switch failure.Code {
		case FailureAuthentication:
			return AuditResultAuthentication
		case FailurePermission:
			return AuditResultPermission
		case FailureRateLimit:
			return AuditResultRateLimit
		case FailureService:
			return AuditResultService
		case FailureTimeout:
			return AuditResultTimeout
		case FailureCanceled:
			return AuditResultCanceled
		case FailureSchemaAdmission:
			return AuditResultSchemaRejected
		case FailureProtocol:
			return AuditResultProtocol
		default:
			return AuditResultTransport
		}
	}
	if errors.Is(err, context.Canceled) {
		return AuditResultCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return AuditResultTimeout
	}
	if errors.Is(err, ErrDenied) {
		return AuditResultDenied
	}
	return AuditResultUnknown
}

// finishOperation 在下游清理返回后结算终态。defer 的顺序保证先解开 g.mu，
// 再释放准入并发槽，最后通知 Close 的等待者；取消信号本身不提前归还容量。
func (g *Gateway) finishOperation(opID uint64, e AuditEvent, started time.Time, operationErr error, toolIsError bool, permit *admissionPermit) {
	defer g.operationWG.Done()
	defer permit.Release()
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.operations, opID)
	if g.auditPending > 0 {
		g.auditPending--
	}
	if g.auditFault {
		return
	}
	e.Phase = AuditPhaseTerminal
	e.Result = auditOutcome(operationErr)
	e.Time = time.Now().UTC()
	e.DurationMillis = time.Since(started).Milliseconds()
	e.ToolIsError = operationErr == nil && toolIsError
	var failure *DownstreamFailure
	e.OutcomeUnknown = errors.As(operationErr, &failure) && failure.OutcomeUnknown
	_ = g.appendAuditLocked(e) // A confirmed tool result is never replaced by audit failure.
}
func (g *Gateway) auditContext() (context.Context, context.CancelFunc) {
	parent := context.Background()
	if g.closingContext != nil {
		parent = g.closingContext
	}
	return context.WithTimeout(parent, time.Second)
}

// writeAudit 只在调用方事务内追加一条记录，不修改 store 的内存链头。
// 调用方须在同一事务更新认证清单，并在提交成功后发布新序号与链头。
func (s *sqliteStore) writeAudit(ctx context.Context, tx *sql.Tx, e AuditEvent) (uint64, string, error) {
	sequence := s.auditSequence + 1
	e.Sequence = sequence
	mac, err := AuditMAC(s.auditKey, s.auditHead, e)
	if err != nil {
		return 0, "", err
	}
	raw, err := json.Marshal(e)
	if err != nil || len(raw) > 2048 {
		return 0, "", ErrAuditInvalid
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit(sequence,event,mac) VALUES(?,?,?)", sequence, string(raw), mac); err != nil {
		return 0, "", err
	}
	return sequence, mac, nil
}
func (s *sqliteStore) appendAudit(g *Gateway, e AuditEvent) error {
	ctx, cancel := g.auditContext()
	defer cancel()
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	sequence, head, err := s.writeAudit(ctx, tx, e)
	if err != nil {
		return err
	}
	if err = s.updateAuditManifest(ctx, tx, s.records, sequence, head); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.auditSequence, s.auditHead = sequence, head
	return nil
}
func (s *sqliteStore) updateAuditManifest(ctx context.Context, tx *sql.Tx, records map[string]storedPrincipal, sequence uint64, head string) error {
	result, err := tx.ExecContext(ctx, "UPDATE meta SET state_mac=?,audit_sequence=?,audit_head=?,audit_base_sequence=?,audit_base_head=?,audit_archive_hash=? WHERE id=1", s.stateMACAt(records, sequence, head), sequence, head, s.auditBaseSequence, s.auditBaseHead, s.auditArchiveHash)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrStorage
	}
	return nil
}

// loadAudit 从归档锚点恢复保留的日志，检查连续序号、每条 MAC 和最终链头。
// 整体状态 MAC 仍由外层 load 校验；重建未完成集合不重试任何历史业务操作。
func (s *sqliteStore) loadAudit(ctx context.Context, g *Gateway) error {
	if s.version >= 4 {
		if err := s.conn.QueryRowContext(ctx, "SELECT audit_base_sequence,audit_base_head,audit_archive_hash FROM meta WHERE id=1").Scan(&s.auditBaseSequence, &s.auditBaseHead, &s.auditArchiveHash); err != nil {
			return ErrStorage
		}
		if s.auditBaseSequence == 0 {
			if s.auditBaseHead != "" || s.auditArchiveHash != "" {
				return ErrStorage
			}
		} else if !auditDigest(s.auditBaseHead) || !auditDigest(s.auditArchiveHash) {
			return ErrStorage
		}
	}
	g.auditRing.sequence = s.auditBaseSequence
	g.auditRing.dropped = s.auditBaseSequence
	var sequence int64
	if err := s.conn.QueryRowContext(ctx, "SELECT audit_sequence,audit_head,audit_id_key FROM meta WHERE id=1").Scan(&sequence, &s.auditHead, &s.auditIDCipher); err != nil || sequence < 0 || uint64(sequence) < s.auditBaseSequence || uint64(sequence)-s.auditBaseSequence > uint64(g.auditCapacity) || len(s.auditIDCipher) > 128 {
		return ErrStorage
	}
	s.auditSequence = uint64(sequence)
	key, err := s.aead.Open(nil, nil, s.auditIDCipher, s.auditIDAAD())
	if err != nil || len(key) != 32 {
		return ErrStorage
	}
	g.auditIDKey = key
	rows, err := s.conn.QueryContext(ctx, "SELECT sequence,event,mac FROM audit ORDER BY sequence")
	if err != nil {
		return err
	}
	defer rows.Close()
	previous := s.auditBaseHead
	count := s.auditBaseSequence
	for rows.Next() {
		var row int64
		var raw, mac string
		if err := rows.Scan(&row, &raw, &mac); err != nil {
			return err
		}
		count++
		if row != int64(count) || count > s.auditSequence || len(raw) > 2048 {
			return ErrStorage
		}
		var event AuditEvent
		if err := json.Unmarshal([]byte(raw), &event); err != nil || event.Sequence != count || VerifyAuditMAC(s.auditKey, previous, event, mac) != nil {
			return ErrStorage
		}
		canonical, _ := json.Marshal(event)
		if string(canonical) != raw {
			return ErrStorage
		}
		if err := g.auditRing.Append(event); err != nil {
			return ErrStorage
		}
		g.trackAuditLocked(event)
		previous = mac
	}
	if rows.Err() != nil || count != s.auditSequence || previous != s.auditHead {
		return ErrStorage
	}
	return nil
}
func (s *sqliteStore) auditIDAAD() []byte {
	return append([]byte("mcp-entry/audit-id-key/v3\x00"), s.topology...)
}

// AuditAll is an offline owner API, including global storage-maintenance events.
func (g *Gateway) AuditAll(after uint64, limit int) (AuditPage, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.maintenance {
		return AuditPage{}, ErrDenied
	}
	if g.auditFault {
		return AuditPage{}, ErrStorage
	}
	return g.auditRing.Read(AuditFilter{After: after, Limit: limit})
}
