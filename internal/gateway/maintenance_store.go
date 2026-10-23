package gateway

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// migrateStorage upgrades only an already authenticated, exclusively owned
// legacy store. No policy, credential or audit state is imported from config.
func (g *Gateway) migrateStorage(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return ErrClosed
	}
	if !g.maintenance || g.store == nil {
		return ErrDenied
	}
	s := g.store
	if s.version == 4 {
		return nil
	}
	if s.version != 2 && s.version != 3 {
		return ErrStorageVersion
	}
	if !g.auditRoomLocked(1) {
		return ErrAuditFull
	}
	// 迁移只在候选状态上改版本和记录；数据库提交后才整体替换当前 store。
	candidate := *s
	candidate.version = 4
	candidate.records = make(map[string]storedPrincipal, len(s.records))
	for id, r := range s.records {
		r.EntryGeneration = 1
		r.EntryRevoked = false
		r.EntryStrong = false
		candidate.records[id] = r
	}
	if len(g.auditIDKey) != 32 {
		return ErrStorage
	}
	// v2 没有持久审计链；v3 已有的链和标识密钥必须继续沿用。
	if s.version == 2 {
		candidate.auditSequence, candidate.auditHead = 0, ""
		candidate.auditIDCipher = candidate.aead.Seal(nil, nil, g.auditIDKey, candidate.auditIDAAD())
	}
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return ErrStorage
	}
	committed := false
	defer func() {
		rollbackErr := tx.Rollback()
		if !g.closed && (!committed || rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone)) {
			g.auditFailureLocked()
		}
	}()
	statements := []string{
		"ALTER TABLE meta ADD COLUMN audit_base_sequence INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE meta ADD COLUMN audit_base_head TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE meta ADD COLUMN audit_archive_hash TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE principals ADD COLUMN entry_generation INTEGER NOT NULL DEFAULT 1",
		"ALTER TABLE principals ADD COLUMN entry_revoked INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE principals ADD COLUMN entry_strong INTEGER NOT NULL DEFAULT 0",
	}
	if s.version == 2 {
		statements = append(statements,
			"ALTER TABLE meta ADD COLUMN audit_sequence INTEGER NOT NULL DEFAULT 0",
			"ALTER TABLE meta ADD COLUMN audit_head TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE meta ADD COLUMN audit_id_key BLOB NOT NULL DEFAULT X''",
			"CREATE TABLE audit(sequence INTEGER PRIMARY KEY,event TEXT NOT NULL,mac TEXT NOT NULL)")
	}
	for _, statement := range statements {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return ErrStorage
		}
	}
	for _, r := range candidate.records {
		if err = writePrincipal(ctx, tx, r, false); err != nil {
			return ErrStorage
		}
	}
	event := g.maintenanceAuditEvent(AuditActionStorageMigrate)
	sequence, head, err := candidate.writeAudit(ctx, tx, event)
	if err != nil {
		return ErrStorage
	}
	candidate.auditSequence, candidate.auditHead = sequence, head
	event.Sequence = sequence
	check := candidate.aead.Seal(nil, nil, []byte("mcp-entry-state-v4"), candidate.topology)
	result, err := tx.ExecContext(ctx, "UPDATE meta SET version=4,key_check=?,state_mac=?,audit_sequence=?,audit_head=?,audit_id_key=? WHERE id=1", check, candidate.stateMAC(candidate.records), candidate.auditSequence, candidate.auditHead, candidate.auditIDCipher)
	if !maintenanceUpdatedOne(result, err) {
		return ErrStorage
	}
	if err = tx.Commit(); err != nil {
		// A failed commit may have reached disk. Never keep serving the old view.
		g.auditFailureLocked()
		return ErrStorage
	}
	committed = true
	*s = candidate
	if err := g.auditRing.Append(event); err != nil {
		g.auditFailureLocked()
		return ErrStorage
	}
	return nil
}

// RotateKey replaces the external root key for an offline maintenance store.
// The caller must retain both externally supplied keys until reopening succeeds:
// a commit error has an uncertain outcome. Neither key is persisted in plaintext.
// Historical audit identifiers are deliberately stable across root rotation.
func (g *Gateway) RotateKey(newKey []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return ErrClosed
	}
	if !g.maintenance || g.store == nil {
		return ErrDenied
	}
	if len(newKey) != 32 || g.store.version != 4 || len(g.auditIDKey) != 32 {
		return ErrStorage
	}
	s := g.store
	if !g.auditRoomLocked(1) {
		return ErrAuditFull
	}
	candidate := *s
	credentialKey, err := derivedKey(newKey, "credentials")
	if err != nil {
		return ErrStorage
	}
	block, err := aes.NewCipher(credentialKey)
	if err != nil {
		return ErrStorage
	}
	candidate.aead, err = cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return ErrStorage
	}
	candidate.macKey, err = derivedKey(newKey, "metadata")
	if err != nil {
		return ErrStorage
	}
	if hmac.Equal(candidate.macKey, s.macKey) {
		return ErrDenied
	}
	candidate.auditKey, err = derivedKey(newKey, "audit-chain")
	if err != nil {
		return ErrStorage
	}
	candidate.auditIDCipher = candidate.aead.Seal(nil, nil, g.auditIDKey, candidate.auditIDAAD())
	candidate.records = make(map[string]storedPrincipal, len(s.records))
	// 复制绑定切片后再重加密，避免候选状态的写入污染仍使用旧密钥的记录。
	for id, r := range s.records {
		r.Bindings = append([]storedBinding(nil), r.Bindings...)
		for i := range r.Bindings {
			b := &r.Bindings[i]
			p := &principalState{identity: Identity{r.Tenant, r.Principal}}
			binding := &bindingRecord{info: BindingInfo{ID: b.ID, Tenant: r.Tenant, Principal: r.Principal, System: b.System, Generation: b.Generation, State: b.State, ExpiresAt: b.ExpiresAt}}
			aad := bindingAAD(id, p, binding)
			secret, err := s.aead.Open(nil, nil, b.Credential, aad)
			if err != nil {
				return ErrStorage
			}
			b.Credential = candidate.aead.Seal(nil, nil, secret, aad)
			clear(secret)
		}
		candidate.records[id] = r
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return ErrStorage
	}
	committed := false
	defer func() {
		rollbackErr := tx.Rollback()
		if !g.closed && (!committed || rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone)) {
			g.auditFailureLocked()
		}
	}()
	// Verify the old chain again while deriving its replacement; retain exact event
	// bytes and sequence values, including unfinished operations and all outcomes.
	rows, err := tx.QueryContext(ctx, "SELECT sequence,event,mac FROM audit ORDER BY sequence")
	if err != nil {
		return ErrStorage
	}
	type rewrittenAudit struct {
		sequence uint64
		mac      string
	}
	rewritten := make([]rewrittenAudit, 0)
	// 已归档前缀不重写；从保留的归档锚点开始，用旧密钥验链、用新密钥续链。
	previous, next := s.auditBaseHead, s.auditBaseHead
	count := s.auditBaseSequence
	for rows.Next() {
		var sequence int64
		var raw, mac string
		if err = rows.Scan(&sequence, &raw, &mac); err != nil {
			rows.Close()
			return ErrStorage
		}
		count++
		var event AuditEvent
		if sequence != int64(count) || count > s.auditSequence || len(raw) > 2048 || json.Unmarshal([]byte(raw), &event) != nil || event.Sequence != count || VerifyAuditMAC(s.auditKey, previous, event, mac) != nil {
			rows.Close()
			return ErrStorage
		}
		canonical, err := json.Marshal(event)
		if err != nil || !bytes.Equal(canonical, []byte(raw)) {
			rows.Close()
			return ErrStorage
		}
		previous = mac
		next, err = AuditMAC(candidate.auditKey, next, event)
		if err != nil {
			rows.Close()
			return ErrStorage
		}
		rewritten = append(rewritten, rewrittenAudit{count, next})
	}
	err = rows.Err()
	rows.Close()
	if err != nil || count != s.auditSequence || previous != s.auditHead {
		return ErrStorage
	}
	candidate.auditHead = next
	for _, row := range rewritten {
		result, err := tx.ExecContext(ctx, "UPDATE audit SET mac=? WHERE sequence=?", row.mac, row.sequence)
		if !maintenanceUpdatedOne(result, err) {
			return ErrStorage
		}
	}
	for _, r := range candidate.records {
		if err = writePrincipal(ctx, tx, r, false); err != nil {
			return ErrStorage
		}
	}
	event := g.maintenanceAuditEvent(AuditActionStorageRotate)
	sequence, head, err := candidate.writeAudit(ctx, tx, event)
	if err != nil {
		return ErrStorage
	}
	candidate.auditSequence, candidate.auditHead = sequence, head
	event.Sequence = sequence
	check := candidate.aead.Seal(nil, nil, []byte("mcp-entry-state-v4"), candidate.topology)
	result, err := tx.ExecContext(ctx, "UPDATE meta SET key_check=?,state_mac=?,audit_sequence=?,audit_head=?,audit_id_key=? WHERE id=1 AND version=4", check, candidate.stateMAC(candidate.records), candidate.auditSequence, candidate.auditHead, candidate.auditIDCipher)
	if !maintenanceUpdatedOne(result, err) {
		return ErrStorage
	}
	if err = tx.Commit(); err != nil {
		g.auditFailureLocked()
		return ErrStorage
	}
	committed = true
	*s = candidate
	if err := g.auditRing.Append(event); err != nil {
		g.auditFailureLocked()
		return ErrStorage
	}
	return nil
}

// maintenanceUpdatedOne 将未命中或异常影响行数也视为失败，避免把缺失元数据
// 或缺失审计行误当作成功的迁移/轮换。
func maintenanceUpdatedOne(result sql.Result, err error) bool {
	if err != nil || result == nil {
		return false
	}
	n, err := result.RowsAffected()
	return err == nil && n == 1
}

// The reserved storage scope is not a tenant or principal identity. Global
// operator export can show these events without attributing them to a user.
func (g *Gateway) maintenanceAuditEvent(action AuditAction) AuditEvent {
	return AuditEvent{Actor: AuditActorOperator, IdentityID: AuditIdentifier(g.auditIDKey, "identity", "mcp-entry/storage-maintenance"), TenantID: AuditIdentifier(g.auditIDKey, "tenant", "mcp-entry/storage-maintenance"), RequestID: AuditIdentifier(g.auditIDKey, "request", rand.Text()), Action: action, Phase: AuditPhaseCommit, Result: AuditResultSuccess, Time: time.Now().UTC()}
}
