package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sync"
	"time"
)

const (
	DefaultAuditCapacity = 4096
	MaxAuditCapacity     = 65536
	MaxAuditReadLimit    = 1000
)

var (
	ErrAuditInvalid   = errors.New("invalid audit metadata")
	ErrAuditFull      = errors.New("audit capacity exhausted")
	ErrAuditIntegrity = errors.New("audit integrity verification failed")
)

type AuditAction string
type AuditPhase string
type AuditResult string

// AuditActor describes the trusted invocation path, not a claimed human identity.
// Empty actor is equivalent to gateway for older helper callers.
type AuditActor string

const (
	AuditActorEntry             AuditActor  = "entry"
	AuditActorOperator          AuditActor  = "operator"
	AuditActorGateway           AuditActor  = "gateway"
	AuditActionDiscovery        AuditAction = "discovery"
	AuditActionCall             AuditAction = "call"
	AuditActionBindingReplace   AuditAction = "binding_replace"
	AuditActionBindingRevoke    AuditAction = "binding_revoke"
	AuditActionPolicyUpdate     AuditAction = "policy_update"
	AuditActionPrincipalDisable AuditAction = "principal_disable"
	AuditActionStorageArchive   AuditAction = "storage_archive"
	AuditActionStorageMigrate   AuditAction = "storage_migrate"
	AuditActionStorageRotate    AuditAction = "storage_rotate"
	AuditActionEntryRotate      AuditAction = "entry_rotate"
	AuditActionEntryRevoke      AuditAction = "entry_revoke"
	AuditPhaseAdmission         AuditPhase  = "admission"
	AuditPhaseStart             AuditPhase  = "start"
	AuditPhaseTerminal          AuditPhase  = "terminal"
	AuditPhaseCommit            AuditPhase  = "commit"
	AuditResultPending          AuditResult = "pending"
	AuditResultSuccess          AuditResult = "success"
	AuditResultDenied           AuditResult = "denied"
	AuditResultConflict         AuditResult = "conflict"
	AuditResultAuthentication   AuditResult = "authentication"
	AuditResultPermission       AuditResult = "permission"
	AuditResultRateLimit        AuditResult = "rate_limit"
	AuditResultService          AuditResult = "service"
	AuditResultTimeout          AuditResult = "timeout"
	AuditResultCanceled         AuditResult = "canceled"
	AuditResultTransport        AuditResult = "transport"
	AuditResultProtocol         AuditResult = "protocol"
	AuditResultSchemaRejected   AuditResult = "schema_rejected"
	AuditResultUnknown          AuditResult = "unknown"
	AuditResultStorage          AuditResult = "storage"
)

// AuditEvent contains only bounded metadata. IDs are keyed opaque digests of
// authoritative server identities, never client headers or JSON-RPC IDs. There
// is deliberately no generic detail, error, params, result, URL or header field.
// Sequence is assigned by storage. Times must be server-generated UTC values.
type AuditEvent struct {
	ArchivedUnfinished uint64      `json:"archived_unfinished,omitempty"`
	Actor              AuditActor  `json:"actor,omitempty"`
	OutcomeUnknown     bool        `json:"outcome_unknown,omitempty"`
	Sequence           uint64      `json:"sequence"`
	IdentityID         string      `json:"identity_id"`
	TenantID           string      `json:"tenant_id"`
	SystemID           string      `json:"system_id,omitempty"`
	ToolID             string      `json:"tool_id,omitempty"`
	ToolIsError        bool        `json:"tool_is_error,omitempty"`
	RequestID          string      `json:"request_id"`
	BindingVersion     uint64      `json:"binding_version"`
	PolicyVersion      uint64      `json:"policy_version"`
	Action             AuditAction `json:"action"`
	Phase              AuditPhase  `json:"phase"`
	Result             AuditResult `json:"result_class"`
	Time               time.Time   `json:"time"`
	DurationMillis     int64       `json:"duration_ms"`
}

func auditDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// AuditIdentifier uses domain separation to avoid cross-field correlation.
// Callers MUST supply server-owned values, not arbitrary request metadata.
// Unknown kinds and invalid keys return an empty ID, rejected by validation
// for mandatory fields. No raw value is returned, including on invalid input.
func AuditIdentifier(key []byte, kind, value string) string {
	if len(key) != 32 || value == "" {
		return ""
	}
	switch kind {
	case "identity", "tenant", "system", "request", "tool":
	default:
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("mcp-entry/audit-id/v1\x00" + kind + "\x00"))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func ValidateAuditEvent(e AuditEvent) error {
	if e.ArchivedUnfinished > math.MaxInt64 || (e.ArchivedUnfinished > 0 && (e.Action != AuditActionStorageArchive || e.Phase != AuditPhaseCommit || e.Result != AuditResultSuccess)) {
		return ErrAuditInvalid
	}
	switch e.Actor {
	case "", AuditActorEntry, AuditActorOperator, AuditActorGateway:
	default:
		return ErrAuditInvalid
	}
	if e.OutcomeUnknown && (e.Action != AuditActionCall || e.Phase != AuditPhaseTerminal || e.Result == AuditResultSuccess || e.Result == AuditResultPending) {
		return ErrAuditInvalid
	}
	if e.ToolID != "" && !auditDigest(e.ToolID) || e.ToolIsError && (e.Action != AuditActionCall || e.Phase != AuditPhaseTerminal || e.Result != AuditResultSuccess) {
		return ErrAuditInvalid
	}
	if !auditDigest(e.IdentityID) || !auditDigest(e.TenantID) || !auditDigest(e.RequestID) || e.SystemID != "" && !auditDigest(e.SystemID) {
		return ErrAuditInvalid
	}
	switch e.Action {
	case AuditActionDiscovery, AuditActionCall, AuditActionBindingReplace, AuditActionBindingRevoke:
		if e.SystemID == "" {
			return ErrAuditInvalid
		}
	case AuditActionStorageArchive, AuditActionStorageMigrate, AuditActionStorageRotate, AuditActionPolicyUpdate, AuditActionPrincipalDisable, AuditActionEntryRotate, AuditActionEntryRevoke:
	default:
		return ErrAuditInvalid
	}
	switch e.Phase {
	case AuditPhaseAdmission, AuditPhaseStart, AuditPhaseTerminal, AuditPhaseCommit:
	default:
		return ErrAuditInvalid
	}
	switch e.Result {
	case AuditResultPending, AuditResultSuccess, AuditResultDenied, AuditResultConflict, AuditResultAuthentication, AuditResultPermission, AuditResultRateLimit, AuditResultService, AuditResultTimeout, AuditResultCanceled, AuditResultTransport, AuditResultProtocol, AuditResultSchemaRejected, AuditResultUnknown, AuditResultStorage:
	default:
		return ErrAuditInvalid
	}
	if e.Phase == AuditPhaseStart && e.Result != AuditResultPending || (e.Phase == AuditPhaseTerminal || e.Phase == AuditPhaseCommit) && e.Result == AuditResultPending {
		return ErrAuditInvalid
	}
	_, offset := e.Time.Zone()
	if e.Time.IsZero() || e.Time.Year() < 2000 || e.Time.Year() > 9999 || offset != 0 || e.DurationMillis < 0 || e.DurationMillis > int64((365*24*time.Hour)/time.Millisecond) {
		return ErrAuditInvalid
	}
	return nil
}

// AuditMAC authenticates the full bounded record, its sequence, and its previous
// link. Persistent stores must authenticate the latest sequence/head separately
// with their state manifest to detect deleted suffixes. An HMAC chain alone
// cannot detect rollback of an entire database to an older authentic snapshot.
func AuditMAC(key []byte, previous string, e AuditEvent) (string, error) {
	if len(key) != 32 || previous != "" && !auditDigest(previous) {
		return "", ErrAuditInvalid
	}
	if err := ValidateAuditEvent(e); err != nil {
		return "", err
	}
	if e.Sequence == 0 {
		return "", ErrAuditInvalid
	}
	b, err := json.Marshal(e)
	if err != nil {
		return "", ErrAuditInvalid
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("mcp-entry/audit-event/v1\x00" + previous + "\x00"))
	mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func VerifyAuditMAC(key []byte, previous string, e AuditEvent, expected string) error {
	got, err := AuditMAC(key, previous, e)
	if err != nil || !auditDigest(expected) || !hmac.Equal([]byte(got), []byte(expected)) {
		return ErrAuditIntegrity
	}
	return nil
}

type AuditFilter struct {
	IdentityID string
	SystemID   string
	After      uint64
	Limit      int
}
type AuditPage struct {
	Events       []AuditEvent `json:"events"`
	Dropped      uint64       `json:"dropped"`
	LastSequence uint64       `json:"last_sequence"`
}

func ValidateAuditFilter(f AuditFilter) error {
	if f.IdentityID != "" && !auditDigest(f.IdentityID) || f.SystemID != "" && !auditDigest(f.SystemID) || f.Limit < 0 || f.Limit > MaxAuditReadLimit {
		return ErrAuditInvalid
	}
	return nil
}

// AuditRing is explicitly ephemeral recent-history retention, not durable audit
// storage. Once full it evicts exactly the oldest event and exposes the total
// eviction count on every read; callers must not present it as complete history.
// Persistent stores must instead reject writes at their configured capacity,
// atomically with associated state mutations; silently pruning mandatory durable
// events is not supported. Provision an operator-approved archive/reset flow
// before re-enabling work after a persistent store reaches its capacity.
type AuditRing struct {
	mu       sync.Mutex
	events   []AuditEvent
	capacity int
	next     int
	sequence uint64
	dropped  uint64
}

func NewAuditRing(capacity int) (*AuditRing, error) {
	if capacity < 1 || capacity > MaxAuditCapacity {
		return nil, ErrAuditInvalid
	}
	return &AuditRing{capacity: capacity, events: make([]AuditEvent, 0, capacity)}, nil
}
func (r *AuditRing) Append(e AuditEvent) error {
	if err := ValidateAuditEvent(e); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sequence == math.MaxUint64 {
		return ErrAuditFull
	}
	r.sequence++
	e.Sequence = r.sequence
	if len(r.events) < r.capacity {
		r.events = append(r.events, e)
	} else {
		r.events[r.next] = e
		r.next = (r.next + 1) % r.capacity
		r.dropped++
	}
	return nil
}
func (r *AuditRing) Read(f AuditFilter) (AuditPage, error) {
	if err := ValidateAuditFilter(f); err != nil {
		return AuditPage{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	limit := f.Limit
	if limit == 0 {
		limit = 100
	}
	p := AuditPage{Events: make([]AuditEvent, 0), Dropped: r.dropped, LastSequence: r.sequence}
	for i := 0; i < len(r.events); i++ {
		index := i
		if len(r.events) == r.capacity {
			index = (r.next + i) % r.capacity
		}
		e := r.events[index]
		if e.Sequence <= f.After || f.IdentityID != "" && f.IdentityID != e.IdentityID || f.SystemID != "" && f.SystemID != e.SystemID {
			continue
		}
		p.Events = append(p.Events, e)
		if len(p.Events) == limit {
			break
		}
	}
	return p, nil
}
