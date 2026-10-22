package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func testAuditEvent() AuditEvent {
	key := bytes.Repeat([]byte{7}, 32)
	return AuditEvent{IdentityID: AuditIdentifier(key, "identity", "server-principal"), TenantID: AuditIdentifier(key, "tenant", "server-tenant"), SystemID: AuditIdentifier(key, "system", "server-system"), RequestID: AuditIdentifier(key, "request", "server-generated-request"), BindingVersion: 1, PolicyVersion: 1, Action: AuditActionCall, Phase: AuditPhaseStart, Result: AuditResultPending, Time: time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)}
}
func TestAuditMetadataRejectsArbitraryText(t *testing.T) {
	secrets := []string{"CANARY-secret-token", "https://private.example/token", "Authorization: Bearer canary", strings.Repeat("a", 65537), "bad\nheader", "", strings.Repeat("A", 64), strings.Repeat("f", 63)}
	for _, secret := range secrets {
		setters := []func(*AuditEvent){func(e *AuditEvent) { e.IdentityID = secret }, func(e *AuditEvent) { e.TenantID = secret }, func(e *AuditEvent) { e.SystemID = secret }, func(e *AuditEvent) { e.RequestID = secret }, func(e *AuditEvent) { e.Action = AuditAction(secret) }, func(e *AuditEvent) { e.Phase = AuditPhase(secret) }, func(e *AuditEvent) { e.Result = AuditResult(secret) }}
		for i, set := range setters {
			e := testAuditEvent()
			set(&e)
			if err := ValidateAuditEvent(e); !errors.Is(err, ErrAuditInvalid) {
				t.Fatalf("field %d accepted invalid metadata", i)
			}
		}
	}
}
func TestAuditIdentifierDoesNotRetainSource(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	canary := "CANARY-private-token-header-url"
	e := testAuditEvent()
	e.IdentityID = AuditIdentifier(key, "identity", canary)
	e.TenantID = AuditIdentifier(key, "tenant", canary)
	if e.IdentityID == e.TenantID || !auditDigest(e.IdentityID) {
		t.Fatal("missing domain separation")
	}
	b, _ := json.Marshal(e)
	if bytes.Contains(b, []byte(canary)) {
		t.Fatal("raw source retained")
	}
	if AuditIdentifier(key, "error", canary) != "" || AuditIdentifier(nil, "identity", canary) != "" {
		t.Fatal("unknown domain or key accepted")
	}
	if AuditIdentifier(key, "identity", canary) != e.IdentityID {
		t.Fatal("identifier unstable")
	}
}
func TestAuditMetadataBoundsAndEnums(t *testing.T) {
	mutations := []func(*AuditEvent){
		func(e *AuditEvent) { e.Time = time.Time{} },
		func(e *AuditEvent) { e.Time = e.Time.In(time.FixedZone("non-UTC", 3600)) },
		func(e *AuditEvent) { e.Time = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		func(e *AuditEvent) { e.DurationMillis = -1 },
		func(e *AuditEvent) { e.DurationMillis = int64(366 * 24 * time.Hour / time.Millisecond) },
		func(e *AuditEvent) { e.Result = AuditResultSuccess },
		func(e *AuditEvent) { e.Phase = AuditPhaseTerminal },
		func(e *AuditEvent) { e.Phase = AuditPhaseCommit },
	}
	for i, mutate := range mutations {
		e := testAuditEvent()
		mutate(&e)
		if ValidateAuditEvent(e) == nil {
			t.Fatalf("invalid variant %d accepted", i)
		}
	}
	for _, action := range []AuditAction{AuditActionDiscovery, AuditActionCall, AuditActionBindingReplace, AuditActionBindingRevoke, AuditActionPolicyUpdate, AuditActionPrincipalDisable, AuditActionEntryRotate, AuditActionEntryRevoke} {
		e := testAuditEvent()
		e.Action = action
		if err := ValidateAuditEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	for _, result := range []AuditResult{AuditResultSuccess, AuditResultDenied, AuditResultConflict, AuditResultAuthentication, AuditResultPermission, AuditResultRateLimit, AuditResultService, AuditResultTimeout, AuditResultCanceled, AuditResultTransport, AuditResultProtocol, AuditResultUnknown, AuditResultStorage} {
		e := testAuditEvent()
		e.Phase = AuditPhaseTerminal
		e.Result = result
		if err := ValidateAuditEvent(e); err != nil {
			t.Fatal(err)
		}
	}
}
func TestAuditRingRetentionAndSequence(t *testing.T) {
	ring, err := NewAuditRing(3)
	if err != nil {
		t.Fatal(err)
	}
	e := testAuditEvent()
	for i := 0; i < 8; i++ {
		e.Sequence = 999
		if err := ring.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	p, err := ring.Read(AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Dropped != 5 || p.LastSequence != 8 || len(p.Events) != 3 {
		t.Fatalf("bad retention metadata: %+v", p)
	}
	for i, event := range p.Events {
		if event.Sequence != uint64(i+6) {
			t.Fatal("out of order")
		}
	}
	p.Events[0].IdentityID = "mutable"
	p, _ = ring.Read(AuditFilter{After: 6, Limit: 1})
	if len(p.Events) != 1 || p.Events[0].Sequence != 7 {
		t.Fatal("pagination failed")
	}
	p, _ = ring.Read(AuditFilter{IdentityID: strings.Repeat("0", 64)})
	if len(p.Events) != 0 || p.Dropped != 5 {
		t.Fatal("filter or retention disclosure failed")
	}
	e.RequestID = "SECRET"
	if ring.Append(e) == nil {
		t.Fatal("invalid record accepted")
	}
	p, _ = ring.Read(AuditFilter{})
	if p.LastSequence != 8 || p.Dropped != 5 {
		t.Fatal("invalid append changed state")
	}
}
func TestAuditRingBounds(t *testing.T) {
	for _, n := range []int{-1, 0, MaxAuditCapacity + 1} {
		if _, err := NewAuditRing(n); err == nil {
			t.Fatal("invalid capacity accepted")
		}
	}
	for _, f := range []AuditFilter{{Limit: -1}, {Limit: MaxAuditReadLimit + 1}, {IdentityID: "secret"}, {SystemID: "url"}} {
		if ValidateAuditFilter(f) == nil {
			t.Fatal("invalid filter accepted")
		}
	}
	ring, _ := NewAuditRing(1)
	ring.sequence = ^uint64(0)
	if !errors.Is(ring.Append(testAuditEvent()), ErrAuditFull) {
		t.Fatal("sequence overflow allowed")
	}
}
func TestAuditRingConcurrentBounded(t *testing.T) {
	ring, _ := NewAuditRing(7)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			for j := 0; j < 10; j++ {
				if err := ring.Append(testAuditEvent()); err != nil {
					t.Error(err)
				}
				if _, err := ring.Read(AuditFilter{}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	p, _ := ring.Read(AuditFilter{})
	if len(p.Events) != 7 || p.LastSequence != 200 || p.Dropped != 193 {
		t.Fatal("concurrent retention mismatch")
	}
}
func TestAuditIntegrityChain(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	e := testAuditEvent()
	e.Sequence = 1
	first, err := AuditMAC(key, "", e)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuditMAC(key, "", e, first); err != nil {
		t.Fatal(err)
	}
	e.Sequence = 2
	e.Phase = AuditPhaseTerminal
	e.Result = AuditResultSuccess
	second, err := AuditMAC(key, first, e)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuditMAC(key, first, e, second); err != nil {
		t.Fatal(err)
	}
	e.Result = AuditResultUnknown
	if !errors.Is(VerifyAuditMAC(key, first, e, second), ErrAuditIntegrity) {
		t.Fatal("mutation not detected")
	}
	e.Result = AuditResultSuccess
	if VerifyAuditMAC(key, "", e, second) == nil {
		t.Fatal("deleted prefix not detected")
	}
	e.Sequence = 1
	if VerifyAuditMAC(key, first, e, second) == nil {
		t.Fatal("reordering not detected")
	}
	if _, err := AuditMAC(key, "SECRET", e); err == nil {
		t.Fatal("raw previous link accepted")
	}
	if _, err := AuditMAC(nil, "", e); err == nil {
		t.Fatal("invalid key accepted")
	}
}

func TestAuditToolMetadata(t *testing.T) {
	e := testAuditEvent()
	e.ToolID = "CANARY-token"
	if ValidateAuditEvent(e) == nil {
		t.Fatal("raw tool ID accepted")
	}
	e.ToolID = AuditIdentifier(bytes.Repeat([]byte{7}, 32), "tool", "server-tool")
	if !auditDigest(e.ToolID) {
		t.Fatal("tool domain unavailable")
	}
	e.ToolIsError = true
	if ValidateAuditEvent(e) == nil {
		t.Fatal("unconfirmed tool result accepted")
	}
	e.Phase = AuditPhaseTerminal
	e.Result = AuditResultSuccess
	if err := ValidateAuditEvent(e); err != nil {
		t.Fatal(err)
	}
}

func TestAuditEncodedRecordSizeBound(t *testing.T) {
	e := testAuditEvent()
	e.Sequence = ^uint64(0)
	e.BindingVersion = ^uint64(0)
	e.PolicyVersion = ^uint64(0)
	e.ToolID = strings.Repeat("f", 64)
	e.Action = AuditActionPrincipalDisable
	e.Phase = AuditPhaseTerminal
	e.Result = AuditResultAuthentication
	e.Time = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	e.DurationMillis = int64(365 * 24 * time.Hour / time.Millisecond)
	if err := ValidateAuditEvent(e); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 1024 {
		t.Fatalf("record exceeds fixed storage budget: %d", len(encoded))
	}
}

func TestAuditActorAndOutcomeUncertainty(t *testing.T) {
	for _, actor := range []AuditActor{"", AuditActorEntry, AuditActorOperator, AuditActorGateway} {
		e := testAuditEvent()
		e.Actor = actor
		if err := ValidateAuditEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	for _, actor := range []AuditActor{"CANARY-secret", "admin", AuditActor(strings.Repeat("a", 1000))} {
		e := testAuditEvent()
		e.Actor = actor
		if ValidateAuditEvent(e) == nil {
			t.Fatal("untrusted actor accepted")
		}
	}
	e := testAuditEvent()
	e.OutcomeUnknown = true
	if ValidateAuditEvent(e) == nil {
		t.Fatal("start uncertainty accepted")
	}
	e.Phase = AuditPhaseTerminal
	e.Result = AuditResultSuccess
	if ValidateAuditEvent(e) == nil {
		t.Fatal("confirmed success uncertainty accepted")
	}
	e.Result = AuditResultTransport
	if err := ValidateAuditEvent(e); err != nil {
		t.Fatal(err)
	}
	e.Action = AuditActionDiscovery
	if ValidateAuditEvent(e) == nil {
		t.Fatal("discovery uncertainty accepted")
	}
	e.Action = AuditActionCall
	e.Phase = AuditPhaseCommit
	if ValidateAuditEvent(e) == nil {
		t.Fatal("commit uncertainty accepted")
	}
}
