package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestSchemaAdmissionRegexpPositions(t *testing.T) {
	for _, expression := range []string{`^(?!CANARY)[a-z]+$`, `(?=CANARY)`, `(?<=CANARY)x`, `(CANARY)\1`, `CANARY{1001}`, `[CANARY`} {
		for _, keyword := range []string{"pattern", "patternProperties"} {
			t.Run(keyword+expression, func(t *testing.T) {
				var schema map[string]any
				if keyword == "pattern" {
					schema = map[string]any{"type": "object", "properties": map[string]any{"CANARY-path": map[string]any{"type": "string", "pattern": expression}}}
				} else {
					schema = map[string]any{"type": "object", "patternProperties": map[string]any{expression: map[string]any{"type": "string"}}}
				}
				_, err := analyzeSchema(schema)
				var admission *schemaAdmissionError
				if !errors.As(err, &admission) || admission.reason != SchemaRegexpInvalidOrUnsupported {
					t.Fatalf("missing regexp evidence: %v", err)
				}
				if strings.Contains(err.Error(), "CANARY") {
					t.Fatal("schema detail leaked")
				}
			})
		}
	}
	for _, keyword := range []string{"examples", "default", "const", "enum", "x-extension"} {
		data := map[string]any{"pattern": "(?=CANARY)", "patternProperties": map[string]any{"(?=CANARY)": false}}
		var value any = data
		if keyword == "examples" || keyword == "enum" {
			value = []any{data}
		}
		if _, err := analyzeSchema(map[string]any{"type": "object", keyword: value}); err != nil {
			t.Fatalf("interpreted %s data: %v", keyword, err)
		}
	}
	// A property named pattern is a schema position, not an expression itself.
	if _, err := analyzeSchema(map[string]any{"properties": map[string]any{"pattern": map[string]any{"type": "string"}}}); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaAdmissionValidRegexpConstraintsRemain(t *testing.T) {
	for _, raw := range []string{
		`{"type":"object","properties":{"value":{"type":"string","pattern":"^[a-z]{1,4}$"}},"required":["value"]}`,
		`{"type":"object","patternProperties":{"^value$":{"type":"string","pattern":"^[a-z]{1,4}$"}},"additionalProperties":false}`,
	} {
		schema, err := resolveSchema(policyJSON(t, raw), true)
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(map[string]any{"value": "abc"}); err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(map[string]any{"value": "12345"}); err == nil {
			t.Fatal("regexp constraint dropped")
		}
	}
}

func TestSchemaAdmissionFailureEvidenceAndPrecedence(t *testing.T) {
	admission := &schemaAdmissionError{reason: SchemaRegexpInvalidOrUnsupported}
	ctx, o := withFailureObservation(context.Background())
	o.setPhase(FailureDiscovery)
	observeSchemaAdmission(ctx, admission)
	f := classifyDownstreamFailure(ctx, FailureDiscovery, errors.New("SDK stringified local error"), false)
	if f.Code != FailureSchemaAdmission || f.SchemaReason != admission.reason || f.HTTPStatus != 0 || f.OutcomeUnknown {
		t.Fatalf("lost local evidence: %+v", f)
	}
	if auditOutcome(f) != AuditResultSchemaRejected {
		t.Fatal("missing audit mapping")
	}
	e := testAuditEvent()
	e.Phase = AuditPhaseTerminal
	e.Result = auditOutcome(f)
	if err := ValidateAuditEvent(e); err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{401, 403, 429, 503} {
		o.setPhase(FailureDiscovery)
		observeSchemaAdmission(ctx, admission)
		o.record(o.epoch, failureEvidence{code: statusFailure(status), status: status})
		f = classifyDownstreamFailure(ctx, FailureDiscovery, admission, false)
		if f.Code != statusFailure(status) || f.HTTPStatus != status || f.SchemaReason != "" {
			t.Fatalf("schema overrode HTTP evidence: %+v", f)
		}
		data, _ := json.Marshal(f)
		if strings.Contains(string(data), "schema_reason") {
			t.Fatal("schema evidence leaked to transport result")
		}
	}
	o.setPhase(FailureDiscovery)
	observeSchemaAdmission(ctx, admission)
	if f := classifyDownstreamFailure(ctx, FailureDiscovery, io.ErrUnexpectedEOF, false); f.Code != FailureTransport || f.SchemaReason != "" {
		t.Fatalf("schema overrode typed transport: %+v", f)
	}
	o.setPhase(FailureDiscovery)
	if f := classifyDownstreamFailure(ctx, FailureDiscovery, errors.New(admission.Error()), false); f.Code != FailureProtocol {
		t.Fatal("parsed error string or retained old local evidence")
	}
	if f := classifyDownstreamFailure(context.Background(), FailureDiscovery, fmt.Errorf("wrapped: %w", admission), false); f.Code != FailureSchemaAdmission {
		t.Fatal("lost wrapped typed evidence")
	}
	if f := classifyDownstreamFailure(context.Background(), FailureCall, admission, true); f.Code != FailureProtocol || f.SchemaReason != "" {
		t.Fatal("schema category escaped discovery")
	}
}

func TestSchemaAdmissionGenericReason(t *testing.T) {
	for _, schema := range []any{
		map[string]any{"type": "object", "$ref": "https://CANARY.invalid/schema"},
		map[string]any{"type": "CANARY-invalid-type"},
		map[string]any{"type": "object", "$schema": "https://CANARY.invalid/draft"},
	} {
		_, err := resolveSchema(schema, true)
		f := classifyDownstreamFailure(context.Background(), FailureDiscovery, err, false)
		if f.Code != FailureSchemaAdmission || f.SchemaReason != SchemaInvalidOrUnsupported {
			t.Fatalf("missing generic schema evidence: %+v", f)
		}
		data, _ := json.Marshal(f)
		if strings.Contains(string(data)+f.Error(), "CANARY") {
			t.Fatal("generic admission leaked schema")
		}
	}
}
