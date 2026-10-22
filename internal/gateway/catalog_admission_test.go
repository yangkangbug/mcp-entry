package gateway

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCatalogAdmissionPreservesEmptyPages(t *testing.T) {
	a := &catalogAdmission{system: "test", allowed: map[string]bool{"test__lookup": true}, names: map[string]bool{}, cursors: map[string]bool{}}
	for i, list := range []*mcp.ListToolsResult{
		{Tools: []*mcp.Tool{}, NextCursor: "empty"},
		{Tools: []*mcp.Tool{{Name: "hidden", InputSchema: map[string]any{"type": "object", "pattern": "(?=unsupported)"}}}, NextCursor: "filtered"},
		{Tools: []*mcp.Tool{}},
	} {
		if err := a.admit(context.Background(), list); err != nil {
			t.Fatalf("page %d: %v", i, err)
		}
		if list.Tools == nil || len(list.Tools) != 0 {
			t.Fatalf("page %d lost valid empty list", i)
		}
	}
	if a.total != 1 || len(a.names) != 1 || a.pages != 3 {
		t.Fatal("unselected catalog accounting lost")
	}
}

func TestCatalogStructuralAdmissionDoesNotCompile(t *testing.T) {
	for _, raw := range []string{
		`{"type":"object","pattern":"(?=unsupported)"}`,
		`{"type":"object","patternProperties":{"(?=unsupported)":{"type":"string"}}}`,
		`{"type":"object","properties":{"value":{"type":"string","x-mcp-header":"Invalid Header"}}}`,
		`{"type":"object","$ref":"https://example.invalid/schema"}`,
		`{"type":"object","$ref":"#"}`,
	} {
		value := policyJSON(t, raw)
		if err := validateSchemaStructure(value); err != nil {
			t.Fatalf("structural admission interpreted schema: %v", err)
		}
		if _, err := analyzeSchema(value); err == nil {
			t.Fatal("selected schema bypassed semantic admission")
		}
	}
	for _, raw := range []string{`null`, `"schema"`, `{"properties":[]}`, `{"allOf":{}}`, `{"items":null}`} {
		if err := validateSchemaStructure(policyJSON(t, raw)); err == nil {
			t.Fatalf("invalid structure accepted: %s", raw)
		}
	}
}
