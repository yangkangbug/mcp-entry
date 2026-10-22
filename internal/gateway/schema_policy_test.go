package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

func policyJSON(t *testing.T, text string) any {
	t.Helper()
	var value any
	if err := json.Unmarshal([]byte(text), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSchemaPolicyLocalReferenceTargets(t *testing.T) {
	cases := []struct{ name, schema string }{
		{"definition", `{"$defs":{"value":{"type":"string"}},"properties":{"value":{"$ref":"#/$defs/value"}}}`},
		{"draft7 definition", `{"$schema":"http://json-schema.org/draft-07/schema#","definitions":{"value":true},"$ref":"#/definitions/value"}`},
		{"boolean false", `{"$defs":{"value":false},"$ref":"#/$defs/value"}`},
		{"boolean true", `{"$defs":{"value":true},"$ref":"#/$defs/value"}`},
		{"empty token", `{"$defs":{"":true},"$ref":"#/$defs/"}`},
		{"slash", `{"$defs":{"a/b":true},"$ref":"#/$defs/a~1b"}`},
		{"tilde", `{"$defs":{"a~b":true},"$ref":"#/$defs/a~0b"}`},
		{"tilde once", `{"$defs":{"~1":true},"$ref":"#/$defs/~01"}`},
		{"percent once", `{"$defs":{"%2F":true},"$ref":"#/$defs/%252F"}`},
		{"plus is literal", `{"$defs":{"a+b":true},"$ref":"#/$defs/a+b"}`},
		{"space encoded", `{"$defs":{"a b":true},"$ref":"#/$defs/a%20b"}`},
		{"encoded delimiter", `{"$defs":{"a":true},"$ref":"#%2F$defs%2Fa"}`},
		{"encoded tilde", `{"$defs":{"a/b":true},"$ref":"#/$defs/a%7E1b"}`},
		{"unicode", `{"$defs":{"雪":true},"$ref":"#/$defs/%E9%9B%AA"}`},
		{"object numeric key", `{"$defs":{"01":true,"+0":true},"allOf":[{"$ref":"#/$defs/01"},{"$ref":"#/$defs/+0"}]}`},
		{"tuple item", `{"$schema":"http://json-schema.org/draft-07/schema#","items":[true],"$ref":"#/items/0"}`},
		{"single item", `{"items":true,"$ref":"#/items"}`},
		{"prefix item", `{"prefixItems":[true],"$ref":"#/prefixItems/0"}`},
		{"schema dependency", `{"$schema":"http://json-schema.org/draft-07/schema#","dependencies":{"a":true},"$ref":"#/dependencies/a"}`},
		{"nested schema", `{"$defs":{"a":{"properties":{"":false}}},"$ref":"#/$defs/a/properties/"}`},
		{"array index", `{"allOf":[true],"$ref":"#/allOf/0"}`},
		{"schema position keyword named ref", `{"properties":{"$ref":true},"$ref":"#/properties/$ref"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := policyJSON(t, tc.schema)
			before, _ := json.Marshal(value)
			if work, err := analyzeSchema(value); err != nil || work < 1 {
				t.Fatalf("analyzeSchema = %d, %v", work, err)
			}
			after, _ := json.Marshal(value)
			if string(before) != string(after) {
				t.Fatal("analysis mutated the original schema")
			}
			// Keep the admitted pointer vocabulary aligned with the pinned typed
			// resolver. No network access is possible in this test.
			var schema jsonschema.Schema
			if err := json.Unmarshal(before, &schema); err != nil {
				t.Fatal(err)
			}
			if _, err := schema.Resolve(&jsonschema.ResolveOptions{Loader: func(*url.URL) (*jsonschema.Schema, error) {
				t.Error("local reference unexpectedly invoked loader")
				return nil, errors.New("remote resolution forbidden")
			}}); err != nil {
				t.Fatalf("admitted pointer is not supported by typed resolver: %v", err)
			}
		})
	}
}

func TestSchemaPolicyRejectsUnsafeReferences(t *testing.T) {
	cases := map[string]string{
		"empty":                     `{"$ref":""}`,
		"nonstring":                 `{"$ref":false}`,
		"external":                  `{"$ref":"https://example.invalid/schema"}`,
		"external fragment":         `{"$ref":"https://example.invalid/schema#/$defs/a"}`,
		"file":                      `{"$ref":"file:///tmp/schema"}`,
		"relative":                  `{"$ref":"schema.json"}`,
		"anchor":                    `{"$anchor":"a","$ref":"#a"}`,
		"encoded anchor":            `{"$anchor":"a","$ref":"#%61"}`,
		"bad percent":               `{"$ref":"#/%ZZ"}`,
		"bad tilde":                 `{"$defs":{"a~2":true},"$ref":"#/$defs/a~2"}`,
		"trailing tilde":            `{"$defs":{"a~":true},"$ref":"#/$defs/a~"}`,
		"dynamic":                   `{"$dynamicRef":"#"}`,
		"empty dynamic":             `{"$dynamicRef":""}`,
		"header":                    `{"x-mcp-header":"authorization"}`,
		"missing target":            `{"$ref":"#/$defs/missing"}`,
		"target schema map":         `{"$defs":{"a":true},"$ref":"#/$defs"}`,
		"target schema array":       `{"allOf":[true],"$ref":"#/allOf"}`,
		"target arbitrary object":   `{"extension":{"type":"string"},"$ref":"#/extension"}`,
		"target scalar":             `{"type":"string","$ref":"#/type"}`,
		"target default":            `{"default":{"type":"string"},"$ref":"#/default"}`,
		"target example":            `{"examples":[true],"$ref":"#/examples/0"}`,
		"target const":              `{"const":true,"$ref":"#/const"}`,
		"target enum":               `{"enum":[true],"$ref":"#/enum/0"}`,
		"dependency data":           `{"dependencies":{"a":["b"]},"$ref":"#/dependencies/a"}`,
		"dependency data item":      `{"dependencies":{"a":["b"]},"$ref":"#/dependencies/a/0"}`,
		"synthetic false child":     `{"$defs":{"no":false},"$ref":"#/$defs/no/not"}`,
		"leading zero array index":  `{"allOf":[true],"$ref":"#/allOf/00"}`,
		"positive sign array index": `{"allOf":[true],"$ref":"#/allOf/+0"}`,
		"negative zero array index": `{"allOf":[true],"$ref":"#/allOf/-0"}`,
		"append array index":        `{"allOf":[true],"$ref":"#/allOf/-"}`,
		"root id":                   `{"$id":"https://example.invalid/schema","$defs":{"a":true},"$ref":"#/$defs/a"}`,
		"empty id":                  `{"$id":"","$defs":{"a":true},"$ref":"#/$defs/a"}`,
		"unused nested id":          `{"$defs":{"a":true,"unused":{"$id":"child"}},"$ref":"#/$defs/a"}`,
		"nested dialect":            `{"$defs":{"a":{"$schema":"https://json-schema.org/draft/2020-12/schema"}},"$ref":"#/$defs/a"}`,
		"unused nested dialect":     `{"$defs":{"a":true,"unused":{"$schema":""}},"$ref":"#/$defs/a"}`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := analyzeSchema(policyJSON(t, text)); err == nil {
				t.Fatal("unsafe reference admitted")
			}
		})
	}
}

func TestSchemaPolicyRejectsCyclesIncludingUnusedDefinitions(t *testing.T) {
	for _, text := range []string{
		`{"$ref":"#"}`,
		`{"properties":{"child":{"$ref":"#"}}}`,
		`{"$defs":{"a":{"$ref":"#/$defs/a"}}}`,
		`{"$defs":{"a":{"$ref":"#/$defs/b"},"b":{"$ref":"#/$defs/a"}}}`,
		`{"$defs":{"a":{"properties":{"child":{"$ref":"#/$defs/a"}}}}}`,
		`{"$schema":"http://json-schema.org/draft-07/schema#","$defs":{"a":true},"$ref":"#/$defs/a","properties":{"ignored":{"$ref":"#"}}}`,
	} {
		if _, err := analyzeSchema(policyJSON(t, text)); err == nil {
			t.Errorf("cycle admitted: %s", text)
		}
	}
}

func TestSchemaPolicyPreservesLiteralDataAndNames(t *testing.T) {
	value := policyJSON(t, `{
		"$defs":{"safe":true},
		"properties":{
			"$id":{"type":"string"},"$ref":{"type":"string"},
			"$dynamicRef":{"type":"string"},"x-mcp-header":{"type":"string"},
			"$schema":{"type":"string"},"type":{"type":"string"},
			"value":{"$ref":"#/$defs/safe"}
		},
		"default":{"$ref":"https://example.invalid/","$id":"data"},
		"examples":[{"$schema":"data","x-mcp-header":"data","$dynamicRef":"data"}],
		"enum":[{"$ref":"#","type":"invented"}],
		"const":{"$ref":"#","type":"invented"},
		"extension":{"$ref":"#","$id":"data","properties":{"bad":{"$ref":"#"}}},
		"dependencies":{"data":["$ref","$id","x-mcp-header"]}
	}`)
	before, _ := json.Marshal(value)
	if _, err := analyzeSchema(value); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(value)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("literal data changed")
	}
	// Without references, resource identifiers retain their existing behavior.
	if _, err := analyzeSchema(policyJSON(t, `{"$id":"https://example.invalid/schema","$defs":{"nested":{"$schema":"https://json-schema.org/draft/2020-12/schema"}}}`)); err != nil {
		t.Fatalf("no-reference resource identifier rejected: %v", err)
	}
}

func TestSchemaPolicySchemaPositions(t *testing.T) {
	for _, keyword := range []string{"$defs", "definitions", "properties", "patternProperties", "dependentSchemas", "dependencies"} {
		t.Run(keyword, func(t *testing.T) {
			value := map[string]any{keyword: map[string]any{"bad": map[string]any{"$dynamicRef": "#"}}}
			if _, err := analyzeSchema(value); err == nil {
				t.Fatal("did not inspect schema map")
			}
		})
	}
	for _, keyword := range []string{"allOf", "anyOf", "oneOf", "prefixItems", "items"} {
		t.Run(keyword, func(t *testing.T) {
			value := map[string]any{keyword: []any{map[string]any{"x-mcp-header": "secret"}}}
			if _, err := analyzeSchema(value); err == nil {
				t.Fatal("did not inspect schema array")
			}
		})
	}
	for _, keyword := range []string{"items", "additionalProperties", "additionalItems", "propertyNames", "contains", "not", "if", "then", "else", "unevaluatedProperties", "unevaluatedItems", "contentSchema"} {
		t.Run(keyword, func(t *testing.T) {
			value := map[string]any{keyword: map[string]any{"$dynamicRef": "#"}}
			if _, err := analyzeSchema(value); err == nil {
				t.Fatal("did not inspect single schema")
			}
			value = map[string]any{keyword: true, "$ref": "#/" + keyword}
			if _, err := analyzeSchema(value); err != nil {
				t.Fatalf("supported boolean target rejected: %v", err)
			}
		})
	}
}

func TestSchemaPolicyRejectsMalformedSchemaPositions(t *testing.T) {
	for _, text := range []string{
		`null`, `0`, `[]`, `"schema"`,
		`{"properties":null}`, `{"properties":[]}`, `{"properties":{"a":null}}`,
		`{"allOf":{}}`, `{"allOf":[null]}`, `{"allOf":[[]]}`,
		`{"items":null}`, `{"items":[2]}`, `{"not":[]}`,
		`{"dependencies":{"a":[false]}}`, `{"dependencies":{"a":null}}`,
	} {
		if _, err := analyzeSchema(policyJSON(t, text)); err == nil {
			t.Errorf("invalid schema shape admitted: %s", text)
		}
	}
}

func policyNestedJSON(depth int) any {
	var value any = true
	for i := 0; i < depth; i++ {
		value = map[string]any{"child": value}
	}
	return value
}

func TestSchemaPolicyRawDepthBoundary(t *testing.T) {
	for _, delta := range []int{0, 1} {
		// The root schema and annotation property add one edge to the data depth.
		value := map[string]any{"default": policyNestedJSON(MaxSchemaDepth - 1 + delta)}
		_, err := analyzeSchema(value)
		if (err == nil) != (delta == 0) {
			t.Fatalf("depth %d: err = %v", MaxSchemaDepth+delta, err)
		}
	}
}

func TestSchemaPolicyRawNodeBoundary(t *testing.T) {
	for _, delta := range []int{0, 1} {
		data := make([]any, MaxSchemaRawNodes-2+delta) // Root and annotation array count too.
		value := map[string]any{"examples": data}
		_, err := analyzeSchema(value)
		if (err == nil) != (delta == 0) {
			t.Fatalf("raw nodes %d: err = %v", MaxSchemaRawNodes+delta, err)
		}
	}
}

func TestSchemaPolicySchemaNodeBoundary(t *testing.T) {
	for _, delta := range []int{0, 1} {
		children := make([]any, MaxSchemaNodes-1+delta)
		for i := range children {
			children[i] = true
		}
		_, err := analyzeSchema(map[string]any{"allOf": children})
		if (err == nil) != (delta == 0) {
			t.Fatalf("schema nodes %d: err = %v", MaxSchemaNodes+delta, err)
		}
	}
}

func TestSchemaPolicyReferenceBoundary(t *testing.T) {
	for _, delta := range []int{0, 1} {
		refs := make([]any, MaxSchemaRefs+delta)
		for i := range refs {
			refs[i] = map[string]any{"$ref": "#/$defs/target"}
		}
		value := map[string]any{"$defs": map[string]any{"target": true}, "allOf": refs}
		_, err := analyzeSchema(value)
		if (err == nil) != (delta == 0) {
			t.Fatalf("refs %d: err = %v", MaxSchemaRefs+delta, err)
		}
	}
}

func TestSchemaPolicyExpandedWorkBoundary(t *testing.T) {
	leaves := make([]any, 30)
	for i := range leaves {
		leaves[i] = true
	}
	refs := make([]any, 127)
	for i := range refs {
		refs[i] = map[string]any{"$ref": "#/$defs/target"}
	}
	value := map[string]any{"$defs": map[string]any{"target": map[string]any{"allOf": leaves}}, "allOf": refs}
	if work, err := analyzeSchema(value); err != nil || work != MaxSchemaExpandedWork {
		t.Fatalf("exact work limit: got %d, %v", work, err)
	}
	value["not"] = true // Exactly one additional unit of expanded work.
	if _, err := analyzeSchema(value); err == nil {
		t.Fatal("expanded work above limit admitted")
	}
}

func TestSchemaPolicyExpandedDepthBoundary(t *testing.T) {
	for _, delta := range []int{0, 1} {
		defs := map[string]any{}
		for i := 0; i < MaxSchemaExpandedDepth+delta; i++ {
			var value any = true
			if i+1 < MaxSchemaExpandedDepth+delta {
				value = map[string]any{"$ref": fmt.Sprintf("#/$defs/n%d", i+1)}
			}
			defs[fmt.Sprintf("n%d", i)] = value
		}
		// Map iteration visits the shared tail before the longest path on some
		// runs. Cached subtree height must still enforce the longest path.
		for i := 0; i < 10; i++ {
			_, err := analyzeSchema(map[string]any{"$defs": defs})
			if (err == nil) != (delta == 0) {
				t.Fatalf("expanded depth %d: err = %v", MaxSchemaExpandedDepth+delta, err)
			}
		}
	}
}

func TestSchemaPolicyRejectsExponentialDAG(t *testing.T) {
	defs := map[string]any{"end": true}
	last := "end"
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("n%d", i)
		ref := "#/$defs/" + last
		defs[name] = map[string]any{"allOf": []any{map[string]any{"$ref": ref}, map[string]any{"$ref": ref}}}
		last = name
	}
	if _, err := analyzeSchema(map[string]any{"$defs": defs}); err == nil || !strings.Contains(err.Error(), "work") {
		t.Fatalf("exponential DAG: err = %v", err)
	}
}

func TestInstanceBudgetBoundaries(t *testing.T) {
	for _, delta := range []int{0, 1} {
		if err := validateInstanceBudget(policyNestedJSON(MaxInstanceDepth+delta), 1); (err == nil) != (delta == 0) {
			t.Fatalf("instance depth %d: %v", MaxInstanceDepth+delta, err)
		}
		if err := validateInstanceBudget(make([]any, MaxInstanceNodes-1+delta), 1); (err == nil) != (delta == 0) {
			t.Fatalf("instance nodes %d: %v", MaxInstanceNodes+delta, err)
		}
		nodes := MaxValidationWork/MaxSchemaExpandedWork + delta
		if err := validateInstanceBudget(make([]any, nodes-1), MaxSchemaExpandedWork); (err == nil) != (delta == 0) {
			t.Fatalf("combined work at nodes %d: %v", nodes, err)
		}
	}
	for _, work := range []int{-1, 0, MaxSchemaExpandedWork + 1, int(^uint(0) >> 1)} {
		if err := validateInstanceBudget(nil, work); err == nil {
			t.Errorf("invalid schema work %d admitted", work)
		}
	}
}

func TestBudgetTraversalTerminatesOnCyclicGoValues(t *testing.T) {
	value := map[string]any{}
	value["self"] = value
	if _, err := analyzeSchema(value); err == nil {
		t.Fatal("cyclic Go schema admitted")
	}
	if err := validateInstanceBudget(value, 1); err == nil {
		t.Fatal("cyclic Go instance admitted")
	}
}

func TestSchemaPolicyRootBooleanAndCanonicalRoot(t *testing.T) {
	for _, value := range []any{true, false, map[string]any{}} {
		if work, err := analyzeSchema(value); err != nil || work != 1 {
			t.Fatalf("root %v: work %d, err %v", value, work, err)
		}
	}
	if path, err := canonicalSchemaReference("#"); err != nil || path != "" {
		t.Fatalf("root fragment: %q, %v", path, err)
	}
}

func TestSchemaPolicyRejectsTypedDecoderKeywordAliases(t *testing.T) {
	// Derive all tagged fields independently, then add the custom unmarshaler's
	// untagged union fields and the SDK's separate header annotation keyword.
	keywords := []string{"type", "items", "dependencies", "x-mcp-header"}
	for _, field := range reflect.VisibleFields(reflect.TypeFor[jsonschema.Schema]()) {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if field.IsExported() && name != "-" && name != "" {
			keywords = append(keywords, name)
		}
	}
	for _, keyword := range keywords {
		t.Run(keyword, func(t *testing.T) {
			alias := strings.ToUpper(keyword)
			_, err := analyzeSchema(map[string]any{alias: nil})
			if err == nil || !strings.Contains(err.Error(), "noncanonical") {
				t.Fatalf("typed decoder alias %q admitted or rejected for wrong reason: %v", alias, err)
			}
		})
	}
	for name, value := range map[string]any{
		"root hidden recursion": map[string]any{"type": "object", "$REF": "#"},
		"hidden containment": map[string]any{"PROPERTIES": map[string]any{
			"child": map[string]any{"$ref": "#"},
		}},
		"hidden dynamic reference": map[string]any{"$DYNAMICREF": "#"},
		"nested alias": map[string]any{"properties": map[string]any{
			"child": map[string]any{"$REF": "#"},
		}},
		"mixed reference collision": map[string]any{"$ref": "#/$defs/a", "$REF": "#", "$defs": map[string]any{"a": true}},
		"mixed containment collision": map[string]any{
			"properties": map[string]any{"good": true},
			"PROPERTIES": map[string]any{"bad": map[string]any{"$ref": "#"}},
		},
		"unicode schema fold":             map[string]any{"$ſchema": "https://json-schema.org/draft/2020-12/schema"},
		"unicode containment fold":        map[string]any{"propertieſ": map[string]any{"child": true}},
		"unicode wrapper constraint fold": map[string]any{"minItemſ": 1},
		"unicode constraint fold":         map[string]any{"conſt": "data"},
		"unicode definitions fold":        map[string]any{"definitionſ": map[string]any{"a": true}},
		"header annotation alias":         map[string]any{"X-MCP-HEADER": "authorization"},
		"mixed header capitalization":     map[string]any{"x-Mcp-header": "authorization"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := analyzeSchema(value)
			if err == nil || !strings.Contains(err.Error(), "noncanonical") {
				t.Fatalf("keyword alias admitted or rejected for wrong reason: %v", err)
			}
		})
	}
}

func TestSchemaPolicyPreservesKeywordAliasesInLiteralData(t *testing.T) {
	value := policyJSON(t, `{
		"properties":{
			"$REF":{"type":"string"},"PROPERTIES":{"type":"object"},
			"$DYNAMICREF":{"type":"string"},"X-MCP-HEADER":{"type":"string"},
			"$ſchema":{"type":"string"},"propertieſ":{"type":"string"}
		},
		"default":{"$REF":"#","PROPERTIES":{"bad":{"$ref":"#"}}},
		"examples":[{"$DYNAMICREF":"#","X-MCP-HEADER":"authorization"}],
		"enum":[{"conſt":"data"}],
		"const":{"$ſchema":"data"},
		"extension":{"$REF":"#","PROPERTIES":{"bad":{"$REF":"#"}}}
	}`)
	if _, err := analyzeSchema(value); err != nil {
		t.Fatalf("literal data mistaken for typed schema keywords: %v", err)
	}
}
