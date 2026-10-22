package gateway

import (
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

// These limits are conservative admission budgets, not execution-time guarantees.
// JSON nodes include containers and scalar values; the root has depth zero.
const (
	MaxSchemaRawNodes      = 4096
	MaxSchemaNodes         = 512
	MaxSchemaRefs          = 128
	MaxSchemaDepth         = 32
	MaxSchemaExpandedDepth = 64
	MaxSchemaExpandedWork  = 4096
	MaxInstanceDepth       = 32
	MaxInstanceNodes       = 4096
	MaxValidationWork      = 1 << 20
)

// encoding/json accepts case-insensitive struct-field matches, unlike JSON
// Schema's case-sensitive keyword vocabulary. Reject such aliases before a
// typed decoder could turn an unknown raw key into an unchecked keyword.
// Schema's JSON tags cover its normal fields; its custom UnmarshalJSON adds the
// three union fields below. The SDK separately decodes x-mcp-header as a field.
var typedSchemaJSONKeywords = func() []string {
	keywords := []string{"type", "items", "dependencies", "x-mcp-header"}
	for _, field := range reflect.VisibleFields(reflect.TypeFor[jsonschema.Schema]()) {
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		keywords = append(keywords, name)
	}
	return keywords
}()

func rejectSchemaKeywordAliases(schema map[string]any) error {
	for key := range schema {
		for _, canonical := range typedSchemaJSONKeywords {
			// EqualFold includes the Unicode simple folds used by encoding/json,
			// notably long s. Lowercasing would not match the decoder's behavior.
			if key != canonical && strings.EqualFold(key, canonical) {
				return errors.New("noncanonical schema keyword casing unsupported")
			}
		}
	}
	return nil
}

type schemaPolicyNode struct {
	children []*schemaPolicyNode
	ref      string
	hasRef   bool
	state    uint8
	work     int
	height   int
}

type schemaPolicyGraph struct {
	index            map[string]*schemaPolicyNode
	refs             int
	hasID            bool
	hasNestedDialect bool
}

// analyzeSchema checks a decoded JSON schema before the validator or SDK sees it.
// Only actual schema positions are indexed, including booleans. Annotation data
// and unknown extension values are counted as raw JSON but never interpreted as
// schemas. All containment edges, including unused definitions and ref siblings,
// contribute to a deliberately conservative, dialect-independent graph budget.
// The original schema is never rewritten; the validator retains dialect semantics.
func analyzeSchema(value any) (int, error) {
	if _, err := countJSONBudget(value, MaxSchemaDepth, MaxSchemaRawNodes); err != nil {
		return 0, errors.New("schema raw JSON budget exceeded or invalid JSON shape")
	}
	graph := schemaPolicyGraph{index: make(map[string]*schemaPolicyNode)}
	root, err := graph.add(value, "")
	if err != nil {
		return 0, err
	}
	if graph.refs > 0 && (graph.hasID || graph.hasNestedDialect) {
		return 0, errors.New("reference-bearing schemas cannot contain $id or nested $schema")
	}
	for _, node := range graph.index {
		if node.hasRef {
			target := graph.index[node.ref]
			if target == nil {
				return 0, errors.New("schema reference does not address a supported schema position")
			}
			node.children = append(node.children, target)
		}
	}
	return expandedSchemaBudget(root)
}

func (g *schemaPolicyGraph) add(value any, path string) (*schemaPolicyNode, error) {
	if len(g.index) >= MaxSchemaNodes {
		return nil, errors.New("schema node limit exceeded")
	}
	node := &schemaPolicyNode{}
	g.index[path] = node
	if _, ok := value.(bool); ok {
		return node, nil
	}
	schema, ok := value.(map[string]any)
	if !ok || schema == nil {
		return nil, errors.New("schema must be an object or boolean")
	}
	if err := rejectSchemaKeywordAliases(schema); err != nil {
		return nil, err
	}
	for _, key := range []string{"$dynamicRef", "x-mcp-header"} {
		if _, exists := schema[key]; exists {
			return nil, errors.New("dynamic schema references and header mappings unsupported")
		}
	}
	if _, exists := schema["$id"]; exists {
		g.hasID = true
	}
	if _, exists := schema["$schema"]; exists && path != "" {
		g.hasNestedDialect = true
	}
	if ref, exists := schema["$ref"]; exists {
		g.refs++
		if g.refs > MaxSchemaRefs {
			return nil, errors.New("schema reference limit exceeded")
		}
		text, ok := ref.(string)
		if !ok {
			return nil, errors.New("schema reference must be a string")
		}
		canonical, err := canonicalSchemaReference(text)
		if err != nil {
			return nil, err
		}
		node.ref, node.hasRef = canonical, true
	}
	addChild := func(child any, childPath string) error {
		n, err := g.add(child, childPath)
		if err == nil {
			node.children = append(node.children, n)
		}
		return err
	}
	for key, child := range schema {
		childPath := path + "/" + escapeSchemaPointerToken(key)
		switch key {
		case "$defs", "definitions", "properties", "patternProperties", "dependentSchemas", "dependencies":
			children, ok := child.(map[string]any)
			if !ok || children == nil {
				return nil, errors.New("schema map keyword must contain an object")
			}
			for name, value := range children {
				if key == "dependencies" {
					if names, ok := value.([]any); ok && names != nil {
						for _, name := range names {
							if _, ok := name.(string); !ok {
								return nil, errors.New("dependency names must be strings")
							}
						}
						continue // Property dependencies are data, not schema positions.
					}
				}
				if err := addChild(value, childPath+"/"+escapeSchemaPointerToken(name)); err != nil {
					return nil, err
				}
			}
		case "allOf", "anyOf", "oneOf", "prefixItems":
			children, ok := child.([]any)
			if !ok || children == nil {
				return nil, errors.New("schema array keyword must contain an array")
			}
			for i, value := range children {
				if err := addChild(value, childPath+"/"+strconv.Itoa(i)); err != nil {
					return nil, err
				}
			}
		case "items":
			if children, ok := child.([]any); ok && children != nil {
				for i, value := range children {
					if err := addChild(value, childPath+"/"+strconv.Itoa(i)); err != nil {
						return nil, err
					}
				}
			} else if err := addChild(child, childPath); err != nil {
				return nil, err
			}
		case "additionalProperties", "additionalItems", "propertyNames", "contains", "not", "if", "then", "else", "unevaluatedProperties", "unevaluatedItems", "contentSchema":
			if err := addChild(child, childPath); err != nil {
				return nil, err
			}
		}
	}
	return node, nil
}

func escapeSchemaPointerToken(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

// canonicalSchemaReference decodes the URI fragment once and JSON Pointer
// escapes once. Index lookup then distinguishes literal object keys from the
// canonical decimal indices generated for arrays. In particular, arbitrary
// JSON data, synthetic boolean-schema children, and unrecognized keywords are
// not reference targets, even if the library's typed representation exposes one.
func canonicalSchemaReference(ref string) (string, error) {
	if ref == "" || ref[0] != '#' {
		return "", errors.New("only local fragment schema references are supported")
	}
	// Use the same URI parser as jsonschema-go, so malformed URI characters and
	// percent escapes cannot acquire different meanings during actual resolution.
	u, err := url.Parse(ref)
	if err != nil {
		return "", errors.New("invalid schema reference URI")
	}
	fragment := u.Fragment
	if fragment == "" {
		return "", nil
	}
	if fragment[0] != '/' {
		return "", errors.New("schema anchor references unsupported")
	}
	tokens := strings.Split(fragment[1:], "/")
	for i, token := range tokens {
		var decoded strings.Builder
		for j := 0; j < len(token); j++ {
			if token[j] != '~' {
				decoded.WriteByte(token[j])
				continue
			}
			if j+1 >= len(token) || (token[j+1] != '0' && token[j+1] != '1') {
				return "", errors.New("invalid JSON Pointer escape")
			}
			j++
			if token[j] == '0' {
				decoded.WriteByte('~')
			} else {
				decoded.WriteByte('/')
			}
		}
		tokens[i] = escapeSchemaPointerToken(decoded.String())
	}
	return "/" + strings.Join(tokens, "/"), nil
}

// expandedSchemaBudget memoizes DAG costs but adds each incoming edge's cost,
// bounding repeated-reference amplification without actually expanding schemas.
// Sums saturate at the admission cap before they could overflow.
func expandedSchemaBudget(node *schemaPolicyNode) (int, error) {
	switch node.state {
	case 1:
		return 0, errors.New("schema reference cycle unsupported")
	case 2:
		return node.work, nil
	}
	node.state = 1
	work, height := 1, 0
	for _, child := range node.children {
		childWork, err := expandedSchemaBudget(child)
		if err != nil {
			return 0, err
		}
		if childWork > MaxSchemaExpandedWork-work {
			return 0, errors.New("expanded schema work limit exceeded")
		}
		work += childWork
		if child.height+1 > height {
			height = child.height + 1
		}
		if height > MaxSchemaExpandedDepth {
			return 0, errors.New("expanded schema depth limit exceeded")
		}
	}
	node.work, node.height, node.state = work, height, 2
	return work, nil
}

// validateInstanceBudget bounds instance structure and the conservative product
// of instance nodes and expanded schema work before schema validation begins.
func validateInstanceBudget(value any, schemaWork int) error {
	if schemaWork < 1 || schemaWork > MaxSchemaExpandedWork {
		return errors.New("invalid schema work budget")
	}
	nodes, err := countJSONBudget(value, MaxInstanceDepth, MaxInstanceNodes)
	if err != nil {
		return errors.New("instance JSON budget exceeded or invalid JSON shape")
	}
	if nodes > MaxValidationWork/schemaWork {
		return errors.New("validation work limit exceeded")
	}
	return nil
}

// countJSONBudget expects ordinary decoded JSON containers, not arbitrary Go
// objects. The node and depth checks also terminate cyclic in-memory containers.
func countJSONBudget(value any, maxDepth, maxNodes int) (int, error) {
	nodes := 0
	var visit func(any, int) error
	visit = func(value any, depth int) error {
		if depth > maxDepth || nodes >= maxNodes {
			return errors.New("JSON structure limit exceeded")
		}
		nodes++
		switch value := value.(type) {
		case map[string]any:
			if value == nil {
				return errors.New("unexpected nil JSON object")
			}
			for _, child := range value {
				if err := visit(child, depth+1); err != nil {
					return err
				}
			}
		case []any:
			if value == nil {
				return errors.New("unexpected nil JSON array")
			}
			for _, child := range value {
				if err := visit(child, depth+1); err != nil {
					return err
				}
			}
		case nil, bool, string, json.Number, float64, float32,
			int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		default:
			return errors.New("unexpected non-JSON value")
		}
		return nil
	}
	if err := visit(value, 0); err != nil {
		return 0, err
	}
	return nodes, nil
}
