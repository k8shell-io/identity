// Copyright 2025 The k8shell Authors.
// Package yamlcel provides utilities for working with CEL (Common Expression Language) templates
// in YAML files. It allows defining CEL expressions and nested CEL nodes, evaluating them against
// resource maps, and converting the results into structured data types.

package yamlcel

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"gopkg.in/yaml.v3"
)

// CELNode represents a map of CEL expressions or nested CEL nodes.
type CELNode map[string]CELValue

// CELValue represents a value in a CELNode, which can either be a CEL expression
// or a nested CELNode.
type CELValue struct {
	Expr   *CelExpr // leaf CEL expression
	Nested CELNode  // nested object
}

// CelExpr represents a CEL expression or a literal value.
// If IsCEL is true, Source contains the CEL expression string.
// If IsCEL is false, Literal contains the literal value (could be a string, number, map, etc.).
// CelExpr can be used to evaluate CEL expressions or return literal values.
type CelExpr struct {
	Source  string
	Literal any
	IsCEL   bool
}

// CELTemplate represents a template containing multiple CEL expressions or nested CEL nodes.
type CELTemplate struct {
	Keys map[string]CELNode `yaml:",inline"`
}

//** helper public functions **//

// EvalToStruct evaluates a CELTemplate against a resource map and returns the result as a struct of type T.
// The resource map contains the data to evaluate against, and extraFields can provide additional context.
// The root parameter specifies the root key in the evaluated data to extract the final result.
// If root is empty, the entire evaluated data is returned as a struct.
// The evaluated data is expected to match the structure of the target type T.
func EvalToStruct[T any](t *CELTemplate, resource map[string]any, extraFields map[string]string, root string) (*T, error) {
	data, err := t.Eval(resource, extraFields)
	if err != nil {
		return nil, fmt.Errorf("template evaluation failed: %w", err)
	}

	dataMap := data
	if root != "" {
		rootData, ok := data[root].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("root '%s' not found in evaluated data", root)
		}
		dataMap = rootData
	}

	dataObj, err := UnmarshalToStruct[T](dataMap)
	if err != nil {
		return nil, fmt.Errorf("unmarshal data to struct: %w", err)
	}

	return dataObj, nil
}

// UnmarshalToStruct converts a map[string]any to a given struct pointer.
// It marshals the map to JSON and then unmarshals it into the target struct type T.
func UnmarshalToStruct[T any](data map[string]any) (*T, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal to JSON: %w", err)
	}

	var result T
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to target struct: %w", err)
	}

	return &result, nil
}

// CelExpr implements yaml.Unmarshaler to handle both CEL expressions and literal values.
// If the node is tagged with !cel, it will be treated as a CEL expression.
func (c *CelExpr) UnmarshalYAML(node *yaml.Node) error {
	switch node.Tag {
	case "!cel":
		// CEL expressions must be scalar strings
		if node.Kind != yaml.ScalarNode {
			return fmt.Errorf("CEL expressions must be scalar strings, got kind: %d", node.Kind)
		}
		c.Source = node.Value
		c.IsCEL = true
		return nil
	default:
		// Fallback: decode any kind of literal (scalar, map, list)
		var temp any
		if err := node.Decode(&temp); err != nil {
			return fmt.Errorf("failed to decode literal value: %w", err)
		}
		c.Literal = temp
		c.IsCEL = false
		return nil
	}
}

// Eval evaluates the CelExpr using the provided evaluation function.
// If IsCEL is false, it returns the Literal value directly.
// If IsCEL is true, it calls the evalFn with the Source CEL expression string.
// The evalFn should return the evaluated value or an error if the evaluation fails.
func (c *CelExpr) Eval(evalFn func(string) (any, error)) (any, error) {
	if !c.IsCEL {
		return c.Literal, nil
	}
	return evalFn(c.Source)
}

// NewTemplate loads a CELTemplate from a given file path.
// If the path is not absolute, it will be resolved relative to baseDir.
func NewTemplate(path string) (*CELTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read template file '%s': %w", path, err)
	}

	var tmpl CELTemplate
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("unmarshal template: %w", err)
	}

	return &tmpl, nil
}

// UnmarshalYAML implements yaml.Unmarshaler for CELTemplate.
func (t *CELTemplate) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("template root must be a mapping node")
	}

	t.Keys = make(map[string]CELNode)

	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valNode := node.Content[i+1]
		key := keyNode.Value

		// Parse the value node recursively
		parsed, err := parseCELNode(valNode)
		if err != nil {
			return fmt.Errorf("failed to parse key '%s': %w", key, err)
		}
		t.Keys[key] = parsed
	}
	return nil
}

// Eval evaluates the CELTemplate against a resource map and environment variables.
// It constructs a CEL environment with declarations for each resource key and environment variable,
// and registers a custom functions.
// The resource map contains the data to evaluate against, and envVars provides additional context.
// The result is a map of evaluated sections, where each section corresponds to a key in the template.
func (t *CELTemplate) Eval(resource map[string]any, envVars map[string]string) (map[string]any, error) {
	// CEL declarations
	declsList := []cel.EnvOption{}
	for k := range resource {
		declsList = append(declsList, cel.Declarations(decls.NewVar(k, decls.Dyn)))
	}
	for k := range envVars {
		declsList = append(declsList, cel.Declarations(decls.NewVar(k, decls.String)))
	}

	// distinct() function signature
	declsList = append(declsList, cel.Declarations(
		decls.NewFunction("distinct",
			decls.NewOverload("distinct_list",
				[]*exprpb.Type{decls.NewListType(decls.String)},
				decls.NewListType(decls.String),
			),
		),
	))

	env, err := cel.NewEnv(declsList...)
	if err != nil {
		return nil, fmt.Errorf("CEL env error: %w", err)
	}

	// register custom functions
	programOpts := []cel.ProgramOption{
		cel.Functions(&functions.Overload{
			Operator: "distinct_list",
			Function: customFunctionDistinct,
		}),
	}

	// Evaluation function helper
	evalFn := func(exprStr string) (any, error) {
		ast, issues := env.Compile(exprStr)
		if issues != nil && issues.Err() != nil {
			return nil, issues.Err()
		}
		prg, err := env.Program(ast, programOpts...)
		if err != nil {
			return nil, err
		}
		vars := map[string]any{}
		for k, v := range resource {
			vars[k] = v
		}
		for k, v := range envVars {
			vars[k] = v
		}
		out, _, err := prg.Eval(vars)
		if err != nil {
			return nil, err
		}
		return out.Value(), nil
	}

	result := make(map[string]any)
	for sectionName, fields := range t.Keys {
		sectionMap, err := evalCELNode(fields, evalFn)
		if err != nil {
			return nil, fmt.Errorf("section '%s': %w", sectionName, err)
		}
		result[sectionName] = sectionMap
	}

	return result, nil
}

//** helper private functions **//

// evalCELNode evaluates a CELNode using the provided evaluation function.
// It recursively evaluates each CEL expression or nested CELNode and returns a map of results.
func evalCELNode(node CELNode, evalFn func(string) (any, error)) (map[string]any, error) {
	result := make(map[string]any)
	for key, val := range node {
		if val.Expr != nil {
			v, err := val.Expr.Eval(evalFn)
			if err != nil {
				return nil, fmt.Errorf("field '%s': %w", key, err)
			}
			result[key] = v
		} else {
			submap, err := evalCELNode(val.Nested, evalFn)
			if err != nil {
				return nil, fmt.Errorf("nested field '%s': %w", key, err)
			}
			result[key] = submap
		}
	}
	return result, nil
}

// parseCELNode parses a YAML node into a CELNode.
// It supports CEL expressions (tagged with !cel), nested CEL nodes (tagged with !!map),
// and literal values (which are decoded into CelExpr).
func parseCELNode(node *yaml.Node) (CELNode, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("unsupported YAML node kind: %d", node.Kind)
	}

	result := make(CELNode)
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1]

		var celVal CELValue
		switch val.Tag {
		case "!cel":
			var expr CelExpr
			if err := val.Decode(&expr); err != nil {
				return nil, fmt.Errorf("failed to decode !cel expression for key '%s': %w", key, err)
			}
			celVal.Expr = &expr
		case "!!map":
			nested, err := parseCELNode(val)
			if err != nil {
				return nil, fmt.Errorf("nested map at key '%s': %w", key, err)
			}
			celVal.Nested = nested
		default:
			var expr CelExpr
			if err := val.Decode(&expr); err != nil {
				return nil, fmt.Errorf("failed to decode literal value for key '%s': %w", key, err)
			}
			celVal.Expr = &expr
		}
		result[key] = celVal
	}
	return result, nil
}

// customFunctionDistinct implements a custom CEL function that returns a list of distinct strings from a given list.
func customFunctionDistinct(args ...ref.Val) ref.Val {
	list, ok := args[0].(traits.Lister)
	if !ok {
		return types.NewErr("distinct: expected a list of strings")
	}
	seen := map[string]struct{}{}
	var out []ref.Val
	it := list.Iterator()
	for it.HasNext().Value().(bool) {
		item := it.Next()
		strVal, ok := item.(types.String)
		if !ok {
			continue
		}
		s := string(strVal)
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			out = append(out, strVal)
		}
	}
	return types.NewDynamicList(types.DefaultTypeAdapter, out)
}
