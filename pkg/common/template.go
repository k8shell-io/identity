package common

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter/functions"
	"github.com/k8shell-io/identity/pkg/models"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"gopkg.in/yaml.v3"
)

type CelExpr struct {
	Source  string
	Literal any
	IsCEL   bool
}

type UserTemplate struct {
	User struct {
		Username      CelExpr `yaml:"username"`
		Fullname      CelExpr `yaml:"fullname"`
		UID           CelExpr `yaml:"uid"`
		GID           CelExpr `yaml:"gid"`
		Email         CelExpr `yaml:"email"`
		Blueprints    CelExpr `yaml:"blueprints"`
		Roles         CelExpr `yaml:"roles"`
		IsValid       CelExpr `yaml:"is_valid"`
		Channels      CelExpr `yaml:"channels"`
		Auths         CelExpr `yaml:"auths"`
		AuthProviders CelExpr `yaml:"auth_providers"`
	} `yaml:"user"`
}

// func (c *CelExpr) UnmarshalYAML(node *yaml.Node) error {
// 	switch node.Tag {
// 	case "!cel":
// 		c.Source = node.Value
// 		c.IsCEL = true
// 		return nil

// 	default:
// 		c.IsCEL = false
// 		switch node.Kind {
// 		case yaml.ScalarNode:
// 			c.Source = node.Value
// 			return nil
// 		case yaml.SequenceNode, yaml.MappingNode:
// 			var temp any
// 			if err := node.Decode(&temp); err != nil {
// 				return fmt.Errorf("decode plain YAML node: %w", err)
// 			}
// 			jsonBytes, err := json.Marshal(temp)
// 			if err != nil {
// 				return fmt.Errorf("marshal fallback node to JSON: %w", err)
// 			}
// 			c.Source = string(jsonBytes)
// 			return nil
// 		default:
// 			return fmt.Errorf("unsupported YAML node kind: %d", node.Kind)
// 		}
// 	}
// }

func (c *CelExpr) UnmarshalYAML(node *yaml.Node) error {
	switch node.Tag {
	case "!cel":
		c.Source = node.Value
		c.IsCEL = true
		return nil

	default:
		c.IsCEL = false
		var temp any
		if err := node.Decode(&temp); err != nil {
			return fmt.Errorf("failed to decode literal value: %w", err)
		}
		c.Literal = temp
		return nil
	}
}

// func (c *CelExpr) Eval(evalFn func(string) (any, error)) (any, error) {
// 	if !c.IsCEL {
// 		return c.Source, nil
// 	}
// 	v, err := evalFn(c.Source)
// 	if err != nil {
// 		return nil, fmt.Errorf("evaluate CEL expression '%s': %w", c.Source, err)
// 	}
// 	return v, nil
// }

func (c *CelExpr) Eval(evalFn func(string) (any, error)) (any, error) {
	if !c.IsCEL {
		return c.Literal, nil
	}
	v, err := evalFn(c.Source)
	if err != nil {
		return nil, fmt.Errorf("evaluate CEL expression '%s': %w", c.Source, err)
	}
	return v, nil
}

func (c *CelExpr) EvalString(evalFn func(string) (any, error)) (string, error) {
	v, err := c.Eval(evalFn)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", v), nil
}

func (c *CelExpr) EvalInt(evalFn func(string) (any, error)) (int, error) {
	v, err := c.Eval(evalFn)
	if err != nil {
		return 0, err
	}
	intVal, ok := v.(int64)
	if !ok {
		return 0, fmt.Errorf("expected int, got %T", v)
	}
	return int(intVal), nil
}

func (c *CelExpr) EvalBool(evalFn func(string) (any, error)) (bool, error) {
	v, err := c.Eval(evalFn)
	if err != nil {
		return false, err
	}
	boolVal, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("expected bool, got %T", v)
	}
	return boolVal, nil
}

func (c *CelExpr) EvalStringList(evalFn func(string) (any, error)) ([]string, error) {
	v, err := c.Eval(evalFn)
	if err != nil {
		return nil, err
	}

	switch list := v.(type) {
	case []any:
		raw := list
		out := make([]string, 0, len(raw))
		for _, item := range raw {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("non-string item in list: %T", item)
			}
			out = append(out, s)
		}
		return out, nil

	case []ref.Val:
		out := make([]string, len(list))
		for i, item := range list {
			str, ok := item.Value().(string)
			if !ok {
				return nil, fmt.Errorf("non-string item in CEL list: %T", item)
			}
			out[i] = str
		}
		return out, nil

	default:
		return nil, fmt.Errorf("expected list, got %T", v)
	}
}

func NewUserTemplate(path string, baseDir string) (*UserTemplate, error) {
	var template UserTemplate

	filename := path
	if !filepath.IsAbs(filename) {
		filename = filepath.Join(baseDir, filename)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read template file '%s': %w", path, err)
	}

	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("unmarshal template file '%s': %w", path, err)
	}
	return &template, nil
}

func (t *UserTemplate) Eval(resource map[string]any, envVars map[string]string) (*models.User, error) {
	// Declarations
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

	programOpts := []cel.ProgramOption{
		cel.Functions(
			&functions.Overload{
				Operator: "distinct_list",
				Function: func(args ...ref.Val) ref.Val {
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
				},
			},
		),
	}

	// CEL evaluation helper
	eval := func(exprStr string) (any, error) {
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

	// Evaluate user fields
	username, err := t.User.Username.EvalString(eval)
	if err != nil {
		return nil, err
	}
	fullname, err := t.User.Fullname.EvalString(eval)
	if err != nil {
		return nil, err
	}
	isValid, err := t.User.IsValid.EvalBool(eval)
	if err != nil {
		return nil, err
	}
	uidStr, err := t.User.UID.EvalString(eval)
	if err != nil {
		return nil, err
	}
	gidStr, err := t.User.GID.EvalString(eval)
	if err != nil {
		return nil, err
	}
	email, err := t.User.Email.EvalString(eval)
	if err != nil {
		return nil, err
	}
	blueprints, err := t.User.Blueprints.EvalStringList(eval)
	if err != nil {
		return nil, err
	}
	rolesStr, err := t.User.Roles.EvalStringList(eval)
	if err != nil {
		return nil, err
	}
	channels, err := t.User.Channels.EvalStringList(eval)
	if err != nil {
		return nil, err
	}
	auths, err := t.User.Auths.EvalStringList(eval)
	if err != nil {
		return nil, err
	}

	uid, _ := parseUID(uidStr)
	gid, _ := parseUID(gidStr)

	return &models.User{
		Username:   username,
		Fullname:   fullname,
		IsValid:    isValid,
		UID:        uid,
		GID:        gid,
		Email:      email,
		Auths:      toAuths(auths),
		Roles:      toRoles(rolesStr),
		Blueprints: blueprints,
		Channels:   toChannels(channels),
	}, nil
}

// Utility functions

func ToMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func ToJSON(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func toRoles(strs []string) []models.Role {
	roles := make([]models.Role, 0, len(strs))
	for _, s := range strs {
		roles = append(roles, models.Role(s))
	}
	return roles
}

func toChannels(strs []string) []models.Channel {
	channels := make([]models.Channel, 0, len(strs))
	for _, s := range strs {
		channels = append(channels, models.Channel(s))
	}
	return channels
}

func toAuths(strs []string) []models.AuthMethod {
	auths := make([]models.AuthMethod, 0, len(strs))
	for _, s := range strs {
		auths = append(auths, models.AuthMethod(s))
	}
	return auths
}

const UID_OFFSET_BASE = 100000

func parseUID(uidStr string) (uint32, error) {
	f, err := strconv.ParseFloat(uidStr, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse UID from '%s': %w", uidStr, err)
	}

	if f < 0 {
		return 0, fmt.Errorf("UID must be non-negative: %f", f)
	}

	uidWithOffset := f + UID_OFFSET_BASE

	if uidWithOffset > float64(math.MaxUint32) {
		return 0, fmt.Errorf("UID after offset exceeds uint32 max: %f", uidWithOffset)
	}

	return uint32(uidWithOffset), nil
}
