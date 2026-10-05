package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// Query map entries supply GraphQL arguments. Required inputs remain unresolved
// unless explicitly supplied. Mutations remain approval-only operations.
func MaterializeGraphQLOperations(data []byte, endpoints []APIEndpoint, definitionID string, inputs []assessment.APIOperationInput) []APIEndpoint {
	out := append([]APIEndpoint(nil), endpoints...)
	schema, err := gqlparser.LoadSchema(&ast.Source{Name: definitionID, Input: string(data)})
	if err != nil || schema.Query == nil {
		return out
	}
	supplied := map[string]assessment.APIOperationInput{}
	for _, input := range inputs {
		if input.DefinitionID == definitionID {
			supplied[input.OperationID] = input
		}
	}
	for i := range out {
		op := &out[i]
		op.DefinitionID = definitionID
		if !strings.HasPrefix(op.OperationID, "query ") {
			continue
		}
		field := schema.Query.Fields.ForName(strings.TrimPrefix(op.OperationID, "query "))
		if field == nil {
			continue
		}
		input := supplied[op.OperationID]
		op.MissingInputs = nil
		if len(input.PathParams) > 0 || input.RequestBodyRef != "" {
			op.Eligible, op.Resolved = false, false
			op.Reason = "GraphQL query inputs use argument values only"
			continue
		}
		vars := map[string]any{}
		declarations, arguments := []string{}, []string{}
		failure := ""
		names := make([]string, 0, len(input.Query))
		for name := range input.Query {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			arg := field.Arguments.ForName(name)
			if arg == nil {
				failure = "supplied GraphQL argument is undeclared"
				break
			}
			value, err := graphQLArgumentValue(schema, arg.Type, input.Query[name])
			if err != nil {
				failure = "supplied GraphQL argument is invalid: " + name
				break
			}
			vars[name] = value
			declarations = append(declarations, "$"+name+": "+arg.Type.String())
			arguments = append(arguments, name+": $"+name)
		}
		for _, arg := range field.Arguments {
			if arg.Type.NonNull && arg.DefaultValue == nil {
				if _, ok := vars[arg.Name]; !ok {
					op.MissingInputs = append(op.MissingInputs, arg.Name)
				}
			}
		}
		if len(op.MissingInputs) > 0 || failure != "" {
			op.Eligible, op.Resolved = false, false
			op.Reason = failure
			if failure == "" {
				op.Reason = "GraphQL operation requires supplied arguments"
			}
			continue
		}
		declaration, call := "", ""
		if len(declarations) > 0 {
			declaration = "(" + strings.Join(declarations, ", ") + ")"
			call = "(" + strings.Join(arguments, ", ") + ")"
		}
		selection := ""
		if def := schema.Types[field.Type.Name()]; def != nil && (def.Kind == ast.Object || def.Kind == ast.Interface || def.Kind == ast.Union) {
			selection = " { __typename }"
		}
		query := "query XalgorixRead" + declaration + " { " + field.Name + call + selection + " }"
		if _, errs := gqlparser.LoadQuery(schema, query); len(errs) > 0 {
			op.Eligible, op.Resolved = false, false
			op.Reason = "materialized GraphQL query failed schema validation"
			continue
		}
		destination := op.RequestURL
		if destination == "" {
			destination = strings.TrimSuffix(op.Origin, "/") + op.Path
		}
		u, err := url.Parse(destination)
		if err != nil || u.Host == "" {
			op.Eligible, op.Resolved = false, false
			op.Reason = "GraphQL endpoint unavailable"
			continue
		}
		q := u.Query()
		q.Set("query", query)
		if len(vars) > 0 {
			encoded, _ := json.Marshal(vars)
			q.Set("variables", string(encoded))
		} else {
			q.Del("variables")
		}
		u.RawQuery = q.Encode()
		op.RequestURL = u.String()
		op.Eligible, op.Resolved, op.Reason = true, true, ""
	}
	return out
}

func graphQLArgumentValue(schema *ast.Schema, typ *ast.Type, raw string) (any, error) {
	if typ.Elem != nil {
		var values []json.RawMessage
		if err := json.Unmarshal([]byte(raw), &values); err != nil {
			return nil, err
		}
		out := []any{}
		for _, v := range values {
			value, err := graphQLJSONValue(schema, typ.Elem, v)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		return out, nil
	}
	switch typ.Name() {
	case "String", "ID":
		return raw, nil
	case "Int":
		return strconv.ParseInt(raw, 10, 32)
	case "Float":
		return strconv.ParseFloat(raw, 64)
	case "Boolean":
		if raw != "true" && raw != "false" {
			return nil, fmt.Errorf("invalid boolean")
		}
		return raw == "true", nil
	}
	def := schema.Types[typ.Name()]
	if def == nil {
		return nil, fmt.Errorf("unknown type")
	}
	if def.Kind == ast.Enum {
		if def.EnumValues.ForName(raw) == nil {
			return nil, fmt.Errorf("invalid enum")
		}
		return raw, nil
	}
	if def.Kind != ast.InputObject {
		return nil, fmt.Errorf("custom scalar needs an explicit adapter")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("invalid input object")
	}
	out := map[string]any{}
	for name, v := range fields {
		field := def.Fields.ForName(name)
		if field == nil {
			return nil, fmt.Errorf("undeclared input field")
		}
		value, err := graphQLJSONValue(schema, field.Type, v)
		if err != nil {
			return nil, err
		}
		out[name] = value
	}
	for _, field := range def.Fields {
		if field.Type.NonNull && field.DefaultValue == nil {
			if _, ok := out[field.Name]; !ok {
				return nil, fmt.Errorf("missing required input field")
			}
		}
	}
	return out, nil
}
func graphQLJSONValue(schema *ast.Schema, typ *ast.Type, raw json.RawMessage) (any, error) {
	if string(raw) == "null" {
		if typ.NonNull {
			return nil, fmt.Errorf("required value is null")
		}
		return nil, nil
	}
	text := string(raw)
	if typ.Elem == nil && (typ.Name() == "String" || typ.Name() == "ID" || schema.Types[typ.Name()] != nil && schema.Types[typ.Name()].Kind == ast.Enum) {
		if err := json.Unmarshal(raw, &text); err != nil {
			return nil, err
		}
	}
	return graphQLArgumentValue(schema, typ, text)
}
