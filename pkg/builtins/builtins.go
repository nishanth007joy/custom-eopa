// Package builtins provides custom Rego built-in functions for my-custom-eopa.
package builtins

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	eopaBuiltins "github.com/open-policy-agent/eopa/pkg/builtins"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	opaTypes "github.com/open-policy-agent/opa/v1/types"
)

// Built-in function names
const (
	customQueryName     = "custom.query"
	customTransformName = "custom.transform"
	customHashName      = "custom.hash"
)

// Built-in declarations
var (
	customQueryBuiltin = &ast.Builtin{
		Name:        customQueryName,
		Description: "Queries a custom data source with the given request parameters.",
		Decl: opaTypes.NewFunction(
			opaTypes.Args(
				opaTypes.Named("request", opaTypes.NewObject(
					[]*opaTypes.StaticProperty{},
					opaTypes.NewDynamicProperty(opaTypes.S, opaTypes.A),
				)).Description("query parameters as an object"),
			),
			opaTypes.Named("response", opaTypes.NewObject(
				[]*opaTypes.StaticProperty{},
				opaTypes.NewDynamicProperty(opaTypes.S, opaTypes.A),
			)).Description("query result object"),
		),
		Nondeterministic: true,
	}

	customTransformBuiltin = &ast.Builtin{
		Name:        customTransformName,
		Description: "Transforms input data according to a specified operation.",
		Decl: opaTypes.NewFunction(
			opaTypes.Args(
				opaTypes.Named("data", opaTypes.A).Description("data to transform"),
				opaTypes.Named("operation", opaTypes.S).Description("transformation operation: uppercase, lowercase, reverse"),
			),
			opaTypes.Named("result", opaTypes.A).Description("transformed data"),
		),
	}

	customHashBuiltin = &ast.Builtin{
		Name:        customHashName,
		Description: "Computes a simple hash of the input string.",
		Decl: opaTypes.NewFunction(
			opaTypes.Args(
				opaTypes.Named("input", opaTypes.S).Description("string to hash"),
			),
			opaTypes.Named("hash", opaTypes.N).Description("numeric hash value"),
		),
	}
)

func init() {
	// Ensure EOPA builtins are initialized first
	eopaBuiltins.Init()

	// Register all custom built-ins
	registerBuiltin(customQueryBuiltin, customQueryImpl)
	registerBuiltin(customTransformBuiltin, customTransformImpl)
	registerBuiltin(customHashBuiltin, customHashImpl)
}

// registerBuiltin registers a built-in with both EOPA and OPA registries
func registerBuiltin(b *ast.Builtin, fn topdown.BuiltinFunc) {
	// Register with EOPA
	eopaBuiltins.RegisterBuiltin(b)
	eopaBuiltins.RegisterBuiltinFunc(b.Name, fn)

	// Register with OPA core
	ast.RegisterBuiltin(b)
	topdown.RegisterBuiltinFunc(b.Name, fn)
}

// customQueryImpl implements the custom.query built-in
func customQueryImpl(bctx topdown.BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	// Extract request object from arguments
	request, err := ast.JSON(args[0].Value)
	if err != nil {
		return fmt.Errorf("custom.query: failed to parse request: %w", err)
	}

	requestMap, ok := request.(map[string]interface{})
	if !ok {
		return fmt.Errorf("custom.query: request must be an object")
	}

	// Simulate querying a data source
	// In a real implementation, this would connect to your database, API, etc.
	result := map[string]interface{}{
		"status":    "success",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"request":   requestMap,
		"data":      simulateDataQuery(requestMap),
	}

	// Convert result to AST value
	v, err := ast.InterfaceToValue(result)
	if err != nil {
		return fmt.Errorf("custom.query: failed to convert result: %w", err)
	}

	return iter(ast.NewTerm(v))
}

// simulateDataQuery simulates fetching data based on the request
func simulateDataQuery(request map[string]interface{}) interface{} {
	// Example: if querying for a user, return mock user data
	if userID, ok := request["user_id"]; ok {
		userStr := strings.ToLower(fmt.Sprintf("%v", userID))

		// Simulated user database
		users := map[string]map[string]interface{}{
			"alice": {
				"user_id": "alice",
				"name":    "Alice Admin",
				"role":    "admin",
				"active":  true,
				"groups":  []string{"developers", "admins"},
			},
			"bob": {
				"user_id": "bob",
				"name":    "Bob Writer",
				"role":    "writer",
				"active":  true,
				"groups":  []string{"developers"},
			},
			"charlie": {
				"user_id": "charlie",
				"name":    "Charlie Reader",
				"role":    "reader",
				"active":  true,
				"groups":  []string{"viewers"},
			},
			"inactive": {
				"user_id": "inactive",
				"name":    "Inactive User",
				"role":    "admin",
				"active":  false,
				"groups":  []string{"admins"},
			},
		}

		if userData, exists := users[userStr]; exists {
			return userData
		}

		// Unknown user - return minimal data
		return map[string]interface{}{
			"user_id": userID,
			"name":    "Unknown User",
			"role":    "none",
			"active":  false,
			"groups":  []string{},
		}
	}

	// Example: if querying for resources, return mock resources
	if resourceType, ok := request["resource_type"]; ok {
		return map[string]interface{}{
			"type":  resourceType,
			"count": 42,
			"items": []string{"item1", "item2", "item3"},
		}
	}

	// Default: return the request as echo
	return request
}

// customTransformImpl implements the custom.transform built-in
func customTransformImpl(bctx topdown.BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	// Get the data argument
	data, err := ast.JSON(args[0].Value)
	if err != nil {
		return fmt.Errorf("custom.transform: failed to parse data: %w", err)
	}

	// Get the operation argument
	opVal, err := builtins.StringOperand(args[1].Value, 2)
	if err != nil {
		return fmt.Errorf("custom.transform: operation must be a string: %w", err)
	}
	operation := string(opVal)

	// Transform based on operation
	var result interface{}
	switch operation {
	case "uppercase":
		result = transformUppercase(data)
	case "lowercase":
		result = transformLowercase(data)
	case "reverse":
		result = transformReverse(data)
	case "json":
		b, _ := json.Marshal(data)
		result = string(b)
	default:
		return fmt.Errorf("custom.transform: unknown operation %q (valid: uppercase, lowercase, reverse, json)", operation)
	}

	v, err := ast.InterfaceToValue(result)
	if err != nil {
		return fmt.Errorf("custom.transform: failed to convert result: %w", err)
	}

	return iter(ast.NewTerm(v))
}

func transformUppercase(data interface{}) interface{} {
	switch v := data.(type) {
	case string:
		return strings.ToUpper(v)
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = transformUppercase(item)
		}
		return result
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, val := range v {
			result[k] = transformUppercase(val)
		}
		return result
	default:
		return data
	}
}

func transformLowercase(data interface{}) interface{} {
	switch v := data.(type) {
	case string:
		return strings.ToLower(v)
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = transformLowercase(item)
		}
		return result
	case map[string]interface{}:
		result := make(map[string]interface{})
		for k, val := range v {
			result[k] = transformLowercase(val)
		}
		return result
	default:
		return data
	}
}

func transformReverse(data interface{}) interface{} {
	switch v := data.(type) {
	case string:
		runes := []rune(v)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		return string(runes)
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[len(v)-1-i] = item
		}
		return result
	default:
		return data
	}
}

// customHashImpl implements the custom.hash built-in
func customHashImpl(bctx topdown.BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	input, err := builtins.StringOperand(args[0].Value, 1)
	if err != nil {
		return fmt.Errorf("custom.hash: input must be a string: %w", err)
	}

	// Simple FNV-1a inspired hash
	var hash uint64 = 14695981039346656037
	for _, c := range string(input) {
		hash ^= uint64(c)
		hash *= 1099511628211
	}

	v, err := ast.InterfaceToValue(hash)
	if err != nil {
		return fmt.Errorf("custom.hash: failed to convert result: %w", err)
	}

	return iter(ast.NewTerm(v))
}
