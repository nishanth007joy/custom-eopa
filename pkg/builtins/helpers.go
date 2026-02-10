package builtins

import (
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
)

// StringOperand extracts a string value from an AST Value
func StringOperand(v ast.Value, pos int) (ast.String, error) {
	s, ok := v.(ast.String)
	if !ok {
		return "", fmt.Errorf("operand %d must be a string, got %T", pos, v)
	}
	return s, nil
}

// NumberOperand extracts a number value from an AST Value
func NumberOperand(v ast.Value, pos int) (ast.Number, error) {
	n, ok := v.(ast.Number)
	if !ok {
		return "", fmt.Errorf("operand %d must be a number, got %T", pos, v)
	}
	return n, nil
}

// ObjectOperand extracts an object value from an AST Value
func ObjectOperand(v ast.Value, pos int) (ast.Object, error) {
	o, ok := v.(ast.Object)
	if !ok {
		return nil, fmt.Errorf("operand %d must be an object, got %T", pos, v)
	}
	return o, nil
}

// ArrayOperand extracts an array value from an AST Value
func ArrayOperand(v ast.Value, pos int) (*ast.Array, error) {
	a, ok := v.(*ast.Array)
	if !ok {
		return nil, fmt.Errorf("operand %d must be an array, got %T", pos, v)
	}
	return a, nil
}
