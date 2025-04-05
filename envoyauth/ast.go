package envoyauth

import (
	"github.com/open-policy-agent/opa/v1/ast"
)

func keyValue(k, v string) [2]*ast.Term {
	return [2]*ast.Term{{Value: ast.String(k)}, {Value: ast.String(v)}}
}
