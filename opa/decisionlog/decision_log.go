package decisionlog

import (
	"context"

	"github.com/open-policy-agent/opa-envoy-plugin/envoyauth"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/plugins/logs"
	"github.com/open-policy-agent/opa/v1/server"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/topdown"
)

type internalError struct {
	Message string `json:"message"`
}

func (e *internalError) Error() string {
	return e.Message
}

// LogDecision - Logs a decision log event
func LogDecision(ctx context.Context, plugin *logs.Plugin, info *server.Info, result *envoyauth.EvalResult, err error) error {
	info.Revision = result.Revision

	bundles := make(map[string]server.BundleInfo, len(result.Revisions))
	for name, rev := range result.Revisions {
		bundles[name] = server.BundleInfo{Revision: rev}
	}
	info.Bundles = bundles

	info.DecisionID = result.DecisionID
	info.Metrics = result.Metrics
	info.Txn = result.Txn

	if err != nil {
		switch err.(type) {
		case *storage.Error, *ast.Error, ast.Errors:
			break
		case *topdown.Error:
			if topdown.IsCancel(err) {
				err = &topdown.Error{
					Code:    topdown.CancelErr,
					Message: "context deadline reached during query execution",
				}
			}
		default:
			// Wrap errors that may not serialize to JSON well (e.g., fmt.Errorf, etc.)
			err = &internalError{Message: err.Error()}
		}
		info.Error = err
	} else {
		var x interface{}
		if result != nil {
			x = result.Decision
		}
		info.Results = &x
	}

	return plugin.Log(ctx, info)
}
