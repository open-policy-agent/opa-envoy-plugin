package envoyauth

import (
	"context"
	"errors"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/config"
	"github.com/open-policy-agent/opa/v1/logging"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	iCache "github.com/open-policy-agent/opa/v1/topdown/cache"
	"github.com/open-policy-agent/opa/v1/topdown/print"
	"github.com/open-policy-agent/opa/v1/tracing"
)

// EvalContext - This is an SPI that has to be provided if the envoy external authorization
// is used from outside the plugin, i.e. as a Go module
type EvalContext interface {
	ParsedQuery() ast.Body
	Store() storage.Store
	Compiler() *ast.Compiler
	Runtime() *ast.Term
	InterQueryBuiltinCache() iCache.InterQueryCache
	InterQueryBuiltinValueCache() iCache.InterQueryValueCache
	Logger() logging.Logger
	Config() *config.Config
	DistributedTracing() tracing.Options
	CreatePreparedQueryOnce(opts PrepareQueryOpts) (*rego.PreparedEvalQuery, error)
}

// PrepareQueryOpts - Options to prepare a Rego query to be passed to the CreatePreparedQueryOnce method
type PrepareQueryOpts struct {
	Opts        []func(*rego.Rego)
	PrepareOpts []rego.PrepareOption
}

// Eval - Evaluates an input against a provided EvalContext and yields result
func Eval(ctx context.Context, evalContext EvalContext, input ast.Value, result *EvalResult, evalOpts ...rego.EvalOption) error {
	var err error
	logger := evalContext.Logger()

	if result.Txn == nil {
		var txn storage.Transaction
		var txnClose TransactionCloser
		txn, txnClose, err = result.GetTxn(ctx, evalContext.Store())
		if err != nil {
			logger.WithFields(map[string]any{"err": err}).Error("Unable to start new storage transaction.")
			return err
		}
		defer func() {
			_ = txnClose(ctx, err)
		}()
		result.Txn = txn
	}

	result.TxnID = result.Txn.ID()

	if logger.GetLevel() == logging.Debug {
		logger.WithFields(map[string]any{
			"input": input,
			"query": evalContext.ParsedQuery().String(),
			"txn":   result.TxnID,
		}).Debug("Executing policy query.")
	}

	pq, err := evalContext.CreatePreparedQueryOnce(
		PrepareQueryOpts{
			Opts: []func(*rego.Rego){
				rego.Metrics(result.Metrics),
				rego.ParsedQuery(evalContext.ParsedQuery()),
				rego.Compiler(evalContext.Compiler()),
				rego.Store(evalContext.Store()),
				rego.Transaction(result.Txn),
				rego.Runtime(evalContext.Runtime()),
				rego.EnablePrintStatements(true),
				rego.DistributedTracingOpts(evalContext.DistributedTracing()),
			},
		})
	if err != nil {
		return err
	}

	ph := hook{logger: logger.WithFields(map[string]any{"decision-id": result.DecisionID})}

	var ndbCache builtins.NDBCache
	if evalContext.Config().NDBuiltinCacheEnabled() {
		ndbCache = builtins.NDBCache{}
	}

	evalOpts = append(
		[]rego.EvalOption{
			rego.EvalParsedInput(input),
			rego.EvalTransaction(result.Txn),
			rego.EvalMetrics(result.Metrics),
			rego.EvalInterQueryBuiltinCache(evalContext.InterQueryBuiltinCache()),
			rego.EvalInterQueryBuiltinValueCache(evalContext.InterQueryBuiltinValueCache()),
			rego.EvalPrintHook(&ph),
			rego.EvalNDBuiltinCache(ndbCache),
		},
		evalOpts...,
	)

	var rs rego.ResultSet
	rs, err = pq.Eval(
		ctx,
		evalOpts...,
	)

	switch {
	case err != nil:
		return err
	case len(rs) == 0:
		return errors.New("undefined decision")
	case len(rs) > 1:
		return errors.New("multiple evaluation results")
	}

	result.NDBuiltinCache = ndbCache
	result.Decision = rs[0].Expressions[0].Value

	return err
}

type hook struct {
	logger logging.Logger
}

func (h *hook) Print(pctx print.Context, msg string) error {
	h.logger.Info("%v: %s", pctx.Location, msg)
	return nil
}
