package envoyextproc

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/config"
	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/topdown/builtins"
	iCache "github.com/open-policy-agent/opa/topdown/cache"
	"github.com/open-policy-agent/opa/topdown/print"
	"github.com/open-policy-agent/opa/tracing"
)

// EvalContext - This is an SPI that has to be provided if the envoy external authorization
// is used from outside the plugin, i.e. as a Go module
type EvalContext interface {
	ParsedQuery() ast.Body
	Store() storage.Store
	Compiler() *ast.Compiler
	Runtime() *ast.Term
	InterQueryBuiltinCache() iCache.InterQueryCache
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
			logger.WithFields(map[string]interface{}{"err": err}).Error("Unable to start new storage transaction.")
			return err
		}
		defer txnClose(ctx, err)
		result.Txn = txn
	}

	err = getRevision(ctx, evalContext.Store(), result.Txn, result)
	if err != nil {
		return err
	}

	result.TxnID = result.Txn.ID()

	logger.WithFields(map[string]interface{}{
		"input": input,
		"query": evalContext.ParsedQuery().String(),
		"txn":   result.TxnID,
	}).Debug("Executing policy query.")

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

	ph := hook{logger: logger.WithFields(map[string]interface{}{"decision-id": result.DecisionID})}

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
		return fmt.Errorf("undefined decision")
	case len(rs) > 1:
		return fmt.Errorf("multiple evaluation results")
	}

	result.NDBuiltinCache = ndbCache
	result.Decision = rs[0].Expressions[0].Value
	return nil
}

func getRevision(ctx context.Context, store storage.Store, txn storage.Transaction, result *EvalResult) error {
	revisions := map[string]string{}

	names, err := bundle.ReadBundleNamesFromStore(ctx, store, txn)
	if err != nil && !storage.IsNotFound(err) {
		return err
	}

	for _, name := range names {
		r, err := bundle.ReadBundleRevisionFromStore(ctx, store, txn, name)
		if err != nil && !storage.IsNotFound(err) {
			return err
		}
		revisions[name] = r
	}

	// Check legacy bundle manifest in the store
	revision, err := bundle.LegacyReadRevisionFromStore(ctx, store, txn)
	if err != nil && !storage.IsNotFound(err) {
		return err
	}

	result.Revisions = revisions
	result.Revision = revision
	return nil
}

type hook struct {
	logger logging.Logger
}

func (h *hook) Print(pctx print.Context, msg string) error {
	h.logger.Info("%v: %s", pctx.Location, msg)
	return nil
}
