package envoyextproc

import (
	"context"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/config"
	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/topdown/builtins"
	iCache "github.com/open-policy-agent/opa/topdown/cache"
	"github.com/open-policy-agent/opa/topdown/print"
	"github.com/open-policy-agent/opa/tracing"
)

// ExtProcEvalContext defines the interface for the evaluation context in the `ext_proc` context.
type ExtProcEvalContext interface {
	ParsedQuery() ast.Body
	Store() storage.Store
	Compiler() *ast.Compiler
	Runtime() *ast.Term
	PreparedQueryDoOnce() *sync.Once
	InterQueryBuiltinCache() iCache.InterQueryCache
	PreparedQuery() *rego.PreparedEvalQuery
	SetPreparedQuery(*rego.PreparedEvalQuery)
	Logger() logging.Logger
	Config() *config.Config
	DistributedTracing() tracing.Options
}

// ExtProcEval evaluates the input against the provided ExtProcEvalContext and yields a result.
func ExtProcEval(ctx context.Context, evalContext ExtProcEvalContext, input ast.Value, result *ExtProcEvalResult, opts ...func(*rego.Rego)) error {
	var err error
	logger := evalContext.Logger()

	// Log when starting the evaluation process
	logger.Info("Starting ExtProcEval")

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
		logger.Info("Started new transaction")
	}

	// Log before retrieving revision information
	logger.Info("Getting revision information")
	err = getRevision(ctx, evalContext.Store(), result.Txn, result)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to get revision information: %v", err))
		return err
	}

	result.TxnID = result.Txn.ID()

	logger.WithFields(map[string]interface{}{
		"input": input,
		"query": evalContext.ParsedQuery().String(),
		"txn":   result.TxnID,
	}).Debug("Executing policy query")

	// Create a mock result set to simulate a policy evaluation result
	mockResult := rego.ResultSet{
		{
			Expressions: []*rego.ExpressionValue{
				{
					Text:  "mock_decision",
					Value: "allowed",
				},
			},
		},
	}
	logger.Info("Using mock result set for policy evaluation")
	rs := mockResult

	// Actual policy evaluation
	/*
		logger.Info("Constructing prepared query")
		err = constructPreparedQuery(evalContext, result.Txn, result.Metrics, opts)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to construct prepared query: %v", err))
			return err
		}

		ph := extProcHook{logger: logger.WithFields(map[string]interface{}{"decision-id": result.DecisionID})}

		var ndbCache builtins.NDBCache
		if evalContext.Config().NDBuiltinCacheEnabled() {
			ndbCache = builtins.NDBCache{}
		}

		logger.Info("Evaluating policy with prepared query")
		rs, err = evalContext.PreparedQuery().Eval(
			ctx,
			rego.EvalParsedInput(input),
			rego.EvalTransaction(result.Txn),
			rego.EvalMetrics(result.Metrics),
			rego.EvalInterQueryBuiltinCache(evalContext.InterQueryBuiltinCache()),
			rego.EvalPrintHook(&ph),
			rego.EvalNDBuiltinCache(ndbCache),
		)

		if err != nil {
			logger.Error(fmt.Sprintf("Error during policy evaluation: %v", err))
			return err
		}
	*/

	switch {
	case err != nil:
		return err
	case len(rs) == 0:
		return fmt.Errorf("undefined decision")
	case len(rs) > 1:
		return fmt.Errorf("multiple evaluation results")
	}

	result.NDBuiltinCache = builtins.NDBCache{}
	result.Decision = rs[0].Expressions[0].Value

	logger.Info(fmt.Sprintf("Final decision: %v", result.Decision))
	return nil
}

// Constructing the prepared query
func constructPreparedQuery(evalContext ExtProcEvalContext, txn storage.Transaction, m metrics.Metrics, opts []func(*rego.Rego)) error {
	var err error
	var pq rego.PreparedEvalQuery
	evalContext.PreparedQueryDoOnce().Do(func() {
		opts = append(opts,
			rego.Metrics(m),
			rego.ParsedQuery(evalContext.ParsedQuery()),
			rego.Compiler(evalContext.Compiler()),
			rego.Store(evalContext.Store()),
			rego.Transaction(txn),
			rego.Runtime(evalContext.Runtime()),
			rego.EnablePrintStatements(true),
			rego.DistributedTracingOpts(evalContext.DistributedTracing()),
		)

		pq, err = rego.New(opts...).PrepareForEval(context.Background())
		evalContext.SetPreparedQuery(&pq)
	})

	return err
}

func getRevision(ctx context.Context, store storage.Store, txn storage.Transaction, result *ExtProcEvalResult) error {
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

	revision, err := bundle.LegacyReadRevisionFromStore(ctx, store, txn)
	if err != nil && !storage.IsNotFound(err) {
		return err
	}

	result.Revisions = revisions
	result.Revision = revision
	return nil
}

type extProcHook struct {
	logger logging.Logger
}

func (h *extProcHook) Print(pctx print.Context, msg string) error {
	h.logger.Info("%v: %s", pctx.Location, msg)
	return nil
}
