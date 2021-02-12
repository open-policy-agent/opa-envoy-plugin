package envoyauth

import (
	"context"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	iCache "github.com/open-policy-agent/opa/topdown/cache"
	"github.com/sirupsen/logrus"
)

//EvalContext - This is an SPI that has to be provided if the envoy external authorization
// is used from outside the plugin, i.e. as a Go module
type EvalContext interface {
	ParsedQuery() ast.Body
	Store() storage.Store
	Compiler() *ast.Compiler
	Runtime() *ast.Term
	PreparedQueryDoOnce() *sync.Once
	InterQueryBuiltinCache() iCache.InterQueryCache
	PreparedQuery() *rego.PreparedEvalQuery
	SetPreparedQuery(*rego.PreparedEvalQuery)
}

//Eval - Evaluates an input against a provided EvalContext and yields result
func Eval(ctx context.Context, evalContext EvalContext, input ast.Value, result *EvalResult, opts ...func(*rego.Rego)) error {

	err := storage.Txn(ctx, evalContext.Store(), storage.TransactionParams{}, func(txn storage.Transaction) error {
		err := getRevision(ctx, evalContext.Store(), txn, result)
		if err != nil {
			return err
		}

		result.TxnID = txn.ID()

		logrus.WithFields(logrus.Fields{
			"input": input,
			"query": evalContext.ParsedQuery().String(),
			"txn":   result.TxnID,
		}).Debug("Executing policy query.")

		err = constructPreparedQuery(evalContext, txn, result.Metrics, opts)
		if err != nil {
			return err
		}

		rs, err := evalContext.PreparedQuery().Eval(
			ctx,
			rego.EvalParsedInput(input),
			rego.EvalTransaction(txn),
			rego.EvalMetrics(result.Metrics),
			rego.EvalInterQueryBuiltinCache(evalContext.InterQueryBuiltinCache()),
		)

		if err != nil {
			return err
		} else if len(rs) == 0 {
			return fmt.Errorf("undefined decision")
		} else if len(rs) > 1 {
			return fmt.Errorf("multiple evaluation results")
		}

		result.Decision = rs[0].Expressions[0].Value
		return nil
	})

	return err
}

func constructPreparedQuery(evalContext EvalContext, txn storage.Transaction, m metrics.Metrics, opts []func(*rego.Rego)) error {
	var err error
	var pq rego.PreparedEvalQuery

	evalContext.PreparedQueryDoOnce().Do(func() {
		opts = append(opts,
			rego.Metrics(m),
			rego.ParsedQuery(evalContext.ParsedQuery()),
			rego.Compiler(evalContext.Compiler()),
			rego.Store(evalContext.Store()),
			rego.Transaction(txn),
			rego.Runtime(evalContext.Runtime()))

		r := rego.New(opts...)

		pq, err = r.PrepareForEval(context.Background())
		evalContext.SetPreparedQuery(&pq)
	})

	return err
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
