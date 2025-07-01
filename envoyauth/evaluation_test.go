package envoyauth

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/config"
	"github.com/open-policy-agent/opa/v1/logging"
	loggingtest "github.com/open-policy-agent/opa/v1/logging/test"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/plugins/logs"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	iCache "github.com/open-policy-agent/opa/v1/topdown/cache"
	"github.com/open-policy-agent/opa/v1/topdown/print"
	"github.com/open-policy-agent/opa/v1/tracing"
)

type testPrintHook struct {
	printed string
}

func (h *testPrintHook) Print(pctx print.Context, msg string) error {
	h.printed = msg
	return nil
}

func TestEval(t *testing.T) {
	ctx := context.Background()

	logger := loggingtest.New()
	logger.SetLevel(logging.Debug)
	server, err := testAuthzServer(logger)
	if err != nil {
		t.Fatal(err)
	}

	inputValue := ast.MustInterfaceToValue(map[string]any{
		"parsed_body": map[string]any{
			"firstname": "foo",
			"lastname":  "bar",
		},
	})

	res, _, _ := NewEvalResult()
	if err := Eval(ctx, server, inputValue, res); err != nil {
		t.Fatal(err)
	}

	logs := logger.Entries()
	if exp, act := 3, len(logs); exp != act {
		t.Fatalf("expected %d logs, got %d: %v", exp, act, logs)
	}
	if exp, act := logging.Info, logs[0].Level; exp != act {
		t.Errorf("expected log level info, got %d", act)
	}
	if exp, act := "Starting decision logger.", logs[0].Message; exp != act {
		t.Errorf("expected log message %q, got %q", exp, act)
	}
	if exp, act := logging.Debug, logs[1].Level; exp != act {
		t.Errorf("expected log level debug, got %d", act)
	}
	if exp, act := "Executing policy query.", logs[1].Message; exp != act {
		t.Errorf("expected log message %q, got %q", exp, act)
	}
	if exp, act := logging.Info, logs[2].Level; exp != act {
		t.Errorf("expected log level info, got %d", act)
	}
	if exp, act := `example.rego:9: {"firstname": "foo", "lastname": "bar"}`, logs[2].Message; exp != act {
		t.Errorf("expected log message %q, got %q", exp, act)
	}
	if exp, act := res.DecisionID, logs[2].Fields["decision-id"]; exp != act {
		t.Errorf("expected log field decision-id %q, got %q", exp, act)
	}

	// include transaction in the result object
	er, _, _ := NewEvalResult()
	var txn storage.Transaction
	var txnClose TransactionCloser

	txn, txnClose, err = er.GetTxn(ctx, server.Store())
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		_ = txnClose(ctx, err)
	}()

	er.Txn = txn

	err = Eval(ctx, server, inputValue, er)
	if err != nil {
		t.Fatal(err)
	}

	hook := testPrintHook{}

	erp, _, _ := NewEvalResult()
	if err := Eval(ctx, server, inputValue, erp, rego.EvalPrintHook(&hook)); err != nil {
		t.Fatal(err)
	}

	if exp, act := "{\"firstname\": \"foo\", \"lastname\": \"bar\"}", hook.printed; exp != act {
		t.Errorf("expected last printed message to be %q, got %q", exp, act)
	}
}

func testAuthzServer(logger logging.Logger) (*mockExtAuthzGrpcServer, error) {

	module := `
		package envoy.authz

		default allow = false

		allow if {
			input.parsed_body.firstname == "foo"
			input.parsed_body.lastname == "bar"
			print(input.parsed_body)
		}`

	ctx := context.Background()
	store := inmem.New()
	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)
	if err := store.UpsertPolicy(ctx, txn, "example.rego", []byte(module)); err != nil {
		return nil, err
	}
	if err := store.Commit(ctx, txn); err != nil {
		return nil, err
	}

	m, err := plugins.New([]byte{}, "test", store,
		plugins.EnablePrintStatements(true),
		plugins.Logger(logger),
	)
	if err != nil {
		return nil, err
	}

	m.Register("test_plugin", &testPlugin{})
	config, err := logs.ParseConfig([]byte(`{"plugin": "test_plugin"}`), nil, []string{"test_plugin"})
	if err != nil {
		return nil, err
	}

	plugin := logs.New(config, m)
	m.Register(logs.Name, plugin)

	if err := m.Start(ctx); err != nil {
		return nil, err
	}

	path := "envoy/authz/allow"
	query := "data." + strings.ReplaceAll(path, "/", ".")
	parsedQuery, err := ast.ParseBody(query)
	if err != nil {
		return nil, err
	}

	cfg := Config{
		Addr:        ":0",
		Path:        path,
		parsedQuery: parsedQuery,
	}

	return &mockExtAuthzGrpcServer{
		cfg:                 cfg,
		manager:             m,
		preparedQueryDoOnce: new(sync.Once),
		//	interQueryBuiltinCache: iCache.NewInterQueryCache(m.InterQueryBuiltinCacheConfig()),
	}, nil
}

type Config struct {
	Addr        string `json:"addr"`
	Path        string `json:"path"`
	parsedQuery ast.Body
}

type mockExtAuthzGrpcServer struct {
	cfg                    Config
	manager                *plugins.Manager
	preparedQuery          *rego.PreparedEvalQuery
	preparedQueryDoOnce    *sync.Once
	preparedQueryErr       error
	distributedTracingOpts tracing.Options
}

func (m *mockExtAuthzGrpcServer) ParsedQuery() ast.Body {
	return m.cfg.parsedQuery
}

func (m *mockExtAuthzGrpcServer) Store() storage.Store {
	return m.manager.Store
}

func (m *mockExtAuthzGrpcServer) Compiler() *ast.Compiler {
	return m.manager.GetCompiler()
}

func (m *mockExtAuthzGrpcServer) Runtime() *ast.Term {
	return m.manager.Info
}

func (m *mockExtAuthzGrpcServer) Config() *config.Config {
	return m.manager.Config
}

func (m *mockExtAuthzGrpcServer) PreparedQueryDoOnce() *sync.Once {
	return m.preparedQueryDoOnce
}

func (*mockExtAuthzGrpcServer) InterQueryBuiltinCache() iCache.InterQueryCache {
	return nil
}

func (m *mockExtAuthzGrpcServer) PreparedQuery() *rego.PreparedEvalQuery {
	return m.preparedQuery
}

func (m *mockExtAuthzGrpcServer) SetPreparedQuery(pq *rego.PreparedEvalQuery) {
	m.preparedQuery = pq
}

func (m *mockExtAuthzGrpcServer) Logger() logging.Logger {
	return m.manager.Logger()
}

func (m *mockExtAuthzGrpcServer) DistributedTracing() tracing.Options {
	return m.distributedTracingOpts
}

func (m *mockExtAuthzGrpcServer) CreatePreparedQueryOnce(opts PrepareQueryOpts) (*rego.PreparedEvalQuery, error) {
	m.preparedQueryDoOnce.Do(func() {
		pq, err := rego.New(opts.Opts...).PrepareForEval(context.Background())

		m.preparedQuery = &pq
		m.preparedQueryErr = err
	})

	return m.preparedQuery, m.preparedQueryErr
}

type testPlugin struct {
	events []logs.EventV1
}

func (*testPlugin) Start(context.Context) error {
	return nil
}

func (*testPlugin) Stop(context.Context) {
}

func (*testPlugin) Reconfigure(context.Context, any) {
}

func (p *testPlugin) Log(_ context.Context, event logs.EventV1) error {
	p.events = append(p.events, event)
	return nil
}
