package envoyauth

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/plugins/logs"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	iCache "github.com/open-policy-agent/opa/topdown/cache"
)

func TestGetRevisionLegacy(t *testing.T) {
	store := inmem.New()
	ctx := context.Background()

	result := EvalResult{}

	tb := bundle.Manifest{
		Revision: "abc123",
		Roots:    &[]string{"/a/b", "/a/c"},
	}

	// write a "legacy" manifest
	err := storage.Txn(ctx, store, storage.WriteParams, func(txn storage.Transaction) error {
		if err := bundle.LegacyWriteManifestToStore(ctx, store, txn, tb); err != nil {
			t.Fatalf("Failed to write manifest to store: %s", err)
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Unexpected error finishing transaction: %s", err)
	}

	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)

	err = getRevision(ctx, store, txn, &result)
	if err != nil {
		t.Fatal(err)
	}

	expected := "abc123"
	if result.Revision != "abc123" {
		t.Fatalf("Expected revision %v but got %v", expected, result.Revision)
	}

	if len(result.Revisions) != 0 {
		t.Fatal("Unexpected multiple bundles")
	}
}

func TestGetRevisionMulti(t *testing.T) {
	store := inmem.New()
	ctx := context.Background()

	result := EvalResult{}

	bundles := map[string]bundle.Manifest{
		"bundle1": {
			Revision: "abc123",
			Roots:    &[]string{"/a/b", "/a/c"},
		},
		"bundle2": {
			Revision: "def123",
			Roots:    &[]string{"/x/y", "/z"},
		},
	}

	// write bundles
	for name, manifest := range bundles {
		err := storage.Txn(ctx, store, storage.WriteParams, func(txn storage.Transaction) error {
			err := bundle.WriteManifestToStore(ctx, store, txn, name, manifest)
			if err != nil {
				t.Fatalf("Failed to write manifest to store: %s", err)
			}
			return err
		})
		if err != nil {
			t.Fatalf("Unexpected error finishing transaction: %s", err)
		}
	}

	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)

	err := getRevision(ctx, store, txn, &result)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Revisions) != 2 {
		t.Fatalf("Expected two bundles but got %v", len(result.Revisions))
	}

	expected := map[string]string{"bundle1": "abc123", "bundle2": "def123"}
	if !reflect.DeepEqual(result.Revisions, expected) {
		t.Fatalf("Expected result: %v, got: %v", expected, result.Revisions)
	}

	if result.Revision != "" {
		t.Fatalf("Unexpected revision %v", result.Revision)
	}

}

func TestEval(t *testing.T) {
	ctx := context.Background()
	server, err := testAuthzServer()
	if err != nil {
		t.Fatal(err)
	}

	parsedBody := make(map[string]interface{})
	parsedBody["firstname"] = "foo"
	parsedBody["lastname"] = "bar"

	input := make(map[string]interface{})
	input["parsed_body"] = parsedBody

	inputValue, err := ast.InterfaceToValue(input)
	if err != nil {
		t.Fatal(err)
	}

	err = Eval(ctx, server, inputValue, &EvalResult{})
	if err != nil {
		t.Fatal(err)
	}

	// include transaction in the result object
	er := &EvalResult{}
	var txn storage.Transaction
	var txnClose TransactionCloser

	txn, txnClose, err = er.GetTxn(ctx, server.Store())
	if err != nil {
		t.Fatal(err)
	}

	defer txnClose(ctx, err)
	er.Txn = txn

	err = Eval(ctx, server, inputValue, er)
	if err != nil {
		t.Fatal(err)
	}
}

func testAuthzServer() (*mockExtAuthzGrpcServer, error) {

	module := `
		package envoy.authz

		default allow = false

        allow {
			input.parsed_body.firstname == "foo"
			input.parsed_body.lastname == "bar"
		}`

	ctx := context.Background()
	store := inmem.New()
	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)
	store.UpsertPolicy(ctx, txn, "example.rego", []byte(module))
	store.Commit(ctx, txn)

	m, err := plugins.New([]byte{}, "test", store)
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
	query := "data." + strings.Replace(path, "/", ".", -1)
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
	cfg                 Config
	manager             *plugins.Manager
	preparedQuery       *rego.PreparedEvalQuery
	preparedQueryDoOnce *sync.Once
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

func (m *mockExtAuthzGrpcServer) PreparedQueryDoOnce() *sync.Once {
	return m.preparedQueryDoOnce
}

func (m *mockExtAuthzGrpcServer) InterQueryBuiltinCache() iCache.InterQueryCache {
	return nil
}

func (m *mockExtAuthzGrpcServer) PreparedQuery() *rego.PreparedEvalQuery {
	return m.preparedQuery
}

func (m *mockExtAuthzGrpcServer) SetPreparedQuery(pq *rego.PreparedEvalQuery) {
	m.preparedQuery = pq
}

type testPlugin struct {
	events []logs.EventV1
}

func (p *testPlugin) Start(context.Context) error {
	return nil
}

func (p *testPlugin) Stop(context.Context) {
}

func (p *testPlugin) Reconfigure(context.Context, interface{}) {
}

func (p *testPlugin) Log(_ context.Context, event logs.EventV1) error {
	p.events = append(p.events, event)
	return nil
}
