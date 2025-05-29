package e2e

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa-envoy-plugin/internal"
	"github.com/open-policy-agent/opa-envoy-plugin/plugin"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/plugins/logs"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

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

// TestAuthzServerWithWithOpts creates a new AuthzServer
// that implements the Envoy ext_authz API. Options for
// plugins.Manager can/should be customized for the test case.
func TestAuthzServerWithWithOpts(module string, path string, addr string, opts ...func(*plugins.Manager)) (*plugins.Manager, error) {
	ctx := context.Background()
	store := inmem.New()
	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)
	store.UpsertPolicy(ctx, txn, "example.rego", []byte(module))
	store.Commit(ctx, txn)
	m, err := plugins.New([]byte{}, "test", store, opts...)
	if err != nil {
		return nil, err
	}
	query := "data." + strings.Replace(path, "/", ".", -1)

	cfgJSON := fmt.Sprintf(`{
		addr: "%s",
		path:"%s",
		enable-reflection: true
	}`, addr, query)
	cfg, err := internal.Validate(m, []byte(cfgJSON))
	if err != nil {
		return nil, err
	}
	m.Register(plugin.PluginName, internal.New(m, cfg))

	m.Register("test_plugin", &testPlugin{})
	config, err := logs.ParseConfig([]byte(`{"plugin": "test_plugin"}`), nil, []string{"test_plugin"})

	if err != nil {
		return nil, err
	}
	config.ConsoleLogs = true

	logPlugin := logs.New(config, m)
	m.Register(logs.Name, logPlugin)

	if err := m.Start(ctx); err != nil {
		return nil, err
	}
	return m, nil
}
