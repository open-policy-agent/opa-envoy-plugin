// Copyright 2019 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package e2e

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa-envoy-plugin/internal"
	"github.com/open-policy-agent/opa-envoy-plugin/plugin"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

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

	cfgJson := fmt.Sprintf(`{
		addr: "%s",
		path:"%s",
		enable-reflection: true
	}`, addr, query)
	cfg, err := internal.Validate(m, []byte(cfgJson))
	if err != nil {
		return nil, err
	}
	m.Register(plugin.PluginName, internal.New(m, cfg))
	if err := m.Start(ctx); err != nil {
		return nil, err
	}
	return m, nil
}
