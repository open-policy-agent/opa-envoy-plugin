// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package main

import (
	"os"

	"github.com/open-policy-agent/opa-envoy-plugin/plugin"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/runtime"
	"github.com/open-policy-agent/opa/v1/types"

	"github.com/open-policy-agent/opa-envoy-plugin/airline_dc"
)

func main() {
	runtime.RegisterPlugin("envoy.ext_authz.grpc", plugin.Factory{}) // for backwards compatibility
	runtime.RegisterPlugin(plugin.PluginName, plugin.Factory{})

	rego.RegisterBuiltin1(
		&rego.Function{
			Name:             "parse_xml_dc",
			Decl:             types.NewFunction(types.Args(types.S), types.A),
			Memoize:          true,
			Nondeterministic: false,
		},
		airline_dc.ParseXmlDc,
	)

	if err := cmd.RootCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
