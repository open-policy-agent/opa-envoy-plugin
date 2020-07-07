// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"

	"github.com/open-policy-agent/opa-istio-plugin/plugin"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/runtime"
)

func main() {
	runtime.RegisterPlugin("envoy.ext_authz.grpc", plugin.Factory{}) // for backwards compatibility
	runtime.RegisterPlugin(plugin.PluginName, plugin.Factory{})

	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
