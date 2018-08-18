// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"

	"github.com/open-policy-agent/opa-istio-plugin/server"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/runtime"
)

func init() {

	runtime.RegisterPlugin("envoy.ext_authz.grpc", func(m *plugins.Manager, config []byte) (plugins.Plugin, error) {
		// Create the plugin which implements Istio Mixer's Check api
		params, err := server.NewParams(config)
		if err != nil {
			return nil, err
		}
		return server.NewPlugin(m, params)
	})
}

func main() {
	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
