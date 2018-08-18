// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"

	"github.com/open-policy-agent/opa-istio-plugin/internal"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/runtime"
)

func init() {
	runtime.RegisterPlugin("envoy.ext_authz.grpc", func(m *plugins.Manager, config []byte) (plugins.Plugin, error) {
		return internal.New(m, config)
	})
}

func main() {
	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
