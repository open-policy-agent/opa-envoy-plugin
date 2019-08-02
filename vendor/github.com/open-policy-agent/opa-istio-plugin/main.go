// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package main

import (
	"github.com/open-policy-agent/opa-istio-plugin/internal"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/runtime"
)

// Factory defines the interface OPA uses to instantiate a plugin.
type Factory struct{}

// New returns the object initialized with a valid plugin configuration.
func (Factory) New(m *plugins.Manager, config interface{}) plugins.Plugin {
	return internal.New(m, config.(*internal.Config))
}

// Validate returns a valid configuration to instantiate the plugin.
func (Factory) Validate(m *plugins.Manager, config []byte) (interface{}, error) {
	return internal.Validate(m, config)
}

// Init register plugin factory with OPA.
func Init() error {
	runtime.RegisterPlugin("envoy.ext_authz.grpc", Factory{}) // for backwards compatibility
	runtime.RegisterPlugin("envoy_ext_authz_grpc", Factory{})
	return nil
}
