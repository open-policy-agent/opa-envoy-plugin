// Copyright 2020 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package plugin

import (
	"github.com/open-policy-agent/opa/v1/plugins"

	"github.com/open-policy-agent/opa-envoy-plugin/internal"
)

// Factory defines the interface OPA uses to instantiate a plugin.
type Factory struct{}

// ExtProcFactory defines the factory for the ExtProc plugin.
type ExtProcFactory struct{}

// Plugin names to register with the OPA plugin manager.
const (
	PluginName        = internal.PluginName
	ExtProcPluginName = "envoy_ext_proc_grpc"
)

// New returns the object initialized with a valid plugin configuration.
func (Factory) New(m *plugins.Manager, config interface{}) plugins.Plugin {
	return internal.New(m, config.(*internal.Config))
}

// Validate returns a valid configuration to instantiate the plugin.
func (Factory) Validate(m *plugins.Manager, configBytes []byte) (interface{}, error) {
	return internal.Validate(m, configBytes)
}

// New returns the object initialized with a valid plugin configuration.
func (ExtProcFactory) New(m *plugins.Manager, config interface{}) plugins.Plugin {
	return internal.NewExtProc(m, config.(*internal.Config))
}

// Validate returns a valid configuration to instantiate the plugin.
func (ExtProcFactory) Validate(m *plugins.Manager, configBytes []byte) (interface{}, error) {
	return internal.Validate(m, configBytes)
}
