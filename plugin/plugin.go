// Copyright 2020 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package plugin

import (
	"github.com/open-policy-agent/opa/v1/plugins"

	"github.com/open-policy-agent/opa-envoy-plugin/internal"
)

// AuthZFactory defines the factory for the AuthZ plugin.
type AuthZFactory struct{}

// ExtProcFactory defines the factory for the ExtProc plugin.
type ExtProcFactory struct{}

// Plugin names to register with the OPA plugin manager.
const (
	AuthZPluginName   = "envoy_ext_authz_grpc"
	ExtProcPluginName = "envoy_ext_proc_grpc"
)

// New method for AuthZFactory.
func (AuthZFactory) New(m *plugins.Manager, config interface{}) plugins.Plugin {
	return internal.NewAuthZ(m, config.(*internal.Config))
}

// Validate method for AuthZFactory.
func (AuthZFactory) Validate(m *plugins.Manager, configBytes []byte) (interface{}, error) {
	return internal.Validate(m, configBytes)
}

// New method for ExtProcFactory.
func (ExtProcFactory) New(m *plugins.Manager, config interface{}) plugins.Plugin {
	return internal.NewExtProc(m, config.(*internal.Config))
}

// Validate method for ExtProcFactory.
func (ExtProcFactory) Validate(m *plugins.Manager, configBytes []byte) (interface{}, error) {
	return internal.Validate(m, configBytes)
}
