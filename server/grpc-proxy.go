// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// A gRPC reverse proxy

package server

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"

	ext_authz "github.com/envoyproxy/data-plane-api/envoy/service/auth/v2alpha"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/util"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const defaultAddr = ":9191"
const defaultQuery = "data.istio.authz.allow"

// Config represents configuration of the plguin.
type Config struct {
	PluginAddr  string `json:"addr"`
	PolicyQuery string `json:"decision"`
}

// Params stores the configuration for a gRPC proxy server instance.
type Params struct {
	Config Config
}

// Plugin implements Envoy's ext_authz Check API.
type Plugin struct {
	manager *plugins.Manager   // plugin manager for storage and service clients
	params  *Params            // gRPC server parameters
	stop    chan chan struct{} // used to signal plugin to stop running
}

// NewConfig returns a new Config object.
func NewConfig() Config {
	return Config{}
}

// NewParams returns a new Params object. It parses the config file provided on
// the command line and sets the appropriate plugin-related fields in the
// plugin config.
func NewParams(bs []byte) (*Params, error) {
	params := Params{}

	if err := util.Unmarshal(bs, &params.Config); err != nil {
		return nil, err
	}

	logrus.WithFields(logrus.Fields{}).Infof("Plugin Config: %+v", params.Config)
	return &params, nil
}

// NewPlugin returns a new Plugin object.
func NewPlugin(manager *plugins.Manager, params *Params) (*Plugin, error) {
	plugin := &Plugin{
		manager: manager,
		params:  params,
		stop:    make(chan chan struct{}),
	}

	return plugin, nil
}

// Start starts the plugin.
func (p *Plugin) Start(ctx context.Context) error {
	go p.startProxyServer()
	return nil
}

// Stop stops the plugin.
func (p *Plugin) Stop(ctx context.Context) {
	done := make(chan struct{})
	p.stop <- done
	_ = <-done
}

func (p *Plugin) startProxyServer() {

	laddr := p.params.Config.PluginAddr
	if laddr == "" {
		laddr = defaultAddr
	}

	query := p.params.Config.PolicyQuery
	if query == "" {
		p.params.Config.PolicyQuery = defaultQuery
	}

	lis, err := net.Listen("tcp", laddr)
	defer lis.Close()

	if err != nil {
		logrus.WithField("err", err).Fatalf("Failed to listen")
	}

	logrus.WithFields(logrus.Fields{
		"addr": laddr,
	}).Infof("Starting gRPC Proxy")

	grpcServer := grpc.NewServer()
	authzServer, err := NewAuthzServer(p)
	if err != nil {
		logrus.WithField("err", err).Fatalf("Unable to start server")
	}

	ext_authz.RegisterAuthorizationServer(grpcServer, authzServer)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			logrus.WithField("err", err).Fatalf("Failed to serve")
		}
	}()

	// Use a buffered channel so we don't miss any signals
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM)
	s := <-c
	logrus.WithFields(logrus.Fields{
		"signal": s,
	}).Infof("Got signal")
}
