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

	mixerpb "github.com/istio/api/mixer/v1"
	"github.com/mwitkow/grpc-proxy/proxy"
	"github.com/open-policy-agent/opa-istio-plugin/utils"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/util"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// default listening address for the gRPC server
const defaultAddr = ":50051"

// default policy query
const defaultQuery = "data.istio.authz.allow"

// Config represents configuration of the plguin.
type Config struct {
	PluginAddr  string `json:"plugin_addr"`
	PolicyQuery string `json:"policy_query"`
}

// Params stores the configuration for a gRPC proxy server instance
type Params struct {
	Config Config
}

// Plugin implements Istio Mixer's Check api
type Plugin struct {
	manager *plugins.Manager   // plugin manager for storage and service clients
	params  *Params            // gRPC server parameters
	stop    chan chan struct{} // used to signal plugin to stop running
}

// NewConfig returns a new Config object
func NewConfig() Config {
	return Config{}
}

// NewParams returns a new Params object.
// It parses the config file provided on the command line
// and sets the appropriate plugin-related fields in the plugin config
func NewParams(bs []byte) (*Params, error) {
	params := Params{}

	if err := util.Unmarshal(bs, &params.Config); err != nil {
		return nil, err
	}

	logrus.WithFields(logrus.Fields{}).Infof("Plugin Config: %+v", params.Config)
	return &params, nil
}

// NewPlugin returns a new Plugin object
func NewPlugin(manager *plugins.Manager, params *Params) (*Plugin, error) {
	plugin := &Plugin{
		manager: manager,
		params:  params,
		stop:    make(chan chan struct{}),
	}

	return plugin, nil
}

// Start starts the plugin
func (p *Plugin) Start(ctx context.Context) error {
	go p.startProxyServer()
	return nil
}

// Stop stops the plugin
func (p *Plugin) Stop(ctx context.Context) {
	done := make(chan struct{})
	p.stop <- done
	_ = <-done
}

// startProxyServer starts the gRPC proxy server and configures the forwarding
// rules such that Istio Mixer's Check call is handled by the service and
// the Report call is forwarded to Istio Mixer
func (p *Plugin) startProxyServer() {

	// check proxy address
	laddr := p.params.Config.PluginAddr
	if laddr == "" {
		laddr = defaultAddr
	}

	// check policy query
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

	grpcServer := getGrpcServer()
	authzServer, err := NewAuthzServer(p)
	if err != nil {
		logrus.WithField("err", err).Fatalf("Unable to start server")
	}

	mixerpb.RegisterMixerServer(grpcServer, authzServer)
	reflection.Register(grpcServer)

	// Run gRPC server on separate goroutine
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			logrus.WithField("err", err).Fatalf("Failed to serve")
		}
	}()

	// Use a buffered channel so we don't miss any signals
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM)

	// Block until a signal is received.
	s := <-c
	logrus.WithFields(logrus.Fields{
		"signal": s,
	}).Infof("Got signal")
}

func getGrpcServer() *grpc.Server {
	var grpcOptions []grpc.ServerOption

	// Add custom codec and handler
	grpcOptions = append(grpcOptions, grpc.CustomCodec(proxy.Codec()),
		grpc.UnknownServiceHandler(proxy.TransparentHandler(utils.GetDirector())))

	return grpc.NewServer(grpcOptions...)
}
