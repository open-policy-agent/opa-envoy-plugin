// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	ext_authz "github.com/envoyproxy/data-plane-api/envoy/service/auth/v2alpha"
	google_rpc "github.com/gogo/googleapis/google/rpc"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/util"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const defaultAddr = ":9191"
const defaultQuery = "data.istio.authz.allow"

// New returns a Plugin that implements the Envoy ext_authz API.
func New(m *plugins.Manager, bs []byte) (plugins.Plugin, error) {

	cfg := config{
		Addr:  defaultAddr,
		Query: defaultQuery,
	}

	if err := util.Unmarshal(bs, &cfg); err != nil {
		return nil, err
	}

	plugin := &envoyExtAuthzGrpcServer{
		manager: m,
		cfg:     cfg,
		server:  grpc.NewServer(),
	}

	ext_authz.RegisterAuthorizationServer(plugin.server, plugin)

	return plugin, nil
}

type config struct {
	Addr  string `json:"addr"`
	Query string `json:"decision"`
}

type envoyExtAuthzGrpcServer struct {
	cfg     config
	server  *grpc.Server
	manager *plugins.Manager
}

func (p *envoyExtAuthzGrpcServer) Start(ctx context.Context) error {
	go p.listen()
	return nil
}

func (p *envoyExtAuthzGrpcServer) Stop(ctx context.Context) {
	p.server.Stop()
}

func (p *envoyExtAuthzGrpcServer) listen() {

	// The listener is closed automatically by Serve when it returns.
	l, err := net.Listen("tcp", p.cfg.Addr)
	if err != nil {
		logrus.WithField("err", err).Fatalf("Unable to create listener.")
	}

	logrus.WithFields(logrus.Fields{
		"addr":  p.cfg.Addr,
		"query": p.cfg.Query,
	}).Infof("Starting gRPC server.")

	if err := p.server.Serve(l); err != nil {
		logrus.WithField("err", err).Fatalf("Listener failed.")
	}

	logrus.Info("Listener exited.")
}

func (p *envoyExtAuthzGrpcServer) Check(ctx context.Context, req *ext_authz.CheckRequest) (*ext_authz.CheckResponse, error) {

	bs, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	input, err := ast.ParseTerm(string(bs))
	if err != nil {
		return nil, err
	}

	result, err := p.eval(ctx, input)
	if err != nil {
		return nil, err
	}

	status := int32(google_rpc.PERMISSION_DENIED)

	if result {
		status = int32(google_rpc.OK)
	}

	resp := &ext_authz.CheckResponse{
		Status: &google_rpc.Status{Code: status},
	}

	return resp, nil
}

func (p *envoyExtAuthzGrpcServer) eval(ctx context.Context, input *ast.Term, opts ...func(*rego.Rego)) (bool, error) {

	m := metrics.New()
	var decision bool
	var txnID uint64

	err := storage.Txn(ctx, p.manager.Store, storage.TransactionParams{}, func(txn storage.Transaction) error {

		txnID = txn.ID()

		logrus.WithFields(logrus.Fields{
			"input": input,
			"query": p.cfg.Query,
			"txn":   txnID,
		}).Infof("Executing policy query.")

		opts = append(opts,
			rego.Metrics(m),
			rego.Query(p.cfg.Query),
			rego.ParsedInput(input.Value),
			rego.Compiler(p.manager.GetCompiler()),
			rego.Store(p.manager.Store),
			rego.Transaction(txn))

		rs, err := rego.New(opts...).Eval(ctx)

		if err != nil {
			return err
		} else if len(rs) == 0 {
			return fmt.Errorf("undefined decision")
		} else if b, ok := rs[0].Expressions[0].Value.(bool); !ok || len(rs) > 1 {
			return fmt.Errorf("non-boolean decision")
		} else {
			decision = b
		}

		return nil
	})

	logrus.WithFields(logrus.Fields{
		"query":    p.cfg.Query,
		"decision": decision,
		"err":      err,
		"txn":      txnID,
		"metrics":  m.All(),
	}).Info("Returning policy decision.")

	return decision, err
}
