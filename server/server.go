// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package server

import (
	"encoding/json"
	"fmt"

	"github.com/envoyproxy/data-plane-api/envoy/service/auth/v2alpha"
	google_rpc "github.com/gogo/googleapis/google/rpc"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

// AuthzServer implements the Envoy ext_authz API.
type AuthzServer struct {
	plugin *Plugin
}

// NewAuthzServer return a new AuthzServer object.
func NewAuthzServer(p *Plugin) (*AuthzServer, error) {
	return &AuthzServer{plugin: p}, nil
}

// Check returns a v2alpha.CheckResponse indicating whether the request should
// allowed or denied.
func (as *AuthzServer) Check(ctx context.Context, req *v2alpha.CheckRequest) (*v2alpha.CheckResponse, error) {

	bs, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	input, err := ast.ParseTerm(string(bs))
	if err != nil {
		return nil, err
	}

	result, err := as.getPolicyDecision(ctx, input)
	if err != nil {
		logrus.WithField("err", err).Errorf("error while getting a policy decision")
		return nil, err
	}

	var status int32
	if result {
		logrus.WithFields(logrus.Fields{}).Infof("OPA Decision: Operation allowed")
		status = int32(google_rpc.OK)
	} else {

		logrus.WithFields(logrus.Fields{}).Infof("OPA Decision: Operation not allowed")
		status = int32(google_rpc.PERMISSION_DENIED)
	}

	response := &v2alpha.CheckResponse{
		Status: &google_rpc.Status{Code: status},
	}

	return response, nil
}

func (as *AuthzServer) getPolicyDecision(ctx context.Context, input *ast.Term) (bool, error) {

	txn, err := as.plugin.manager.Store.NewTransaction(ctx)
	if err != nil {
		return false, err
	}

	defer func() {
		logrus.WithFields(logrus.Fields{
			"Id": txn.ID(),
		}).Infof("Aborting transaction")
		as.plugin.manager.Store.Abort(ctx, txn)
	}()

	compiler := as.plugin.manager.GetCompiler()
	query := as.plugin.params.Config.PolicyQuery

	logrus.WithFields(logrus.Fields{
		"Transaction Id": txn.ID(),
		"Query":          query,
		"Request":        input,
	}).Infof("OPA Request")

	rego := rego.New(
		rego.Query(query),
		rego.ParsedInput(input.Value),
		rego.Compiler(compiler),
		rego.Store(as.plugin.manager.Store))

	var result, ok bool
	rs, err := rego.Eval(ctx)
	if err != nil {
		return false, fmt.Errorf("policy evaluation failure: %s", err.Error())
	} else if len(rs) == 0 {
		return false, fmt.Errorf("policy evalution result empty")
	} else if result, ok = rs[0].Expressions[0].Value.(bool); !ok {
		return false, fmt.Errorf("policy evalution result is not boolean")
	}

	return result, nil
}
