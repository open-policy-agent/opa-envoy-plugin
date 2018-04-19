// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package server

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	google_rpc "github.com/gogo/googleapis/google/rpc"
	mixerpb "github.com/istio/api/mixer/v1"
	"github.com/open-policy-agent/opa-istio-plugin/attribute"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

// AuthzServer represents an instance of the authz server that implements
// Istio Mixer's Check api
type (
	AuthzServer struct {
		// Istio's global dictionary
		globalWordList []string
		globalDict     map[string]int32
		plugin         *Plugin
		result         bool
	}
)

// NewAuthzServer return a new authzServer object
func NewAuthzServer(p *Plugin) (*AuthzServer, error) {
	list := attribute.GlobalList()
	globalDict := make(map[string]int32, len(list))
	for i := 0; i < len(list); i++ {
		globalDict[list[i]] = int32(i)
	}

	return &AuthzServer{
		globalWordList: list,
		globalDict:     globalDict,
		plugin:         p,
	}, nil
}

// Check implements Istio Mixer's Check api. It talks to OPA to get
// policy decisions from based on the incoming attributes
func (as *AuthzServer) Check(ctx context.Context, req *mixerpb.CheckRequest) (*mixerpb.CheckResponse, error) {
	// Get the http request info from Istio's attributes
	protoBag := attribute.NewProtoBag(&req.Attributes, as.globalDict, as.globalWordList)
	checkBag := attribute.GetMutableBag(protoBag)
	defer checkBag.Done()

	logrus.WithFields(logrus.Fields{}).Infof("Attributes are: %+v", checkBag.DebugString())

	input, err := processIstioAttributes(checkBag)
	if err != nil {
		logrus.WithField("err", err).Errorf("error processing OPA input")
		return nil, err
	}

	// ask OPA for a policy decision
	err = as.getPolicyDecision(ctx, input)
	if err != nil {
		logrus.WithField("err", err).Errorf("error while getting a policy decision")
		return nil, err
	}

	var status int32
	if as.result {
		logrus.WithFields(logrus.Fields{}).Infof("OPA Decision: Operation allowed")
		status = int32(google_rpc.OK)
	} else {

		logrus.WithFields(logrus.Fields{}).Infof("OPA Decision: Operation not allowed")
		status = int32(google_rpc.PERMISSION_DENIED)
	}

	response := &mixerpb.CheckResponse{
		Precondition: mixerpb.CheckResponse_PreconditionResult{
			Status: google_rpc.Status{Code: status},
		},
	}

	return response, nil
}

// Report returns an empty Mixer response. Istio Mixer's Report call is
// forwarded to Istio Mixer and not implemented by this service
func (as *AuthzServer) Report(ctx context.Context, req *mixerpb.ReportRequest) (*mixerpb.ReportResponse, error) {
	return new(mixerpb.ReportResponse), nil
}

// getPolicyDecision gets a policy decision from OPA
func (as *AuthzServer) getPolicyDecision(ctx context.Context, input *ast.Term) error {

	txn, err := as.plugin.manager.Store.NewTransaction(ctx)
	if err != nil {
		return err
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
		return fmt.Errorf("policy evaluation failure: %s", err.Error())
	} else if len(rs) == 0 {
		return fmt.Errorf("policy evalution result empty")
	} else if result, ok = rs[0].Expressions[0].Value.(bool); !ok {
		return fmt.Errorf("policy evalution result is not boolean")
	}
	as.result = result
	return nil
}

// processIstioAttributes processes the Istio's attribute bag and returns an
// input that be provided to OPA
func processIstioAttributes(attributeBag *attribute.MutableBag) (*ast.Term, error) {
	input := make(map[string]interface{})
	attributes := attributeBag.Names()

	for _, attr := range attributes {
		value, _ := attributeBag.Get(attr)

		switch v := value.(type) {
		case attribute.StringMap:
			value = v.GetEntries()

		case []uint8:
			value = net.IP(v).String()
		}

		// Istio attributes are of the form <x>.<y> eg. source.ip
		attributeList := strings.Split(attr, ".")
		key := attributeList[0]
		subKey := attributeList[1]

		if _, ok := input[key]; !ok {
			temp := make(map[string]interface{})
			input[key] = temp
		}
		subMap := input[key].(map[string]interface{})
		subMap[subKey] = value
	}

	inputBytes, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	inputTerm, err := ast.ParseTerm(string(inputBytes))
	if err != nil {
		return nil, err
	}

	return inputTerm, nil
}
