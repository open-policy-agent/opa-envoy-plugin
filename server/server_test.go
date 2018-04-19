// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	google_rpc "github.com/gogo/googleapis/google/rpc"
	mixerpb "github.com/istio/api/mixer/v1"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

func TestCheckAllow(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  bob:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	// Positive integers index into the global deployment-wide dictionary. See attribute/list.gen.go
	stringsMap := make(map[int32]int32)
	stringsMap[19] = 90
	stringsMap[17] = -3

	stringMapsMap := make(map[int32]mixerpb.StringMap)
	entries := make(map[int32]int32)
	entries[50] = -11

	stringMapsMap[15] = mixerpb.StringMap{
		Entries: entries,
	}

	req := mixerpb.CheckRequest{}
	req.Attributes = mixerpb.CompressedAttributes{}
	req.Attributes.Words = []string{"192.168.99.100:32706", "curl/7.54.0", "/api/v1/products", "connection.mtls", "kubernetes://istio-ingress-5bb556fcbf-6xbff.istio-system", "productpage.default.svc.cluster.local", "kubernetes://productpage-v1-86f5569bc8-79clt.default", "172.17.0.1", "*/*", "7b523fe59f726d29", "Basic Ym9iOnBhc3N3b3Jk", "7b523fe59f726d29;7b523fe59f726d29;0000000000000000", "356f4318-43e9-956f-9e45-9f22eb80ff7b"}
	req.Attributes.Strings = stringsMap
	req.Attributes.StringMaps = stringMapsMap

	server := testAuthzServer()
	ctx := context.Background()

	output, _ := server.Check(ctx, &req)

	expected := &mixerpb.CheckResponse{
		Precondition: mixerpb.CheckResponse_PreconditionResult{
			Status: google_rpc.Status{Code: int32(google_rpc.OK)},
		},
	}

	if !reflect.DeepEqual(expected, output) {
		t.Errorf("Expected Output: %+v, Actual Output: %+v", expected, output)
	}

}

func TestCheckDeny(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  alice:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	// Positive integers index into the global deployment-wide dictionary. See attribute/list.gen.go
	stringsMap := make(map[int32]int32)
	stringsMap[19] = 90
	stringsMap[17] = -2

	stringMapsMap := make(map[int32]mixerpb.StringMap)
	entries := make(map[int32]int32)
	entries[50] = -9

	stringMapsMap[15] = mixerpb.StringMap{
		Entries: entries,
	}

	req := mixerpb.CheckRequest{}
	req.Attributes = mixerpb.CompressedAttributes{}
	req.Attributes.Words = []string{"kubernetes://productpage-v1-86f5569bc8-79clt.default", "/api/v1/products", "06dc1f8fb01d45ff", "192.168.99.100:32706", "341f4341-2596-93e5-873b-0f597e6a735e", "172.17.0.1", "*/*", "curl/7.54.0", "Basic YWxpY2U6cGFzc3dvcmQ=", "06dc1f8fb01d45ff;06dc1f8fb01d45ff;0000000000000000", "connection.mtls", "kubernetes://istio-ingress-5bb556fcbf-6xbff.istio-system", "productpage.default.svc.cluster.local"}
	req.Attributes.Strings = stringsMap
	req.Attributes.StringMaps = stringMapsMap

	server := testAuthzServer()
	ctx := context.Background()

	output, _ := server.Check(ctx, &req)

	expected := &mixerpb.CheckResponse{
		Precondition: mixerpb.CheckResponse_PreconditionResult{
			Status: google_rpc.Status{Code: int32(google_rpc.PERMISSION_DENIED)},
		},
	}

	if !reflect.DeepEqual(expected, output) {
		t.Errorf("Expected Output: %+v, Actual Output: %+v", expected, output)
	}

}

func testAuthzServer() *AuthzServer {
	ctx := context.Background()

	// Define a RBAC policy to allow or deny requests based on user roles
	module := `
		package example

		import data.role_perms
		import data.user_roles

		default allow = false

		allow {
		    # get the user
		    headers = input.request.headers
		    auth = headers.authorization
		    userAuth = split(auth, " ")
		    user_pass = base64url.decode(userAuth[1])
		    user_parts = split(user_pass, ":")
		    user = user_parts[0]

		    # lookup the list of roles for the user
		    roles = user_roles[user]
		    # for each role in that list
		    r = roles[_]
		    # lookup the permissions list for role r
		    permissions = role_perms[r]
		    # for each permission
		    p = permissions[_]
		    # check if the permission granted to r matches the user's request
		    {"method": input.request.method, "path": input.request.path} = p
		}

	`

	// Define dummy roles and permissions for the example
	store := inmem.NewFromReader(bytes.NewBufferString(`{
		"user_roles": {
				"alice":  ["guest"],
				"bob": ["admin"]
		},
		"role_perms": {
				"guest": [{"method": "GET",  "path": "/productpage"}],
				"admin": [{"method": "GET",  "path": "/productpage"},
					  {"method": "GET",  "path": "/api/v1/products"}]
		}
	}`))

	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)
	store.UpsertPolicy(ctx, txn, "example.rego", []byte(module))
	store.Commit(ctx, txn)

	m, err := plugins.New([]byte{}, "test", store)
	if err != nil {
		panic(err)
	}

	if err := m.Start(ctx); err != nil {
		panic(err)
	}

	params, err := NewParams([]byte{})
	if err != nil {
		panic(err)
	}
	params.Config.PluginAddr = ":50052"
	params.Config.PolicyQuery = "data.example.allow"

	plugin, err := NewPlugin(m, params)
	if err != nil {
		panic(err)
	}

	server, err := NewAuthzServer(plugin)
	if err != nil {
		panic(err)
	}

	return server
}
