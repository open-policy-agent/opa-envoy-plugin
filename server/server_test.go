// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/envoyproxy/data-plane-api/envoy/service/auth/v2alpha"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

func TestCheckAllow(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  bob:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	req := &v2alpha.CheckRequest{}
	server := testAuthzServer()
	ctx := context.Background()
	output, _ := server.Check(ctx, req)
	expected := v2alpha.CheckResponse{}

	if !reflect.DeepEqual(expected, output) {
		t.Errorf("Expected Output: %+v, Actual Output: %+v", expected, output)
	}

}

func TestCheckDeny(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  alice:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	req := &v2alpha.CheckRequest{}
	server := testAuthzServer()
	ctx := context.Background()
	output, _ := server.Check(ctx, req)
	expected := v2alpha.CheckResponse{}

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
