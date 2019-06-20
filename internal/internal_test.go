// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"fmt"
	"testing"

	"github.com/envoyproxy/data-plane-api/envoy/service/auth/v2"
	google_rpc "github.com/gogo/googleapis/google/rpc"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/plugins/logs"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

const exampleAllowedRequest = `{
	"attributes": {
	  "request": {
		"http": {
		  "id": "13359530607844510314",
		  "method": "GET",
		  "headers": {
			":authority": "192.168.99.100:31380",
			":method": "GET",
			":path": "/api/v1/products",
			"accept": "*/*",
			"authorization": "Basic Ym9iOnBhc3N3b3Jk",
			"content-length": "0",
			"user-agent": "curl/7.54.0",
			"x-b3-sampled": "1",
			"x-b3-spanid": "537f473f27475073",
			"x-b3-traceid": "537f473f27475073",
			"x-envoy-internal": "true",
			"x-forwarded-for": "172.17.0.1",
			"x-forwarded-proto": "http",
			"x-istio-attributes": "Cj4KE2Rlc3RpbmF0aW9uLnNlcnZpY2USJxIlcHJvZHVjdHBhZ2UuZGVmYXVsdC5zdmMuY2x1c3Rlci5sb2NhbApPCgpzb3VyY2UudWlkEkESP2t1YmVybmV0ZXM6Ly9pc3Rpby1pbmdyZXNzZ2F0ZXdheS02Nzk5NWM0ODZjLXFwOGpyLmlzdGlvLXN5c3RlbQpBChdkZXN0aW5hdGlvbi5zZXJ2aWNlLnVpZBImEiRpc3RpbzovL2RlZmF1bHQvc2VydmljZXMvcHJvZHVjdHBhZ2UKQwoYZGVzdGluYXRpb24uc2VydmljZS5ob3N0EicSJXByb2R1Y3RwYWdlLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwKKgodZGVzdGluYXRpb24uc2VydmljZS5uYW1lc3BhY2USCRIHZGVmYXVsdAopChhkZXN0aW5hdGlvbi5zZXJ2aWNlLm5hbWUSDRILcHJvZHVjdHBhZ2U=",
			"x-request-id": "92a6c0f7-0250-944b-9cfc-ae10cbcedd8e"
		  },
		  "path": "/api/v1/products",
		  "host": "192.168.99.100:31380",
		  "protocol": "HTTP/1.1"
		}
	  }
	}
  }`

const exampleAllowedRequestParsedPath = `{
	"attributes": {
	  "request": {
		"http": {
		  "id": "13359530607844510314",
		  "method": "GET",
		  "path": "/my/test/path"
		}
	  }
	}
  }`

// Identical to the request above except authorization header is different.
const exampleDeniedRequest = `{
	"attributes": {
	  "request": {
		"http": {
		  "id": "13359530607844510314",
		  "method": "GET",
		  "headers": {
			":authority": "192.168.99.100:31380",
			":method": "GET",
			":path": "/api/v1/products",
			"accept": "*/*",
			"authorization": "Basic YWxpY2U6cGFzc3dvcmQ=",
			"content-length": "0",
			"user-agent": "curl/7.54.0",
			"x-b3-sampled": "1",
			"x-b3-spanid": "537f473f27475073",
			"x-b3-traceid": "537f473f27475073",
			"x-envoy-internal": "true",
			"x-forwarded-for": "172.17.0.1",
			"x-forwarded-proto": "http",
			"x-istio-attributes": "Cj4KE2Rlc3RpbmF0aW9uLnNlcnZpY2USJxIlcHJvZHVjdHBhZ2UuZGVmYXVsdC5zdmMuY2x1c3Rlci5sb2NhbApPCgpzb3VyY2UudWlkEkESP2t1YmVybmV0ZXM6Ly9pc3Rpby1pbmdyZXNzZ2F0ZXdheS02Nzk5NWM0ODZjLXFwOGpyLmlzdGlvLXN5c3RlbQpBChdkZXN0aW5hdGlvbi5zZXJ2aWNlLnVpZBImEiRpc3RpbzovL2RlZmF1bHQvc2VydmljZXMvcHJvZHVjdHBhZ2UKQwoYZGVzdGluYXRpb24uc2VydmljZS5ob3N0EicSJXByb2R1Y3RwYWdlLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwKKgodZGVzdGluYXRpb24uc2VydmljZS5uYW1lc3BhY2USCRIHZGVmYXVsdAopChhkZXN0aW5hdGlvbi5zZXJ2aWNlLm5hbWUSDRILcHJvZHVjdHBhZ2U=",
			"x-request-id": "92a6c0f7-0250-944b-9cfc-ae10cbcedd8e"
		  },
		  "path": "/api/v1/products",
		  "host": "192.168.99.100:31380",
		  "protocol": "HTTP/1.1"
		}
	  }
	}
  }`

func TestCheckAllow(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  bob:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	var req v2.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}

	server := testAuthzServer(&testPlugin{})
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(google_rpc.OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}
}

func TestCheckAllowParsedPath(t *testing.T) {

	var req v2.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequestParsedPath), &req); err != nil {
		panic(err)
	}

	server := testAuthzServer(&testPlugin{})
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(google_rpc.OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}
}

func TestCheckAllowWithLogger(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  bob:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	var req v2.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	server := testAuthzServer(customLogger)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(google_rpc.OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}

	if len(customLogger.events) != 1 {
		t.Fatal("Unexpected events:", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error != nil || event.Query != "data.istio.authz.allow" || event.Revision != "" || *event.Result == false {
		t.Fatal("Unexpected events:", customLogger.events)
	}
}

func TestCheckDeny(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  alice:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	var req v2.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	server := testAuthzServer(&testPlugin{})
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(google_rpc.PERMISSION_DENIED) {
		t.Fatal("Expected request to be denied but got:", output)
	}
}

func TestCheckDenyWithLogger(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  alice:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	var req v2.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	server := testAuthzServer(customLogger)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(google_rpc.PERMISSION_DENIED) {
		t.Fatal("Expected request to be denied but got:", output)
	}

	if len(customLogger.events) != 1 {
		t.Fatal("Unexpected events:", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error != nil || event.Query != "data.istio.authz.allow" || event.Revision != "" || *event.Result == true {
		t.Fatal("Unexpected events:", customLogger.events)
	}
}

func TestCheckWithLoggerError(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  alice:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	var req v2.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPluginError{}

	server := testAuthzServer(customLogger)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(google_rpc.UNKNOWN) {
		t.Fatalf("Expected logger error code UNKNOWN but got %v", output.Status.Code)
	}

	expectedMsg := "Bad Logger Error"
	if output.Status.Message != expectedMsg {
		t.Fatalf("Expected error message %v, but got %v", expectedMsg, output.Status.Message)
	}
}

func testAuthzServer(customLogger plugins.Plugin) *envoyExtAuthzGrpcServer {
	ctx := context.Background()

	// Define a RBAC policy to allow or deny requests based on user roles
	module := `
	package istio.authz

	import input.attributes.request.http as http_request

	default allow = false

	allow {
		roles_for_user[r]
		required_roles[r]
	}

	allow {
		input.parsed_path = ["my", "test", "path"]
	}

	roles_for_user[r] {
		r := user_roles[user_name][_]
	}

	required_roles[r] {
		perm := role_perms[r][_]
		perm.method = http_request.method
		perm.path = http_request.path
	}

	user_name = parsed {
		[_, encoded] := split(http_request.headers.authorization, " ")
		[parsed, _] := split(base64url.decode(encoded), ":")
	}

	user_roles = {
		"alice": ["guest"],
		"bob": ["admin"]
	}

	role_perms = {
		"guest": [
			{"method": "GET",  "path": "/productpage"},
		],
		"admin": [
			{"method": "GET",  "path": "/productpage"},
			{"method": "GET",  "path": "/api/v1/products"},
		],
	}`

	store := inmem.New()
	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)
	store.UpsertPolicy(ctx, txn, "example.rego", []byte(module))
	store.Commit(ctx, txn)

	m, err := plugins.New([]byte{}, "test", store)
	if err != nil {
		panic(err)
	}

	m.Register("test_plugin", customLogger)
	config, err := logs.ParseConfig([]byte(`{"plugin": "test_plugin"}`), nil, []string{"test_plugin"})

	plugin := logs.New(config, m)
	m.Register(logs.Name, plugin)

	if err := m.Start(ctx); err != nil {
		panic(err)
	}

	query := "data.istio.authz.allow"
	parsedQuery, err := ast.ParseBody(query)
	if err != nil {
		panic(err)
	}

	s := &envoyExtAuthzGrpcServer{
		cfg: Config{
			Addr:        ":50052",
			Query:       query,
			parsedQuery: parsedQuery,
		},
		manager: m,
	}

	return s
}

type testPlugin struct {
	events []logs.EventV1
}

func (p *testPlugin) Start(context.Context) error {
	return nil
}

func (p *testPlugin) Stop(context.Context) {
}

func (p *testPlugin) Reconfigure(context.Context, interface{}) {
}

func (p *testPlugin) Log(_ context.Context, event logs.EventV1) error {
	p.events = append(p.events, event)
	return nil
}

type testPluginError struct {
	events []logs.EventV1
}

func (p *testPluginError) Start(context.Context) error {
	return nil
}

func (p *testPluginError) Stop(context.Context) {
}

func (p *testPluginError) Reconfigure(context.Context, interface{}) {
}

func (p *testPluginError) Log(_ context.Context, event logs.EventV1) error {
	p.events = append(p.events, event)
	return fmt.Errorf("Bad Logger Error")
}
