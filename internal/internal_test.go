// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	ext_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	ext_authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
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
		  "protocol": "HTTP/1.1",
		  "body": "{\"firstname\": \"foo\", \"lastname\": \"bar\"}"
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
		  "protocol": "HTTP/1.1",
		  "body": "foo"
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

const exampleAllowedRequestParsedBody = `{
	"attributes": {
	  "request": {
		"http": {
		  "id": "13359530607844510314",
		  "method": "GET",
		  "body": "{\"firstname\": \"foo\", \"lastname\": \"bar\", \"dept\": {\"it\": \"eng\"}}",
		}
	  }
	}
  }`

const exampleDeniedRequestParsedBody = `{
	"attributes": {
	  "request": {
		"http": {
		  "id": "13359530607844510314",
		  "method": "GET",
		  "body": "foo",
		}
	  }
	}
  }`

func TestCheckAllow(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  bob:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}

	server := testAuthzServer(&testPlugin{}, false)
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

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequestParsedPath), &req); err != nil {
		panic(err)
	}

	server := testAuthzServer(&testPlugin{}, false)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(google_rpc.OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}
}

func TestCheckAllowParsedBody(t *testing.T) {

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequestParsedBody), &req); err != nil {
		panic(err)
	}

	server := testAuthzServer(&testPlugin{}, false)
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

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	server := testAuthzServer(customLogger, false)
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

	if event.Error != nil || event.Query != "data.istio.authz.allow" || event.Path != "istio/authz/allow" || event.Revision != "" || *event.Result == false {
		t.Fatal("Unexpected events:", customLogger.events)
	}

	expected := []string{
		"timer_rego_module_compile_ns",
		"timer_rego_module_parse_ns",
		"timer_rego_query_compile_ns",
		"timer_rego_query_eval_ns",
		"timer_rego_query_parse_ns",
		"timer_server_handler_ns",
	}

	for _, key := range expected {
		if event.Metrics[key] == nil {
			t.Fatalf("Expected non-zero metric for %v", key)
		}
	}
}

func TestCheckDeny(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  alice:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	server := testAuthzServer(&testPlugin{}, false)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(google_rpc.PERMISSION_DENIED) {
		t.Fatal("Expected request to be denied but got:", output)
	}
}

func TestCheckDenyParsedBody(t *testing.T) {

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequestParsedBody), &req); err != nil {
		panic(err)
	}

	server := testAuthzServer(&testPlugin{}, false)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(google_rpc.PERMISSION_DENIED) {
		t.Fatal("Expected request to be denied but got:", output)
	}
}

func TestCheckAllowWithDryRunTrue(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  alice:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	server := testAuthzServer(customLogger, true)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(google_rpc.OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}
}

func TestCheckDenyWithDryRunTrue(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  alice:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	server := testAuthzServer(customLogger, true)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(google_rpc.OK) {
		t.Fatal("Expected request to be allowed since config.DryRun is true, but got:", output)
	}
}

func TestCheckDenyWithLogger(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  alice:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	server := testAuthzServer(customLogger, false)
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

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPluginError{}

	server := testAuthzServer(customLogger, false)
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

func TestConfigValid(t *testing.T) {

	m, err := plugins.New([]byte{}, "test", inmem.New())
	if err != nil {
		t.Fatal(err)
	}

	in := `{"addr": ":9292", "query": "data.test"}`
	config, err := Validate(m, []byte(in))
	if err != nil {
		t.Fatal(err)
	}

	if config.Addr != ":9292" {
		t.Fatalf("Expected address :9292 but got %v", config.Addr)
	}

	if config.parsedQuery.String() != "data.test" {
		t.Fatalf("Expected query data.test but got %v", config.Query)
	}
}

func TestConfigValidDefault(t *testing.T) {

	m, err := plugins.New([]byte{}, "test", inmem.New())
	if err != nil {
		t.Fatal(err)
	}

	config, err := Validate(m, []byte{})
	if err != nil {
		t.Fatal(err)
	}

	if config.Addr != defaultAddr {
		t.Fatalf("Expected address %v but got %v", defaultAddr, config.Addr)
	}

	if config.parsedQuery.String() != defaultQuery {
		t.Fatalf("Expected query %v but got %v", defaultQuery, config.parsedQuery.String())
	}
}

func TestCheckAllowObjectDecision(t *testing.T) {

	// Example Mixer Check Request for input:
	// curl --user  bob:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequestParsedPath), &req); err != nil {
		panic(err)
	}

	server := testAuthzServerWithObjectDecision(&testPlugin{}, false)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}

	if output.Status.Code != int32(google_rpc.OK) {
		t.Fatalf("Expected request to be allowed but got: %v", output)
	}

	response := output.GetOkResponse()
	if response == nil {
		t.Fatal("Expected OkHttpResponse struct but got nil")
	}

	headers := response.GetHeaders()
	if len(headers) != 2 {
		t.Fatalf("Expected two headers but got %v", len(headers))
	}

	expectedHeaders := make(map[string]string)
	expectedHeaders["x"] = "hello"
	expectedHeaders["y"] = "world"

	assertHeaders(t, headers, expectedHeaders)
}

func TestCheckDenyObjectDecision(t *testing.T) {

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	server := testAuthzServerWithObjectDecision(&testPlugin{}, false)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Result is %v\n", output)

	if output.Status.Code != int32(google_rpc.PERMISSION_DENIED) {
		t.Fatalf("Expected request to be denied but got: %v", output)
	}

	response := output.GetDeniedResponse()
	if response == nil {
		t.Fatal("Expected DeniedHttpResponse struct but got nil")
	}

	headers := response.GetHeaders()
	if len(headers) != 2 {
		t.Fatalf("Expected two headers but got %v", len(headers))
	}

	expectedHeaders := make(map[string]string)
	expectedHeaders["foo"] = "bar"
	expectedHeaders["baz"] = "taz"

	assertHeaders(t, headers, expectedHeaders)

	if response.GetBody() != "Unauthorized Request" {
		t.Fatalf("Expected response body \"Unauthorized Request\" but got %v", response.GetBody())
	}

	actualHTTPStatusCode := response.GetStatus().GetCode().String()
	if actualHTTPStatusCode != "MovedPermanently" {
		t.Fatalf("Expected http status code \"MovedPermanently\" but got %v", actualHTTPStatusCode)
	}
}

func TestCheckDenyWithDryRunObjectDecision(t *testing.T) {

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	server := testAuthzServerWithObjectDecision(&testPlugin{}, true)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}

	if output.Status.Code != int32(google_rpc.OK) {
		t.Fatalf("Expected request to be allowed since config.DryRun is true, but got: %v", output)
	}

	response := output.GetOkResponse()
	if response == nil {
		t.Fatal("Expected OkHttpResponse struct but got nil")
	}
}

func TestCheckAllowWithDryRunObjectDecision(t *testing.T) {

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequestParsedPath), &req); err != nil {
		panic(err)
	}

	server := testAuthzServerWithObjectDecision(&testPlugin{}, true)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}

	if output.Status.Code != int32(google_rpc.OK) {
		t.Fatalf("Expected request to be allowed but got: %v", output)
	}

	response := output.GetOkResponse()
	if response == nil {
		t.Fatal("Expected OkHttpResponse struct but got nil")
	}

	headers := response.GetHeaders()
	if len(headers) != 2 {
		t.Fatalf("Expected two headers but got %v", len(headers))
	}

	expectedHeaders := make(map[string]string)
	expectedHeaders["x"] = "hello"
	expectedHeaders["y"] = "world"

	assertHeaders(t, headers, expectedHeaders)
}

func TestGetResponseStatus(t *testing.T) {

	input := make(map[string]interface{})
	var err error

	_, err = getResponseStatus(input)
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	input["allowed"] = 1
	_, err = getResponseStatus(input)
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	input["allowed"] = true
	var result int32
	result, err = getResponseStatus(input)

	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if result != int32(google_rpc.OK) {
		t.Fatalf("Expected result %v but got %v", int32(google_rpc.OK), result)
	}
}

func TestGetResponeHeaders(t *testing.T) {
	input := make(map[string]interface{})

	result, err := getResponseHeaders(input)
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result) != 0 {
		t.Fatal("Expected no headers")
	}

	badHeader := "test"
	input["headers"] = badHeader

	_, err = getResponseHeaders(input)
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	testHeaders := make(map[string]interface{})
	testHeaders["foo"] = "bar"
	input["headers"] = testHeaders

	result, err = getResponseHeaders(input)
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected one header but got %v", len(result))
	}

	testHeaders["baz"] = 1

	_, err = getResponseHeaders(input)
	if err == nil {
		t.Fatal("Expected error but got nil")
	}
}

func TestGetResponseBody(t *testing.T) {
	input := make(map[string]interface{})

	result, err := getResponseBody(input)
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if result != "" {
		t.Fatalf("Expected empty body but got %v", result)
	}

	input["body"] = "hello"
	result, err = getResponseBody(input)
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if result != "hello" {
		t.Fatalf("Expected result \"hello\" but got %v", result)
	}

	input["body"] = 123
	result, err = getResponseBody(input)
	if err == nil {
		t.Fatal("Expected error but got nil", err)
	}
}

func TestGetResponseHttpStatus(t *testing.T) {
	input := make(map[string]interface{})

	result, err := getResponseHTTPStatus(input)
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if result.GetCode().String() != "Forbidden" {
		t.Fatalf("Expected http status code \"Forbidden\" but got %v", result.GetCode().String())
	}

	input["http_status"] = true
	result, err = getResponseHTTPStatus(input)
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	input["http_status"] = json.Number(301)
	result, err = getResponseHTTPStatus(input)
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	input["http_status"] = json.Number("9999")
	result, err = getResponseHTTPStatus(input)
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	input["http_status"] = json.Number("400")
	result, err = getResponseHTTPStatus(input)
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if result.GetCode().String() != "BadRequest" {
		t.Fatalf("Expected http status code \"BadRequest\" but got %v", result.GetCode().String())
	}
}

func TestGetParsedBodyJSON(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}

	result := getParsedBody(&req)

	expected := map[string]interface{}{}
	expected["firstname"] = "foo"
	expected["lastname"] = "bar"

	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected result %v but got %v", expected, result)
	}
}

func TestGetParsedBodyNotJSON(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	result := getParsedBody(&req)

	if len(result) != 0 {
		t.Fatalf("Expected empty result but got %v", result)
	}
}

func testAuthzServer(customLogger plugins.Plugin, dryRun bool) *envoyExtAuthzGrpcServer {

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

		allow {
			input.parsed_body.firstname == "foo"
			input.parsed_body.lastname == "bar"
			input.parsed_body.dept.it == "eng"
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

	m, err := getPluginManager(module, customLogger)
	if err != nil {
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
			DryRun:      dryRun,
			parsedQuery: parsedQuery,
		},
		manager: m,
	}
	return s
}

func testAuthzServerWithObjectDecision(customLogger plugins.Plugin, dryRun bool) *envoyExtAuthzGrpcServer {

	module := `
		package istio.authz

		default allow = {
		  "allowed": false,
		  "headers": {"foo": "bar", "baz": "taz"},
		  "body": "Unauthorized Request",
		  "http_status": 301
		}

		allow = response {
			input.parsed_path = ["my", "test", "path"]
		    response := {
				"allowed": true,
				"headers": {"x": "hello", "y": "world"}
		    }
		}`

	m, err := getPluginManager(module, customLogger)
	if err != nil {
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
			DryRun:      dryRun,
			parsedQuery: parsedQuery,
		},
		manager: m,
	}

	return s
}

func getPluginManager(module string, customLogger plugins.Plugin) (*plugins.Manager, error) {
	ctx := context.Background()
	store := inmem.New()
	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)
	store.UpsertPolicy(ctx, txn, "example.rego", []byte(module))
	store.Commit(ctx, txn)

	m, err := plugins.New([]byte{}, "test", store)
	if err != nil {
		return nil, err
	}

	m.Register("test_plugin", customLogger)
	config, err := logs.ParseConfig([]byte(`{"plugin": "test_plugin"}`), nil, []string{"test_plugin"})
	if err != nil {
		return nil, err
	}

	plugin := logs.New(config, m)
	m.Register(logs.Name, plugin)

	if err := m.Start(ctx); err != nil {
		return nil, err
	}

	return m, nil
}

func assertHeaders(t *testing.T, actualHeaders []*ext_core.HeaderValueOption, expectedHeaders map[string]string) {
	t.Helper()

	for _, header := range actualHeaders {
		key := header.GetHeader().GetKey()
		value := header.GetHeader().GetValue()

		var expVal string
		var ok bool

		if expVal, ok = expectedHeaders[key]; !ok {
			t.Fatalf("Expected header \"%v\" does not exist in map", key)
		} else {
			if expVal != value {
				t.Fatalf("Expected value for header \"%v\" is \"%v\" but got \"%v\"", key, expVal, value)
			}
		}
	}

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
