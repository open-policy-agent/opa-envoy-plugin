// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	ext_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_authz_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	ext_authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/code"

	"github.com/open-policy-agent/opa-envoy-plugin/envoyauth"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/plugins/logs"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown"
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
		  "path": "/my/test/path?a=1&a=2&x=y"
		}
	  }
	}
  }`

const exampleAllowedRequestParsedBody = `{
	"attributes": {
	  "request": {
		"http": {
		  "id": "13359530607844510314",
		  "headers": {
			"content-type": "application/json"
		  },
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

const exampleInvalidRequest = `{
	"attributes": {
	  "request": {
		"http": {
		  "headers": { "content-type": "application/json"},
		  "body": "[\"foo\" : 42}"
		}
	  }
	}
  }`

func TestCheckAllow(t *testing.T) {

	// Example Envoy Check Request for input:
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
	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}
}

func TestCheckTrigger(t *testing.T) {

	// Example Envoy Check Request for input:
	// curl --user  bob:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

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
	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}

	originalPreparedQuery := server.preparedQuery

	output, err = server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}

	if !reflect.DeepEqual(originalPreparedQuery, server.preparedQuery) {
		t.Fatal("Expected same instance of prepared query")
	}

	// call compiler trigger
	txn := storage.NewTransactionOrDie(ctx, server.manager.Store, storage.WriteParams)
	server.compilerUpdated(txn)

	output, err = server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}

	if reflect.DeepEqual(originalPreparedQuery, server.preparedQuery) {
		t.Fatal("Expected different instance of prepared query")
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
	if output.Status.Code != int32(code.Code_OK) {
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
	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}
}

func TestCheckAllowWithLogger(t *testing.T) {

	// Example Envoy Check Request for input:
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
	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}

	if len(customLogger.events) != 1 {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error != nil || event.Path != "envoy/authz/allow" ||
		event.Revision != "" || *event.Result == false {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}

	expected := []string{
		"timer_rego_query_compile_ns",
		"timer_rego_query_eval_ns",
		"timer_server_handler_ns",
	}

	for _, key := range expected {
		if event.Metrics[key] == nil {
			t.Fatalf("Expected non-zero metric for %v", key)
		}
	}
}

func TestCheckDeny(t *testing.T) {

	// Example Envoy Check Request for input:
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
	if output.Status.Code != int32(code.Code_PERMISSION_DENIED) {
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
	if output.Status.Code != int32(code.Code_PERMISSION_DENIED) {
		t.Fatal("Expected request to be denied but got:", output)
	}
}

func TestCheckAllowWithDryRunTrue(t *testing.T) {

	// Example Envoy Check Request for input:
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
	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}
}

func TestCheckDenyWithDryRunTrue(t *testing.T) {

	// Example Envoy Check Request for input:
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
	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed since config.DryRun is true, but got:", output)
	}
}

func TestCheckDenyWithLogger(t *testing.T) {

	// Example Envoy Check Request for input:
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
	if output.Status.Code != int32(code.Code_PERMISSION_DENIED) {
		t.Fatal("Expected request to be denied but got:", output)
	}

	if len(customLogger.events) != 1 {
		t.Fatal("Unexpected events:", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error != nil || event.Path != "envoy/authz/allow" || event.Revision != "" || *event.Result == true ||
		event.DecisionID == "" || event.Metrics == nil {
		t.Fatal("Unexpected events:", customLogger.events)
	}
}

func TestCheckAllowWithLoggerNDBCache(t *testing.T) {

	exampleRequest := `{
	"attributes": {
	  "request": {
		"http": {
		  "method": "GET",
		}
	  }
	}
  }`

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	module := `
		package envoy.authz

		default allow = false

		allow {
          res := http.send({"url": "http://httpbin.org", "method": "GET"})
          res.status_code == 200
		}
`
	server := testAuthzServerWithModule(module, "envoy/authz/allow", customLogger, false, false)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}

	if len(customLogger.events) != 1 {
		t.Fatal("Unexpected events:", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error != nil || event.Path != "envoy/authz/allow" || *event.Result == false ||
		event.DecisionID == "" || event.Metrics == nil {
		t.Fatal("Unexpected events:", customLogger.events)
	}

	cache := *event.NDBuiltinCache
	nd, ok := cache.(map[string]interface{})
	if !ok {
		t.Errorf("bad type assertion")
	}

	_, ok = nd["http.send"]
	if !ok {
		t.Errorf("expected http.send cache entry")
	}
}

func TestCheckContextTimeout(t *testing.T) {

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	server := testAuthzServer(customLogger, false)

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond*1)
	defer cancel()

	time.Sleep(time.Millisecond * 1)
	_, err := server.Check(ctx, &req)
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	expectedErrMsg := "check request timed out before query execution: context deadline exceeded"
	if err.Error() != expectedErrMsg {
		t.Fatalf("Expected error message %v but got %v", expectedErrMsg, err.Error())
	}

	if len(customLogger.events) != 1 {
		t.Fatal("Unexpected events:", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error == nil {
		t.Fatal("Expected error but got nil")
	}

	if event.Error.Error() != expectedErrMsg {
		t.Fatalf("Expected error message %v but got %v", expectedErrMsg, event.Error.Error())
	}

}

func TestCheckIllegalDecisionWithLogger(t *testing.T) {

	// Example Envoy Check Request for input:
	// curl --user  alice:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	module := `
		package envoy.authz

		default allow = 1
		`
	server := testAuthzServerWithModule(module, "envoy/authz/allow", customLogger, false, false)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	expectedErrMsg := "failed to get response status: illegal value for policy evaluation result: json.Number"
	if err.Error() != expectedErrMsg {
		t.Fatalf("Expected error message %v but got %v", expectedErrMsg, err)
	}

	if output != nil {
		t.Fatal("Expected nil output")
	}

	if len(customLogger.events) != 1 {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error == nil || event.Path != "envoy/authz/allow" || event.Revision != "" || event.Result != nil ||
		event.DecisionID == "" || event.Metrics == nil {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}
}

func TestCheckDenyDecisionTruncatedBodyWithLogger(t *testing.T) {

	exampleDeniedRequestTruncatedBody := `{
	"attributes": {
	  "request": {
		"http": {
		  "id": "13359530607844510314",
		  "headers": {
			"content-type": "application/json",
			"content-length": "100000"
		  },
		  "method": "GET",
		  "body": "{\"firstname\": \"foo\", \"lastname\": \"bar\", \"dept\": {\"it\": \"eng\"}}",
		}
	  }
	}
  }`

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequestTruncatedBody), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	server := testAuthzServerWithTruncatedBody(customLogger, false, false)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}

	if output.Status.Code != int32(code.Code_PERMISSION_DENIED) {
		t.Fatal("Expected request to be denied but got:", output)
	}

	if len(customLogger.events) != 1 {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error != nil || event.Path != "envoy/authz/allow" || *event.Result == true ||
		event.DecisionID == "" || event.Metrics == nil {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}

	input := *event.Input
	inputMap, _ := input.(map[string]interface{})
	isTruncated, _ := inputMap["truncated_body"].(bool)

	if !isTruncated {
		t.Fatal("Expected truncated request body")
	}
}

func TestCheckAllowDecisionWithSkipRequestBodyParse(t *testing.T) {

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleInvalidRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	server := testAuthzServerWithTruncatedBody(customLogger, false, true)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}

	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}

	if len(customLogger.events) != 1 {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error != nil || event.Path != "envoy/authz/allow" || *event.Result == false ||
		event.DecisionID == "" || event.Metrics == nil {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}

	input := *event.Input
	inputMap, _ := input.(map[string]interface{})

	if _, ok := inputMap["truncated_body"]; ok {
		t.Fatal("Unexpected key \"truncated_body\" in input")
	}

	if _, ok := inputMap["parsed_body"]; ok {
		t.Fatal("Unexpected key \"parsed_body\" in input")
	}
}

func TestCheckDecisionTruncatedBodyWithLogger(t *testing.T) {

	exampleDeniedRequestTruncatedBody := `{
		"attributes": {
		  "request": {
			"http": {
			  "id": "13359530607844510314",
			  "headers": {
				"content-type": "application/json",
				"content-length": "100000"
			  },
			  "method": "GET",
			  "body": "{\"firstname\": \"foo\", \"lastname\": \"bar\", \"dept\": {\"it\": \"eng\"}}",
			}
		  }
		}
	}`

	exampleAllowedRequestTruncatedBody := `{
		"attributes": {
			"request": {
				"http": {
				  "id": "13359530607844510314",
				  "headers": {
					"content-type": "application/json",
					"content-length": "62"
				  },
				  "method": "GET",
				  "body": "{\"firstname\": \"foo\", \"lastname\": \"bar\", \"dept\": {\"it\": \"eng\"}}",
				}
			}
		}
	}`

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequestTruncatedBody), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	server := testAuthzServerWithTruncatedBody(customLogger, false, false)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}

	// denied decision
	if output.Status.Code != int32(code.Code_PERMISSION_DENIED) {
		t.Fatal("Expected request to be denied but got:", output)
	}

	if len(customLogger.events) != 1 {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error != nil || event.Path != "envoy/authz/allow" || *event.Result == true ||
		event.DecisionID == "" || event.Metrics == nil {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}

	input := *event.Input
	inputMap, _ := input.(map[string]interface{})
	isTruncated, _ := inputMap["truncated_body"].(bool)

	if !isTruncated {
		t.Fatal("Expected truncated request body")
	}

	// allowed decision
	if err := util.Unmarshal([]byte(exampleAllowedRequestTruncatedBody), &req); err != nil {
		panic(err)
	}

	output, err = server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}

	// denied decision
	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}

	if len(customLogger.events) != 2 {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}

	event = customLogger.events[1]

	if event.Error != nil || event.Path != "envoy/authz/allow" || *event.Result == false ||
		event.DecisionID == "" || event.Metrics == nil {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}

	input = *event.Input
	inputMap, _ = input.(map[string]interface{})
	isTruncated, _ = inputMap["truncated_body"].(bool)

	if isTruncated {
		t.Fatal("Unexpected truncated request body")
	}
}

func TestCheckBadDecisionWithLogger(t *testing.T) {

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleInvalidRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	server := testAuthzServer(customLogger, false)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)

	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	if output != nil {
		t.Fatalf("Expected no output but got %v", output)
	}

	if len(customLogger.events) != 1 {
		t.Fatal("Unexpected events:", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error == nil || event.Path != "envoy/authz/allow" || event.Revision != "" || event.Result != nil ||
		event.DecisionID == "" || event.Metrics == nil {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}
}

func TestCheckWithLoggerError(t *testing.T) {

	// Example Envoy Check Request for input:
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
	if output.Status.Code != int32(code.Code_UNKNOWN) {
		t.Errorf("Expected logger error code UNKNOWN but got %v", output.Status.Code)
	}

	expectedMsg := "Bad Logger Error"
	if output.Status.Message != expectedMsg {
		t.Fatalf("Expected error message %v, but got %v", expectedMsg, output.Status.Message)
	}
}

// Some decision log related tests are replicated for envoy.service.auth.v2.Authorization/Check
// here to ensure the stop()-function logic is correct.
func TestCheckWithLoggerErrorV2(t *testing.T) {
	var req ext_authz_v2.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	server := envoyExtAuthzV2Wrapper{testAuthzServer(&testPluginError{}, false)}
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(code.Code_UNKNOWN) {
		t.Errorf("Expected logger error code UNKNOWN but got %v", output.Status.Code)
	}

	expectedMsg := "Bad Logger Error"
	if output.Status.Message != expectedMsg {
		t.Fatalf("Expected error message %v, but got %v", expectedMsg, output.Status.Message)
	}
}

func TestCheckBadDecisionWithLoggerV2(t *testing.T) {
	var req ext_authz_v2.CheckRequest
	if err := util.Unmarshal([]byte(exampleInvalidRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	server := envoyExtAuthzV2Wrapper{testAuthzServer(customLogger, false)}
	ctx := context.Background()
	output, err := server.Check(ctx, &req)

	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	if output != nil {
		t.Fatalf("Expected no output but got %v", output)
	}

	if len(customLogger.events) != 1 {
		t.Fatal("Unexpected events:", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error == nil || event.Path != "envoy/authz/allow" || event.Revision != "" || event.Result != nil ||
		event.DecisionID == "" || event.Metrics == nil {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}
}

func TestCheckDenyWithLoggerV2(t *testing.T) {
	var req ext_authz_v2.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	customLogger := &testPlugin{}
	server := envoyExtAuthzV2Wrapper{testAuthzServer(customLogger, false)}
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(code.Code_PERMISSION_DENIED) {
		t.Fatal("Expected request to be denied but got:", output)
	}

	if len(customLogger.events) != 1 {
		t.Fatal("Unexpected events:", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error != nil || event.Path != "envoy/authz/allow" || event.Revision != "" || *event.Result == true ||
		event.DecisionID == "" || event.Metrics == nil {
		t.Fatal("Unexpected events:", customLogger.events)
	}
}

func TestCheckTwiceWithCachedBuiltinCall(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	// http server that counts how often it was called, returns that number in JSON
	count := 0
	countMutex := sync.Mutex{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		countMutex.Lock()
		count = count + 1
		countMutex.Unlock()
		fmt.Fprintf(w, `{"count": %d}`, count)
	}))
	defer ts.Close()

	// create custom logger
	customLogger := &testPlugin{}

	moduleFmt := `
		package envoy.authz

		default allow = false
		allow {
			resp := http.send({"url": "%s", "method":"GET",
			  "force_cache": true, "force_cache_duration_seconds": 10})
			resp.body.count == 1
		}
	`
	module := fmt.Sprintf(moduleFmt, ts.URL)
	server := testAuthzServerWithModule(module, "envoy/authz/allow", customLogger, false, false)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}

	// second call, should be cached
	output, err = server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}
}

func TestConfigValidWithQuery(t *testing.T) {

	m, err := plugins.New([]byte{}, "test", inmem.New())
	if err != nil {
		t.Fatal(err)
	}

	in := `{"addr": ":9292", "query": "data.test", "dry-run": true, "enable-reflection": true}`
	config, err := Validate(m, []byte(in))
	if err != nil {
		t.Fatal(err)
	}

	if config.Addr != ":9292" {
		t.Fatalf("Expected address :9292 but got %v", config.Addr)
	}

	if config.parsedQuery.String() != "data.test" {
		t.Fatalf("Expected query data.test but got %v", config.parsedQuery.String())
	}

	if !config.DryRun {
		t.Fatal("Expected dry-run config to be enabled")
	}

	if !config.EnableReflection {
		t.Fatal("Expected enable-reflection config to be enabled")
	}
}

func TestConfigValidWithPath(t *testing.T) {

	m, err := plugins.New([]byte{}, "test", inmem.New())
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		path string
		want string
	}{
		"empty_path":               {path: "", want: "data.envoy.authz.allow"},
		"path_no_lt_slash":         {path: "test/allow/main", want: "data.test.allow.main"},
		"path_with_leading_slash":  {path: "/test/allow/main", want: "data.test.allow.main"},
		"path_with_trailing_slash": {path: "test/allow/main/", want: "data.test.allow.main"},
		"path_with_lt_slash":       {path: "/test/allow/main/", want: "data.test.allow.main"},
		"path_with_periods":        {path: "test/com.foo.envoy.ingress/allow/main/", want: "data.test[\"com.foo.envoy.ingress\"].allow.main"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {

			in := fmt.Sprintf(`{"path": %v}`, tc.path)
			config, err := Validate(m, []byte(in))
			if err != nil {
				t.Fatal(err)
			}

			if config.parsedQuery.String() != tc.want {
				t.Fatalf("Expected query %v but got %v", tc.want, config.parsedQuery.String())
			}
		})
	}
}

func TestConfigValidWithGRPCMaxMessageSizes(t *testing.T) {

	m, err := plugins.New([]byte{}, "test", inmem.New())
	if err != nil {
		t.Fatal(err)
	}

	in := `{"grpc-max-recv-msg-size": 1000, "grpc-max-send-msg-size": 1000}`
	config, err := Validate(m, []byte(in))
	if err != nil {
		t.Fatal(err)
	}

	if config.GRPCMaxRecvMsgSize != 1000 {
		t.Fatalf("Expected GRPC max receive message size to be 1000 but got %v", config.GRPCMaxRecvMsgSize)
	}

	if config.GRPCMaxSendMsgSize != 1000 {
		t.Fatalf("Expected GRPC max send message size to be 1000 but got %v", config.GRPCMaxSendMsgSize)
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

	expected := "data." + strings.Replace(defaultPath, "/", ".", -1)
	if config.parsedQuery.String() != expected {
		t.Fatalf("Expected query %v but got %v", expected, config.parsedQuery.String())
	}

	if config.Path != defaultPath {
		t.Fatalf("Expected path %v but got %v", defaultPath, config.Path)
	}

	if config.Query != "" {
		t.Fatalf("Expected empty query but got %v", config.Query)
	}

	if config.DryRun {
		t.Fatal("Expected dry-run config to be disabled by default")
	}

	if config.EnableReflection {
		t.Fatal("Expected enable-reflection config to be disabled by default")
	}

	if config.GRPCMaxRecvMsgSize != defaultGRPCServerMaxReceiveMessageSize {
		t.Fatalf("Expected GRPC max receive message size %d but got %d", defaultGRPCServerMaxReceiveMessageSize, config.GRPCMaxRecvMsgSize)
	}

	if config.GRPCMaxSendMsgSize != defaultGRPCServerMaxSendMessageSize {
		t.Fatalf("Expected GRPC max send message size %d but got %d", defaultGRPCServerMaxSendMessageSize, config.GRPCMaxSendMsgSize)
	}
}

func TestConfigInvalid(t *testing.T) {

	m, err := plugins.New([]byte{}, "test", inmem.New())
	if err != nil {
		t.Fatal(err)
	}

	in := `{"query": "data.test.allow", "path": "test/allow"}`
	_, err = Validate(m, []byte(in))
	if err == nil {
		t.Fatal("Expected error but got nil")
	}
}

func TestConfigWithProtoDescriptor(t *testing.T) {
	tests := map[string]struct {
		path    string
		wantErr bool
	}{
		"nonexistent":     {"this/does/not/exist", true},
		"other file type": {"../test/files/book/Book.proto", true},
		"valid file":      {"../test/files/combined.pb", false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := plugins.New([]byte{}, "test", inmem.New())
			if err != nil {
				t.Fatal(err)
			}

			in := fmt.Sprintf(`{"proto-descriptor": "%s"}`, tc.path)
			_, err = Validate(m, []byte(in))
			if expected, actual := tc.wantErr, err != nil; expected != actual {
				t.Errorf("expected err: %v", expected)
			}
		})
	}
}

func TestCheckAllowObjectDecisionReqHeadersToRemove(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequestParsedPath), &req); err != nil {
		panic(err)
	}

	module := `
		package envoy.authz

		default allow = false

		allow {
			input.parsed_path = ["my", "test", "path"]
		}

		headers["x"] = "hello"
		headers["y"] = "world"

		request_headers_to_remove := ["foo", "bar"]

		result["allowed"] = allow
		result["headers"] = headers
		result["request_headers_to_remove"] = request_headers_to_remove`

	server := testAuthzServerWithModule(module, "envoy/authz/result", &testPlugin{}, false, false)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}

	if output.Status.Code != int32(code.Code_OK) {
		t.Fatalf("Expected request to be allowed but got: %v", output)
	}

	response := output.GetOkResponse()
	if response == nil {
		t.Fatal("Expected OkHttpResponse struct but got nil")
	}

	headers := response.GetHeadersToRemove()
	if len(headers) != 2 {
		t.Fatalf("Expected two headers but got %v", len(headers))
	}

	expectedHeaders := []string{"foo", "bar"}

	if !reflect.DeepEqual(expectedHeaders, headers) {
		t.Fatalf("Expected headers %v but got %v", expectedHeaders, headers)
	}
}

func TestCheckAllowObjectDecisionResponseHeadersToAdd(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequestParsedPath), &req); err != nil {
		panic(err)
	}

	module := `
		package envoy.authz

		default allow = false

		allow {
			input.parsed_path = ["my", "test", "path"]
		}

		response_headers_to_add["x"] = "hello"
		response_headers_to_add["y"] = "world"

		result["allowed"] = allow
		result["response_headers_to_add"] = response_headers_to_add`

	server := testAuthzServerWithModule(module, "envoy/authz/result", &testPlugin{}, false, false)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}

	if output.Status.Code != int32(code.Code_OK) {
		t.Fatalf("Expected request to be allowed but got: %v", output)
	}

	response := output.GetOkResponse()
	if response == nil {
		t.Fatal("Expected OkHttpResponse struct but got nil")
	}

	headers := response.GetResponseHeadersToAdd()
	if len(headers) != 2 {
		t.Fatalf("Expected two headers but got %v", len(headers))
	}

	keys := []string{}
	for _, h := range headers {
		keys = append(keys, h.Header.GetKey())
	}

	if len(keys) != 2 {
		t.Fatalf("Expected two keys but got %v", len(keys))
	}
}

func TestCheckAllowObjectDecision(t *testing.T) {

	// Example Envoy Check Request for input:
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

	if output.Status.Code != int32(code.Code_OK) {
		t.Fatalf("Expected request to be allowed but got: %v", output)
	}

	response := output.GetOkResponse()
	if response == nil {
		t.Fatal("Expected OkHttpResponse struct but got nil")
	}

	headersToRemove := response.GetHeadersToRemove()
	if len(headersToRemove) != 0 {
		t.Fatalf("Expected no headers to remove but got %v", headersToRemove)
	}

	headersToAdd := response.GetResponseHeadersToAdd()
	if len(headersToAdd) != 0 {
		t.Fatalf("Expected no headers to add but got %v", headersToAdd)
	}

	headers := response.GetHeaders()
	if len(headers) != 2 {
		t.Fatalf("Expected two headers but got %v", len(headers))
	}

	expectedHeaders := make(map[string]string)
	expectedHeaders[http.CanonicalHeaderKey("x")] = "hello"
	expectedHeaders[http.CanonicalHeaderKey("y")] = "world"

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

	if output.Status.Code != int32(code.Code_PERMISSION_DENIED) {
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
	expectedHeaders[http.CanonicalHeaderKey("foo")] = "bar"
	expectedHeaders[http.CanonicalHeaderKey("baz")] = "taz"

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

	if output.Status.Code != int32(code.Code_OK) {
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

	if output.Status.Code != int32(code.Code_OK) {
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
	expectedHeaders[http.CanonicalHeaderKey("x")] = "hello"
	expectedHeaders[http.CanonicalHeaderKey("y")] = "world"

	assertHeaders(t, headers, expectedHeaders)
}

func TestPluginStatusLifeCycle(t *testing.T) {
	m, err := getPluginManager("package foo", &testPlugin{})
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	p := New(m, &Config{
		Addr: ":0",
	})
	m.Register(PluginName, p)

	assertPluginState(t, m, plugins.StateNotReady)

	ctx := context.Background()
	err = m.Start(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	// Wait a short time for the plugin to reach OK state
	// If it hits this timeout something bad has almost definitely happened
	waitForPluginState(t, m, plugins.StateOK, 5*time.Second)

	m.Stop(ctx)

	assertPluginState(t, m, plugins.StateNotReady)
}

func waitForPluginState(t *testing.T, m *plugins.Manager, desired plugins.State, timeout time.Duration) {
	after := time.After(timeout)
	tick := time.Tick(10 * time.Microsecond)
	for {
		select {
		case <-after:
			t.Fatal("Plugin failed to reach OK state in time")
		case <-tick:
			state, err := getPluginState(t, m)
			if err == nil && state == desired {
				return
			}
		}
	}
}

func getPluginState(t *testing.T, m *plugins.Manager) (plugins.State, error) {
	t.Helper()
	status, ok := m.PluginStatus()[PluginName]
	if !ok {
		return plugins.StateNotReady, fmt.Errorf("expected plugin %s to be in manager plugin status map", PluginName)
	}
	if status == nil {
		return plugins.StateNotReady, errors.New("expected a non-nil status value")
	}
	return status.State, nil
}

func assertPluginState(t *testing.T, m *plugins.Manager, expected plugins.State) {
	t.Helper()
	state, err := getPluginState(t, m)
	if err != nil {
		t.Fatal(err)
	}
	if state != expected {
		t.Fatalf("Expected plugin state %v, got %v", expected, state)
	}
}

func testAuthzServer(customLogger plugins.Plugin, dryRun bool) *envoyExtAuthzGrpcServer {

	// Define a RBAC policy to allow or deny requests based on user roles
	module := `
		package envoy.authz

		import input.attributes.request.http as http_request

		default allow = false

		allow {
			roles_for_user[r]
			required_roles[r]
		}

		allow {
			input.parsed_path = ["my", "test", "path"]
			input.parsed_query.a = ["1", "2"]
			input.parsed_query.x = ["y"]
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

	return testAuthzServerWithModule(module, "envoy/authz/allow", customLogger, dryRun, false)
}

func testAuthzServerWithModule(module string, path string, customLogger plugins.Plugin, dryRun bool, skipRequestBodyParse bool) *envoyExtAuthzGrpcServer {

	m, err := getPluginManager(module, customLogger)
	if err != nil {
		panic(err)
	}

	m.Config.NDBuiltinCache = true

	query := "data." + strings.Replace(path, "/", ".", -1)
	parsedQuery, err := ast.ParseBody(query)
	if err != nil {
		panic(err)
	}

	cfg := Config{
		Addr:                 ":0",
		Path:                 path,
		DryRun:               dryRun,
		SkipRequestBodyParse: skipRequestBodyParse,
		parsedQuery:          parsedQuery,
	}
	s := New(m, &cfg)
	return s.(*envoyExtAuthzGrpcServer)
}

func testAuthzServerWithObjectDecision(customLogger plugins.Plugin, dryRun bool) *envoyExtAuthzGrpcServer {

	module := `
		package envoy.authz

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

	return testAuthzServerWithModule(module, "envoy/authz/allow", customLogger, dryRun, false)
}

func testAuthzServerWithTruncatedBody(customLogger plugins.Plugin, dryRun, skipRequestBodyParse bool) *envoyExtAuthzGrpcServer {

	module := `
		package envoy.authz

		default allow = false

		allow {
			not input.truncated_body
		}
		`
	return testAuthzServerWithModule(module, "envoy/authz/allow", customLogger, dryRun, skipRequestBodyParse)
}

func TestLogWithASTError(t *testing.T) {
	server := testAuthzServer(&testPlugin{}, false)
	err := server.log(context.Background(), nil, &envoyauth.EvalResult{}, &ast.Error{Code: "foo"})
	if err != nil {
		panic(err)
	}
}

func TestLogWithCancelError(t *testing.T) {
	// create custom logger
	customLogger := &testPlugin{}

	server := testAuthzServer(customLogger, false)
	err := server.log(context.Background(), nil, &envoyauth.EvalResult{}, &topdown.Error{
		Code:    topdown.CancelErr,
		Message: "caller cancelled query execution",
	})
	if err != nil {
		panic(err)
	}

	if len(customLogger.events) != 1 {
		t.Fatal("Unexpected events:", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error == nil {
		t.Fatal("Expected error but got nil")
	}

	expectedErrMsg := "eval_cancel_error: context deadline reached during query execution"
	if event.Error.Error() != expectedErrMsg {
		t.Fatalf("Expected error message %v but got %v", expectedErrMsg, event.Error.Error())
	}
}

func TestVersionInfoInputV3(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}
	customLogger := &testPlugin{}

	module := `
		package envoy.authz

		allow {
			input.version.ext_authz == "v3"
			input.version.encoding == "protojson"
		}
		`
	server := testAuthzServerWithModule(module, "envoy/authz/allow", customLogger, false, false)
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}
}

func TestVersionInfoInputV2(t *testing.T) {
	var req ext_authz_v2.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}
	customLogger := &testPlugin{}

	module := `
		package envoy.authz

		allow {
			input.version.ext_authz == "v2"
			input.version.encoding == "encoding/json"
		}
		`
	serverV3 := testAuthzServerWithModule(module, "envoy/authz/allow", customLogger, false, false)
	server := &envoyExtAuthzV2Wrapper{serverV3}
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if output.Status.Code != int32(code.Code_OK) {
		t.Fatal("Expected request to be allowed but got:", output)
	}
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
		key := http.CanonicalHeaderKey(header.GetHeader().GetKey())
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
