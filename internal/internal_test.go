// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	ext_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_authz_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	ext_authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	ext_type_v2 "github.com/envoyproxy/go-control-plane/envoy/type"
	ext_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	_structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/plugins/logs"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/util"

	"github.com/open-policy-agent/opa-envoy-plugin/envoyauth"
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

	server := testAuthzServer(nil, withCustomLogger(&testPlugin{}))
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

	server := testAuthzServer(nil, withCustomLogger(&testPlugin{}))
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

	server := testAuthzServer(nil, withCustomLogger(&testPlugin{}))
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

	server := testAuthzServer(nil, withCustomLogger(&testPlugin{}))
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

	server := testAuthzServer(nil, withCustomLogger(customLogger))
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

	if event.Error != nil || event.Path != "envoy/authz/result" ||
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

	server := testAuthzServer(nil, withCustomLogger(&testPlugin{}))
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(code.Code_PERMISSION_DENIED) {
		t.Fatal("Expected request to be denied but got:", output)
	}
}

func TestCheckDenyDynamicMetadataDecisionID(t *testing.T) {
	// Example Envoy Check Request for input:
	// curl --user  alice:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	server := testAuthzServer(nil, withCustomLogger(&testPlugin{}))
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}
	if output.Status.Code != int32(code.Code_PERMISSION_DENIED) {
		t.Fatal("Expected request to be denied but got:", output)
	}

	assertDynamicMetadataDecisionID(t, output.GetDynamicMetadata())
}

func TestCheckDenyParsedBody(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequestParsedBody), &req); err != nil {
		panic(err)
	}

	server := testAuthzServer(nil, withCustomLogger(&testPlugin{}))
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

	server := testAuthzServer(&Config{DryRun: true}, withCustomLogger(customLogger))
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

	server := testAuthzServer(&Config{DryRun: true}, withCustomLogger(customLogger))
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

	server := testAuthzServer(nil, withCustomLogger(customLogger))
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

	if event.Error != nil || event.Path != "envoy/authz/result" || event.Revision != "" || *event.Result == true ||
		event.DecisionID == "" || event.Metrics == nil {
		t.Fatal("Unexpected events:", customLogger.events)
	}
}

func TestCheckAllowWithLoggerNDBCache(t *testing.T) {
	// test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	defer ts.Close()

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

	module := fmt.Sprintf(`
		package envoy.authz

		default allow = false

		allow if {
          res := http.send({"url": "%s", "method": "GET"})
          res.status_code == 200
		}
`, ts.URL)

	server := testAuthzServerWithModule(module, "envoy/authz/allow", nil, withCustomLogger(customLogger))
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
	nd, ok := cache.(map[string]any)
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

	server := testAuthzServer(&Config{EnablePerformanceMetrics: true}, withCustomLogger(customLogger))

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

	if len((*event.Input).(map[string]any)) == 0 {
		t.Fatalf("Expected non empty input but got %v", *event.Input)
	}

	assertErrorCounterMetric(t, server, CheckRequestTimeoutErr)
}

func TestCheckContextTimeoutMetricsDisabled(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	server := testAuthzServer(&Config{EnablePerformanceMetrics: false}, withCustomLogger(customLogger))

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

	if len((*event.Input).(map[string]any)) == 0 {
		t.Fatalf("Expected non empty input but got %v", *event.Input)
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
	server := testAuthzServerWithModule(module, "envoy/authz/allow", &Config{EnablePerformanceMetrics: true}, withCustomLogger(customLogger))
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

	assertErrorCounterMetric(t, server, EnvoyAuthResultErr)
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

	server := testAuthzServerWithTruncatedBody(nil, withCustomLogger(customLogger))
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
	inputMap, _ := input.(map[string]any)
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

	server := testAuthzServerWithTruncatedBody(&Config{SkipRequestBodyParse: true}, withCustomLogger(customLogger))
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
	inputMap, _ := input.(map[string]any)

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

	server := testAuthzServerWithTruncatedBody(nil, withCustomLogger(customLogger))
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
	inputMap, _ := input.(map[string]any)
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
	inputMap, _ = input.(map[string]any)
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

	server := testAuthzServer(&Config{EnablePerformanceMetrics: true}, withCustomLogger(customLogger))
	ctx := context.Background()
	output, err := server.Check(ctx, &req)

	if err != nil {
		t.Fatal("Expected nil err")
	}

	if output == nil {
		t.Fatal("Expected output but got nil")
	}
	if output.Status.Code != int32(code.Code_PERMISSION_DENIED) {
		t.Fatalf("Expected status %v status: %v", int32(code.Code_PERMISSION_DENIED), output.Status.Code)
	}
	if deniedResponse, ok := output.HttpResponse.(*ext_authz.CheckResponse_DeniedResponse); !ok {
		t.Fatalf("Expected http response of type ext_authz.CheckResponse_DeniedResponse")
	} else if deniedResponse.DeniedResponse.Status.Code != ext_type_v3.StatusCode_BadRequest {
		t.Fatalf("Unexpected http status code: %v", deniedResponse.DeniedResponse.Status.Code)
	}

	if len(customLogger.events) != 1 {
		t.Fatal("Unexpected events:", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error == nil || event.Path != "envoy/authz/result" || event.Revision != "" || event.Result != nil ||
		event.DecisionID == "" || event.Metrics == nil {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}

	assertErrorCounterMetric(t, server, RequestParseErr)
}

func TestCheckEvalErrorWithLogger(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	module := `
		package envoy.authz

		allow := false

        allow:= true`

	server := testAuthzServerWithModule(module, "envoy/authz/allow", &Config{EnablePerformanceMetrics: true}, withCustomLogger(customLogger))
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

	expectedMsg := "eval_conflict_error: complete rules must not produce multiple outputs"
	if !strings.Contains(event.Error.Error(), expectedMsg) {
		t.Fatalf("Expected error message %v, but got %v", expectedMsg, event.Error.Error())
	}

	assertErrorCounterMetric(t, server, topdown.ConflictErr)
}

func TestCheckAllowObjectDecisionWithBadReqHeadersToRemoveWithLogger(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequestParsedPath), &req); err != nil {
		panic(err)
	}

	module := `
		package envoy.authz

		default allow = false

		allow if {
			input.parsed_path = ["my", "test", "path"]
		}

		headers["x"] = "hello"
		headers["y"] = "world"

		request_headers_to_remove := "foo"

		result["allowed"] = allow
		result["headers"] = headers
		result["request_headers_to_remove"] = request_headers_to_remove`

	customLogger := &testPlugin{}

	server := testAuthzServerWithModule(module, "envoy/authz/result", &Config{EnablePerformanceMetrics: true}, withCustomLogger(customLogger))
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

	if event.Error == nil || event.Path != "envoy/authz/result" || event.Revision != "" || event.Result != nil ||
		event.DecisionID == "" || event.Metrics == nil {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}

	expectedMsg := "type assertion error"
	if !strings.Contains(event.Error.Error(), expectedMsg) {
		t.Fatalf("Expected error message %v, but got %v", expectedMsg, event.Error.Error())
	}

	assertErrorCounterMetric(t, server, EnvoyAuthResultErr)
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

	server := testAuthzServer(&Config{EnablePerformanceMetrics: true}, withCustomLogger(customLogger))
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

	assertErrorCounterMetric(t, server, "unknown_log_error")
}

// Some decision log related tests are replicated for envoy.service.auth.v2.Authorization/Check
// here to ensure the stop()-function logic is correct.
func TestCheckWithLoggerErrorV2(t *testing.T) {
	var req ext_authz_v2.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	server := envoyExtAuthzV2Wrapper{testAuthzServer(&Config{EnablePerformanceMetrics: true}, withCustomLogger(&testPluginError{}))}
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

	assertErrorCounterMetric(t, server.v3, "unknown_log_error")
}

func TestCheckBadDecisionWithLoggerV2(t *testing.T) {
	var req ext_authz_v2.CheckRequest
	if err := util.Unmarshal([]byte(exampleInvalidRequest), &req); err != nil {
		panic(err)
	}

	// create custom logger
	customLogger := &testPlugin{}

	server := envoyExtAuthzV2Wrapper{testAuthzServer(&Config{EnablePerformanceMetrics: true}, withCustomLogger(customLogger))}
	ctx := context.Background()
	output, err := server.Check(ctx, &req)

	if err != nil {
		t.Fatal("Expected nil err")
	}

	if output == nil {
		t.Fatal("Expected output but got nil")
	}
	if output.Status.Code != int32(code.Code_PERMISSION_DENIED) {
		t.Fatalf("Expected status %v status: %v", int32(code.Code_PERMISSION_DENIED), output.Status.Code)
	}
	if deniedResponse, ok := output.HttpResponse.(*ext_authz_v2.CheckResponse_DeniedResponse); !ok {
		t.Fatalf("Expected http response of type ext_authz.CheckResponse_DeniedResponse")
	} else if deniedResponse.DeniedResponse.Status.Code != ext_type_v2.StatusCode_BadRequest {
		t.Fatalf("Unexpected http status code: %v", deniedResponse.DeniedResponse.Status.Code)
	}

	if len(customLogger.events) != 1 {
		t.Fatal("Unexpected events:", customLogger.events)
	}

	event := customLogger.events[0]

	if event.Error == nil || event.Path != "envoy/authz/result" || event.Revision != "" || event.Result != nil ||
		event.DecisionID == "" || event.Metrics == nil {
		t.Fatalf("Unexpected events: %+v", customLogger.events)
	}

	assertErrorCounterMetric(t, server.v3, RequestParseErr)
}

func TestCheckDenyWithLoggerV2(t *testing.T) {
	var req ext_authz_v2.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	customLogger := &testPlugin{}
	server := envoyExtAuthzV2Wrapper{testAuthzServer(nil, withCustomLogger(customLogger))}
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

	if event.Error != nil || event.Path != "envoy/authz/result" || event.Revision != "" || *event.Result == true ||
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
		allow if {
			resp := http.send({"url": "%s", "method":"GET",
			  "force_cache": true, "force_cache_duration_seconds": 10})
			resp.body.count == 1
		}
	`
	module := fmt.Sprintf(moduleFmt, ts.URL)
	server := testAuthzServerWithModule(module, "envoy/authz/allow", nil, withCustomLogger(customLogger))
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

func TestConfigValidWithGRPCRequestDurationSecondsBuckets(t *testing.T) {
	m, err := plugins.New([]byte{}, "test", inmem.New())
	if err != nil {
		t.Fatal(err)
	}

	in := `{"grpc-request-duration-seconds-buckets": [1e-5, 0.2, 1, 5]}`
	config, err := Validate(m, []byte(in))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(config.GRPCRequestDurationSecondsBuckets, []float64{1e-5, 0.2, 1, 5}) {
		t.Fatalf("Expected grpc_request_duration_seconds buckets to be [1e-5 0.2 1 5] but got %v", config.GRPCRequestDurationSecondsBuckets)
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

	if config.EnablePerformanceMetrics != defaultEnablePerformanceMetrics {
		t.Fatalf("Expected enabled-prometheus-metrics to be disabled by default")
	}

	if !reflect.DeepEqual(config.GRPCRequestDurationSecondsBuckets, defaultGRPCRequestDurationSecondsBuckets) {
		t.Fatalf("Exptected grpc_request_duration_seconds buckets %v but got %v", defaultGRPCRequestDurationSecondsBuckets, config.GRPCRequestDurationSecondsBuckets)
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

func TestCheckAllowObjectDecisionDynamicMetadata(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequestParsedPath), &req); err != nil {
		panic(err)
	}

	module := `
		package envoy.authz
	
		default allow = false

		allow if {
			input.parsed_path = ["my", "test", "path"]
		}

		dynamic_metadata["foo"] = "bar"
		dynamic_metadata["bar"] = "baz"

		result["allowed"] = allow
		result["dynamic_metadata"] = dynamic_metadata
	`

	server := testAuthzServerWithModule(module, "envoy/authz/result", nil, withCustomLogger(&testPlugin{}))
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

	assertDynamicMetadata(t, &_structpb.Struct{
		Fields: map[string]*_structpb.Value{
			"foo": {
				Kind: &_structpb.Value_StringValue{
					StringValue: "bar",
				},
			},
			"bar": {
				Kind: &_structpb.Value_StringValue{
					StringValue: "baz",
				},
			},
		},
	}, output.GetDynamicMetadata())
}

func TestCheckAllowObjectDecisionDynamicMetadataDecisionID(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequestParsedPath), &req); err != nil {
		panic(err)
	}

	module := `
		package envoy.authz
	
		default allow = false

		allow if {
			input.parsed_path = ["my", "test", "path"]
		}

		dynamic_metadata["foo"] = "bar"
		dynamic_metadata["bar"] = "baz"

		result["allowed"] = allow
		result["dynamic_metadata"] = dynamic_metadata
	`

	server := testAuthzServerWithModule(module, "envoy/authz/result", nil, withCustomLogger(&testPlugin{}))
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}

	if output.Status.Code != int32(code.Code_OK) {
		t.Fatalf("Expected request to be allowed but got: %v", output)
	}

	assertDynamicMetadataDecisionID(t, output.GetDynamicMetadata())
}

func TestCheckAllowBooleanDecisionDynamicMetadata(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequestParsedPath), &req); err != nil {
		panic(err)
	}

	module := `
		package envoy.authz
	
		default allow = false

		allow if {
			input.parsed_path = ["my", "test", "path"]
		}
	`

	server := testAuthzServerWithModule(module, "envoy/authz/allow", nil, withCustomLogger(&testPlugin{}))
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}

	if output.Status.Code != int32(code.Code_OK) {
		t.Fatalf("Expected request to be allowed but got: %v", output)
	}

	assertDynamicMetadata(t, &_structpb.Struct{}, output.GetDynamicMetadata())
}

func TestCheckAllowBooleanDecisionDynamicMetadataDecisionID(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequestParsedPath), &req); err != nil {
		panic(err)
	}

	module := `
		package envoy.authz
	
		default allow = false

		allow if {
			input.parsed_path = ["my", "test", "path"]
		}
	`

	server := testAuthzServerWithModule(module, "envoy/authz/allow", nil, withCustomLogger(&testPlugin{}))
	ctx := context.Background()
	output, err := server.Check(ctx, &req)
	if err != nil {
		t.Fatal(err)
	}

	if output.Status.Code != int32(code.Code_OK) {
		t.Fatalf("Expected request to be allowed but got: %v", output)
	}

	assertDynamicMetadataDecisionID(t, output.GetDynamicMetadata())
}

func TestCheckAllowObjectDecisionReqQueryParamsToRemove(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}

	module := `
		package envoy.authz

		default allow = true

		query_parameters_to_remove := ["foo", "bar"]

		result["allowed"] = allow
		result["query_parameters_to_remove"] = query_parameters_to_remove`

	server := testAuthzServerWithModule(module, "envoy/authz/result", nil, withCustomLogger(&testPlugin{}))
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

	queryParams := response.GetQueryParametersToRemove()
	if len(queryParams) != 2 {
		t.Fatalf("Expected two query params but got %v", len(queryParams))
	}

	expectedQueryParams := []string{"foo", "bar"}

	if !reflect.DeepEqual(expectedQueryParams, queryParams) {
		t.Fatalf("Expected query params %v but got %v", expectedQueryParams, queryParams)
	}
}

func TestCheckAllowObjectDecisionReqQueryParamsToSet(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}

	module := `
		package envoy.authz

		default allow = true

		query_parameters_to_set := {
			"foo": "value1",
			"bar": ["value2", "value3"]
		}

		result["allowed"] = allow
		result["query_parameters_to_set"] = query_parameters_to_set`

	server := testAuthzServerWithModule(module, "envoy/authz/result", nil, withCustomLogger(&testPlugin{}))
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

	queryParams := response.GetQueryParametersToSet()
	if len(queryParams) != 3 {
		t.Fatalf("Expected three query params but got %v", len(queryParams))
	}

	expectedQueryParamsToSet := []*ext_core.QueryParameter{
		{
			Key:   "foo",
			Value: "value1",
		},
		{
			Key:   "bar",
			Value: "value2",
		},
		{
			Key:   "bar",
			Value: "value3",
		},
	}

	// sort first by key, then by value

	sort.Slice(queryParams, func(i, j int) bool {
		if queryParams[i].Key == queryParams[j].Key {
			return queryParams[i].Value < queryParams[j].Value
		}
		return queryParams[i].Key < queryParams[j].Key
	})

	sort.Slice(expectedQueryParamsToSet, func(i, j int) bool {
		if expectedQueryParamsToSet[i].Key == expectedQueryParamsToSet[j].Key {
			return expectedQueryParamsToSet[i].Value < expectedQueryParamsToSet[j].Value
		}
		return expectedQueryParamsToSet[i].Key < expectedQueryParamsToSet[j].Key
	})

	for i, param := range queryParams {
		if !reflect.DeepEqual(expectedQueryParamsToSet[i], param) {
			t.Fatalf("Expected query param %v but got %v", expectedQueryParamsToSet[i], param)
		}
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

		allow if {
			input.parsed_path = ["my", "test", "path"]
		}

		headers["x"] = "hello"
		headers["y"] = "world"

		request_headers_to_remove := ["foo", "bar"]

		result["allowed"] = allow
		result["headers"] = headers
		result["request_headers_to_remove"] = request_headers_to_remove`

	server := testAuthzServerWithModule(module, "envoy/authz/result", nil, withCustomLogger(&testPlugin{}))
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

		allow if {
			input.parsed_path = ["my", "test", "path"]
		}

		response_headers_to_add["x"] = "hello"
		response_headers_to_add["y"] = "world"

		result["allowed"] = allow
		result["response_headers_to_add"] = response_headers_to_add`

	server := testAuthzServerWithModule(module, "envoy/authz/result", nil, withCustomLogger(&testPlugin{}))
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

func TestCheckAllowObjectDecisionMultiValuedHeaders(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequestParsedPath), &req); err != nil {
		panic(err)
	}

	module := `
		package envoy.authz

		default allow = false

		allow if {
			input.parsed_path = ["my", "test", "path"]
		}

		response_headers_to_add["x"] = ["hello", "world"]

		result["allowed"] = allow
		result["response_headers_to_add"] = response_headers_to_add`

	server := testAuthzServerWithModule(module, "envoy/authz/result", nil, withCustomLogger(&testPlugin{}))

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

	headersToAdd := response.GetResponseHeadersToAdd()
	if len(headersToAdd) != 2 {
		t.Fatalf("Expected two headers to add but got %v", headersToAdd)
	}

	expected := []*ext_core.HeaderValueOption{
		{
			Header: &ext_core.HeaderValue{
				Key:   "x",
				Value: "hello",
			},
		},
		{
			Header: &ext_core.HeaderValue{
				Key:   "x",
				Value: "world",
			},
		},
	}

	if !reflect.DeepEqual(expected, headersToAdd) {
		t.Fatal("Unexpected response_headers_to_add")
	}

	headers := response.GetHeaders()
	if len(headers) != 0 {
		t.Fatalf("Expected no headers but got %v", len(headers))
	}
}

func TestCheckAllowObjectDecision(t *testing.T) {
	// Example Envoy Check Request for input:
	// curl --user  bob:password  -o /dev/null -s -w "%{http_code}\n" http://${GATEWAY_URL}/api/v1/products

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequestParsedPath), &req); err != nil {
		panic(err)
	}

	server := testAuthzServerWithObjectDecision(nil, withCustomLogger(&testPlugin{}))
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

	dynamicMetadata := output.GetDynamicMetadata()
	if dynamicMetadata == nil {
		t.Fatal("Expected DynamicMetadata struct but got nil")
	}
}

func TestCheckDenyObjectDecision(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleDeniedRequest), &req); err != nil {
		panic(err)
	}

	server := testAuthzServerWithObjectDecision(nil, withCustomLogger(&testPlugin{}))
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

	server := testAuthzServerWithObjectDecision(&Config{DryRun: true}, withCustomLogger(&testPlugin{}))
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

	server := testAuthzServerWithObjectDecision(&Config{DryRun: true}, withCustomLogger(&testPlugin{}))
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

	assertDynamicMetadata(t, &_structpb.Struct{
		Fields: map[string]*_structpb.Value{
			"test": {
				Kind: &_structpb.Value_StringValue{
					StringValue: "foo",
				},
			},
			"bar": {
				Kind: &_structpb.Value_StringValue{
					StringValue: "baz",
				},
			},
		},
	}, output.GetDynamicMetadata())
}

func TestPluginStatusLifeCycle(t *testing.T) {
	m, err := getPluginManager("package foo", withCustomLogger(&testPlugin{}))
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

func testAuthzServer(customConfig *Config, customPluginFuncs ...customPluginFunc) *envoyExtAuthzGrpcServer {
	// Define a RBAC policy to allow or deny requests based on user roles
	module := `
		package envoy.authz

		import input.attributes.request.http as http_request

		default allow = false

		allow if {
			roles_for_user[r]
			required_roles[r]
		}

		allow if {
			input.parsed_path = ["my", "test", "path"]
			input.parsed_query.a = ["1", "2"]
			input.parsed_query.x = ["y"]
		}

		allow if {
			input.parsed_body.firstname == "foo"
			input.parsed_body.lastname == "bar"
			input.parsed_body.dept.it == "eng"
		}

		roles_for_user[r] if {
			r := user_roles[user_name][_]
		}

		required_roles[r] if {
			perm := role_perms[r][_]
			perm.method = http_request.method
			perm.path = http_request.path
		}

		user_name = parsed if {
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
		}

		result.allowed = allow

		result.headers = {
		  "foo": "bar",
		  "baz": "qux",
		}

		result.request_headers_to_remove = ["foo", "bar", "baz", "qux"]

		result.query_parameters_to_remove = ["foo", "bar", "baz", "qux"]

		result.query_parameters_to_set = {
		  "foo": "bar",
		  "baz": ["qux", "quux"]
		}

		result.response_headers_to_add = {
		  "foo": "bar",
		  "baz": "qux",
		}`

	return testAuthzServerWithModule(module, "envoy/authz/result", customConfig, customPluginFuncs...)
}

func testAuthzServerWithModule(module string, path string, customConfig *Config, customPluginFuncs ...customPluginFunc) *envoyExtAuthzGrpcServer {
	m, err := getPluginManager(module, customPluginFuncs...)
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
		Addr:                     ":0",
		Path:                     path,
		parsedQuery:              parsedQuery,
		DryRun:                   defaultDryRun,
		EnableReflection:         defaultEnableReflection,
		GRPCMaxRecvMsgSize:       defaultGRPCServerMaxReceiveMessageSize,
		GRPCMaxSendMsgSize:       defaultGRPCServerMaxSendMessageSize,
		SkipRequestBodyParse:     defaultSkipRequestBodyParse,
		EnablePerformanceMetrics: defaultEnablePerformanceMetrics,
	}

	if customConfig != nil {
		if customConfig.DryRun != defaultDryRun {
			cfg.DryRun = customConfig.DryRun
		}
		if customConfig.SkipRequestBodyParse != defaultSkipRequestBodyParse {
			cfg.SkipRequestBodyParse = customConfig.SkipRequestBodyParse
		}
		if customConfig.EnablePerformanceMetrics != defaultEnablePerformanceMetrics {
			cfg.EnablePerformanceMetrics = customConfig.EnablePerformanceMetrics
		}
	}

	s := New(m, &cfg)
	return s.(*envoyExtAuthzGrpcServer)
}

func testAuthzServerWithObjectDecision(customConfig *Config, customPluginFuncs ...customPluginFunc) *envoyExtAuthzGrpcServer {
	module := `
		package envoy.authz

		default allow = {
		  "allowed": false,
		  "headers": {"foo": "bar", "baz": "taz"},
		  "body": "Unauthorized Request",
		  "http_status": 301,
		  "dynamic_metadata": {"test": "foo", "bar": "baz"}
		}

		allow = response if {
			input.parsed_path = ["my", "test", "path"]
		    response := {
				"allowed": true,
				"headers": {"x": "hello", "y": "world"},
				"dynamic_metadata": {"test": "foo", "bar": "baz"}
		    }
		}`

	return testAuthzServerWithModule(module, "envoy/authz/allow", customConfig, customPluginFuncs...)
}

func testAuthzServerWithTruncatedBody(customConfig *Config, customPluginFuncs ...customPluginFunc) *envoyExtAuthzGrpcServer {
	module := `
		package envoy.authz

		default allow = false

		allow if {
			not input.truncated_body
		}
		`
	return testAuthzServerWithModule(module, "envoy/authz/allow", customConfig, customPluginFuncs...)
}

func TestPrometheusMetrics(t *testing.T) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}

	ctx := context.Background()
	testLogPlugin := &testPlugin{}
	server := testAuthzServer(&Config{EnablePerformanceMetrics: true}, withCustomLogger(testLogPlugin))
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer server.Stop(ctx)

	for i := 0; i < 10; i++ {
		output, err := server.Check(ctx, &req)
		if err != nil {
			t.Fatal(err)
		}
		if output.Status.Code != int32(code.Code_OK) {
			t.Fatal("Expected request to be allowed but got:", output)
		}
	}

	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(server.metricAuthzDuration); err != nil {
		panic(fmt.Errorf("registering collector failed: %w", err))
	}

	g := prometheus.ToTransactionalGatherer(reg)
	fam, _, err := g.Gather()
	if err != nil {
		panic(err)
	}
	if len(fam) != 1 {
		t.Fatalf("Expected 1 metric, got %d", len(fam))
	}
	if *fam[0].Metric[0].Histogram.SampleCount != 10 {
		t.Fatalf("Exptected 10 records, got %d", *fam[0].Metric[0].Histogram.SampleCount)
	}
	if *fam[0].Metric[0].Histogram.SampleSum == 0 {
		t.Fatalf("Exptected sum gather then 0, got %f", *fam[0].Metric[0].Histogram.SampleSum)
	}
}

func TestLogWithASTError(t *testing.T) {
	server := testAuthzServer(nil, withCustomLogger(&testPlugin{}))
	err := server.logDecision(context.Background(), nil, &envoyauth.EvalResult{}, &ast.Error{Code: "foo"})
	if err != nil {
		panic(err)
	}
}

func TestLogWithCancelError(t *testing.T) {
	// create custom logger
	customLogger := &testPlugin{}

	server := testAuthzServer(nil, withCustomLogger(customLogger))
	err := server.logDecision(context.Background(), nil, &envoyauth.EvalResult{}, &topdown.Error{
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

		allow if {
			input.version.ext_authz == "v3"
			input.version.encoding == "protojson"
		}
		`
	server := testAuthzServerWithModule(module, "envoy/authz/allow", nil, withCustomLogger(customLogger))
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

		allow if {
			input.version.ext_authz == "v2"
			input.version.encoding == "encoding/json"
		}
		`
	serverV3 := testAuthzServerWithModule(module, "envoy/authz/allow", nil, withCustomLogger(customLogger))
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

type customPluginFunc func(m *plugins.Manager)

func withCustomLogger(customLogger plugins.Plugin) customPluginFunc {
	return func(m *plugins.Manager) {
		m.Register("test_log_plugin", customLogger)
		config, err := logs.ParseConfig([]byte(`{"plugin": "test_log_plugin"}`), nil, []string{"test_log_plugin"})
		if err != nil {
			panic(err)
		}

		logPlugin := logs.New(config, m)
		m.Register(logs.Name, logPlugin)
	}
}

func getPluginManager(module string, customPluginFuncs ...customPluginFunc) (*plugins.Manager, error) {
	ctx := context.Background()
	store := inmem.New()
	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)
	store.UpsertPolicy(ctx, txn, "example.rego", []byte(module))
	store.Commit(ctx, txn)

	registry := prometheus.NewRegistry()
	m, err := plugins.New([]byte{}, "test", store, plugins.WithPrometheusRegister(registry))
	if err != nil {
		return nil, err
	}

	for _, opt := range customPluginFuncs {
		opt(m)
	}

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

func assertErrorCounterMetric(t *testing.T, server *envoyExtAuthzGrpcServer, labelValues ...string) {
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(server.metricErrorCounter); err != nil {
		t.Fatalf("registering collector failed: %v", err)
	}

	g := prometheus.ToTransactionalGatherer(reg)
	fam, _, err := g.Gather()
	if err != nil {
		t.Fatalf("gathering metrics failed: %v", err)
	}
	if len(fam) != 1 {
		t.Fatalf("Expected 1 metric, got %d", len(fam))
	}
	if fam[0].Metric[0].Counter.GetValue() != 1 {
		t.Fatalf("Expected counter value 1, got %v", fam[0].Metric[0].Counter.GetValue())
	}
	if len(fam[0].Metric[0].GetLabel()) != len(labelValues) {
		t.Fatalf("Expected %v labels in the counter metric, got %v labels", len(labelValues), len(fam[0].Metric[0].GetLabel()))
	}
	for labelIndex, labelValue := range labelValues {
		if fam[0].Metric[0].GetLabel()[labelIndex].GetValue() != labelValue {
			t.Fatalf("Expected error metric with reason label %v, got %v", labelValue, fam[0].Metric[0].GetLabel()[labelIndex].GetValue())
		}
	}
}

func assertDynamicMetadata(t *testing.T, expectedMetadata, actualMetadata *_structpb.Struct) {
	t.Helper()

	// Remove decision_id from actual metadata since it is randomly generated.
	delete(actualMetadata.Fields, "decision_id")

	if !proto.Equal(expectedMetadata, actualMetadata) {
		t.Fatalf("Expected metadata %v but got %v", expectedMetadata, actualMetadata)
	}
}

func assertDynamicMetadataDecisionID(t *testing.T, dynamicMetadata *_structpb.Struct) {
	t.Helper()

	if dynamicMetadata == nil {
		t.Fatal("Expected dynamic metadata but got nil")
	}

	if dynamicMetadata.Fields == nil {
		t.Fatal("Expected dynamic metadata fields but got nil")
	}

	key, ok := dynamicMetadata.Fields["decision_id"]
	if !ok {
		t.Fatal("Expected decision_id but got nil")
	}

	if len(key.GetStringValue()) != 36 { // 32 + 4 dashes
		t.Fatalf("Expected decision_id to be 36 characters but got %v", len(key.GetStringValue()))
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

func (p *testPlugin) Reconfigure(context.Context, any) {
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

func (p *testPluginError) Reconfigure(context.Context, any) {
}

func (p *testPluginError) Log(_ context.Context, event logs.EventV1) error {
	p.events = append(p.events, event)
	return fmt.Errorf("Bad Logger Error")
}

// mockExtProcStream is a mock implementation of the ProcessServer interface
type mockExtProcStream struct {
	ctx              context.Context
	t                *testing.T
	requestsToSend   []*ext_proc_v3.ProcessingRequest
	receivedIndex    int
	receivedMessages []*ext_proc_v3.ProcessingResponse
	sendError        error
	recvError        error
}

func (m *mockExtProcStream) Send(resp *ext_proc_v3.ProcessingResponse) error {
	if m.sendError != nil {
		return m.sendError
	}
	m.receivedMessages = append(m.receivedMessages, resp)
	return nil
}

func (m *mockExtProcStream) Recv() (*ext_proc_v3.ProcessingRequest, error) {
	if m.recvError != nil {
		return nil, m.recvError
	}

	if m.receivedIndex >= len(m.requestsToSend) {
		return nil, io.EOF
	}

	req := m.requestsToSend[m.receivedIndex]
	m.receivedIndex++
	return req, nil
}

// Additional methods required by the interface
func (m *mockExtProcStream) SetHeader(metadata.MD) error {
	return nil // No-op for tests
}

func (m *mockExtProcStream) SendHeader(metadata.MD) error {
	return nil // No-op for tests
}

func (m *mockExtProcStream) SetTrailer(metadata.MD) {
	// No-op for tests
}

func (m *mockExtProcStream) SendMsg(msg interface{}) error {
	resp, ok := msg.(*ext_proc_v3.ProcessingResponse)
	if !ok {
		return fmt.Errorf("expected ProcessingResponse")
	}
	return m.Send(resp)
}

func (m *mockExtProcStream) RecvMsg(msg interface{}) error {
	req, ok := msg.(*ext_proc_v3.ProcessingRequest)
	if !ok {
		return fmt.Errorf("expected ProcessingRequest")
	}

	received, err := m.Recv()
	if err != nil {
		return err
	}

	*req = *received
	return nil
}

func (m *mockExtProcStream) Context() context.Context {
	return m.ctx
}

func buildHeaders(m map[string]string) *ext_proc_v3.HttpHeaders {
	var kv []*ext_core.HeaderValue
	for k, v := range m {
		kv = append(kv, &ext_core.HeaderValue{Key: k, Value: v})
	}
	return &ext_proc_v3.HttpHeaders{
		Headers: &ext_core.HeaderMap{
			Headers: kv,
		},
	}
}

func buildBody(body string) *ext_proc_v3.HttpBody {
	return &ext_proc_v3.HttpBody{
		Body:        []byte(body),
		EndOfStream: true,
	}
}

func buildTrailers(m map[string]string) *ext_proc_v3.HttpTrailers {
	var kv []*ext_core.HeaderValue
	for k, v := range m {
		kv = append(kv, &ext_core.HeaderValue{Key: k, Value: v})
	}
	return &ext_proc_v3.HttpTrailers{
		Trailers: &ext_core.HeaderMap{
			Headers: kv,
		},
	}
}

func TestProcessRequestHeaders(t *testing.T) {
	ctx := context.Background()
	module := `
		package ext_proc

		response = {
			"headers_to_add": [
				{"key": "X-Added-Header", "value": "TestValue"}
			]
		} if {
			input.path == "/test-path"
		}
	`

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	// Test request with headers
	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":      "/test-path",
						":method":    "GET",
						":scheme":    "http",
						":authority": "example.com",
						"user-agent": "test-agent",
					}),
				},
			},
		},
	}

	err = server.Process(mockStream)
	if err != nil {
		t.Fatalf("Process returned an error: %v", err)
	}

	if len(mockStream.receivedMessages) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(mockStream.receivedMessages))
	}

	// Check that headers were added properly
	response := mockStream.receivedMessages[0]
	reqHeaders := response.GetRequestHeaders()

	if reqHeaders == nil {
		t.Fatal("Expected RequestHeaders in response, got nil")
	}

	headerMutation := reqHeaders.GetResponse().GetHeaderMutation()
	if headerMutation == nil {
		t.Fatal("Expected HeaderMutation in response, got nil")
	}

	if len(headerMutation.GetSetHeaders()) != 1 {
		t.Fatalf("Expected 1 header to be added, got %d", len(headerMutation.GetSetHeaders()))
	}

	addedHeader := headerMutation.GetSetHeaders()[0]
	if addedHeader.GetHeader().GetKey() != "X-Added-Header" || addedHeader.GetHeader().GetValue() != "TestValue" {
		t.Fatalf("Expected header X-Added-Header: TestValue, got %s: %s",
			addedHeader.GetHeader().GetKey(),
			addedHeader.GetHeader().GetValue())
	}
}

func TestProcessRequestBody(t *testing.T) {
	ctx := context.Background()
	module := `
        package ext_proc

        # Default empty response
        default response = {}

        # Rule for request headers
        response = {} if {
            input.request_type == "request_headers"
        }

        # Rule for request body
        response = body_response if {
            input.request_type == "request_body"
        }

        # Determine body response based on action
        body_response = {
            "body": "Modified body content"
        } if {
            input.parsed_body.action == "read"
        } else = {
            "body": "Default body response"
        }
    `

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	// Test request with body
	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":        "/api/data",
						":method":      "POST",
						"content-type": "application/json",
					}),
				},
			},
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestBody{
					RequestBody: buildBody(`{"action":"read","resource":"document1"}`),
				},
			},
		},
	}

	err = server.Process(mockStream)
	if err != nil {
		t.Fatalf("Process returned an error: %v", err)
	}

	if len(mockStream.receivedMessages) != 2 {
		t.Fatalf("Expected 2 responses, got %d", len(mockStream.receivedMessages))
	}

	// Check body modification
	bodyResponse := mockStream.receivedMessages[1].GetRequestBody()
	if bodyResponse == nil {
		t.Fatal("Expected RequestBody in response, got nil")
	}

	if bodyResponse.GetResponse() == nil {
		t.Fatal("Expected CommonResponse in RequestBody, got nil")
	}

	bodyMutation := bodyResponse.GetResponse().GetBodyMutation()
	if bodyMutation == nil {
		t.Fatal("Expected BodyMutation in response, got nil")
	}

	modifiedBody := string(bodyMutation.GetBody())
	if modifiedBody != "Modified body content" {
		t.Fatalf("Expected modified body content, got %s", modifiedBody)
	}
}

func TestProcessImmediateResponse(t *testing.T) {
	ctx := context.Background()
	module := `
		package ext_proc

		response = {
			"immediate_response": {
				"status": 403,
				"body": "Access Denied",
				"headers": [
					{"key": "Content-Type", "value": "text/plain"},
					{"key": "X-Denied-Reason", "value": "Unauthorized"}
				]
			}
		} if {
			input.path == "/forbidden"
		}
	`

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	// Test request that should trigger immediate response
	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":      "/forbidden",
						":method":    "GET",
						":authority": "example.com",
					}),
				},
			},
		},
	}

	err = server.Process(mockStream)
	if err != nil {
		t.Fatalf("Process returned an error: %v", err)
	}

	if len(mockStream.receivedMessages) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(mockStream.receivedMessages))
	}

	response := mockStream.receivedMessages[0]
	immediateResponse := response.GetImmediateResponse()
	if immediateResponse == nil {
		t.Fatal("Expected ImmediateResponse, got nil")
	}

	// Check status
	if immediateResponse.GetStatus().GetCode() != ext_type_v3.StatusCode_Forbidden {
		t.Fatalf("Expected Forbidden status, got %v", immediateResponse.GetStatus().GetCode())
	}

	// Check body
	if string(immediateResponse.GetBody()) != "Access Denied" {
		t.Fatalf("Expected 'Access Denied' body, got '%s'", string(immediateResponse.GetBody()))
	}

	// Check headers
	headers := immediateResponse.GetHeaders().GetSetHeaders()
	if len(headers) != 2 {
		t.Fatalf("Expected 2 headers, got %d", len(headers))
	}

	foundContentType := false
	foundDeniedReason := false

	for _, h := range headers {
		if h.GetHeader().GetKey() == "Content-Type" && h.GetHeader().GetValue() == "text/plain" {
			foundContentType = true
		}
		if h.GetHeader().GetKey() == "X-Denied-Reason" && h.GetHeader().GetValue() == "Unauthorized" {
			foundDeniedReason = true
		}
	}

	if !foundContentType {
		t.Error("Missing expected Content-Type header")
	}
	if !foundDeniedReason {
		t.Error("Missing expected X-Denied-Reason header")
	}
}

func TestProcessDynamicMetadata(t *testing.T) {
	ctx := context.Background()
	module := `
		package ext_proc

		response = {
			"dynamic_metadata": {
				"filter_metadata": {
					"user_id": "12345",
					"roles": ["admin", "user"]
				}
			}
		} if {
			input.path == "/metadata"
		}
	`

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	// Test request for dynamic metadata
	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":      "/metadata",
						":method":    "GET",
						":authority": "example.com",
					}),
				},
			},
		},
	}

	err = server.Process(mockStream)
	if err != nil {
		t.Fatalf("Process returned an error: %v", err)
	}

	if len(mockStream.receivedMessages) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(mockStream.receivedMessages))
	}

	response := mockStream.receivedMessages[0]
	dynamicMetadata := response.GetDynamicMetadata()
	if dynamicMetadata == nil {
		t.Fatal("Expected DynamicMetadata, got nil")
	}

	filterMetadata, ok := dynamicMetadata.GetFields()["filter_metadata"]
	if !ok {
		t.Fatal("Expected filter_metadata field in dynamic metadata")
	}

	structValue := filterMetadata.GetStructValue()
	if structValue == nil {
		t.Fatal("Expected struct value for filter_metadata")
	}

	userId, ok := structValue.GetFields()["user_id"]
	if !ok || userId.GetStringValue() != "12345" {
		t.Fatalf("Expected user_id: 12345, got %v", userId)
	}

	roles, ok := structValue.GetFields()["roles"]
	if !ok {
		t.Fatal("Expected roles field")
	}

	listValue := roles.GetListValue()
	if listValue == nil || len(listValue.GetValues()) != 2 {
		t.Fatalf("Expected list with 2 values, got %v", listValue)
	}

	if listValue.GetValues()[0].GetStringValue() != "admin" ||
		listValue.GetValues()[1].GetStringValue() != "user" {
		t.Fatalf("Expected roles [admin, user], got %v", listValue)
	}
}

func TestProcessResponseHeaders(t *testing.T) {
	ctx := context.Background()
	module := `
		package ext_proc

		response = {
			"headers_to_add": [
				{"key": "X-Response-Header", "value": "ResponseValue"}
			]
		} if {
			input.request_type == "response_headers"
		}
	`

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	// Test response headers processing
	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: buildHeaders(map[string]string{
						":status":      "200",
						"content-type": "application/json",
					}),
				},
			},
		},
	}

	err = server.Process(mockStream)
	if err != nil {
		t.Fatalf("Process returned an error: %v", err)
	}

	if len(mockStream.receivedMessages) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(mockStream.receivedMessages))
	}

	response := mockStream.receivedMessages[0]
	respHeaders := response.GetResponseHeaders()
	if respHeaders == nil {
		t.Fatal("Expected ResponseHeaders in response, got nil")
	}

	headerMutation := respHeaders.GetResponse().GetHeaderMutation()
	if headerMutation == nil {
		t.Fatal("Expected HeaderMutation in response, got nil")
	}

	if len(headerMutation.GetSetHeaders()) != 1 {
		t.Fatalf("Expected 1 header to be added, got %d", len(headerMutation.GetSetHeaders()))
	}

	addedHeader := headerMutation.GetSetHeaders()[0]
	if addedHeader.GetHeader().GetKey() != "X-Response-Header" || addedHeader.GetHeader().GetValue() != "ResponseValue" {
		t.Fatalf("Expected header X-Response-Header: ResponseValue, got %s: %s",
			addedHeader.GetHeader().GetKey(),
			addedHeader.GetHeader().GetValue())
	}
}

func TestProcessResponseTrailers(t *testing.T) {
	ctx := context.Background()
	module := `
		package ext_proc

		response = {
			"trailers_to_add": [
				{"key": "X-Trailer-Added", "value": "TrailerValue"}
			]
		} if {
			input.request_type == "response_trailers"
		}
	`

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	// Test response trailers processing
	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_ResponseTrailers{
					ResponseTrailers: buildTrailers(map[string]string{
						"grpc-status": "0",
					}),
				},
			},
		},
	}

	err = server.Process(mockStream)
	if err != nil {
		t.Fatalf("Process returned an error: %v", err)
	}

	if len(mockStream.receivedMessages) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(mockStream.receivedMessages))
	}

	response := mockStream.receivedMessages[0]
	respTrailers := response.GetResponseTrailers()
	if respTrailers == nil {
		t.Fatal("Expected ResponseTrailers in response, got nil")
	}

	headerMutation := respTrailers.GetHeaderMutation()
	if headerMutation == nil {
		t.Fatal("Expected HeaderMutation in response, got nil")
	}

	if len(headerMutation.GetSetHeaders()) != 1 {
		t.Fatalf("Expected 1 trailer to be added, got %d", len(headerMutation.GetSetHeaders()))
	}

	addedTrailer := headerMutation.GetSetHeaders()[0]
	if addedTrailer.GetHeader().GetKey() != "X-Trailer-Added" || addedTrailer.GetHeader().GetValue() != "TrailerValue" {
		t.Fatalf("Expected trailer X-Trailer-Added: TrailerValue, got %s: %s",
			addedTrailer.GetHeader().GetKey(),
			addedTrailer.GetHeader().GetValue())
	}
}

func TestProcessContextTimeout(t *testing.T) {
	// Create a context with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*10)
	defer cancel()

	module := `
		package ext_proc

		# Add a deliberate delay to force timeout
		response = {
			"headers_to_add": [
				{"key": "X-Test", "value": "Test"}
			]
		}
	`

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":   "/test",
						":method": "GET",
					}),
				},
			},
		},
	}

	// Sleep to ensure the context times out
	time.Sleep(time.Millisecond * 20)

	err = server.Process(mockStream)
	if err == nil {
		t.Fatal("Expected context timeout error, got nil")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Expected DeadlineExceeded error, got: %v", err)
	}
}

func TestProcessSendError(t *testing.T) {
	ctx := context.Background()
	module := `
		package ext_proc

		response = {
			"headers_to_add": [
				{"key": "X-Test", "value": "Test"}
			]
		}
	`

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":   "/test",
						":method": "GET",
					}),
				},
			},
		},
		sendError: fmt.Errorf("send error"),
	}

	err = server.Process(mockStream)
	if err == nil {
		t.Fatal("Expected send error, got nil")
	}

	if err.Error() != "send error" {
		t.Fatalf("Expected 'send error', got: %v", err)
	}
}

func TestProcessReceiveError(t *testing.T) {
	ctx := context.Background()
	module := `
		package ext_proc

		response = {
			"headers_to_add": [
				{"key": "X-Test", "value": "Test"}
			]
		}
	`

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	mockStream := &mockExtProcStream{
		ctx:       ctx,
		t:         t,
		recvError: fmt.Errorf("receive error"),
	}

	err = server.Process(mockStream)
	if err == nil {
		t.Fatal("Expected receive error, got nil")
	}

	if err.Error() != "receive error" {
		t.Fatalf("Expected 'receive error', got: %v", err)
	}
}

func TestProcessMultipleRequests(t *testing.T) {
	ctx := context.Background()
	module := `
		package ext_proc

		# Rule for request headers
		response = {
			"headers_to_add": [
				{"key": "X-Request-Header", "value": "RequestValue"}
			]
		} if {
			input.request_type == "request_headers"
		}

		# Rule for request body
		response = {
			"body": "Modified body"
		} if {
			input.request_type == "request_body"
		}

		# Rule for response headers
		response = {
			"headers_to_add": [
				{"key": "X-Response-Header", "value": "ResponseValue"}
			]
		} if {
			input.request_type == "response_headers"
		}
	`

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	// Test complete request-response flow
	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			// Request headers
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":        "/api/resource",
						":method":      "POST",
						"content-type": "application/json",
					}),
				},
			},
			// Request body
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestBody{
					RequestBody: buildBody(`{"action":"update"}`),
				},
			},
			// Response headers
			{
				Request: &ext_proc_v3.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: buildHeaders(map[string]string{
						":status":      "200",
						"content-type": "application/json",
					}),
				},
			},
		},
	}

	err = server.Process(mockStream)
	if err != nil {
		t.Fatalf("Process returned an error: %v", err)
	}

	if len(mockStream.receivedMessages) != 3 {
		t.Fatalf("Expected 3 responses, got %d", len(mockStream.receivedMessages))
	}

	// Check first response - request headers
	reqHeadersResp := mockStream.receivedMessages[0].GetRequestHeaders()
	if reqHeadersResp == nil {
		t.Fatal("Expected RequestHeaders in first response")
	}

	reqHeader := reqHeadersResp.GetResponse().GetHeaderMutation().GetSetHeaders()[0]
	if reqHeader.GetHeader().GetKey() != "X-Request-Header" || reqHeader.GetHeader().GetValue() != "RequestValue" {
		t.Fatalf("Unexpected request header: %s: %s", reqHeader.GetHeader().GetKey(), reqHeader.GetHeader().GetValue())
	}

	// Check second response - request body
	reqBodyResp := mockStream.receivedMessages[1].GetRequestBody()
	if reqBodyResp == nil {
		t.Fatal("Expected RequestBody in second response")
	}

	modifiedBody := string(reqBodyResp.GetResponse().GetBodyMutation().GetBody())
	if modifiedBody != "Modified body" {
		t.Fatalf("Expected modified body 'Modified body', got '%s'", modifiedBody)
	}

	// Check third response - response headers
	respHeadersResp := mockStream.receivedMessages[2].GetResponseHeaders()
	if respHeadersResp == nil {
		t.Fatal("Expected ResponseHeaders in third response")
	}

	respHeader := respHeadersResp.GetResponse().GetHeaderMutation().GetSetHeaders()[0]
	if respHeader.GetHeader().GetKey() != "X-Response-Header" || respHeader.GetHeader().GetValue() != "ResponseValue" {
		t.Fatalf("Unexpected response header: %s: %s", respHeader.GetHeader().GetKey(), respHeader.GetHeader().GetValue())
	}
}

func TestProcessEvalError(t *testing.T) {
	ctx := context.Background()
	// Create a module with an error that will occur during evaluation
	module := `
		package ext_proc

		default response = {"headers_to_add": "this will fail as it's not an array"}
	`

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":   "/test",
						":method": "GET",
					}),
				},
			},
		},
	}

	err = server.Process(mockStream)
	if err == nil {
		t.Fatal("Expected evaluation error, got nil")
	}

	// Check that the error message contains the expected text
	if !strings.Contains(err.Error(), "headers_to_add") {
		t.Errorf("Expected error about headers_to_add, got: %v", err)
	}
}

func TestStreamStateManagement(t *testing.T) {
	ctx := context.Background()
	module := `
        package ext_proc

        # Default response to avoid undefined decision errors
        default response = {}

        # For request headers: store the path
        response = {} if {
            input.request_type == "request_headers"
        }

        # For request body: verify state contains correct path
        response = {
            "headers_to_add": [
                {"key": "X-Path-Seen", "value": input.path}
            ]
        } if {
            input.request_type == "request_body"
        }

        # For response headers: handle case when path might be missing
        response = {
            "headers_to_add": [
                {"key": "X-Response-Processed", "value": "true"}
            ]
        } if {
            input.request_type == "response_headers"
        }
    `

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	testPath := "/test/state/management"

	// Test state management across multiple request types
	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			// 1. Request headers
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":        testPath,
						":method":      "GET",
						"content-type": "application/json",
					}),
				},
			},
			// 2. Request body
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestBody{
					RequestBody: buildBody(`{"test":"value"}`),
				},
			},
			// 3. Response headers
			{
				Request: &ext_proc_v3.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: buildHeaders(map[string]string{
						":status": "200",
					}),
				},
			},
		},
	}

	err = server.Process(mockStream)
	if err != nil {
		t.Fatalf("Process returned an error: %v", err)
	}

	if len(mockStream.receivedMessages) != 3 {
		t.Fatalf("Expected 3 responses, got %d", len(mockStream.receivedMessages))
	}

	// Check if path from state was correctly used in request body processing
	bodyResp := mockStream.receivedMessages[1].GetRequestBody()
	if bodyResp == nil {
		t.Fatal("Expected RequestBody in second response")
	}

	headerMutation := bodyResp.GetResponse().GetHeaderMutation()
	if headerMutation == nil {
		t.Fatal("Expected HeaderMutation in second response")
	}

	found := false
	for _, header := range headerMutation.GetSetHeaders() {
		if header.GetHeader().GetKey() == "X-Path-Seen" && header.GetHeader().GetValue() == testPath {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("Expected header X-Path-Seen: %s in request body response", testPath)
	}

	// For response headers, we are just checking if we got a response
	respHeadersResp := mockStream.receivedMessages[2].GetResponseHeaders()
	if respHeadersResp == nil {
		t.Fatal("Expected ResponseHeaders in third response")
	}
}

func TestProcessSkipRequestBodyParse(t *testing.T) {
	ctx := context.Background()
	module := `
		package ext_proc

		response = {
			"body": "Parsed JSON"
		} if {
			input.parsed_body.action == "read"
		}

		response = {
			"body": "No parsed body"
		} if {
			not input.parsed_body
		}
	`

	// Create server with SkipRequestBodyParse enabled
	skipParseServer, err := testExtProcServerWithConfig(module, t, &Config{
		Addr:                 ":0",
		Path:                 "ext_proc/response",
		SkipRequestBodyParse: true,
	})
	if err != nil {
		t.Fatalf("Failed to create skip-parse server: %v", err)
	}

	// Create a regular server with parsing enabled
	parseServer, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create regular server: %v", err)
	}

	// Test with body parsing skipped
	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":        "/api/data",
						":method":      "POST",
						"content-type": "application/json",
					}),
				},
			},
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestBody{
					RequestBody: buildBody(`{"action":"read","resource":"document1"}`),
				},
			},
		},
	}

	err = skipParseServer.Process(mockStream)
	if err != nil {
		t.Fatalf("Process returned an error: %v", err)
	}

	if len(mockStream.receivedMessages) != 2 {
		t.Fatalf("Expected 2 responses, got %d", len(mockStream.receivedMessages))
	}

	// Check that no parsing occurred
	bodyResponse := mockStream.receivedMessages[1].GetRequestBody()
	if bodyResponse == nil {
		t.Fatal("Expected RequestBody in response, got nil")
	}

	bodyMutation := bodyResponse.GetResponse().GetBodyMutation()
	if bodyMutation == nil {
		t.Fatal("Expected BodyMutation in response, got nil")
	}

	modifiedBody := string(bodyMutation.GetBody())
	if modifiedBody != "No parsed body" {
		t.Fatalf("Expected 'No parsed body', got '%s'", modifiedBody)
	}

	// Now test with normal parsing
	mockStream = &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":        "/api/data",
						":method":      "POST",
						"content-type": "application/json",
					}),
				},
			},
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestBody{
					RequestBody: buildBody(`{"action":"read","resource":"document1"}`),
				},
			},
		},
	}

	err = parseServer.Process(mockStream)
	if err != nil {
		t.Fatalf("Process returned an error: %v", err)
	}

	if len(mockStream.receivedMessages) != 2 {
		t.Fatalf("Expected 2 responses, got %d", len(mockStream.receivedMessages))
	}

	// Check that parsing did occur
	bodyResponse = mockStream.receivedMessages[1].GetRequestBody()
	if bodyResponse == nil {
		t.Fatal("Expected RequestBody in response, got nil")
	}

	bodyMutation = bodyResponse.GetResponse().GetBodyMutation()
	if bodyMutation == nil {
		t.Fatal("Expected BodyMutation in response, got nil")
	}

	modifiedBody = string(bodyMutation.GetBody())
	if modifiedBody != "Parsed JSON" {
		t.Fatalf("Expected 'Parsed JSON', got '%s'", modifiedBody)
	}
}

func TestProcessInvalidJSON(t *testing.T) {
	ctx := context.Background()
	module := `
        package ext_proc

        # Default response to avoid undefined decision errors
        default response = {}

        # Handle request headers
        response = {} if {
            input.request_type == "request_headers"
        }

        # Handle request body
        response = {
            "body": "Valid JSON"
        } if {
            input.request_type == "request_body"
        }
    `

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	// Test with invalid JSON
	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":        "/api/data",
						":method":      "POST",
						"content-type": "application/json",
					}),
				},
			},
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestBody{
					RequestBody: buildBody(`{"this is invalid json`),
				},
			},
		},
	}

	err = server.Process(mockStream)
	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}

	// Check that the error message contains expected text related to JSON parsing
	if !strings.Contains(err.Error(), "EOF") &&
		!strings.Contains(err.Error(), "JSON") &&
		!strings.Contains(err.Error(), "parse") {
		t.Fatalf("Expected JSON parsing error, got: %v", err)
	}

	// We should have at least received one response for the headers
	if len(mockStream.receivedMessages) < 1 {
		t.Fatalf("Expected at least 1 response, got %d", len(mockStream.receivedMessages))
	}
}

func TestProcessTruncatedBody(t *testing.T) {
	ctx := context.Background()
	module := `
        package ext_proc

        # Default response to avoid undefined decision errors
        default response = {}

        # Handle request headers
        response = {} if {
            input.request_type == "request_headers"
        }

        # Handle truncated body
        response = {
            "immediate_response": {
                "status": 413,
                "body": "Payload Too Large"
            }
        } if {
            input.truncated_body == true
        }

        # Handle non-truncated body
        response = {
            "body": "Normal response"
        } if {
            input.request_type == "request_body"
            not input.truncated_body
        }
    `

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	// Test with truncated body (content-length mismatch)
	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":          "/api/data",
						":method":        "POST",
						"content-type":   "application/json",
						"content-length": "1000", // Much larger than actual body
					}),
				},
			},
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestBody{
					RequestBody: buildBody(`{"small":"body"}`),
				},
			},
		},
	}

	err = server.Process(mockStream)
	if err != nil {
		t.Fatalf("Process returned an error: %v", err)
	}

	if len(mockStream.receivedMessages) != 2 {
		t.Fatalf("Expected 2 responses, got %d", len(mockStream.receivedMessages))
	}

	// The second response should be an immediate response with payload too large
	immediateResponse := mockStream.receivedMessages[1].GetImmediateResponse()
	if immediateResponse == nil {
		t.Fatal("Expected ImmediateResponse for truncated body, got nil")
	}

	if immediateResponse.GetStatus().GetCode() != ext_type_v3.StatusCode_PayloadTooLarge {
		t.Fatalf("Expected Payload Too Large status, got %v", immediateResponse.GetStatus().GetCode())
	}

	if string(immediateResponse.GetBody()) != "Payload Too Large" {
		t.Fatalf("Expected 'Payload Too Large' body, got '%s'", string(immediateResponse.GetBody()))
	}
}

func TestProcessUnsupportedContentType(t *testing.T) {
	ctx := context.Background()
	module := `
        package ext_proc

        # Default response to avoid undefined decision errors
        default response = {}

        # Handle request headers
        response = {} if {
            input.request_type == "request_headers"
        }

        # Handle request body - both for JSON and non-JSON
        response = {} if {
            input.request_type == "request_body"
        }
    `

	server, err := testExtProcServer(module, t)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	// Test with unsupported content type
	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":        "/api/data",
						":method":      "POST",
						"content-type": "text/plain", // Not JSON
					}),
				},
			},
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestBody{
					RequestBody: buildBody(`This is plain text, not JSON`),
				},
			},
		},
	}

	err = server.Process(mockStream)
	if err != nil {
		t.Fatalf("Process returned an error: %v", err)
	}

	// Check that we got responses without errors
	if len(mockStream.receivedMessages) != 2 {
		t.Fatalf("Expected 2 responses, got %d", len(mockStream.receivedMessages))
	}

	// Check that the first response is for request headers
	headersResp := mockStream.receivedMessages[0].GetRequestHeaders()
	if headersResp == nil {
		t.Fatal("Expected RequestHeaders in first response")
	}

	// Check that the second response is for request body
	bodyResp := mockStream.receivedMessages[1].GetRequestBody()
	if bodyResp == nil {
		t.Fatal("Expected RequestBody in second response")
	}
}

func TestProcessPerformanceMetrics(t *testing.T) {
	ctx := context.Background()
	module := `
		package ext_proc

		response = {
			"headers_to_add": [
				{"key": "X-Test", "value": "Test"}
			]
		}
	`

	// Create server with metrics enabled
	server, err := testExtProcServerWithConfig(module, t, &Config{
		Addr:                     ":0",
		Path:                     "ext_proc/response",
		EnablePerformanceMetrics: true,
	})
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	mockStream := &mockExtProcStream{
		ctx: ctx,
		t:   t,
		requestsToSend: []*ext_proc_v3.ProcessingRequest{
			{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":   "/test",
						":method": "GET",
					}),
				},
			},
		},
	}

	err = server.Process(mockStream)
	if err != nil {
		t.Fatalf("Process returned an error: %v", err)
	}

	// Check that the method completes without error
	if len(mockStream.receivedMessages) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(mockStream.receivedMessages))
	}
}

// Helper function to create a test server with custom config
func testExtProcServerWithConfig(module string, t *testing.T, customConfig *Config) (*envoyExtProcGrpcServer, error) {
	ctx := context.Background()
	store := inmem.New()
	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)

	// Insert the module into storage
	err := store.UpsertPolicy(ctx, txn, "example.rego", []byte(module))
	if err != nil {
		return nil, fmt.Errorf("failed to insert policy: %w", err)
	}

	err = store.Commit(ctx, txn)
	if err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Create a plugin manager
	m, err := plugins.New([]byte{}, "test", store)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin manager: %w", err)
	}

	// Start the plugin manager
	if err := m.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start plugin manager: %w", err)
	}

	// Set up the query path for external processor
	path := customConfig.Path
	if path == "" {
		path = "ext_proc/response"
	}

	query := "data." + strings.Replace(path, "/", ".", -1)
	parsedQuery, err := ast.ParseBody(query)
	if err != nil {
		return nil, fmt.Errorf("failed to parse query: %w", err)
	}

	// Create default config and merge with custom config
	cfg := Config{
		Addr:                     ":0",
		Path:                     path,
		parsedQuery:              parsedQuery,
		DryRun:                   false,
		EnableReflection:         false,
		GRPCMaxRecvMsgSize:       4 * 1024 * 1024,
		GRPCMaxSendMsgSize:       4 * 1024 * 1024,
		SkipRequestBodyParse:     false,
		EnablePerformanceMetrics: false,
	}

	// Override with custom config values
	if customConfig != nil {
		if customConfig.SkipRequestBodyParse {
			cfg.SkipRequestBodyParse = true
		}
		if customConfig.EnablePerformanceMetrics {
			cfg.EnablePerformanceMetrics = true
		}
		if customConfig.DryRun {
			cfg.DryRun = true
		}
	}

	// Create the ext_proc server
	server := &envoyExtProcGrpcServer{
		cfg:                 cfg,
		manager:             m,
		preparedQueryDoOnce: new(sync.Once),
		metricErrorCounter:  *prometheus.NewCounterVec(prometheus.CounterOpts{Name: "error_counter"}, []string{"reason"}),
	}

	if cfg.EnablePerformanceMetrics {
		server.metricExtProcDuration = *prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "grpc_request_duration_seconds",
			Help:    "A histogram of duration for grpc extproc requests.",
			Buckets: []float64{0.001, 0.01, 0.1, 0.5, 1.0},
		}, []string{"handler"})
	}

	return server, nil
}

// testExtProcServer creates a test server with the given OPA module
func testExtProcServer(module string, t *testing.T) (*envoyExtProcGrpcServer, error) {
	ctx := context.Background()
	store := inmem.New()
	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)

	// Insert the module into storage
	err := store.UpsertPolicy(ctx, txn, "example.rego", []byte(module))
	if err != nil {
		return nil, fmt.Errorf("failed to insert policy: %w", err)
	}

	err = store.Commit(ctx, txn)
	if err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Create a plugin manager
	m, err := plugins.New([]byte{}, "test", store)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin manager: %w", err)
	}

	// Start the plugin manager
	if err := m.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start plugin manager: %w", err)
	}

	// Set up the query path for external processor
	path := "ext_proc/response"
	query := "data." + strings.Replace(path, "/", ".", -1)
	parsedQuery, err := ast.ParseBody(query)
	if err != nil {
		return nil, fmt.Errorf("failed to parse query: %w", err)
	}

	// Create the server config
	cfg := Config{
		Addr:                     ":0",
		Path:                     path,
		parsedQuery:              parsedQuery,
		DryRun:                   false,
		EnableReflection:         false,
		GRPCMaxRecvMsgSize:       4 * 1024 * 1024,
		GRPCMaxSendMsgSize:       4 * 1024 * 1024,
		SkipRequestBodyParse:     false,
		EnablePerformanceMetrics: false,
	}

	// Create the ext_proc server
	server := &envoyExtProcGrpcServer{
		cfg:                 cfg,
		manager:             m,
		preparedQueryDoOnce: new(sync.Once),
		metricErrorCounter:  *prometheus.NewCounterVec(prometheus.CounterOpts{Name: "error_counter"}, []string{"reason"}),
	}

	return server, nil
}
