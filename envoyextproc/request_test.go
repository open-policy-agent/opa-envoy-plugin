package envoyextproc

import (
	"reflect"
	"testing"

	ext_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	loggingtest "github.com/open-policy-agent/opa/v1/logging/test"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/open-policy-agent/opa-envoy-plugin/internal/types"
)

func TestRequestToInput(t *testing.T) {
	buildHeaders := func(m map[string]string) *ext_proc_v3.HttpHeaders {
		var kv []*ext_core_v3.HeaderValue
		for k, v := range m {
			kv = append(kv, &ext_core_v3.HeaderValue{Key: k, Value: v})
		}
		return &ext_proc_v3.HttpHeaders{
			Headers: &ext_core_v3.HeaderMap{
				Headers: kv,
			},
		}
	}

	buildTrailers := func(m map[string]string) *ext_proc_v3.HttpTrailers {
		var kv []*ext_core_v3.HeaderValue
		for k, v := range m {
			kv = append(kv, &ext_core_v3.HeaderValue{Key: k, Value: v})
		}
		return &ext_proc_v3.HttpTrailers{
			Trailers: &ext_core_v3.HeaderMap{
				Headers: kv,
			},
		}
	}

	buildBody := func(body string) *ext_proc_v3.HttpBody {
		return &ext_proc_v3.HttpBody{
			Body:        []byte(body),
			EndOfStream: true,
		}
	}

	tests := map[string]struct {
		req                  *ext_proc_v3.ProcessingRequest
		skipRequestBodyParse bool
		protoSet             *protoregistry.Files
		initState            *types.StreamState
		expectedInput        map[string]interface{}
		expectError          bool
	}{
		"request_headers_basic": {
			req: &ext_proc_v3.ProcessingRequest{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":path":      "/test/path",
						":method":    "GET",
						":scheme":    "http",
						":authority": "example.com",
						"Host":       "example.com",
					}),
				},
			},
			initState: &types.StreamState{},
			expectedInput: map[string]interface{}{
				"request_type": "request_headers",
				"headers": map[string]string{
					":path":      "/test/path",
					":method":    "GET",
					":scheme":    "http",
					":authority": "example.com",
					"Host":       "example.com",
				},
				"path":         "/test/path",
				"method":       "GET",
				"scheme":       "http",
				"authority":    "example.com",
				"parsed_path":  []interface{}{"test", "path"},
				"parsed_query": map[string]interface{}{},
			},
		},
		"request_headers_missing_path": {
			req: &ext_proc_v3.ProcessingRequest{
				Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
					RequestHeaders: buildHeaders(map[string]string{
						":method": "GET",
						"Host":    "example.com",
					}),
				},
			},
			initState: &types.StreamState{},
			expectedInput: map[string]interface{}{
				"request_type": "request_headers",
				"headers": map[string]string{
					":method": "GET",
					"Host":    "example.com",
				},
				"path":         "",
				"method":       "GET",
				"scheme":       "",
				"authority":    "",
				"parsed_path":  []interface{}{""},
				"parsed_query": map[string]interface{}{},
			},
		},
		"request_body_json": {
			req: &ext_proc_v3.ProcessingRequest{
				Request: &ext_proc_v3.ProcessingRequest_RequestBody{
					RequestBody: buildBody(`{"action":"read","user":"alice"}`),
				},
			},
			initState: &types.StreamState{
				Headers: map[string]string{
					"content-type": "application/json",
					":path":        "/api/data",
				},
				Path: "/api/data",
			},
			skipRequestBodyParse: false,
			expectedInput: map[string]interface{}{
				"request_type":   "request_body",
				"path":           "/api/data",
				"parsed_body":    map[string]interface{}{"action": "read", "user": "alice"},
				"truncated_body": false,
			},
		},
		"request_body_skip_parse": {
			req: &ext_proc_v3.ProcessingRequest{
				Request: &ext_proc_v3.ProcessingRequest_RequestBody{
					RequestBody: buildBody(`{"should":"not_parse"}`),
				},
			},
			initState: &types.StreamState{
				Headers: map[string]string{
					"content-type": "application/json",
					":path":        "/no-parse",
				},
				Path: "/no-parse",
			},
			skipRequestBodyParse: true,
			expectedInput: map[string]interface{}{
				"request_type": "request_body",
				"path":         "/no-parse",
			},
		},
		"request_body_unsupported_type": {
			req: &ext_proc_v3.ProcessingRequest{
				Request: &ext_proc_v3.ProcessingRequest_RequestBody{
					RequestBody: buildBody("just some plain text"),
				},
			},
			initState: &types.StreamState{
				Headers: map[string]string{
					"content-type": "text/plain",
					":path":        "/unsupported",
				},
				Path: "/unsupported",
			},
			skipRequestBodyParse: false,
			expectedInput: map[string]interface{}{
				"request_type":   "request_body",
				"path":           "/unsupported",
				"parsed_body":    nil,
				"truncated_body": false,
			},
		},
		"request_body_truncated_json": {
			req: &ext_proc_v3.ProcessingRequest{
				Request: &ext_proc_v3.ProcessingRequest_RequestBody{
					RequestBody: buildBody(`{"user":"alice"}`),
				},
			},
			initState: &types.StreamState{
				Headers: map[string]string{
					"content-type":   "application/json",
					"content-length": "1000",
					":path":          "/truncated",
				},
				Path: "/truncated",
			},
			skipRequestBodyParse: false,
			expectedInput: map[string]interface{}{
				"request_type":   "request_body",
				"path":           "/truncated",
				"parsed_body":    nil,
				"truncated_body": true,
			},
		},
		"response_headers_basic": {
			req: &ext_proc_v3.ProcessingRequest{
				Request: &ext_proc_v3.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: buildHeaders(map[string]string{
						":status":         "200",
						"Content-Type":    "application/json",
						"X-Custom-Header": "CustomValue",
						":path":           "/response",
					}),
				},
			},
			initState: &types.StreamState{},
			expectedInput: map[string]interface{}{
				"request_type": "response_headers",
				"response_headers": map[string]string{
					":status":         "200",
					"Content-Type":    "application/json",
					"X-Custom-Header": "CustomValue",
					":path":           "/response",
				},
				"path": "/response",
			},
		},
		"response_body_form": {
			req: &ext_proc_v3.ProcessingRequest{
				Request: &ext_proc_v3.ProcessingRequest_ResponseBody{
					ResponseBody: buildBody("firstname=alice&lastname=smith"),
				},
			},
			initState: &types.StreamState{
				Headers: map[string]string{
					"content-type": "application/x-www-form-urlencoded",
					":path":        "/submit-form",
				},
				Path: "/submit-form",
			},
			skipRequestBodyParse: false,
			expectedInput: map[string]interface{}{
				"request_type":            "response_body",
				"response_parsed_body":    map[string][]string{"firstname": {"alice"}, "lastname": {"smith"}},
				"response_truncated_body": false,
			},
		},
		"response_body_unsupported_type": {
			req: &ext_proc_v3.ProcessingRequest{
				Request: &ext_proc_v3.ProcessingRequest_ResponseBody{
					ResponseBody: buildBody("random data"),
				},
			},
			initState: &types.StreamState{
				Headers: map[string]string{
					"content-type": "application/octet-stream",
					":path":        "/binary-data",
				},
				Path: "/binary-data",
			},
			skipRequestBodyParse: false,
			expectedInput: map[string]interface{}{
				"request_type": "response_body",
				// No response_parsed_body for unsupported type
				"response_parsed_body":    nil,
				"response_truncated_body": false,
			},
		},
		"request_trailers": {
			req: &ext_proc_v3.ProcessingRequest{
				Request: &ext_proc_v3.ProcessingRequest_RequestTrailers{
					RequestTrailers: buildTrailers(map[string]string{"X-Trailer": "TrailerValue"}),
				},
			},
			initState: &types.StreamState{
				Headers: map[string]string{
					":path":   "/trailer",
					":method": "POST",
				},
				Path:   "/trailer",
				Method: "POST",
			},
			expectedInput: map[string]interface{}{
				"request_type": "request_trailers",
				"request_trailers": map[string]string{
					"X-Trailer": "TrailerValue",
				},
				"headers": map[string]string{
					":path":   "/trailer",
					":method": "POST",
				},
				"path":   "/trailer",
				"method": "POST",
			},
		},
		"response_trailers": {
			req: &ext_proc_v3.ProcessingRequest{
				Request: &ext_proc_v3.ProcessingRequest_ResponseTrailers{
					ResponseTrailers: buildTrailers(map[string]string{"X-Response-Trailer": "ResponseTrailerValue"}),
				},
			},
			initState: &types.StreamState{
				Headers: map[string]string{
					":path":   "/response-trailer",
					":method": "GET",
				},
				Path:   "/response-trailer",
				Method: "GET",
			},
			expectedInput: map[string]interface{}{
				"request_type": "response_trailers",
				"response_trailers": map[string]string{
					"X-Response-Trailer": "ResponseTrailerValue",
				},
				"headers": map[string]string{
					":path":   "/response-trailer",
					":method": "GET",
				},
				"path":   "/response-trailer",
				"method": "GET",
			},
		},
		"unknown_request_type": {
			req:         &ext_proc_v3.ProcessingRequest{},
			initState:   &types.StreamState{},
			expectError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			logger := loggingtest.New()
			inputMap, err := RequestToInput(tc.req, logger, tc.protoSet, tc.skipRequestBodyParse, tc.initState)

			if tc.expectError {
				if err == nil {
					t.Fatalf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if !reflect.DeepEqual(inputMap, tc.expectedInput) {
				t.Fatalf("Expected input: %#v\nGot: %#v", tc.expectedInput, inputMap)
			}
		})
	}
}

func TestGetParsedPathAndQuery(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		expectedPath  []interface{}
		expectedQuery map[string]interface{}
	}{
		{
			name:          "Simple Path without Query",
			path:          "/my/test/path",
			expectedPath:  []interface{}{"my", "test", "path"},
			expectedQuery: map[string]interface{}{},
		},
		{
			name:         "Path with Single Query Parameter",
			path:         "/my/test/path?a=1",
			expectedPath: []interface{}{"my", "test", "path"},
			expectedQuery: map[string]interface{}{
				"a": []interface{}{"1"},
			},
		},
		{
			name:         "Path with Multiple Query Parameters",
			path:         "/my/test/path?a=1&a=2&b=2",
			expectedPath: []interface{}{"my", "test", "path"},
			expectedQuery: map[string]interface{}{
				"a": []interface{}{"1", "2"},
				"b": []interface{}{"2"},
			},
		},
		{
			name:         "Path with URL Encoded Characters",
			path:         "/%2Fmy%2Ftest%2Fpath?a=1&a=new%0aline",
			expectedPath: []interface{}{"my", "test", "path"},
			expectedQuery: map[string]interface{}{
				"a": []interface{}{"1", "new\nline"},
			},
		},
		{
			name:         "Path with Multiple Different Query Parameters",
			path:         "/my/test/path?a=1&b=2",
			expectedPath: []interface{}{"my", "test", "path"},
			expectedQuery: map[string]interface{}{
				"a": []interface{}{"1"},
				"b": []interface{}{"2"},
			},
		},
		{
			name:          "Root Path without Query",
			path:          "/",
			expectedPath:  []interface{}{""},
			expectedQuery: map[string]interface{}{},
		},
		{
			name:          "Empty Path",
			path:          "",
			expectedPath:  []interface{}{""},
			expectedQuery: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualPath, actualQuery, err := getParsedPathAndQuery(tt.path)
			if err != nil {
				t.Fatalf("Error parsing path and query: %v", err)
			}
			if !reflect.DeepEqual(actualPath, tt.expectedPath) {
				t.Errorf("Parsed path mismatch.\nExpected: %v\nGot: %v", tt.expectedPath, actualPath)
			}
			if !reflect.DeepEqual(actualQuery, tt.expectedQuery) {
				t.Errorf("Parsed query mismatch.\nExpected: %v\nGot: %v", tt.expectedQuery, actualQuery)
			}
		})
	}
}

func TestGetParsedBody(t *testing.T) {
	logger := loggingtest.New()

	// Basic JSON test
	headers := map[string]string{"content-type": "application/json"}
	body := `{"action":"read","user":"alice"}`
	got, truncated, err := getParsedBody(logger, headers, body, nil, nil, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if truncated {
		t.Fatalf("Expected not truncated, got truncated")
	}
	expected := map[string]interface{}{"action": "read", "user": "alice"}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("Expected %v, got %v", expected, got)
	}

	// Truncated body test
	headers = map[string]string{"content-type": "application/json", "content-length": "1000"}
	body = `{"key":"value"}`
	got, truncated, err = getParsedBody(logger, headers, body, nil, nil, nil)
	if err != nil {
		t.Fatalf("Unexpected error for truncated test: %v", err)
	}
	if !truncated {
		t.Fatalf("Expected truncated, got not truncated")
	}
	if got != nil {
		t.Fatalf("Expected nil for truncated body, got %v", got)
	}

	// Unsupported content type
	headers = map[string]string{"content-type": "text/plain"}
	body = "plain text data"
	got, truncated, err = getParsedBody(logger, headers, body, nil, nil, nil)
	if err != nil {
		t.Fatalf("Unexpected error for unsupported type: %v", err)
	}
	if truncated {
		t.Fatalf("Expected not truncated for unsupported type")
	}
	if got != nil {
		t.Fatalf("Expected nil for unsupported type, got %v", got)
	}

	// Empty body with JSON
	headers = map[string]string{"content-type": "application/json"}
	body = ""
	got, truncated, err = getParsedBody(logger, headers, body, nil, nil, nil)
	if err != nil {
		t.Fatalf("Unexpected error for empty body: %v", err)
	}
	if truncated {
		t.Fatalf("Expected not truncated for empty body")
	}
	if got != nil {
		t.Fatalf("Expected nil for empty body, got %v", got)
	}

	// Form URL Encoded
	headers = map[string]string{"content-type": "application/x-www-form-urlencoded"}
	body = "firstname=alice&lastname=smith"
	got, truncated, err = getParsedBody(logger, headers, body, nil, nil, nil)
	if err != nil {
		t.Fatalf("Unexpected error for form-url-encoded: %v", err)
	}
	if truncated {
		t.Fatalf("Expected not truncated for form-url-encoded")
	}
	expectedForm := map[string][]string{"firstname": {"alice"}, "lastname": {"smith"}}
	if !reflect.DeepEqual(got, expectedForm) {
		t.Fatalf("Expected %v, got %v", expectedForm, got)
	}
}
