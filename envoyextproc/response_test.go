package envoyextproc

import (
	"encoding/json"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	ext_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	ext_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

// jsonNumber is a helper to return a json.Number type from a string.
func jsonNumber(numStr string) interface{} {
	return json.Number(numStr)
}

func TestEvalResult_GetImmediateResponse(t *testing.T) {
	tests := map[string]struct {
		decision    interface{}
		expected    *ext_proc_v3.ImmediateResponse
		expectError bool
	}{
		"no_decision": {
			decision: nil,
			expected: nil, // no immediate_response key
		},
		"decision_not_map": {
			decision:    "not a map",
			expected:    nil,
			expectError: false,
		},
		"no_immediate_response_key": {
			decision: map[string]interface{}{
				"user": "alice",
			},
			expected: nil,
		},
		"valid_immediate_response": {
			decision: map[string]interface{}{
				"immediate_response": map[string]interface{}{
					"status": jsonNumber("403"),
					"body":   "Access denied",
					"headers": []interface{}{
						map[string]interface{}{"key": "X-Reason", "value": "Forbidden"},
					},
				},
			},
			expected: &ext_proc_v3.ImmediateResponse{
				Status: &ext_type_v3.HttpStatus{Code: ext_type_v3.StatusCode_Forbidden},
				Body:   []byte("Access denied"),
				Headers: &ext_proc_v3.HeaderMutation{
					SetHeaders: []*ext_core_v3.HeaderValueOption{
						{Header: &ext_core_v3.HeaderValue{Key: "X-Reason", Value: "Forbidden"}},
					},
				},
			},
		},
		"valid_immediate_response_with_grpc": {
			decision: map[string]interface{}{
				"immediate_response": map[string]interface{}{
					"status":      jsonNumber("401"),
					"body":        "Unauthorized",
					"headers":     []interface{}{},
					"grpc_status": float64(16), // e.g. UNAUTHENTICATED in gRPC
					"details":     "Missing token",
				},
			},
			expected: &ext_proc_v3.ImmediateResponse{
				Status: &ext_type_v3.HttpStatus{Code: ext_type_v3.StatusCode_Unauthorized},
				Body:   []byte("Unauthorized"),
				Headers: &ext_proc_v3.HeaderMutation{
					SetHeaders: []*ext_core_v3.HeaderValueOption{},
				},
				GrpcStatus: &ext_proc_v3.GrpcStatus{
					Status: uint32(16),
				},
				Details: "Missing token",
			},
		},
		"invalid_status_type": {
			decision: map[string]interface{}{
				"immediate_response": map[string]interface{}{
					"status": "not a number",
				},
			},
			expectError: true,
		},
		"invalid_status_code": {
			decision: map[string]interface{}{
				"immediate_response": map[string]interface{}{
					"status": jsonNumber("999"), // invalid HTTP status code
				},
			},
			expectError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := &EvalResult{Decision: tc.decision}
			resp, err := result.GetImmediateResponse()
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !proto.Equal(resp, tc.expected) {
				t.Fatalf("expected: %#v\ngot: %#v", tc.expected, resp)
			}
		})
	}
}

func TestEvalResult_GetCommonResponse(t *testing.T) {
	tests := map[string]struct {
		decision    interface{}
		expected    *ext_proc_v3.CommonResponse
		expectError bool
	}{
		"no_decision": {
			decision: nil,
			expected: nil,
		},
		"decision_not_map": {
			decision: "not a map",
			expected: nil,
		},
		"no_modifications": {
			decision: map[string]interface{}{
				"user": "alice",
			},
			expected: nil,
		},
		"add_headers_only": {
			decision: map[string]interface{}{
				"headers_to_add": []interface{}{
					map[string]interface{}{"key": "X-Added", "value": "HeaderVal"},
				},
			},
			expected: &ext_proc_v3.CommonResponse{
				HeaderMutation: &ext_proc_v3.HeaderMutation{
					SetHeaders: []*ext_core_v3.HeaderValueOption{
						{Header: &ext_core_v3.HeaderValue{Key: "X-Added", Value: "HeaderVal"}},
					},
					RemoveHeaders: []string{},
				},
			},
		},
		"add_body_only": {
			decision: map[string]interface{}{
				"body": "modified response body",
			},
			expected: &ext_proc_v3.CommonResponse{
				BodyMutation: &ext_proc_v3.BodyMutation{
					Mutation: &ext_proc_v3.BodyMutation_Body{
						Body: []byte("modified response body"),
					},
				},
				Status: ext_proc_v3.CommonResponse_CONTINUE_AND_REPLACE,
			},
		},
		"add_headers_and_remove_headers": {
			decision: map[string]interface{}{
				"headers_to_add": []interface{}{
					map[string]interface{}{"key": "X-Added-Header", "value": "Val"},
				},
				"headers_to_remove": []interface{}{"X-Remove-Me"},
			},
			expected: &ext_proc_v3.CommonResponse{
				HeaderMutation: &ext_proc_v3.HeaderMutation{
					SetHeaders: []*ext_core_v3.HeaderValueOption{
						{Header: &ext_core_v3.HeaderValue{Key: "X-Added-Header", Value: "Val"}},
					},
					RemoveHeaders: []string{"X-Remove-Me"},
				},
			},
		},
		"invalid_headers_to_remove": {
			decision: map[string]interface{}{
				"headers_to_remove": []interface{}{123}, // not a string
			},
			expectError: true,
		},
		"invalid_headers_to_add": {
			decision: map[string]interface{}{
				"headers_to_add": []interface{}{"not a map"},
			},
			// With no valid header entries, there are no modifications so we expect nil.
			expected: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := &EvalResult{Decision: tc.decision}
			resp, err := result.GetCommonResponse()
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// Compare proto messages
			if !proto.Equal(resp, tc.expected) {
				t.Fatalf("expected: %#v\ngot: %#v", tc.expected, resp)
			}
		})
	}
}

func TestEvalResult_GetDynamicMetadata(t *testing.T) {
	tests := map[string]struct {
		decision    interface{}
		expectError bool
		expected    map[string]interface{}
	}{
		"no_decision": {
			decision: nil,
			expected: nil,
		},
		"decision_not_map": {
			decision: "not a map",
			expected: nil,
		},
		"no_dynamic_metadata": {
			decision: map[string]interface{}{
				"user": "alice",
			},
			expected: nil,
		},
		"with_dynamic_metadata": {
			decision: map[string]interface{}{
				"dynamic_metadata": map[string]interface{}{
					"foo": "bar",
					"num": 42,
				},
			},
			expected: map[string]interface{}{
				"foo": "bar",
				"num": 42.0, // numbers are converted to float64
			},
		},
		"invalid_dynamic_metadata": {
			decision: map[string]interface{}{
				"dynamic_metadata": "not a map",
			},
			expectError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := &EvalResult{Decision: tc.decision}
			dm, err := result.GetDynamicMetadata()
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.expected == nil && dm != nil {
				t.Fatalf("expected nil dynamic_metadata, got %v", dm)
			}
			if tc.expected != nil {
				// Convert dm back to map for comparison
				dmMap := dm.AsMap()
				// Use deep equal for maps
				if !reflect.DeepEqual(dmMap, tc.expected) {
					t.Fatalf("expected: %v, got: %v", tc.expected, dmMap)
				}
			}
		})
	}
}

func TestEvalResult_GetTrailerMutation(t *testing.T) {
	tests := map[string]struct {
		decision    interface{}
		expectError bool
		expected    *ext_proc_v3.HeaderMutation
	}{
		"no_decision": {
			decision: nil,
			// If decision is nil we return nil without error.
			expected: nil,
		},
		"decision_not_map": {
			decision: "not a map",
			// Return nil (no error) when decision is not a map.
			expected: nil,
		},
		"no_trailers": {
			decision: map[string]interface{}{
				"user": "alice",
			},
			expected: nil,
		},
		"add_trailers": {
			decision: map[string]interface{}{
				"trailers_to_add": []interface{}{
					map[string]interface{}{"key": "X-Added-Trailer", "value": "Val"},
				},
			},
			expected: &ext_proc_v3.HeaderMutation{
				SetHeaders:    []*ext_core_v3.HeaderValueOption{{Header: &ext_core_v3.HeaderValue{Key: "X-Added-Trailer", Value: "Val"}}},
				RemoveHeaders: []string{}, // use empty slice instead of nil
			},
		},
		"remove_trailers": {
			decision: map[string]interface{}{
				"trailers_to_remove": []interface{}{"X-Remove-Trailer"},
			},
			expected: &ext_proc_v3.HeaderMutation{
				SetHeaders:    []*ext_core_v3.HeaderValueOption{}, // explicitly empty
				RemoveHeaders: []string{"X-Remove-Trailer"},
			},
		},
		"add_and_remove_trailers": {
			decision: map[string]interface{}{
				"trailers_to_add": []interface{}{
					map[string]interface{}{"key": "X-Add", "value": "Val"},
				},
				"trailers_to_remove": []interface{}{"X-Remove"},
			},
			expected: &ext_proc_v3.HeaderMutation{
				SetHeaders:    []*ext_core_v3.HeaderValueOption{{Header: &ext_core_v3.HeaderValue{Key: "X-Add", Value: "Val"}}},
				RemoveHeaders: []string{"X-Remove"},
			},
		},
		"invalid_trailers_to_remove": {
			decision: map[string]interface{}{
				"trailers_to_remove": []interface{}{123},
			},
			expectError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := &EvalResult{Decision: tc.decision}
			tm, err := result.GetTrailerMutation()
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !proto.Equal(tm, tc.expected) {
				t.Fatalf("expected: %#v\ngot: %#v", tc.expected, tm)
			}
		})
	}
}

func TestEvalResult_NewEvalResult(t *testing.T) {
	er, stop, err := NewEvalResult()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if er.DecisionID == "" {
		t.Fatal("expected decision ID to be set")
	}
	if er.Metrics == nil {
		t.Fatal("expected metrics to be initialized")
	}
	stop() // stop metrics timer
}

func TestNewEvalResultWithDecisionID(t *testing.T) {
	type Opt func(*EvalResult)

	withDecisionID := func(decisionID string) Opt {
		return func(result *EvalResult) {
			result.DecisionID = decisionID
		}
	}

	expectedDecisionID := "some-decision-id"

	er, _, err := NewEvalResult(withDecisionID(expectedDecisionID))
	if err != nil {
		t.Fatalf("NewEvalResult() error = %v, wantErr %v", err, false)
	}
	if er.DecisionID != expectedDecisionID {
		t.Errorf("Expected DecisionID to be '%v', got '%v'", expectedDecisionID, er.DecisionID)
	}
}
