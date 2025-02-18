package envoyauth

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	_structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"google.golang.org/protobuf/proto"
)

func TestIsAllowed(t *testing.T) {

	input := make(map[string]interface{})
	er := EvalResult{
		Decision: input,
	}
	var err error

	_, err = er.IsAllowed()
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	input["allowed"] = 1
	_, err = er.IsAllowed()
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	if !strings.Contains(err.Error(), "but got 'int'") {
		t.Fatal("Assertion error type reflection failed")
	}

	input["allowed"] = true
	var result bool
	result, err = er.IsAllowed()

	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if result != true {
		t.Fatalf("Expected value for IsAllowed %v but got %v", true, result)
	}
}

func TestReadRevisionsLegacy(t *testing.T) {
	store := inmem.New()
	ctx := context.Background()

	tb := bundle.Manifest{
		Revision: "abc123",
		Roots:    &[]string{"/a/b", "/a/c"},
	}

	// write a "legacy" manifest
	err := storage.Txn(ctx, store, storage.WriteParams, func(txn storage.Transaction) error {
		if err := bundle.LegacyWriteManifestToStore(ctx, store, txn, tb); err != nil {
			t.Fatalf("Failed to write manifest to store: %s", err)
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Unexpected error finishing transaction: %s", err)
	}

	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)

	result := EvalResult{
		Txn: txn,
	}

	err = result.ReadRevisions(ctx, store)
	if err != nil {
		t.Fatal(err)
	}

	expected := "abc123"
	if result.Revision != "abc123" {
		t.Fatalf("Expected revision %v but got %v", expected, result.Revision)
	}

	if len(result.Revisions) != 0 {
		t.Fatal("Unexpected multiple bundles")
	}
}

func TestReadRevisionsMulti(t *testing.T) {
	store := inmem.New()
	ctx := context.Background()

	bundles := map[string]bundle.Manifest{
		"bundle1": {
			Revision: "abc123",
			Roots:    &[]string{"/a/b", "/a/c"},
		},
		"bundle2": {
			Revision: "def123",
			Roots:    &[]string{"/x/y", "/z"},
		},
	}

	// write bundles
	for name, manifest := range bundles {
		err := storage.Txn(ctx, store, storage.WriteParams, func(txn storage.Transaction) error {
			err := bundle.WriteManifestToStore(ctx, store, txn, name, manifest)
			if err != nil {
				t.Fatalf("Failed to write manifest to store: %s", err)
			}
			return err
		})
		if err != nil {
			t.Fatalf("Unexpected error finishing transaction: %s", err)
		}
	}

	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)

	result := EvalResult{
		Txn: txn,
	}

	err := result.ReadRevisions(ctx, store)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Revisions) != 2 {
		t.Fatalf("Expected two bundles but got %v", len(result.Revisions))
	}

	expected := map[string]string{"bundle1": "abc123", "bundle2": "def123"}
	if !reflect.DeepEqual(result.Revisions, expected) {
		t.Fatalf("Expected result: %v, got: %v", expected, result.Revisions)
	}

	if result.Revision != "" {
		t.Fatalf("Unexpected revision %v", result.Revision)
	}
}

func TestGetRequestQueryParametersToRemove(t *testing.T) {
	tests := map[string]struct {
		decision interface{}
		exp      []string
		wantErr  bool
	}{
		"bool_eval_result": {
			true,
			nil,
			false,
		},
		"invalid_eval_result": {
			"hello",
			nil,
			true,
		},
		"empty_map_result": {
			map[string]interface{}{},
			nil,
			false,
		},
		"bad_param_value": {
			map[string]interface{}{"query_parameters_to_remove": "test"},
			nil,
			true,
		},
		"string_array_param_value": {
			map[string]interface{}{"query_parameters_to_remove": []string{"foo", "bar"}},
			[]string{"foo", "bar"},
			false,
		},
		"interface_array_param_value": {
			map[string]interface{}{"query_parameters_to_remove": []interface{}{"foo", "bar", "fuz"}},
			[]string{"foo", "bar", "fuz"},
			false,
		},
		"interface_array_bad_param_value": {
			map[string]interface{}{"query_parameters_to_remove": []interface{}{1}},
			nil,
			true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			er := EvalResult{
				Decision: tc.decision,
			}

			result, err := er.GetRequestQueryParametersToRemove()

			if tc.wantErr {
				if err == nil {
					t.Fatal("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error %v", err)
				}

				if !reflect.DeepEqual(tc.exp, result) {
					t.Fatalf("Expected result %v but got %v", tc.exp, result)
				}
			}
		})
	}
}

func TestGetRequestHTTPHeadersToRemove(t *testing.T) {
	tests := map[string]struct {
		decision interface{}
		exp      []string
		wantErr  bool
	}{
		"bool_eval_result": {
			true,
			nil,
			false,
		},
		"invalid_eval_result": {
			"hello",
			nil,
			true,
		},
		"empty_map_result": {
			map[string]interface{}{},
			nil,
			false,
		},
		"bad_header_value": {
			map[string]interface{}{"request_headers_to_remove": "test"},
			nil,
			true,
		},
		"string_array_header_value": {
			map[string]interface{}{"request_headers_to_remove": []string{"foo", "bar"}},
			[]string{"foo", "bar"},
			false,
		},
		"interface_array_header_value": {
			map[string]interface{}{"request_headers_to_remove": []interface{}{"foo", "bar", "fuz"}},
			[]string{"foo", "bar", "fuz"},
			false,
		},
		"interface_array_bad_header_value": {
			map[string]interface{}{"request_headers_to_remove": []interface{}{1}},
			nil,
			true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			er := EvalResult{
				Decision: tc.decision,
			}

			result, err := er.GetRequestHTTPHeadersToRemove()

			if tc.wantErr {
				if err == nil {
					t.Fatal("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error %v", err)
				}

				if !reflect.DeepEqual(tc.exp, result) {
					t.Fatalf("Expected result %v but got %v", tc.exp, result)
				}
			}
		})
	}

	t.Run("type_assertion_error", func(t *testing.T) {
		er := EvalResult{
			Decision: map[string]interface{}{"request_headers_to_remove": 1},
		}

		_, err := er.GetRequestHTTPHeadersToRemove()
		if err == nil {
			t.Fatal("Expected error but got nil")
		}

		if !strings.Contains(err.Error(), "but got 'int'") {
			t.Fatalf("Assertion error type reflection failed")
		}
	})
}

func TestGetResponseHTTPHeadersToAdd(t *testing.T) {
	input := make(map[string]interface{})
	er := EvalResult{
		Decision: input,
	}

	result, err := er.GetResponseHTTPHeadersToAdd()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result) != 0 {
		t.Fatal("Expected no headers")
	}

	badHeader := "test"
	input["response_headers_to_add"] = badHeader

	_, err = er.GetResponseHTTPHeadersToAdd()
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	testHeaders := make(map[string]interface{})
	testHeaders["foo"] = "bar"
	input["response_headers_to_add"] = testHeaders

	result, err = er.GetResponseHTTPHeadersToAdd()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected one header but got %v", len(result))
	}

	testHeaders["baz"] = 1

	_, err = er.GetResponseHTTPHeadersToAdd()
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	input["response_headers_to_add"] = []interface{}{
		map[string]interface{}{
			"foo": "bar",
		},
		map[string]interface{}{
			"foo": "baz",
		},
	}

	result, err = er.GetResponseHTTPHeadersToAdd()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("Expected two headers but got %v", len(result))
	}

	testAddHeaders := make(map[string]interface{})
	testAddHeaders["foo"] = []string{"bar", "baz"}
	input["response_headers_to_add"] = testAddHeaders

	result, err = er.GetResponseHTTPHeadersToAdd()

	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("Expected two header but got %v", len(result))
	}
}

func TestGetResponseHeaderValueOptions(t *testing.T) {
	input := make(map[string]interface{})
	er := EvalResult{
		Decision: input,
	}

	result, err := er.GetResponseEnvoyHeaderValueOptions()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result) != 0 {
		t.Fatal("Expected no headers")
	}

	badHeader := "test"
	input["headers"] = badHeader

	_, err = er.GetResponseEnvoyHeaderValueOptions()
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	testHeaders := make(map[string]interface{})
	testHeaders["foo"] = "bar"
	input["headers"] = testHeaders

	result, err = er.GetResponseEnvoyHeaderValueOptions()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected one header but got %v", len(result))
	}

	testHeaders["baz"] = 1

	_, err = er.GetResponseEnvoyHeaderValueOptions()
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	input["headers"] = []interface{}{
		map[string]interface{}{
			"foo": "bar",
		},
		map[string]interface{}{
			"foo": "baz",
		},
	}

	result, err = er.GetResponseEnvoyHeaderValueOptions()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("Expected two header but got %v", len(result))
	}

	seen := map[string]int{}
	for _, hdr := range result {
		seen[hdr.Header.Value]++
	}
	if seen["bar"] != 1 || seen["baz"] != 1 {
		t.Errorf("expected 'bar' and 'baz', got %v", seen)
	}

	testAddHeaders := make(map[string]interface{})
	testAddHeaders["foo"] = []string{"bar", "baz"}
	input["headers"] = testAddHeaders

	result, err = er.GetResponseEnvoyHeaderValueOptions()

	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("Expected two header but got %v", len(result))
	}
	//
	//testAddHeaders["foo"] = []interface{}{"bar", "baz"}
	//input["headers"] = testAddHeaders
	//
	//result, err = er.GetResponseEnvoyHeaderValueOptions()
	//
	//if err != nil {
	//	t.Fatalf("Expected no error but got %v", err)
	//}
	//
	//if len(result) != 2 {
	//	t.Fatalf("Expected two header but got %v", len(result))
	//}
	//
	//if seen["bar"] != 1 || seen["baz"] != 1 {
	//	t.Errorf("expected 'bar' and 'baz', got %v", seen)
	//}
}

func TestGetResponseHeaders(t *testing.T) {
	input := make(map[string]interface{})
	er := EvalResult{
		Decision: input,
	}

	result, err := er.GetResponseHTTPHeaders()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result) != 0 {
		t.Fatal("Expected no headers")
	}

	badHeader := "test"
	input["headers"] = badHeader

	_, err = er.GetResponseHTTPHeaders()
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	testHeaders := make(map[string]interface{})
	testHeaders["foo"] = "bar"
	input["headers"] = testHeaders

	result, err = er.GetResponseHTTPHeaders()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected one header but got %v", len(result))
	}

	testHeaders["baz"] = 1

	_, err = er.GetResponseHTTPHeaders()
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	input["headers"] = []interface{}{
		map[string]interface{}{
			"foo": "bar",
		},
		map[string]interface{}{
			"foo": "baz",
		},
	}

	result, err = er.GetResponseHTTPHeaders()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result.Values("foo")) != 2 {
		t.Fatalf("Expected two header values but got %v", result.Values("foo"))
	}

	seen := map[string]int{}
	for _, values := range result {
		for _, value := range values {
			seen[value]++
		}
	}

	if seen["bar"] != 1 || seen["baz"] != 1 {
		t.Errorf("expected 'bar' and 'baz', got %v", seen)
	}

	testAddHeaders := make(map[string]interface{})
	testAddHeaders["foo"] = []string{"bar", "baz"}
	input["headers"] = testAddHeaders

	result, err = er.GetResponseHTTPHeaders()

	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result.Values("foo")) != 2 {
		t.Fatalf("Expected two header but got %v", len(result.Values("foo")))
	}

	testAddHeaders["foo"] = []interface{}{"bar", "baz"}
	input["headers"] = testAddHeaders

	result, err = er.GetResponseHTTPHeaders()

	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if len(result.Values("foo")) != 2 {
		t.Fatalf("Expected two header but got %v", len(result.Values("foo")))
	}

	if seen["bar"] != 1 || seen["baz"] != 1 {
		t.Errorf("expected 'bar' and 'baz', got %v", seen)
	}
}

func TestGetResponseBody(t *testing.T) {
	input := make(map[string]interface{})
	er := EvalResult{
		Decision: input,
	}

	result, err := er.GetResponseBody()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if result != "" {
		t.Fatalf("Expected empty body but got %v", result)
	}

	input["body"] = "hello"
	result, err = er.GetResponseBody()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if result != "hello" {
		t.Fatalf("Expected result \"hello\" but got %v", result)
	}

	input["body"] = 123
	_, err = er.GetResponseBody()
	if err == nil {
		t.Fatal("Expected error but got nil", err)
	}

	if !strings.Contains(err.Error(), "but got 'int'") {
		t.Fatalf("Assertion error type reflection failed")
	}
}

func TestGetResponseHttpStatus(t *testing.T) {
	input := make(map[string]interface{})
	er := EvalResult{
		Decision: input,
	}

	result, err := er.GetResponseEnvoyHTTPStatus()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if result.GetCode().String() != "Forbidden" {
		t.Fatalf("Expected http status code \"Forbidden\" but got %v", result.GetCode().String())
	}

	input["http_status"] = true
	_, err = er.GetResponseEnvoyHTTPStatus()
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	if !strings.Contains(err.Error(), "but got 'bool'") {
		t.Fatalf("Assertion error type reflection failed")
	}

	input["http_status"] = json.Number("1")
	_, err = er.GetResponseEnvoyHTTPStatus()
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	input["http_status"] = json.Number("9999")
	_, err = er.GetResponseEnvoyHTTPStatus()
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	input["http_status"] = json.Number("400")
	result, err = er.GetResponseEnvoyHTTPStatus()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if result.GetCode().String() != "BadRequest" {
		t.Fatalf("Expected http status code \"BadRequest\" but got %v", result.GetCode().String())
	}
}

func TestGetDynamicMetadata(t *testing.T) {
	input := make(map[string]interface{})
	er := EvalResult{
		Decision: input,
	}

	result, err := er.GetDynamicMetadata()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	if result != nil {
		t.Fatalf("Expected no dynamic metadata but got %v", result)
	}

	input["dynamic_metadata"] = map[string]interface{}{
		"foo": "bar",
	}
	result, err = er.GetDynamicMetadata()
	if err != nil {
		t.Fatalf("Expected no error but got %v", err)
	}

	expectedDynamicMetadata := &_structpb.Struct{
		Fields: map[string]*_structpb.Value{
			"foo": {
				Kind: &_structpb.Value_StringValue{
					StringValue: "bar",
				},
			},
		},
	}
	if !proto.Equal(result, expectedDynamicMetadata) {
		t.Fatalf("Expected result %v but got %v", expectedDynamicMetadata, result)
	}

	input["dynamic_metadata"] = 123
	_, err = er.GetDynamicMetadata()
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	if !strings.Contains(err.Error(), "but got 'int'") {
		t.Fatalf("Assertion error type reflection failed")
	}
}

func TestGetDynamicMetadataWithBooleanDecision(t *testing.T) {
	er := EvalResult{
		Decision: true,
	}

	result, err := er.GetDynamicMetadata()
	if err == nil {
		t.Fatal("Expected error error but got none")
	}

	if result != nil {
		t.Fatalf("Expected no result but got %v", result)
	}
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
