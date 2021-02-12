package envoyauth

import (
	"encoding/json"
	"testing"
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

func TestGetResponseHeaders(t *testing.T) {
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
	result, err = er.GetResponseBody()
	if err == nil {
		t.Fatal("Expected error but got nil", err)
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
	result, err = er.GetResponseEnvoyHTTPStatus()
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	input["http_status"] = json.Number("1")
	result, err = er.GetResponseEnvoyHTTPStatus()
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	input["http_status"] = json.Number("9999")
	result, err = er.GetResponseEnvoyHTTPStatus()
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
