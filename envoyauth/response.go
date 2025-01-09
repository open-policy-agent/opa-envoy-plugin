package envoyauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	ext_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	_structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"google.golang.org/protobuf/types/known/structpb"
)

// EvalResult - Captures the result from evaluating a query against an input
type EvalResult struct {
	Revision       string // Deprecated: Use `revisions` instead.
	Revisions      map[string]string
	DecisionID     string
	TxnID          uint64
	Decision       interface{}
	Metrics        metrics.Metrics
	Txn            storage.Transaction
	NDBuiltinCache builtins.NDBCache
}

// StopFunc should be called as soon as the evaluation is finished
type StopFunc = func()

// TransactionCloser should be called to abort the transaction
type TransactionCloser func(ctx context.Context, err error) error

func noopTransactionCloser(context.Context, error) error {
	return nil // no-op default
}

// NewEvalResult creates a new EvalResult and a StopFunc that is used to stop the timer for metrics
func NewEvalResult(opts ...func(*EvalResult)) (*EvalResult, StopFunc, error) {
	er := &EvalResult{
		Metrics: metrics.New(),
	}

	for _, opt := range opts {
		opt(er)
	}

	if er.DecisionID == "" {
		er.DecisionID = uuid.NewString()
	}

	er.Metrics.Timer(metrics.ServerHandler).Start()

	stop := func() {
		_ = er.Metrics.Timer(metrics.ServerHandler).Stop()
	}

	return er, stop, nil
}

// GetTxn creates a read transaction suitable for the configured EvalResult object
func (result *EvalResult) GetTxn(ctx context.Context, store storage.Store) (storage.Transaction, TransactionCloser, error) {
	params := storage.TransactionParams{}

	txn, err := store.NewTransaction(ctx, params)
	if err != nil {
		return nil, noopTransactionCloser, err
	}

	// Setup a closer function that will abort the transaction.
	closer := func(ctx context.Context, txnErr error) error {
		store.Abort(ctx, txn)
		result.Txn = nil
		return nil
	}

	return txn, closer, nil
}

func (result *EvalResult) invalidDecisionErr() error {
	return fmt.Errorf("illegal value for policy evaluation result: %T", result.Decision)
}

// IsAllowed - Returns if the decision is representing an "allow" depending on the decision structure.
// Returns an error if the decision structure is invalid
func (result *EvalResult) IsAllowed() (bool, error) {
	switch decision := result.Decision.(type) {
	case bool:
		return decision, nil
	case map[string]interface{}:
		var val interface{}
		var ok, allowed bool

		if val, ok = decision["allowed"]; !ok {
			return false, fmt.Errorf("unable to determine evaluation result due to missing \"allowed\" key")
		}

		if allowed, ok = val.(bool); !ok {
			return false, fmt.Errorf("type assertion error, expected allowed to be of type 'boolean' but got '%T'", val)
		}

		return allowed, nil
	}

	return false, result.invalidDecisionErr()
}

func (result *EvalResult) getStringSliceFromDecision(fieldName string) ([]string, error) {
	switch decision := result.Decision.(type) {
	case bool:
		return nil, nil
	case map[string]interface{}:
		var ok bool
		var val interface{}

		if val, ok = decision[fieldName]; !ok {
			return nil, nil
		}

		switch val := val.(type) {
		case []string:
			return val, nil
		case []interface{}:
			ss := make([]string, len(val))
			for i, v := range val {
				s, ok := v.(string)
				if !ok {
					return nil, fmt.Errorf("type assertion error, expected %s value to be of type 'string' but got '%T'", fieldName, v)
				}
				ss[i] = s
			}
			return ss, nil
		default:
			return nil, fmt.Errorf("type assertion error, expected %s to be of type '[]string' but got '%T'", fieldName, val)
		}
	}

	return nil, result.invalidDecisionErr()
}

// GetRequestQueryParametersToRemove - returns the query parameters to remove from the original request before dispatching
// it to the upstream
func (result *EvalResult) GetRequestQueryParametersToRemove() ([]string, error) {
	return result.getStringSliceFromDecision("query_parameters_to_remove")
}

// GetRequestHTTPHeadersToRemove - returns the http headers to remove from the original request before dispatching
// it to the upstream
func (result *EvalResult) GetRequestHTTPHeadersToRemove() ([]string, error) {
	return result.getStringSliceFromDecision("request_headers_to_remove")
}

func (result *EvalResult) getHeadersFromDecision(fieldName string) ([]*ext_core_v3.HeaderValueOption, error) {
	switch decision := result.Decision.(type) {
	case bool:
		return nil, nil
	case map[string]interface{}:
		val, ok := decision[fieldName]
		if !ok {
			return nil, nil
		}

		return transformHeadersToEnvoy(val)
	default:
		return nil, result.invalidDecisionErr()
	}
}

// GetResponseEnvoyHeaderValueOptions - returns the http headers to return if they are part of the decision as envoy header value options
func (result *EvalResult) GetResponseEnvoyHeaderValueOptions() ([]*ext_core_v3.HeaderValueOption, error) {
	return result.getHeadersFromDecision("headers")
}

// GetResponseHTTPHeadersToAdd - returns the http headers to send to the downstream client
func (result *EvalResult) GetResponseHTTPHeadersToAdd() ([]*ext_core_v3.HeaderValueOption, error) {
	return result.getHeadersFromDecision("response_headers_to_add")
}

// HasResponseBody returns true if the decision defines a body (only true for structured decisions)
func (result *EvalResult) HasResponseBody() bool {
	decision, ok := result.Decision.(map[string]interface{})

	if !ok {
		return false
	}

	_, ok = decision["body"]

	return ok
}

// GetResponseBody returns the http body to return if they are part of the decision
func (result *EvalResult) GetResponseBody() (string, error) {
	var ok bool
	var val interface{}
	var body string
	var decision map[string]interface{}

	if decision, ok = result.Decision.(map[string]interface{}); !ok {
		return "", nil
	}

	if val, ok = decision["body"]; !ok {
		return "", nil
	}

	if body, ok = val.(string); !ok {
		return "", fmt.Errorf("type assertion error, expected body to be of type 'string' but got '%T'", val)
	}

	return body, nil
}

// GetResponseHTTPStatus returns the http status to return if they are part of the decision
func (result *EvalResult) GetResponseHTTPStatus() (int, error) {
	var ok bool
	var val interface{}
	var statusCode json.Number

	status := http.StatusForbidden

	switch decision := result.Decision.(type) {
	case bool:
		if decision {
			return http.StatusOK, fmt.Errorf("HTTP status code undefined for simple 'allow'")
		}

		return status, nil
	case map[string]interface{}:
		if val, ok = decision["http_status"]; !ok {
			return status, nil
		}

		if statusCode, ok = val.(json.Number); !ok {
			return status, fmt.Errorf("type assertion error, expected http_status to be of type 'number' but got '%T'", val)
		}

		httpStatusCode, err := statusCode.Int64()
		if err != nil {
			return status, fmt.Errorf("error converting JSON number to int: %v", err)
		}

		if http.StatusText(int(httpStatusCode)) == "" {
			return status, fmt.Errorf("Invalid HTTP status code %v", httpStatusCode)
		}

		return int(httpStatusCode), nil
	}

	return http.StatusForbidden, result.invalidDecisionErr()
}

// GetDynamicMetadata returns the dynamic metadata to return if part of the decision
func (result *EvalResult) GetDynamicMetadata() (*_structpb.Struct, error) {
	switch decision := result.Decision.(type) {
	case bool:
		if decision {
			return nil, fmt.Errorf("dynamic metadata undefined for boolean decision")
		}
	case map[string]interface{}:
		var (
			val interface{}
			ok  bool
		)
		if val, ok = decision["dynamic_metadata"]; !ok {
			return nil, nil
		}

		metadata, ok := val.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("type assertion error, expected dynamic_metadata to be of type 'object' but got '%T'", val)
		}

		return structpb.NewStruct(metadata)
	}

	return nil, nil
}

// GetResponseEnvoyHTTPStatus returns the http status to return if they are part of the decision
func (result *EvalResult) GetResponseEnvoyHTTPStatus() (*ext_type_v3.HttpStatus, error) {
	status := &ext_type_v3.HttpStatus{
		Code: ext_type_v3.StatusCode(ext_type_v3.StatusCode_Forbidden),
	}

	httpStatusCode, err := result.GetResponseHTTPStatus()

	if err != nil {
		return nil, err
	}

	//This check is partially redundant but might be more strict than http.StatusText()
	if _, ok := ext_type_v3.StatusCode_name[int32(httpStatusCode)]; !ok {
		return nil, fmt.Errorf("Invalid HTTP status code %v", httpStatusCode)
	}

	status.Code = ext_type_v3.StatusCode(int32(httpStatusCode))

	return status, nil
}

func makeHeaderValueOption(k, v string) *ext_core_v3.HeaderValueOption {
	return &ext_core_v3.HeaderValueOption{
		Header: &ext_core_v3.HeaderValue{
			Key:   k,
			Value: v,
		},
	}
}

func makeEnvoyHeaderValueOptionsFromHeadersMap(hvo []*ext_core_v3.HeaderValueOption, headers map[string]any) ([]*ext_core_v3.HeaderValueOption, error) {
	hvo = slices.Grow(hvo, len(headers))
	for key, value := range headers {
		switch val := value.(type) {
		case string:
			hvo = append(hvo, makeHeaderValueOption(key, val))
		case []string:
			hvo = slices.Grow(hvo, len(val))
			for _, v := range val {
				hvo = append(hvo, makeHeaderValueOption(key, v))
			}
		case []interface{}:
			hvo = slices.Grow(hvo, len(val))
			for _, v := range val {
				s, ok := v.(string)
				if !ok {
					return nil, fmt.Errorf("invalid value type %T for header '%s'", v, key)
				}
				hvo = append(hvo, makeHeaderValueOption(key, s))
			}
		default:
			return nil, fmt.Errorf("type assertion error for header '%s'", key)
		}
	}
	return hvo, nil
}

func transformHeadersToEnvoy(input any) ([]*ext_core_v3.HeaderValueOption, error) {
	switch input := input.(type) {
	case []any:
		var (
			hvo []*ext_core_v3.HeaderValueOption
			err error
		)
		for _, val := range input {
			headers, ok := val.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("type assertion error, expected headers to be of type 'object' but got '%T'", val)
			}

			hvo, err = makeEnvoyHeaderValueOptionsFromHeadersMap(hvo, headers)
			if err != nil {
				return nil, err
			}
		}
		return hvo, nil
	case map[string]any:
		return makeEnvoyHeaderValueOptionsFromHeadersMap(nil, input)
	}
	return nil, fmt.Errorf("type assertion error, expected headers to be of type 'object' but got '%T'", input)
}
