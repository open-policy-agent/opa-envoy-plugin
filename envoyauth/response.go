package envoyauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	ext_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/open-policy-agent/opa-envoy-plugin/internal/util"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/storage"
)

// EvalResult - Captures the result from evaluating a query against an input
type EvalResult struct {
	Revision   string // Deprecated: Use `revisions` instead.
	Revisions  map[string]string
	DecisionID string
	TxnID      uint64
	Decision   interface{}
	Metrics    metrics.Metrics
	Txn        storage.Transaction
}

// StopFunc should be called as soon as the evaluation is finished
type StopFunc = func()

// TransactionCloser should be called to abort the transaction
type TransactionCloser func(ctx context.Context, err error) error

// NewEvalResult creates a new EvalResult and a StopFunc that is used to stop the timer for metrics
func NewEvalResult() (*EvalResult, StopFunc, error) {
	var err error

	er := EvalResult{
		Metrics: metrics.New(),
	}
	er.DecisionID, err = util.UUID4()

	if err != nil {
		return nil, nil, err
	}

	er.Metrics.Timer(metrics.ServerHandler).Start()

	stop := func() {
		_ = er.Metrics.Timer(metrics.ServerHandler).Stop()
	}

	return &er, stop, nil
}

// GetTxn creates a read transaction suitable for the configured EvalResult object
func (result *EvalResult) GetTxn(ctx context.Context, store storage.Store) (storage.Transaction, TransactionCloser, error) {
	params := storage.TransactionParams{}

	noopCloser := func(ctx context.Context, err error) error {
		return nil // no-op default
	}

	txn, err := store.NewTransaction(ctx, params)
	if err != nil {
		return nil, noopCloser, err
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
			return false, fmt.Errorf("type assertion error")
		}

		return allowed, nil
	}

	return false, result.invalidDecisionErr()
}

// GetResponseHTTPHeaders - returns the http headers to return if they are part of the decision
func (result *EvalResult) GetResponseHTTPHeaders() (http.Header, error) {
	var ok bool
	var val interface{}

	var responseHeaders = make(http.Header)

	switch decision := result.Decision.(type) {
	case bool:
		return responseHeaders, nil
	case map[string]interface{}:
		if val, ok = decision["headers"]; !ok {
			return responseHeaders, nil
		}

		takeResponseHeaders := func(headers map[string]interface{}, targetHeaders *http.Header) error {
			for key, value := range headers {
				var headerVal string
				if headerVal, ok = value.(string); !ok {
					return fmt.Errorf("type assertion error")
				}

				targetHeaders.Add(key, headerVal)
			}

			return nil
		}

		switch val := val.(type) {
		case []interface{}:
			for _, vval := range val {
				headers, ok := vval.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("type assertion error")
				}

				err := takeResponseHeaders(headers, &responseHeaders)
				if err != nil {
					return nil, err
				}
			}

		case map[string]interface{}:
			err := takeResponseHeaders(val, &responseHeaders)
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("type assertion error")
		}

		return responseHeaders, nil
	}

	return nil, result.invalidDecisionErr()
}

// GetResponseEnvoyHeaderValueOptions - returns the http headers to return if they are part of the decision as envoy header value options
func (result *EvalResult) GetResponseEnvoyHeaderValueOptions() ([]*ext_core_v3.HeaderValueOption, error) {
	headers, err := result.GetResponseHTTPHeaders()
	if err != nil {
		return nil, err
	}

	responseHeaders := []*ext_core_v3.HeaderValueOption{}

	for key, values := range headers {
		for idx := range values {
			headerValue := &ext_core_v3.HeaderValue{
				Key:   key,
				Value: values[idx],
			}
			headerValueOption := &ext_core_v3.HeaderValueOption{
				Header: headerValue,
			}
			responseHeaders = append(responseHeaders, headerValueOption)
		}
	}

	return responseHeaders, nil
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
		return "", fmt.Errorf("type assertion error")
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
			return status, fmt.Errorf("type assertion error")
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
