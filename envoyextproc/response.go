package envoyextproc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	ext_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	ext_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/metrics"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"google.golang.org/protobuf/types/known/structpb"
)

// EvalResult captures the result from evaluating a query against an input.
type EvalResult struct {
	Revision       string // Deprecated: Use `revisions` instead.
	Revisions      map[string]string
	DecisionID     string
	TxnID          uint64
	Decision       any
	Metrics        metrics.Metrics
	Txn            storage.Transaction
	NDBuiltinCache builtins.NDBCache
}

// StopFunc should be called as soon as the evaluation is finished.
type StopFunc = func()

// TransactionCloser should be called to abort the transaction.
type TransactionCloser func(ctx context.Context, err error) error

// NewEvalResult creates a new EvalResult and a StopFunc that is used to stop the timer for metrics.
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

// ReadRevisions adds bundle revisions to the result.
func (result *EvalResult) ReadRevisions(ctx context.Context, store storage.Store) error {
	if result.Txn == nil {
		return nil
	}
	names, err := bundle.ReadBundleNamesFromStore(ctx, store, result.Txn)
	if err != nil && !storage.IsNotFound(err) {
		return err
	}

	revisions := make(map[string]string, len(names))
	for _, name := range names {
		r, err := bundle.ReadBundleRevisionFromStore(ctx, store, result.Txn, name)
		if err != nil && !storage.IsNotFound(err) {
			return err
		}
		revisions[name] = r
	}

	// Check legacy bundle manifest in the store
	revision, err := bundle.LegacyReadRevisionFromStore(ctx, store, result.Txn)
	if err != nil && !storage.IsNotFound(err) {
		return err
	}

	result.Revisions = revisions
	result.Revision = revision
	return nil
}

// GetTxn creates a read transaction suitable for the configured EvalResult object.
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

// invalidDecisionErr returns an error indicating that the decision is invalid.
func (result *EvalResult) invalidDecisionErr() error {
	return fmt.Errorf("illegal value for policy evaluation result: %T", result.Decision)
}

// GetImmediateResponse constructs an ImmediateResponse message based on the policy decision.
func (result *EvalResult) GetImmediateResponse() (*ext_proc_v3.ImmediateResponse, error) {
	decisionMap, ok := result.Decision.(map[string]any)
	if !ok {
		return nil, nil // No immediate response
	}

	immediateRespData, ok := decisionMap["immediate_response"].(map[string]any)
	if !ok {
		return nil, nil // No immediate response
	}

	// Default status code
	statusInt := http.StatusForbidden

	// Extract status code
	if val, ok := immediateRespData["status"]; ok {
		var statusCode json.Number
		if statusCode, ok = val.(json.Number); !ok {
			return nil, fmt.Errorf("type assertion error, expected status to be of type 'number' but got '%T'", val)
		}

		httpStatusCode, err := statusCode.Int64()
		if err != nil {
			return nil, fmt.Errorf("error converting JSON number to int: %v", err)
		}

		if http.StatusText(int(httpStatusCode)) == "" {
			return nil, fmt.Errorf("invalid HTTP status code %v", httpStatusCode)
		}

		statusInt = int(httpStatusCode)
	}

	// Construct HttpStatus
	statusCode := &ext_type_v3.HttpStatus{
		Code: ext_type_v3.StatusCode(statusInt),
	}

	// Extract body
	body := []byte{}
	if bodyVal, ok := immediateRespData["body"].(string); ok {
		body = []byte(bodyVal)
	}

	// Extract headers
	headers := []*ext_core_v3.HeaderValueOption{}
	if headersVal, ok := immediateRespData["headers"].([]any); ok {
		for _, headerObj := range headersVal {
			headerMap, ok := headerObj.(map[string]any)
			if !ok {
				continue
			}

			key, ok := headerMap["key"].(string)
			if !ok {
				continue
			}

			value, ok := headerMap["value"].(string)
			if !ok {
				continue
			}

			headerValueOption := &ext_core_v3.HeaderValueOption{
				Header: &ext_core_v3.HeaderValue{Key: key, Value: value},
			}
			headers = append(headers, headerValueOption)
		}
	}

	immediateResponse := &ext_proc_v3.ImmediateResponse{
		Status: statusCode,
		Body:   body,
		Headers: &ext_proc_v3.HeaderMutation{
			SetHeaders: headers,
		},
	}

	// Optional: Handle gRPC status and details if needed
	if grpcStatusVal, ok := immediateRespData["grpc_status"].(float64); ok {
		immediateResponse.GrpcStatus = &ext_proc_v3.GrpcStatus{
			Status: uint32(grpcStatusVal),
		}
	}

	if detailsVal, ok := immediateRespData["details"].(string); ok {
		immediateResponse.Details = detailsVal
	}

	return immediateResponse, nil
}

// GetCommonResponse constructs a CommonResponse based on the policy decision.
func (result *EvalResult) GetCommonResponse() (*ext_proc_v3.CommonResponse, error) {
	_, ok := result.Decision.(map[string]any)
	if !ok {
		return nil, nil // No modifications
	}

	headerMutation, err := result.getHeaderMutation()
	if err != nil {
		return nil, err
	}

	bodyMutation, err := result.getBodyMutation()
	if err != nil {
		return nil, err
	}

	if headerMutation == nil && bodyMutation == nil {
		return nil, nil // No modifications
	}

	commonResponse := &ext_proc_v3.CommonResponse{
		HeaderMutation: headerMutation,
		BodyMutation:   bodyMutation,
	}

	// Set status if needed
	if bodyMutation != nil {
		commonResponse.Status = ext_proc_v3.CommonResponse_CONTINUE_AND_REPLACE
	}

	return commonResponse, nil
}

// getHeaderMutation constructs a HeaderMutation from the policy decision.
func (result *EvalResult) getHeaderMutation() (*ext_proc_v3.HeaderMutation, error) {
	decisionMap, ok := result.Decision.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("decision is not a map")
	}

	// Initialize slices for set and remove headers
	setHeaders := []*ext_core_v3.HeaderValueOption{}
	removeHeaders := []string{}

	// Process headers to add
	if responseHeaders, ok := decisionMap["headers_to_add"]; ok {
		headersSlice, ok := responseHeaders.([]any)
		if !ok {
			return nil, fmt.Errorf("headers_to_add is not an array")
		}

		for _, headerObj := range headersSlice {
			headerMap, ok := headerObj.(map[string]any)
			if !ok {
				continue
			}

			key, ok := headerMap["key"].(string)
			if !ok {
				continue
			}

			value, ok := headerMap["value"].(string)
			if !ok {
				continue
			}

			headerValueOption := &ext_core_v3.HeaderValueOption{
				Header: &ext_core_v3.HeaderValue{Key: key, Value: value},
			}

			setHeaders = append(setHeaders, headerValueOption)
		}
	}

	// Process headers to remove
	if removeHeadersVal, ok := decisionMap["headers_to_remove"]; ok {
		removeHeadersSlice, ok := removeHeadersVal.([]any)
		if !ok {
			return nil, fmt.Errorf("headers_to_remove is not an array")
		}
		for _, v := range removeHeadersSlice {
			header, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("header to remove is not a string")
			}
			removeHeaders = append(removeHeaders, header)
		}
	}

	// Check if there are any header mutations
	if len(setHeaders) == 0 && len(removeHeaders) == 0 {
		return nil, nil // No header mutations
	}

	headerMutation := &ext_proc_v3.HeaderMutation{
		SetHeaders:    setHeaders,
		RemoveHeaders: removeHeaders,
	}

	return headerMutation, nil
}

// getBodyMutation constructs a BodyMutation from the policy decision.
func (result *EvalResult) getBodyMutation() (*ext_proc_v3.BodyMutation, error) {
	decisionMap, ok := result.Decision.(map[string]any)
	if !ok {
		return nil, nil
	}

	bodyVal, ok := decisionMap["body"]
	if !ok {
		return nil, nil
	}

	bodyStr, ok := bodyVal.(string)
	if !ok {
		return nil, fmt.Errorf("body is not a string")
	}

	bodyMutation := &ext_proc_v3.BodyMutation{
		Mutation: &ext_proc_v3.BodyMutation_Body{
			Body: []byte(bodyStr),
		},
	}

	return bodyMutation, nil
}

// GetDynamicMetadata retrieves dynamic metadata from the policy decision.
func (result *EvalResult) GetDynamicMetadata() (*structpb.Struct, error) {
	decisionMap, ok := result.Decision.(map[string]any)
	if !ok {
		return nil, nil
	}

	val, ok := decisionMap["dynamic_metadata"]
	if !ok {
		return nil, nil // No dynamic metadata
	}

	metadataMap, ok := val.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("dynamic_metadata is not a map")
	}

	dynamicMetadata, err := structpb.NewStruct(metadataMap)
	if err != nil {
		return nil, fmt.Errorf("failed to convert dynamic_metadata to Struct: %v", err)
	}

	return dynamicMetadata, nil
}

// GetTrailerMutation constructs a HeaderMutation from the policy decision for trailers.
func (result *EvalResult) GetTrailerMutation() (*ext_proc_v3.HeaderMutation, error) {
	// Instead of erroring out if the decision is not a map, return nil to be consistent.
	decisionMap, ok := result.Decision.(map[string]any)
	if !ok {
		return nil, nil
	}

	// Initialize slices for set and remove trailers
	setTrailers := []*ext_core_v3.HeaderValueOption{}
	removeTrailers := []string{}

	// Process trailers to add
	if responseTrailers, ok := decisionMap["trailers_to_add"]; ok {
		trailersSlice, ok := responseTrailers.([]any)
		if !ok {
			return nil, fmt.Errorf("trailers_to_add is not an array")
		}

		for _, trailerObj := range trailersSlice {
			trailerMap, ok := trailerObj.(map[string]any)
			if !ok {
				continue
			}

			key, ok := trailerMap["key"].(string)
			if !ok {
				continue
			}

			value, ok := trailerMap["value"].(string)
			if !ok {
				continue
			}

			headerValueOption := &ext_core_v3.HeaderValueOption{
				Header: &ext_core_v3.HeaderValue{Key: key, Value: value},
			}

			setTrailers = append(setTrailers, headerValueOption)
		}
	}

	// Process trailers to remove
	if removeTrailersVal, ok := decisionMap["trailers_to_remove"]; ok {
		removeTrailersSlice, ok := removeTrailersVal.([]any)
		if !ok {
			return nil, fmt.Errorf("trailers_to_remove is not an array")
		}
		for _, v := range removeTrailersSlice {
			trailer, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("trailer to remove is not a string")
			}
			removeTrailers = append(removeTrailers, trailer)
		}
	}

	// Check if there are any trailer mutations
	if len(setTrailers) == 0 && len(removeTrailers) == 0 {
		return nil, nil // No trailer mutations
	}

	headerMutation := &ext_proc_v3.HeaderMutation{
		SetHeaders:    setTrailers,
		RemoveHeaders: removeTrailers,
	}

	return headerMutation, nil
}
