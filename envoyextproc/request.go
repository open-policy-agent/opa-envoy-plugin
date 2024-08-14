package envoyextproc

import (
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
)

// ProcessRequestHeaders processes incoming request headers.
func ProcessRequestHeaders(headers *ext_proc_v3.HttpHeaders) (*ext_proc_v3.ProcessingResponse, error) {
	return &ext_proc_v3.ProcessingResponse{
		Response: &ext_proc_v3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &ext_proc_v3.HeadersResponse{},
		},
	}, nil
}

// ProcessResponseHeaders processes incoming response headers.
func ProcessResponseHeaders(headers *ext_proc_v3.HttpHeaders) (*ext_proc_v3.ProcessingResponse, error) {
	return &ext_proc_v3.ProcessingResponse{
		Response: &ext_proc_v3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &ext_proc_v3.HeadersResponse{},
		},
	}, nil
}

// ProcessRequestBody processes incoming request bodies.
func ProcessRequestBody(body *ext_proc_v3.HttpBody) (*ext_proc_v3.ProcessingResponse, error) {
	return &ext_proc_v3.ProcessingResponse{
		Response: &ext_proc_v3.ProcessingResponse_RequestBody{
			RequestBody: &ext_proc_v3.BodyResponse{},
		},
	}, nil
}

// ProcessResponseBody processes incoming response bodies.
func ProcessResponseBody(body *ext_proc_v3.HttpBody) (*ext_proc_v3.ProcessingResponse, error) {
	return &ext_proc_v3.ProcessingResponse{
		Response: &ext_proc_v3.ProcessingResponse_ResponseBody{
			ResponseBody: &ext_proc_v3.BodyResponse{},
		},
	}, nil
}

// ProcessRequestTrailers processes incoming request trailers.
func ProcessRequestTrailers(trailers *ext_proc_v3.HttpTrailers) (*ext_proc_v3.ProcessingResponse, error) {
	return &ext_proc_v3.ProcessingResponse{
		Response: &ext_proc_v3.ProcessingResponse_RequestTrailers{
			RequestTrailers: &ext_proc_v3.TrailersResponse{},
		},
	}, nil
}

// ProcessResponseTrailers processes incoming response trailers.
func ProcessResponseTrailers(trailers *ext_proc_v3.HttpTrailers) (*ext_proc_v3.ProcessingResponse, error) {
	return &ext_proc_v3.ProcessingResponse{
		Response: &ext_proc_v3.ProcessingResponse_ResponseTrailers{
			ResponseTrailers: &ext_proc_v3.TrailersResponse{},
		},
	}, nil
}

// Error represents an error with a code and a message.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	return e.Message
}

// internalError creates a new Error with the given code and message.
func internalError(code codes.Code, err error) *Error {
	return &Error{
		Code:    code.String(),
		Message: err.Error(),
	}
}
