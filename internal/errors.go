package internal

import (
	"errors"
	"fmt"
)

// Error is the error type returned by the internal check function
type Error struct {
	Code string `json:"code"`
	err  error  `json:"-"`
}

const (

	// StartCheckErr error code returned when unable to start new execution
	StartCheckErr string = "start_check_error"

	// StartTxnErr error code returned when unable to start new storage transaction
	StartTxnErr string = "start_txn_error"

	// RequestParseErr error code returned when unable to parse protobuf request to input map
	RequestParseErr string = "request_parse_error"

	// CheckRequestTimeoutErr error code returned when context deadline exceeds before eval
	CheckRequestTimeoutErr string = "check_request_timeout"

	// CheckRequestCancelledErr error code returned when context deadline exceeds before eval
	CheckRequestCancelledErr string = "check_request_cancelled"

	// InputParseErr error code returned when unable to convert input map to ast value
	InputParseErr string = "input_parse_error"

	// EnvoyAuthEvalErr error code returned when auth eval fails
	EnvoyAuthEvalErr string = "envoyauth_eval_error"

	// EnvoyAuthResultErr error code returned when error in fetching result from auth eval
	EnvoyAuthResultErr string = "envoyauth_result_error"

	// UnknownContextErr error code returned when EvalContext is not provided
	UnknownContextErr string = "unknown_context_error"
)

// Is allows matching internal errors using errors.Is
func (e *Error) Is(target error) bool {
	var t *Error
	if errors.As(target, &t) {
		return (t.Code == "" || e.Code == t.Code) && errors.Is(e.Unwrap(), t.Unwrap())
	}
	return false
}

// Error allows converting internal Error to string type
func (e *Error) Error() string {
	msg := fmt.Sprintf("%v: %v", e.Code, e.Unwrap().Error())
	return msg
}

// Wrap wraps error as an internal error
func (e *Error) Wrap(err error) *Error {
	e.err = err
	return e
}

// Unwrap gets error wrapped in the internal error
func (e *Error) Unwrap() error {
	return e.err
}

func newInternalError(code string, err error) *Error {
	return &Error{Code: code, err: err}
}
