package envoyextproc

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/config"
	"github.com/open-policy-agent/opa/v1/logging"
	loggingtest "github.com/open-policy-agent/opa/v1/logging/test"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	iCache "github.com/open-policy-agent/opa/v1/topdown/cache"
	"github.com/open-policy-agent/opa/v1/tracing"
)

type evalTestCase struct {
	name        string
	input       map[string]any
	expected    map[string]any
	expectError bool
}

var testCases = []evalTestCase{
	{
		name: "Immediate Response - Forbidden",
		input: map[string]any{
			"path": "/forbidden",
		},
		expected: map[string]any{
			"immediate_response": map[string]any{
				"status": json.Number("403"),
				"body":   "Access Denied",
				"headers": []any{
					map[string]any{"key": "Content-Type", "value": "text/plain"},
					map[string]any{"key": "X-Immediate-Response", "value": "True"},
				},
				"grpc_status": json.Number("7"),
				"details":     "Unauthorized access attempt",
			},
		},
	},
	{
		name: "Add Headers",
		input: map[string]any{
			"path": "/add-headers",
		},
		expected: map[string]any{
			"headers_to_add": []any{
				map[string]any{
					"key":                  "X-Added-Header",
					"value":                "HeaderValue",
					"header_append_action": "OVERWRITE_IF_EXISTS_OR_ADD",
				},
			},
		},
	},
	{
		name: "Remove Headers",
		input: map[string]any{
			"path": "/remove-headers",
		},
		expected: map[string]any{
			"headers_to_remove": []any{
				"X-Remove-Header",
				"X-Another-Header",
			},
		},
	},
	{
		name: "Replace Body",
		input: map[string]any{
			"path":         "/replace-body",
			"request_type": "request_body",
		},
		expected: map[string]any{
			"body": "This is the new body content",
		},
	},
	{
		name: "Dynamic Metadata",
		input: map[string]any{
			"path": "/dynamic-metadata",
			"headers": map[string]any{
				"x-user-id":    "12345",
				"x-session-id": "abcde-12345",
			},
		},
		expected: map[string]any{
			"dynamic_metadata": map[string]any{
				"my_extension": map[string]any{
					"user_id":    "12345",
					"session_id": "abcde-12345",
				},
			},
		},
	},
	{
		name: "Combined Headers and Body",
		input: map[string]any{
			"path": "/combined",
		},
		expected: map[string]any{
			"headers_to_add": []any{
				map[string]any{
					"key":   "X-Combined-Header",
					"value": "CombinedValue",
				},
			},
			"body": "Combined response with headers and body changes",
		},
	},
	{
		name: "Modify Trailers",
		input: map[string]any{
			"path":         "/modify-trailers",
			"request_type": "request_trailers",
		},
		expected: map[string]any{
			"trailers_to_add": []any{
				map[string]any{
					"key":   "X-Trailer-Added",
					"value": "TrailerValue",
				},
			},
		},
	},
	{
		name: "Modify Response Headers",
		input: map[string]any{
			"path":         "/modify-response-headers",
			"request_type": "response_headers",
		},
		expected: map[string]any{
			"headers_to_add": []any{
				map[string]any{
					"key":   "X-Response-Header",
					"value": "ResponseHeaderValue",
				},
			},
		},
	},
	{
		name: "Default Deny",
		input: map[string]any{
			"path": "/unknown-path",
		},
		expected: map[string]any{
			"immediate_response": map[string]any{
				"status": json.Number("403"),
				"body":   "Default Deny",
				"headers": []any{
					map[string]any{"key": "Content-Type", "value": "text/plain"},
					map[string]any{"key": "X-Default-Deny", "value": "True"},
				},
			},
		},
	},
}

func TestEval(t *testing.T) {
	ctx := context.Background()

	logger := loggingtest.New()
	server, err := testExtProcServer(logger)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inputValue := ast.MustInterfaceToValue(tc.input)

			res, stop, err := NewEvalResult()
			if err != nil {
				t.Fatal(err)
			}
			defer stop()

			err = Eval(ctx, server, inputValue, res)
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Eval failed: %v", err)
			}

			// Compare the decision with the expected result
			decisionMap, ok := res.Decision.(map[string]any)
			if !ok {
				t.Fatalf("Decision is not a map")
			}

			if !reflect.DeepEqual(decisionMap, tc.expected) {
				t.Errorf("Test case '%s' failed. Expected decision %v but got %v", tc.name, tc.expected, decisionMap)
			}
		})
	}
}

func testExtProcServer(logger logging.Logger) (*mockExtProcServer, error) {
	module := `
		package ext_proc

		# Default response is an empty object
		default response = {}

		# Immediate response with custom status code, body, and headers
		response = {
			"immediate_response": {
				"status": 403,
				"body": "Access Denied",
				"headers": [
					{"key": "Content-Type", "value": "text/plain"},
					{"key": "X-Immediate-Response", "value": "True"}
				],
				"grpc_status": 7,  # PERMISSION_DENIED
				"details": "Unauthorized access attempt"
			}
		} if {
			input.path == "/forbidden"
		}

		# Add headers to the request or response
		response = {
			"headers_to_add": [
				{
					"key": "X-Added-Header",
					"value": "HeaderValue",
					"header_append_action": "OVERWRITE_IF_EXISTS_OR_ADD"
				}
			]
		} if {
			input.path == "/add-headers"
		}

		# Remove headers from the request or response
		response = {
			"headers_to_remove": [
				"X-Remove-Header",
				"X-Another-Header"
			]
		} if {
			input.path == "/remove-headers"
		}

		# Replace the body of the request or response
		response = {
			"body": "This is the new body content"
		} if {
			input.request_type == "request_body"
			input.path == "/replace-body"
		}

		# Provide dynamic metadata
		response = {
			"dynamic_metadata": {
				"my_extension": {
					"user_id": input.headers["x-user-id"],
					"session_id": input.headers["x-session-id"]
				}
			}
		} if {
			input.path == "/dynamic-metadata"
		}

		# Combine header mutation and body replacement
		response = {
			"headers_to_add": [
				{
					"key": "X-Combined-Header",
					"value": "CombinedValue"
				}
			],
			"body": "Combined response with headers and body changes"
		} if {
			input.path == "/combined"
		}

		# Handle request trailers
		response = {
			"trailers_to_add": [
				{
					"key": "X-Trailer-Added",
					"value": "TrailerValue"
				}
			]
		} if {
			input.request_type == "request_trailers"
			input.path == "/modify-trailers"
		}

		# Handle response headers
		response = {
			"headers_to_add": [
				{
					"key": "X-Response-Header",
					"value": "ResponseHeaderValue"
				}
			]
		} if {
			input.request_type == "response_headers"
			input.path == "/modify-response-headers"
		}

		# Deny all other requests by default with an immediate response
		response = {
			"immediate_response": {
				"status": 403,
				"body": "Default Deny",
				"headers": [
					{"key": "Content-Type", "value": "text/plain"},
					{"key": "X-Default-Deny", "value": "True"}
				]
			}
		} if {
			not allowed_paths[input.path]
		}

		allowed_paths = {
			"/forbidden",
			"/add-headers",
			"/remove-headers",
			"/replace-body",
			"/dynamic-metadata",
			"/combined",
			"/modify-trailers",
			"/modify-response-headers"
		}
	`

	ctx := context.Background()
	store := inmem.New()
	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)

	err := store.UpsertPolicy(ctx, txn, "example.rego", []byte(module))
	if err != nil {
		return nil, err
	}

	err = store.Commit(ctx, txn)
	if err != nil {
		return nil, err
	}

	m, err := plugins.New([]byte{}, "test", store,
		plugins.EnablePrintStatements(true),
		plugins.Logger(logger),
	)
	if err != nil {
		return nil, err
	}

	// Start the plugins manager
	if err := m.Start(ctx); err != nil {
		return nil, err
	}

	path := "ext_proc/response"
	query := "data." + strings.ReplaceAll(path, "/", ".")
	parsedQuery, err := ast.ParseBody(query)
	if err != nil {
		return nil, err
	}

	cfg := Config{
		Addr:        ":0",
		Path:        path,
		parsedQuery: parsedQuery,
	}

	return &mockExtProcServer{
		cfg:                 cfg,
		manager:             m,
		preparedQueryDoOnce: new(sync.Once),
	}, nil
}

type Config struct {
	Addr        string `json:"addr"`
	Path        string `json:"path"`
	parsedQuery ast.Body
}

type mockExtProcServer struct {
	cfg                    Config
	manager                *plugins.Manager
	preparedQuery          *rego.PreparedEvalQuery
	preparedQueryDoOnce    *sync.Once
	preparedQueryErr       error
	distributedTracingOpts tracing.Options
}

func (m *mockExtProcServer) ParsedQuery() ast.Body {
	return m.cfg.parsedQuery
}

func (m *mockExtProcServer) Store() storage.Store {
	return m.manager.Store
}

func (m *mockExtProcServer) Compiler() *ast.Compiler {
	return m.manager.GetCompiler()
}

func (m *mockExtProcServer) Runtime() *ast.Term {
	return m.manager.Info
}

func (m *mockExtProcServer) Config() *config.Config {
	return m.manager.Config
}

func (*mockExtProcServer) InterQueryBuiltinCache() iCache.InterQueryCache {
	return nil
}

func (m *mockExtProcServer) Logger() logging.Logger {
	return m.manager.Logger()
}

func (m *mockExtProcServer) DistributedTracing() tracing.Options {
	return m.distributedTracingOpts
}

func (m *mockExtProcServer) CreatePreparedQueryOnce(opts PrepareQueryOpts) (*rego.PreparedEvalQuery, error) {
	m.preparedQueryDoOnce.Do(func() {
		pq, err := rego.New(opts.Opts...).PrepareForEval(context.Background())

		m.preparedQuery = &pq
		m.preparedQueryErr = err
	})

	return m.preparedQuery, m.preparedQueryErr
}
