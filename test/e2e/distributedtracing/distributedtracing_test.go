package distributedtracing

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	ext_authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa-envoy-plugin/test/e2e"
	"github.com/open-policy-agent/opa/logging/test"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/tracing"
	"github.com/open-policy-agent/opa/util"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var spanExporter *tracetest.InMemoryExporter
var consoleLogger *test.Logger

const exampleRequest = `{
	"attributes": {
	  "request": {
		"http": {
		  "id": "13359530607844510314",
		  "method": "GET",
		  "headers": {
			":authority": "192.168.99.100:31380",
			":method": "GET",
			":path": "/api/v1/products",
			"accept": "*/*",
			"authorization": "Basic Ym9iOnBhc3N3b3Jk",
			"content-length": "0",
			"user-agent": "curl/7.54.0",
		  },
		  "path": "/api/v1/products",
		  "host": "192.168.99.100:31380",
		  "protocol": "HTTP/1.1",
		  "body": "{\"firstname\": \"foo\", \"lastname\": \"bar\"}"
		}
	  }
	}
  }`

type factory struct{}

func (*factory) NewTransport(tr http.RoundTripper, opts tracing.Options) http.RoundTripper {
	return otelhttp.NewTransport(tr, convertOpts(opts)...)
}

func (*factory) NewHandler(f http.Handler, label string, opts tracing.Options) http.Handler {
	return otelhttp.NewHandler(f, label, convertOpts(opts)...)
}

func convertOpts(opts tracing.Options) []otelhttp.Option {
	otelOpts := make([]otelhttp.Option, 0, len(opts))
	for _, opt := range opts {
		otelOpts = append(otelOpts, opt.(otelhttp.Option))
	}
	return otelOpts
}
func TestMain(m *testing.M) {
	tracing.RegisterHTTPTracing(&factory{})
	spanExporter = tracetest.NewInMemoryExporter()
	tracerProvider := trace.NewTracerProvider(trace.WithSpanProcessor(trace.NewSimpleSpanProcessor(spanExporter)))
	consoleLogger = test.New()

	count := 0
	countMutex := sync.Mutex{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		countMutex.Lock()
		count = count + 1
		countMutex.Unlock()
		fmt.Fprintf(w, `{"count": %d}`, count)
	}))
	defer ts.Close()
	moduleFmt := `
	package envoy.authz
	default allow = false
	allow {
		resp := http.send({"url": "%s", "method":"GET"})
		resp.body.count == 1
	}`
	module := fmt.Sprintf(moduleFmt, ts.URL)
	pluginsManager, err := e2e.TestAuthzServerWithWithOpts(module, "envoy/authz/allow", ":9191", plugins.WithTracerProvider(tracerProvider), plugins.ConsoleLogger(consoleLogger))
	if err != nil {
		log.Fatal(err)
	}
	if pluginsManager.TracerProvider() != tracerProvider {
		log.Fatal("unacepted tracer provider")
	}
	os.Exit(m.Run())
}

func TestServerSpanAndTraceIdInDecisionLog(t *testing.T) {
	spanExporter.Reset()

	t.Run("envoy.service.auth.v3.Authorization Check", func(t *testing.T) {
		var req ext_authz.CheckRequest
		if err := util.Unmarshal([]byte(exampleRequest), &req); err != nil {
			t.Fatal(err)
		}
		conn, err := grpc.Dial("localhost:9191", grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatalf("did not connect: %v", err)
		}
		client := ext_authz.NewAuthorizationClient(conn)
		resp, err := client.Check(context.Background(), &req)
		if err != nil {
			t.Fatalf("error when send request %v", err)
		}
		if resp.Status.Code != int32(code.Code_OK) {
			t.Fatal("Expected request to be allowed but got:", resp)
		}
		spans := spanExporter.GetSpans()
		if got, expected := len(spans), 2; got != expected {
			t.Fatalf("got %d span(s), expected %d", got, expected)
		}
		if !spans[0].SpanContext.IsValid() {
			t.Fatalf("invalid span created: %#v", spans[0].SpanContext)
		}
		if !spans[1].SpanContext.IsValid() {
			t.Fatalf("invalid span created: %#v", spans[1].SpanContext)
		}
		if got, expected := spans[1].SpanKind.String(), "server"; got != expected {
			t.Fatalf("Expected span kind to be %q but got %q", expected, got)
		}
		if got, expected := spans[1].Name, "envoy.service.auth.v3.Authorization/Check"; got != expected {
			t.Fatalf("Expected span name to be %q but got %q", expected, got)
		}
		if got, expected := spans[0].SpanKind.String(), "client"; got != expected {
			t.Fatalf("Expected span kind to be %q but got %q", expected, got)
		}
		if got, expected := spans[0].Name, "HTTP GET"; got != expected {
			t.Fatalf("Expected span name to be %q but got %q", expected, got)
		}
		parentSpanID := spans[1].SpanContext.SpanID()
		if got, expected := spans[0].Parent.SpanID(), parentSpanID; got != expected {
			t.Errorf("expected span to be child of %v, got parent %v", expected, got)
		}

		var entry test.LogEntry
		var found bool

		for _, entry = range consoleLogger.Entries() {
			t.Log(entry.Message)
			if entry.Message == "Decision Log" {
				found = true
			}
		}

		if !found {
			t.Fatalf("Did not find 'Decision Log' event in captured log entries")
		}
		// Check for some important fields
		expectedFields := map[string]*struct {
			found bool
			match func(*testing.T, string)
		}{
			"labels":      {},
			"decision_id": {},
			"trace_id":    {},
			"span_id":     {},
			"result":      {},
			"timestamp":   {},
			"type": {match: func(t *testing.T, actual string) {
				if actual != "openpolicyagent.org/decision_logs" {
					t.Fatalf("Expected field 'type' to be 'openpolicyagent.org/decision_logs'")
				}
			}},
		}

		// Ensure expected fields exist
		for fieldName, rawField := range entry.Fields {
			if fd, ok := expectedFields[fieldName]; ok {
				if fieldValue, ok := rawField.(string); ok && fd.match != nil {
					fd.match(t, fieldValue)
				}
				fd.found = true
			}
		}

		for field, fd := range expectedFields {
			if !fd.found {
				t.Errorf("Missing expected field in decision log: %s\n\nEntry: %+v\n\n", field, entry)
			}
		}
	})
}
