package envoyauth

import (
	"testing"

	ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/protobuf/encoding/protojson"
)

const extAuthzRequest = `{
  "attributes": {
    "source": {
      "address": {
        "socketAddress": {
          "address": "127.0.0.1"
        }
      },
      "service": "dummy",
      "labels": {
        "foo": "bar"
      }
    },
    "metadataContext": {
      "filterMetadata": {
        "dummy": {
          "hello": "world",
          "count": 1
        }
      }
    },
    "contextExtensions": {
      "hello": "world"
    },
    "request": {
      "http": {
        "id": "13359530607844510314",
        "method": "GET",
        "headers": {
          ":authority": "192.168.99.100:31380",
          ":method": "GET",
          ":path": "/api/v1/products",
          "accept": "*/*"
        },
        "path": "/api/v1/products",
        "host": "192.168.99.100:31380",
        "protocol": "HTTP/1.1",
        "body": "{\"firstname\": \"foo\", \"lastname\": \"bar\"}"
      }
    }
  }
}`

func Test_protomap(t *testing.T) {
	var req ext_authz_v3.CheckRequest

	if err := protojson.Unmarshal([]byte(extAuthzRequest), &req); err != nil {
		t.Fatal(err)
	}

	result := protomap(req.ProtoReflect())

	if result == nil {
		t.Fatal("not nil expected")
	}

	assertMap(t, result, map[string]any{
		"attributes": map[string]any{
			"source": map[string]any{
				"service": "dummy",
				"labels": map[string]any{
					"foo": "bar",
				},
				"address": map[string]any{
					"socketAddress": map[string]any{
						"address": "127.0.0.1",
					},
				},
			},
			"metadataContext": map[string]any{
				"filterMetadata": map[string]any{
					"dummy": map[string]any{
						"hello": "world",
						"count": float64(1),
					},
				},
			},
			"contextExtensions": map[string]any{
				"hello": "world",
			},
			"request": map[string]any{
				"http": map[string]any{
					"id":       "13359530607844510314",
					"method":   "GET",
					"path":     "/api/v1/products",
					"host":     "192.168.99.100:31380",
					"protocol": "HTTP/1.1",
					"body":     "{\"firstname\": \"foo\", \"lastname\": \"bar\"}",
					"headers": map[string]any{
						":authority": "192.168.99.100:31380",
						":method":    "GET",
						":path":      "/api/v1/products",
						"accept":     "*/*",
					},
				},
			},
		},
	})
}

func assertMap(t *testing.T, actual map[string]any, expected map[string]any) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("different len of maps, actual %v, expected %v", actual, expected)
	}
	for k, ev := range expected {
		av, ok := actual[k]
		if !ok {
			t.Fatalf("expected key %s not found", k)
		}
		if em, ok := ev.(map[string]any); ok {
			am, ok := av.(map[string]any)
			if !ok {
				t.Fatalf("both values must be map[string]any, actual %T", av)
			}
			assertMap(t, em, am)
		} else if ev != av {
			t.Fatalf("values of key %s are different, actual %v (%[2]T), expected %v (%[3]T)", k, av, ev)
		}
	}
}
