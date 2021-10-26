package envoyauth

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	ext_authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	internal_util "github.com/open-policy-agent/opa-envoy-plugin/internal/util"
	"github.com/open-policy-agent/opa/util"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/reflect/protoregistry"
)

func createCheckRequest(policy string) *ext_authz.CheckRequest {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(policy), &req); err != nil {
		panic(err)
	}
	return &req
}

func createExtReqWithPath(path string) *ext_authz.CheckRequest {
	requestString := fmt.Sprintf(`{
	  "attributes": {
		"request": {
		  "http": {
			"path": "%s"
		  }
		}
	  }
	}`, path)

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(requestString), &req); err != nil {
		panic(err)
	}

	return &req
}

func TestGetParsedBody(t *testing.T) {

	requestNoContentType := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-length": "0"
			  }
			}
		  }
		}
	  }`

	requestContentTypeText := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "text/html"
			  }
			}
		  }
		}
	  }`

	requestContentTypeJSONString := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "application/json"
			  },
			  "body": "\"foo\""
			}
		  }
		}
	  }`

	requestContentTypeJSONBoolean := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "application/json"
			  },
			  "body": "true"
			}
		  }
		}
	  }`

	requestContentTypeJSONNumber := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "application/json"
			  },
			  "body": "42"
			}
		  }
		}
	  }`

	requestContentTypeJSONNull := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "application/json"
			  },
			  "body": "null"
			}
		  }
		}
	  }`

	requestContentTypeJSONObject := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "application/json"
			  },
			  "body": "{\"firstname\": \"foo\", \"lastname\": \"bar\"}"
			}
		  }
		}
	  }`

	requestContentTypeJSONArray := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "application/json"
			  },
			  "body": "[\"hello\", \"opa\"]"
			}
		  }
		}
	  }`

	requestContentTypeMultipartFormData := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "multipart/form-data; boundary=foo"
			  },
			  "body": "--foo\nContent-Disposition: form-data; name=\"foo\"\nContent-Type: text/plain\n\nbar\n--foo--
				"
			}
		  }
		}
	  }`

	requestContentTypeMultipartFormDataWithJSON := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "multipart/form-data; boundary=foo"
			  },
			  "body": "--foo\nContent-Disposition: form-data; name=\"foo\"\nContent-Type: text/plain\n\nbar\n--foo\nContent-Disposition: form-data; name=\"bar\"\nContent-Type: application/json;\n\n{\"name\": \"bar\"}\n--foo--
				"
			}
		  }
		}
	  }`

	requestEmptyContent := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "application/json"
			  },
			  "body": ""
			}
		  }
		}
	  }`

	requestBodyTruncated := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "application/json",
				"content-length": "1000"
			  },
			  "body": "true"
			}
		  }
		}
	  }`

	requestBodyWithJSONSpecialChars := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "application/json"
			  },
			  "body": "[\"\\\"\", \"\\\\\", \"\\/\", \"/\", \"\\b\", \"\\f\", \"\\n\", \"\\r\", \"\\t\", \"\\u0041\"]"
			}
		  }
		}
	  }`

	requestContentTypeURLEncoded := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "application/x-www-form-urlencoded"
			  },
			  "body": "firstname=foo&lastname=bar"
			}
		  }
		}
	  }`

	requestContentTypeURLEncodedMultipleKeys := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "application/x-www-form-urlencoded"
			  },
			  "body": "firstname=foo&lastname=bar&lastname=foobar"
			}
		  }
		}
	  }`

	requestContentTypeURLEncodedTruncated := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "application/x-www-form-urlencoded",
				"content-length": "1000"
			  },
			  "body": "firstname=foo&lastname=bar"
			}
		  }
		}
	  }`

	requestContentTypeURLEncodedEmpty := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "application/x-www-form-urlencoded"
			  },
			  "body": ""
			}
		  }
		}
	  }`
	expectedNumber := json.Number("42")
	expectedObject := map[string]interface{}{
		"firstname": "foo",
		"lastname":  "bar",
	}
	expectedURLEncodedObject := map[string][]string{
		"firstname": {"foo"},
		"lastname":  {"bar"},
	}
	expectedURLEncodedObjectMultipleValues := map[string][]string{
		"firstname": {"foo"},
		"lastname":  {"bar", "foobar"},
	}
	expectedArray := []interface{}{"hello", "opa"}
	expectedJSONSpecialChars := []interface{}{`"`, `\`, "/", "/", "\b", "\f", "\n", "\r", "\t", "A"}
	expectedMultipartFormData := map[string][]interface{}{
		"foo": {"bar"},
	}
	expectedMultipartFormDataWithJSON := map[string][]interface{}{
		"foo": {"bar"},
		"bar": {
			map[string]interface{}{"name": "bar"},
		},
	}

	tests := map[string]struct {
		input           *ext_authz.CheckRequest
		want            interface{}
		isBodyTruncated bool
		err             error
	}{
		"no_content_type":                            {input: createCheckRequest(requestNoContentType), want: nil, isBodyTruncated: false, err: nil},
		"content_type_text":                          {input: createCheckRequest(requestContentTypeText), want: nil, isBodyTruncated: false, err: nil},
		"content_type_json_string":                   {input: createCheckRequest(requestContentTypeJSONString), want: "foo", isBodyTruncated: false, err: nil},
		"content_type_json_boolean":                  {input: createCheckRequest(requestContentTypeJSONBoolean), want: true, isBodyTruncated: false, err: nil},
		"content_type_json_number":                   {input: createCheckRequest(requestContentTypeJSONNumber), want: expectedNumber, isBodyTruncated: false, err: nil},
		"content_type_json_null":                     {input: createCheckRequest(requestContentTypeJSONNull), want: nil, isBodyTruncated: false, err: nil},
		"content_type_json_object":                   {input: createCheckRequest(requestContentTypeJSONObject), want: expectedObject, isBodyTruncated: false, err: nil},
		"content_type_json_array":                    {input: createCheckRequest(requestContentTypeJSONArray), want: expectedArray, isBodyTruncated: false, err: nil},
		"content_type_json_with_special_chars":       {input: createCheckRequest(requestBodyWithJSONSpecialChars), want: expectedJSONSpecialChars, isBodyTruncated: false, err: nil},
		"content_type_multipart_form_data":           {input: createCheckRequest(requestContentTypeMultipartFormData), want: expectedMultipartFormData, isBodyTruncated: false, err: nil},
		"content_type_multipart_form_data_with_json": {input: createCheckRequest(requestContentTypeMultipartFormDataWithJSON), want: expectedMultipartFormDataWithJSON, isBodyTruncated: false, err: nil},
		"empty_content":                              {input: createCheckRequest(requestEmptyContent), want: nil, isBodyTruncated: false, err: nil},
		"body_truncated":                             {input: createCheckRequest(requestBodyTruncated), want: nil, isBodyTruncated: true, err: nil},
		"content_type_url_encoded":                   {input: createCheckRequest(requestContentTypeURLEncoded), want: expectedURLEncodedObject, isBodyTruncated: false, err: nil},
		"content_type_url_encoded_empty":             {input: createCheckRequest(requestContentTypeURLEncodedEmpty), want: nil, isBodyTruncated: false, err: nil},
		"content_type_url_encoded_multiple_values":   {input: createCheckRequest(requestContentTypeURLEncodedMultipleKeys), want: expectedURLEncodedObjectMultipleValues, isBodyTruncated: false, err: nil},
		"content_type_url_encoded_truncated":         {input: createCheckRequest(requestContentTypeURLEncodedTruncated), want: nil, isBodyTruncated: true, err: nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			logEntry := logrus.WithField("test", name)
			headers := tc.input.GetAttributes().GetRequest().GetHttp().GetHeaders()
			body := tc.input.GetAttributes().GetRequest().GetHttp().GetBody()
			path := tc.input.GetAttributes().GetRequest().GetHttp().GetPath()
			parsedPath, _, _ := getParsedPathAndQuery(path)
			got, isBodyTruncated, err := getParsedBody(logEntry, headers, body, nil, parsedPath, nil)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expected result: %v, got: %v", tc.want, got)
			}

			if isBodyTruncated != tc.isBodyTruncated {
				t.Fatalf("expected isBodyTruncated: %v, got: %v", tc.isBodyTruncated, got)
			}

			if err != tc.err {
				t.Fatalf("expected error: %v, got: %v", tc.err, err)
			}
		})
	}

	requestContentTypeJSONInvalid := `{
		"attributes": {
		  "request": {
			"http": {
			  "headers": {
				"content-type": "application/json"
			  },
			  "body": "[\"foo\" : 42}"
			}
		  }
		}
	  }`

	logEntry := logrus.WithField("test", "invalid json")
	req := createCheckRequest(requestContentTypeJSONInvalid)
	path := []interface{}{}
	protoSet := (*protoregistry.Files)(nil)
	headers, body := req.GetAttributes().GetRequest().GetHttp().GetHeaders(), req.GetAttributes().GetRequest().GetHttp().GetBody()
	_, _, err := getParsedBody(logEntry, headers, body, nil, path, protoSet)
	if err == nil {
		t.Fatal("Expected error but got nil")
	}
}

func TestGetParsedBodygRPC(t *testing.T) {

	requestValidExample := `{
  "attributes": {
    "request": {
      "http": {
        "headers": {
          "content-type": "application/grpc"
        },
        "method": "POST",
        "path": "/Example.Test.GRPC.ProtoServiceIExampleApplication/RegisterExample",
        "protocol": "HTTP/2",
        "raw_body": "AAAAADYKFgoHCgVFUlJPUhILCglTZWNOdW1iZXISHAoMCgpCb2R5IHZhbHVlEgwKCk5hbWUgVmFsdWU="
      }
    },
    "parsed_path": [
      "Example.Test.GRPC.ProtoServiceIExampleApplication",
      "RegisterExample"
    ]
  }
}
`

	requestValidBook := `{
  "attributes": {
    "request": {
      "http": {
        "headers": {
          "content-type": "application/grpc"
        },
        "method": "POST",
        "path": "/com.book.BookService/GetBooksViaAuthor",
        "protocol": "HTTP/2",
        "raw_body": "AAAAAAYKBEpvaG4="
      }
    }
  }
}
`

	requestInvalidRawBodyExample := `{
  "attributes": {
    "request": {
      "http": {
        "headers": {
          "content-type": "application/grpc"
        },
        "method": "POST",
        "path": "/Example.Test.GRPC.ProtoServiceIExampleApplication/RegisterExample",
        "protocol": "HTTP/2"
      }
    },
    "parsed_path": [
      "Example.Test.GRPC.ProtoServiceIExampleApplication",
      "RegisterExample"
    ]
  }
}
`

	requestInvalidParsedPathExample := `{
  "attributes": {
    "request": {
      "http": {
        "headers": {
          "content-type": "application/grpc"
        },
        "method": "POST",
        "protocol": "HTTP/2",
        "raw_body": "AAAAAC0KDQoHCgVFUlJPUhICCAESHAoMCgpCb2R5IHZhbHVlEgwKCk5hbWUgVmFsdWU="
      }
    }
  }
}
`

	requestUnknownService := `{
  "attributes": {
    "request": {
      "http": {
        "headers": {
          "content-type": "application/grpc"
        },
        "method": "POST",
        "path": "/com.book.SecondBookService/GetBooksViaAuthor",
        "protocol": "HTTP/2",
        "raw_body": "AAAAAAYKBEpvaG4="
      }
    }
  }
}
`

	requestUnknownMethod := `{
  "attributes": {
    "request": {
      "http": {
        "headers": {
          "content-type": "application/grpc"
        },
        "method": "POST",
        "path": "/com.book.BookService/GetBooksViaSecondAuthor",
        "protocol": "HTTP/2",
        "raw_body": "AAAAAAYKBEpvaG4="
      }
    }
  }
}
`
	requestEmpty := `{
  "attributes": {
    "request": {
      "http": {
        "headers": {
          "content-type": "application/grpc"
        },
        "method": "POST",
        "path": "/com.book.BookService/GetBooksViaAuthor",
        "protocol": "HTTP/2",
        "raw_body": "AAAAAAA="
      }
    }
  }
}
`
	requestCompressedPayload := `{
  "attributes": {
    "request": {
      "http": {
        "headers": {
          "content-type": "application/grpc"
        },
        "method": "POST",
        "path": "/com.book.BookService/GetBooksViaAuthor",
        "protocol": "HTTP/2",
        "raw_body": "AQAAADwfiwgAAAAAAAD/4hLkaOi4t49RoOHi+ll//////59RSJCj4dGiE4wCDau/LIYIAQIAAP//aJ9RpSYAAAA="
      }
    }
  }
}
`

	requestTruncatedPayload := `{
  "attributes": {
    "request": {
      "http": {
        "headers": {
          "content-type": "application/grpc"
        },
        "method": "POST",
        "path": "/com.book.BookService/GetBooksViaAuthor",
        "protocol": "HTTP/2",
        "raw_body": "AAAAABEImqaMww=="
      }
    }
  }
}
`

	expectedObject := map[string]interface{}{
		"Data": map[string]interface{}{
			"Body": "Body value",
			"Name": "Name Value",
		},
		"Metadata": map[string]interface{}{
			"SeverityNumber": "SecNumber",
			"SeverityText":   "ERROR",
		},
	}
	expectedObjectExampleBook := map[string]interface{}{"author": "John"}
	protoDescriptorPath := "../test/files/combined.pb"
	protoSet, err := internal_util.ReadProtoSet(protoDescriptorPath)
	if err != nil {
		t.Fatalf("read protoset: %v", err)
	}

	tests := map[string]struct {
		input           *ext_authz.CheckRequest
		want            interface{}
		isBodyTruncated bool
		err             error
	}{
		"parsed_path_error":    {input: createCheckRequest(requestInvalidParsedPathExample), want: nil, isBodyTruncated: false, err: fmt.Errorf("invalid parsed path")},
		"without_raw_body":     {input: createCheckRequest(requestInvalidRawBodyExample), want: nil, isBodyTruncated: false, err: nil},
		"valid_parsed_example": {input: createCheckRequest(requestValidExample), want: expectedObject, isBodyTruncated: false, err: nil},
		"valid_parsed_book":    {input: createCheckRequest(requestValidBook), want: expectedObjectExampleBook, isBodyTruncated: false, err: nil},
		"unknown_service":      {input: createCheckRequest(requestUnknownService), want: nil, isBodyTruncated: false, err: nil},
		"unknown_method":       {input: createCheckRequest(requestUnknownMethod), want: nil, isBodyTruncated: false, err: nil},
		"empty_request":        {input: createCheckRequest(requestEmpty), want: map[string]interface{}{}, isBodyTruncated: false, err: nil},
		"compressed_payload":   {input: createCheckRequest(requestCompressedPayload), want: nil, isBodyTruncated: false, err: nil},
		"truncated_payload":    {input: createCheckRequest(requestTruncatedPayload), want: nil, isBodyTruncated: true, err: nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			logEntry := logrus.WithField("test", name)

			headers := tc.input.GetAttributes().GetRequest().GetHttp().GetHeaders()
			body := tc.input.GetAttributes().GetRequest().GetHttp().GetBody()
			rawBody := tc.input.GetAttributes().GetRequest().GetHttp().GetRawBody()
			path := tc.input.GetAttributes().GetRequest().GetHttp().GetPath()

			parsedPath, _, _ := getParsedPathAndQuery(path)
			got, isBodyTruncated, err := getParsedBody(logEntry, headers, body, rawBody, parsedPath, protoSet)

			if !reflect.DeepEqual(err, tc.err) {
				t.Fatalf("expected error: %v, got: %v", tc.err, err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expected result: %v, got: %v", tc.want, got)
			}

			if isBodyTruncated != tc.isBodyTruncated {
				t.Fatalf("expected isBodyTruncated: %v, got: %v", tc.isBodyTruncated, got)
			}

		})
	}
}

func TestParsedPathAndQuery(t *testing.T) {
	var tests = []struct {
		request       *ext_authz.CheckRequest
		expectedPath  []interface{}
		expectedQuery map[string]interface{}
	}{
		{
			createExtReqWithPath("/my/test/path"),
			[]interface{}{"my", "test", "path"},
			map[string]interface{}{},
		},
		{
			createExtReqWithPath("/my/test/path?a=1"),
			[]interface{}{"my", "test", "path"},
			map[string]interface{}{"a": []interface{}{"1"}},
		},
		{
			createExtReqWithPath("/my/test/path?a=1&a=2"),
			[]interface{}{"my", "test", "path"},
			map[string]interface{}{"a": []interface{}{"1", "2"}},
		},
		{
			createExtReqWithPath("/my/test/path?a=1&b=2"),
			[]interface{}{"my", "test", "path"},
			map[string]interface{}{"a": []interface{}{"1"}, "b": []interface{}{"2"}},
		},
		{
			createExtReqWithPath("/my/test/path?a=1&a=new%0aline"),
			[]interface{}{"my", "test", "path"},
			map[string]interface{}{"a": []interface{}{"1", "new\nline"}},
		},
		{
			createExtReqWithPath("%2Fmy%2Ftest%2Fpath?a=1&a=new%0aline"),
			[]interface{}{"my", "test", "path"},
			map[string]interface{}{"a": []interface{}{"1", "new\nline"}},
		},
	}

	for _, tt := range tests {
		path := tt.request.GetAttributes().GetRequest().GetHttp().GetPath()
		actualPath, actualQuery, _ := getParsedPathAndQuery(path)
		if !reflect.DeepEqual(actualPath, tt.expectedPath) {
			t.Errorf("parsed_path (%s): expected %s, actual %s", tt.request, tt.expectedPath, actualPath)
		}
		if !reflect.DeepEqual(actualQuery, tt.expectedQuery) {
			t.Errorf("parsed_query (%s): expected %s, actual %s", tt.request, tt.expectedQuery, actualQuery)
		}
	}
}
