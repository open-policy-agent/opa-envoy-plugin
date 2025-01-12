package envoyauth

import (
	"encoding/binary"
	"fmt"
	"github.com/open-policy-agent/opa/ast"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strconv"
	"strings"

	ext_authz_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/util"
)

var v2Info = map[string]string{"ext_authz": "v2", "encoding": "encoding/json"}
var v3Info = map[string]string{"ext_authz": "v3", "encoding": "protojson"}

// RequestToAstValue - Converts a request to AST representation
func RequestToAstValue(req interface{}, logger logging.Logger, protoSet *protoregistry.Files, skipRequestBodyParse bool) (ast.Value, error) {
	var (
		headers         map[string]string
		body            string
		rawBody         []byte
		method          string
		path            string
		version         map[string]string
		parsedPath      []interface{}
		parsedQuery     map[string]interface{}
		parsedBody      interface{}
		isBodyTruncated bool
		err             error
	)

	// Extract fields based on request type
	switch r := req.(type) {
	case *ext_authz_v3.CheckRequest:
		headers = r.GetAttributes().GetRequest().GetHttp().GetHeaders()
		body = r.GetAttributes().GetRequest().GetHttp().GetBody()
		rawBody = r.GetAttributes().GetRequest().GetHttp().GetRawBody()
		method = r.GetAttributes().GetRequest().GetHttp().GetMethod()
		path = r.GetAttributes().GetRequest().GetHttp().GetPath()
		version = v3Info
	case *ext_authz_v2.CheckRequest:
		headers = r.GetAttributes().GetRequest().GetHttp().GetHeaders()
		body = r.GetAttributes().GetRequest().GetHttp().GetBody()
		method = r.GetAttributes().GetRequest().GetHttp().GetMethod()
		path = r.GetAttributes().GetRequest().GetHttp().GetPath()
		version = v2Info
	default:
		return nil, fmt.Errorf("unsupported request type")
	}

	parsedPath, parsedQuery, err = getParsedPathAndQuery(path)
	if err != nil {
		return nil, err
	}

	if !skipRequestBodyParse {
		parsedBody, isBodyTruncated, err = getParsedBody(logger, headers, body, rawBody, parsedPath, protoSet)
		if err != nil {
			return nil, err
		}
	}

	astObject := ast.NewObject()
	createRequestHTTP(astObject, headers, method, version, parsedBody, isBodyTruncated, skipRequestBodyParse)

	err = createAstParsedPath(astObject, parsedPath)
	if err != nil {
		return nil, err
	}

	err = createAstParsedQuery(astObject, parsedQuery)
	if err != nil {
		return nil, err
	}

	return astObject, nil
}

func getParsedPathAndQuery(path string) ([]interface{}, map[string]interface{}, error) {
	parsedURL, err := url.Parse(path)
	if err != nil {
		return nil, nil, err
	}

	parsedPath := strings.Split(strings.TrimLeft(parsedURL.Path, "/"), "/")
	parsedPathInterface := make([]interface{}, len(parsedPath))
	for i, v := range parsedPath {
		parsedPathInterface[i] = v
	}

	parsedQueryInterface := make(map[string]interface{})
	for paramKey, paramValues := range parsedURL.Query() {
		queryValues := make([]interface{}, len(paramValues))
		for i, v := range paramValues {
			queryValues[i] = v
		}
		parsedQueryInterface[paramKey] = queryValues
	}

	return parsedPathInterface, parsedQueryInterface, nil
}

func createAstParsedPath(astObj ast.Object, parsedPath []interface{}) error {
	astTerms := make([]*ast.Term, len(parsedPath))
	for i, segment := range parsedPath {
		term, err := ast.InterfaceToValue(segment)
		if err != nil {
			return fmt.Errorf("failed to convert parsed path to AST at index %d: %w", i, err)
		}
		astTerms[i] = ast.NewTerm(term)
	}

	astArray := ast.NewArray(astTerms...)
	astTerm := ast.NewTerm(astArray)

	astObj.Insert(ast.StringTerm("parsed_path"), astTerm)
	return nil
}

func createAstParsedQuery(astObj ast.Object, parsedQuery map[string]interface{}) error {
	kvs := make([][2]*ast.Term, 0, len(parsedQuery)*2)

	for key, value := range parsedQuery {
		termKey, err := ast.InterfaceToValue(key)
		if err != nil {
			return fmt.Errorf("failed to convert query param key to AST: %w", err)
		}

		termValue, err := ast.InterfaceToValue(value)
		if err != nil {
			return fmt.Errorf("failed to convert query param value to AST: %w", err)
		}

		kvs = append(kvs, [2]*ast.Term{ast.NewTerm(termKey), ast.NewTerm(termValue)})
	}

	astObject := ast.NewObject(kvs...)
	astTerm := ast.NewTerm(astObject)

	astObj.Insert(ast.StringTerm("parsed_query"), astTerm)

	return nil
}

func createRequestHTTP(astObj ast.Object, headers map[string]string, method string, version map[string]string, parsedBody interface{}, isBodyTruncated bool, skipBody bool) {
	httpObj := ast.NewObject()
	addAstField(httpObj, "headers", headers)
	addAstField(httpObj, "method", method)
	addAstField(httpObj, "version", version)

	if !skipBody {
		addAstField(httpObj, "parsed_body", parsedBody)
		addAstField(httpObj, "truncated_body", isBodyTruncated)
	}

	astObj.Insert(ast.StringTerm("request"), ast.NewTerm(httpObj))
}

func addAstField(astObject ast.Object, key string, value interface{}) {
	astValue, err := ast.InterfaceToValue(value)
	if err == nil {
		astObject.Insert(ast.StringTerm(key), ast.NewTerm(astValue))
	}
}

func getParsedBody(logger logging.Logger, headers map[string]string, body string, rawBody []byte, parsedPath []interface{}, protoSet *protoregistry.Files) (interface{}, bool, error) {
	var data interface{}

	if val, ok := headers["content-type"]; ok {
		if strings.Contains(val, "application/json") {

			if body == "" {
				if len(rawBody) == 0 {
					return nil, false, nil
				}
				body = string(rawBody)
			}

			if val, ok := headers["content-length"]; ok {
				truncated, err := checkIfHTTPBodyTruncated(val, int64(len(body)))
				if err != nil {
					return nil, false, err
				}
				if truncated {
					return nil, true, nil
				}
			}

			err := util.UnmarshalJSON([]byte(body), &data)
			if err != nil {
				return nil, false, err
			}
		} else if strings.Contains(val, "application/grpc") {

			if protoSet == nil {
				return nil, false, nil
			}

			// This happens when the plugin was configured to read gRPC payloads,
			// but the Envoy instance requesting an authz decision didn't have
			// pack_as_bytes set to true.
			if len(rawBody) == 0 {
				logger.Debug("no rawBody field sent")
				return nil, false, nil
			}
			// In gRPC, a call of method DoThing on service ThingService is a
			// POST to /ThingService/DoThing. If our path length is anything but
			// two, something is wrong.
			if len(parsedPath) != 2 {
				return nil, false, fmt.Errorf("invalid parsed path")
			}

			known, truncated, err := getGRPCBody(logger, rawBody, parsedPath, &data, protoSet)
			if err != nil {
				return nil, false, err
			}
			if truncated {
				return nil, true, nil
			}
			if !known {
				return nil, false, nil
			}
		} else if strings.Contains(val, "application/x-www-form-urlencoded") {
			var payload string
			switch {
			case body != "":
				payload = body
			case len(rawBody) > 0:
				payload = string(rawBody)
			default:
				return nil, false, nil
			}

			if val, ok := headers["content-length"]; ok {
				truncated, err := checkIfHTTPBodyTruncated(val, int64(len(payload)))
				if err != nil {
					return nil, false, err
				}
				if truncated {
					return nil, true, nil
				}
			}

			parsed, err := url.ParseQuery(payload)
			if err != nil {
				return nil, false, err
			}

			data = map[string][]string(parsed)
		} else if strings.Contains(val, "multipart/form-data") {
			var payload string
			switch {
			case body != "":
				payload = body
			case len(rawBody) > 0:
				payload = string(rawBody)
			default:
				return nil, false, nil
			}

			if val, ok := headers["content-length"]; ok {
				truncated, err := checkIfHTTPBodyTruncated(val, int64(len(payload)))
				if err != nil {
					return nil, false, err
				}
				if truncated {
					return nil, true, nil
				}
			}

			_, params, err := mime.ParseMediaType(headers["content-type"])
			if err != nil {
				return nil, false, err
			}

			boundary, ok := params["boundary"]
			if !ok {
				return nil, false, nil
			}

			values := map[string][]interface{}{}

			mr := multipart.NewReader(strings.NewReader(payload), boundary)
			for {
				p, err := mr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					return nil, false, err
				}

				name := p.FormName()
				if name == "" {
					continue
				}

				value, err := io.ReadAll(p)
				if err != nil {
					return nil, false, err
				}

				switch {
				case strings.Contains(p.Header.Get("Content-Type"), "application/json"):
					var jsonValue interface{}
					if err := util.UnmarshalJSON(value, &jsonValue); err != nil {
						return nil, false, err
					}
					values[name] = append(values[name], jsonValue)
				default:
					values[name] = append(values[name], string(value))
				}
			}

			data = values
		} else {
			logger.Debug("content-type: %s parsing not supported", val)
		}
	} else {
		logger.Debug("no content-type header supplied, performing no body parsing")
	}

	return data, false, nil
}

func getGRPCBody(logger logging.Logger, in []byte, parsedPath []interface{}, data interface{}, files *protoregistry.Files) (found, truncated bool, _ error) {

	// the first 5 bytes are part of gRPC framing. We need to remove them to be able to parse
	// https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md

	if len(in) < 5 {
		return false, false, fmt.Errorf("less than 5 bytes")
	}

	// Can be 0 or 1, 1 indicates that the payload is compressed.
	// The method could be looked up in the request headers, and the
	// request decompressed; but for now, let's skip it.
	if in[0] != 0 {
		logger.Debug("gRPC payload compression not supported")
		return false, false, nil
	}

	// Note: we're only reading one message, this is the first message's size
	size := binary.BigEndian.Uint32(in[1:5])
	if int(size) > len(in)-5 {
		return false, true, nil // truncated body
	}
	in = in[5 : size+5]

	// Note: we've already checked that len(path)>=2
	svc, err := findService(parsedPath[0].(string), files)
	if err != nil {
		logger.WithFields(map[string]interface{}{"err": err}).Debug("could not find service")
		return false, false, nil
	}
	msgDesc, err := findMessageInputDesc(parsedPath[1].(string), svc)
	if err != nil {
		logger.WithFields(map[string]interface{}{"err": err}).Debug("could not find message")
		return false, false, nil
	}

	msg := dynamicpb.NewMessage(msgDesc)
	if err := proto.Unmarshal(in, msg); err != nil {
		return true, false, err
	}

	jsonBody, err := protojson.Marshal(msg)
	if err != nil {
		return true, false, err
	}

	if err := util.Unmarshal([]byte(jsonBody), &data); err != nil {
		return true, false, err
	}

	return true, false, nil
}

func findService(path string, files *protoregistry.Files) (protoreflect.ServiceDescriptor, error) {
	desc, err := files.FindDescriptorByName(protoreflect.FullName(path))
	if err != nil {
		return nil, err
	}
	svcDesc, ok := desc.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("could not find service descriptor for path %q", path)
	}
	return svcDesc, nil
}

func findMessageInputDesc(name string, svc protoreflect.ServiceDescriptor) (protoreflect.MessageDescriptor, error) {
	if method := svc.Methods().ByName(protoreflect.Name(name)); method != nil {
		if method.IsStreamingClient() {
			return nil, fmt.Errorf("streaming client method %s not supported", method.Name())
		}
		return method.Input(), nil
	}
	return nil, fmt.Errorf("method %q not found", name)
}

func checkIfHTTPBodyTruncated(contentLength string, bodyLength int64) (bool, error) {
	cl, err := strconv.ParseInt(contentLength, 10, 64)
	if err != nil {
		return false, err
	}
	if cl != -1 && cl > bodyLength {
		return true, nil
	}
	return false, nil
}
