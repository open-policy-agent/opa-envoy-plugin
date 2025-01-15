package envoyextproc

import (
	"encoding/binary"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strconv"
	"strings"

	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/util"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/open-policy-agent/opa-envoy-plugin/internal/types"
)

// RequestToInput converts an incoming ext_proc request to an input map for policy evaluation.
func RequestToInput(req *ext_proc_v3.ProcessingRequest, logger logging.Logger, protoSet *protoregistry.Files, skipRequestBodyParse bool, state *types.StreamState) (map[string]interface{}, error) {
	input := make(map[string]interface{})

	switch request := req.Request.(type) {
	case *ext_proc_v3.ProcessingRequest_RequestHeaders:
		// Log the type of request
		logger.Info("Processing RequestHeaders")
		// Handle RequestHeaders
		input["request_type"] = "request_headers"
		requestHeaders := request.RequestHeaders
		headers := requestHeaders.GetHeaders()

		// Log the raw headers
		logger.Debug(fmt.Sprintf("Raw request headers: %v", headers))

		headerMap := make(map[string]string)
		for _, header := range headers.GetHeaders() {
			headerMap[header.GetKey()] = header.GetValue()
		}

		// Log the extracted headers
		logger.Debug(fmt.Sprintf("Extracted headers: %v", headerMap))

		path := headerMap[":path"]
		method := headerMap[":method"]
		scheme := headerMap[":scheme"]
		authority := headerMap[":authority"]
		input["headers"] = headerMap
		input["path"] = path
		input["method"] = method
		input["scheme"] = scheme
		input["authority"] = authority

		// Log the extracted path and method
		logger.Debug(fmt.Sprintf("Extracted path: %s, method: %s", path, method))

		// Parse path into parsed_path and parsed_query
		parsedPath, parsedQuery, err := getParsedPathAndQuery(path)
		if err != nil {
			logger.Error(fmt.Sprintf("Error parsing path and query: %v", err))
			return nil, err
		}
		input["parsed_path"] = parsedPath
		input["parsed_query"] = parsedQuery

		// Log the parsed path and query
		logger.Debug(fmt.Sprintf("Parsed path: %v", parsedPath))
		logger.Debug(fmt.Sprintf("Parsed query: %v", parsedQuery))

		state.Headers = headerMap
		state.Path = path
		state.Method = method

	case *ext_proc_v3.ProcessingRequest_RequestBody:
		// Log the type of request
		logger.Info("Processing RequestBody")
		// Handle RequestBody
		input["request_type"] = "request_body"
		requestBody := request.RequestBody
		body := requestBody.GetBody()

		// Log the raw body
		logger.Debug(fmt.Sprintf("Raw request body: %s", string(body)))

		input["path"] = state.Path

		if !skipRequestBodyParse {

			headers := state.Headers

			// Log parse the body
			logger.Info("Parsing request body")

			parsedBody, isBodyTruncated, err := getParsedBody(logger, headers, string(body), nil, nil, protoSet)
			if err != nil {
				logger.Error(fmt.Sprintf("Error parsing request body: %v", err))
				return nil, err
			}
			input["parsed_body"] = parsedBody
			input["truncated_body"] = isBodyTruncated

			// Log the parsed body
			logger.Debug(fmt.Sprintf("Parsed body: %v", parsedBody))
			logger.Debug(fmt.Sprintf("Is body truncated: %v", isBodyTruncated))
		}

	case *ext_proc_v3.ProcessingRequest_ResponseHeaders:
		// Log the type of request
		logger.Info("Processing ResponseHeaders")
		// Handle ResponseHeaders
		input["request_type"] = "response_headers"
		responseHeaders := request.ResponseHeaders
		headers := responseHeaders.GetHeaders()

		// Log the raw response headers
		logger.Debug(fmt.Sprintf("Raw response headers: %v", headers))

		headerMap := make(map[string]string)
		for _, header := range headers.GetHeaders() {
			headerMap[header.GetKey()] = header.GetValue()
		}
		input["response_headers"] = headerMap

		// Extract and set 'path' from response_headers
		if path, exists := headerMap[":path"]; exists {
			input["path"] = path
		} else {
			logger.Warn("Path not found in response_headers during ResponseHeaders processing")
		}

		// Log the extracted response headers
		logger.Debug(fmt.Sprintf("Extracted response headers: %v", headerMap))

	case *ext_proc_v3.ProcessingRequest_ResponseBody:
		// Handle ResponseBody
		input["request_type"] = "response_body"
		responseBody := request.ResponseBody
		body := responseBody.GetBody()
		if !skipRequestBodyParse {
			headers := state.Headers
			parsedBody, isBodyTruncated, err := getParsedBody(logger, headers, string(body), nil, nil, protoSet)
			if err != nil {
				return nil, err
			}
			input["response_parsed_body"] = parsedBody
			input["response_truncated_body"] = isBodyTruncated
		}

	case *ext_proc_v3.ProcessingRequest_RequestTrailers:
		// Handle RequestTrailers
		input["request_type"] = "request_trailers"
		requestTrailers := request.RequestTrailers
		trailers := requestTrailers.GetTrailers()
		trailerMap := make(map[string]string)
		for _, trailer := range trailers.GetHeaders() {
			trailerMap[trailer.GetKey()] = trailer.GetValue()
		}
		input["request_trailers"] = trailerMap

		// Use the stored headers from the state
		if state.Headers != nil {
			input["headers"] = state.Headers
			input["path"] = state.Path
			input["method"] = state.Method
		} else {
			logger.Warn("Headers not available in state during RequestTrailers processing")
		}

	case *ext_proc_v3.ProcessingRequest_ResponseTrailers:
		// Handle ResponseTrailers
		input["request_type"] = "response_trailers"
		responseTrailers := request.ResponseTrailers
		trailers := responseTrailers.GetTrailers()
		trailerMap := make(map[string]string)
		for _, trailer := range trailers.GetHeaders() {
			trailerMap[trailer.GetKey()] = trailer.GetValue()
		}
		input["response_trailers"] = trailerMap

		// Use the stored headers from the state
		if state.Headers != nil {
			input["headers"] = state.Headers
			input["path"] = state.Path
			input["method"] = state.Method
		} else {
			logger.Warn("Headers not available in state during ResponseTrailers processing")
		}

	default:
		logger.Error("Unknown request type in ProcessingRequest")
		return nil, fmt.Errorf("unknown request type in ProcessingRequest")
	}
	// Log the final input map
	logger.Info(fmt.Sprintf("Final input map: %v", input))

	return input, nil
}

func getParsedPathAndQuery(path string) ([]interface{}, map[string]interface{}, error) {
	parsedURL, err := url.Parse(path)
	if err != nil {
		return nil, nil, err
	}

	fmt.Sprintf("Parsed URL: %v", parsedURL)

	parsedPath := strings.Split(strings.TrimLeft(parsedURL.Path, "/"), "/")
	parsedPathInterface := make([]interface{}, len(parsedPath))
	for i, v := range parsedPath {
		parsedPathInterface[i] = v
	}

	// Log the parsed path components
	fmt.Sprintf("Parsed path components: %v", parsedPathInterface)

	parsedQueryInterface := make(map[string]interface{})
	for paramKey, paramValues := range parsedURL.Query() {
		queryValues := make([]interface{}, len(paramValues))
		for i, v := range paramValues {
			queryValues[i] = v
		}
		parsedQueryInterface[paramKey] = queryValues
	}

	// Log the parsed query parameters
	fmt.Sprintf("Parsed query parameters: %v", parsedQueryInterface)

	return parsedPathInterface, parsedQueryInterface, nil
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
