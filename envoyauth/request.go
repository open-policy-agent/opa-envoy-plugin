package envoyauth

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/logging"
	"github.com/open-policy-agent/opa/v1/util"
)

var v2Info = ast.NewObject(
	keyValue("ext_authz", "v2"),
	keyValue("encoding", "encoding/json"),
)
var v3Info = ast.NewObject(
	keyValue("ext_authz", "v3"),
	keyValue("encoding", "protojson"),
)
var errInvalidPath = errors.New("invalid parsed path")

// RequestToInput - Converts a CheckRequest in either protobuf 2 or 3 to an input map
func RequestToInput(req any, logger logging.Logger, protoSet *protoregistry.Files, skipRequestBodyParse bool) (map[string]any, error) {
	// we anticipate sending at most 6 items to the request, so if we hint the size of the map,
	// we are less likely to have to grow the map at runtime which can introduce more allocations.
	input := make(map[string]any, 6)
	var (
		err error

		rawBody    []byte
		path, body string
		headers    map[string]string
		version    ast.Value

		// set the easily retrieved attributes of the source peer, per
		// https://www.envoyproxy.io/docs/envoy/v1.34.0/api-v3/service/auth/v3/attribute_context.proto#envoy-v3-api-msg-service-auth-v3-attributecontext-peer
		//
		// All of these parameters are available in the full `input` proto representation, but we will pull out the source.principal field here so that
		// users can easily find it and reference it in policies.
		sourcePrincipal string
	)

	// NOTE: The path/body/headers blocks look silly, but they allow us to retrieve
	//       the parts of the incoming request we care about, without having to convert
	//       the entire v2 message into v3. It's nested, each level has a different type,
	//       etc -- we only care for its JSON representation as fed into evaluation later.
	switch req := req.(type) {
	case *ext_authz_v3.CheckRequest:
		input = protomap(req.ProtoReflect())
		path = req.GetAttributes().GetRequest().GetHttp().GetPath()
		body = req.GetAttributes().GetRequest().GetHttp().GetBody()
		headers = req.GetAttributes().GetRequest().GetHttp().GetHeaders()
		rawBody = req.GetAttributes().GetRequest().GetHttp().GetRawBody()
		sourcePrincipal = req.GetAttributes().GetSource().GetPrincipal()
		version = v3Info
	case *ext_authz_v2.CheckRequest:
		var bs []byte
		if bs, err = json.Marshal(req); err != nil {
			return nil, err
		}
		if err = util.UnmarshalJSON(bs, &input); err != nil {
			return nil, err
		}
		path = req.GetAttributes().GetRequest().GetHttp().GetPath()
		body = req.GetAttributes().GetRequest().GetHttp().GetBody()
		headers = req.GetAttributes().GetRequest().GetHttp().GetHeaders()
		sourcePrincipal = req.GetAttributes().GetSource().GetPrincipal()
		version = v2Info
	}

	input["version"] = version

	parsedPath, parsedQuery, err := getParsedPathAndQuery(path)
	if err != nil {
		return nil, err
	}

	input["parsed_path"] = parsedPath
	input["parsed_query"] = parsedQuery

	if !skipRequestBodyParse {
		parsedBody, isBodyTruncated, err := getParsedBody(logger, headers, body, rawBody, parsedPath, protoSet)
		if err != nil {
			return nil, err
		}

		input["parsed_body"] = parsedBody
		input["truncated_body"] = isBodyTruncated
	}

	if sourcePrincipal != "" {
		input["source_principal"] = sourcePrincipal
	}

	return input, nil
}

func getParsedPathAndQuery(path string) ([]string, map[string]any, error) {
	rawPath, rawQuery, _ := strings.Cut(path, "?")

	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		return nil, nil, err
	}

	parsedPath := strings.Split(strings.TrimLeft(decodedPath, "/"), "/")

	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, nil, err
	}
	parsedQueryInterface := make(map[string]any, len(query))
	for paramKey, paramValues := range query {
		parsedQueryInterface[paramKey] = paramValues
	}

	return parsedPath, parsedQueryInterface, nil
}

func getParsedBody(logger logging.Logger, headers map[string]string, body string, rawBody []byte, parsedPath []string, protoSet *protoregistry.Files) (any, bool, error) {
	var data any

	// Envoy sets x-envoy-auth-partial-body to "true" when the forwarded
	// request body has been truncated to the configured max_request_bytes
	// limit. This check is reliable regardless of whether Content-Length
	// is present (e.g. HTTP/2 or chunked transfers).
	if headers["x-envoy-auth-partial-body"] == "true" {
		return nil, true, nil
	}

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
				return nil, false, errInvalidPath
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

			values := map[string][]any{}

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
					var jsonValue any
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

func getGRPCBody(logger logging.Logger, in []byte, parsedPath []string, data any, files *protoregistry.Files) (found, truncated bool, _ error) {

	// the first 5 bytes are part of gRPC framing. We need to remove them to be able to parse
	// https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md

	if len(in) < 5 {
		return false, false, errors.New("less than 5 bytes")
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
	svc, err := findService(parsedPath[0], files)
	if err != nil {
		logger.WithFields(map[string]any{"err": err}).Debug("could not find service")
		return false, false, nil
	}
	msgDesc, err := findMessageInputDesc(parsedPath[1], svc)
	if err != nil {
		logger.WithFields(map[string]any{"err": err}).Debug("could not find message")
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

	if err := util.Unmarshal(jsonBody, &data); err != nil {
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
