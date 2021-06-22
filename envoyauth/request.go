package envoyauth

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	ext_authz_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa/util"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

var v2Info = map[string]string{"ext_authz": "v2", "encoding": "encoding/json"}
var v3Info = map[string]string{"ext_authz": "v3", "encoding": "protojson"}

//RequestToInput - Converts a CheckRequest in either protobuf 2 or 3 to an input map
func RequestToInput(req interface{}, logEntry *logrus.Entry, protoSet *protoregistry.Files) (map[string]interface{}, error) {
	var err error
	var input map[string]interface{}

	var bs, rawBody []byte
	var path, body string
	var headers, version map[string]string

	// NOTE: The path/body/headers blocks look silly, but they allow us to retrieve
	//       the parts of the incoming request we care about, without having to convert
	//       the entire v2 message into v3. It's nested, each level has a different type,
	//       etc -- we only care for its JSON representation as fed into evaluation later.
	switch req := req.(type) {
	case *ext_authz_v3.CheckRequest:
		bs, err = protojson.Marshal(req)
		if err != nil {
			return nil, err
		}
		path = req.GetAttributes().GetRequest().GetHttp().GetPath()
		body = req.GetAttributes().GetRequest().GetHttp().GetBody()
		headers = req.GetAttributes().GetRequest().GetHttp().GetHeaders()
		rawBody = req.GetAttributes().GetRequest().GetHttp().GetRawBody()
		version = v3Info
	case *ext_authz_v2.CheckRequest:
		bs, err = json.Marshal(req)
		if err != nil {
			return nil, err
		}
		path = req.GetAttributes().GetRequest().GetHttp().GetPath()
		body = req.GetAttributes().GetRequest().GetHttp().GetBody()
		headers = req.GetAttributes().GetRequest().GetHttp().GetHeaders()
		version = v2Info
	}

	err = util.UnmarshalJSON(bs, &input)
	if err != nil {
		return nil, err
	}
	input["version"] = version

	parsedPath, parsedQuery, err := getParsedPathAndQuery(path)
	if err != nil {
		return nil, err
	}

	input["parsed_path"] = parsedPath
	input["parsed_query"] = parsedQuery

	parsedBody, isBodyTruncated, err := getParsedBody(logEntry, headers, body, rawBody, parsedPath, protoSet)
	if err != nil {
		return nil, err
	}

	input["parsed_body"] = parsedBody
	input["truncated_body"] = isBodyTruncated

	return input, nil
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

func getParsedBody(logEntry *logrus.Entry, headers map[string]string, body string, rawBody []byte, parsedPath []interface{}, protoSet *protoregistry.Files) (interface{}, bool, error) {
	var data interface{}

	if val, ok := headers["content-type"]; ok {
		if strings.Contains(val, "application/json") {

			if body == "" {
				return nil, false, nil
			}

			if val, ok := headers["content-length"]; ok {
				cl, err := strconv.ParseInt(val, 10, 64)
				if err != nil {
					return nil, false, err
				}
				if cl != -1 && cl > int64(len(body)) {
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
				logEntry.Debug("no rawBody field sent")
				return nil, false, nil
			}
			// In gRPC, a call of method DoThing on service ThingService is a
			// POST to /ThingService/DoThing. If our path length is anything but
			// two, something is wrong.
			if len(parsedPath) != 2 {
				return nil, false, fmt.Errorf("invalid parsed path")
			}

			known, truncated, err := getGRPCBody(logEntry, rawBody, parsedPath, &data, protoSet)
			if err != nil {
				return nil, false, err
			}
			if truncated {
				return nil, true, nil
			}
			if !known {
				return nil, false, nil
			}
		} else {
			logEntry.Debugf("content-type: %s parsing not supported", val)
		}
	} else {
		logEntry.Debug("no content-type header supplied, performing no body parsing")
	}

	return data, false, nil
}

func getGRPCBody(logEntry *logrus.Entry, in []byte, parsedPath []interface{}, data interface{}, files *protoregistry.Files) (found, truncated bool, _ error) {

	// the first 5 bytes are part of gRPC framing. We need to remove them to be able to parse
	// https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md

	if len(in) < 5 {
		return false, false, fmt.Errorf("less than 5 bytes")
	}

	// Can be 0 or 1, 1 indicates that the payload is compressed.
	// The method could be looked up in the request headers, and the
	// request decompressed; but for now, let's skip it.
	if in[0] != 0 {
		logEntry.Debug("gRPC payload compression not supported")
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
		logEntry.WithField("err", err).Debug("could not find service")
		return false, false, nil
	}
	msgDesc, err := findMessageInputDesc(parsedPath[1].(string), svc)
	if err != nil {
		logEntry.WithField("err", err).Debug("could not find message")
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
