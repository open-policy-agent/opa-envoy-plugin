// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	ext_core_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	ext_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_authz_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	ext_type_v2 "github.com/envoyproxy/go-control-plane/envoy/type"
	ext_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/code"
	rpc_status "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/plugins/logs"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/server"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/topdown"
	iCache "github.com/open-policy-agent/opa/topdown/cache"
	"github.com/open-policy-agent/opa/util"
)

const defaultAddr = ":9191"
const defaultPath = "envoy/authz/allow"
const defaultDryRun = false
const defaultEnableReflection = false

// PluginName is the name to register with the OPA plugin manager
const PluginName = "envoy_ext_authz_grpc"

var revisionPath = storage.MustParsePath("/system/bundle/manifest/revision")

var v2Info = map[string]string{"ext_authz": "v2", "encoding": "encoding/json"}
var v3Info = map[string]string{"ext_authz": "v3", "encoding": "protojson"}

type evalResult struct {
	revision   string
	decisionID string
	txnID      uint64
	decision   interface{}
	metrics    metrics.Metrics
}

// Validate receives a slice of bytes representing the plugin's
// configuration and returns a configuration value that can be used to
// instantiate the plugin.
func Validate(m *plugins.Manager, bs []byte) (*Config, error) {

	cfg := Config{
		Addr:             defaultAddr,
		DryRun:           defaultDryRun,
		EnableReflection: defaultEnableReflection,
	}

	if err := util.Unmarshal(bs, &cfg); err != nil {
		return nil, err
	}

	if cfg.Path != "" && cfg.Query != "" {
		return nil, fmt.Errorf("invalid config: specify a value for only the \"path\" field")
	}

	var parsedQuery ast.Body
	var err error

	if cfg.Query != "" {
		// Deprecated: Use Path instead
		parsedQuery, err = ast.ParseBody(cfg.Query)
	} else {
		if cfg.Path == "" {
			cfg.Path = defaultPath
		}
		path := stringPathToDataRef(cfg.Path)
		parsedQuery, err = ast.ParseBody(path.String())
	}

	if err != nil {
		return nil, err
	}

	cfg.parsedQuery = parsedQuery

	if cfg.ProtoDescriptor != "" {
		ps, err := readProtoSet(cfg.ProtoDescriptor)
		if err != nil {
			return nil, err
		}
		cfg.protoSet = ps
	}

	return &cfg, nil
}

func readProtoSet(path string) (*protoregistry.Files, error) {
	protoSet, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fileSet descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(protoSet, &fileSet); err != nil {
		return nil, err
	}
	return protodesc.NewFiles(&fileSet)
}

// New returns a Plugin that implements the Envoy ext_authz API.
func New(m *plugins.Manager, cfg *Config) plugins.Plugin {

	plugin := &envoyExtAuthzGrpcServer{
		manager:                m,
		cfg:                    *cfg,
		server:                 grpc.NewServer(),
		preparedQueryDoOnce:    new(sync.Once),
		interQueryBuiltinCache: iCache.NewInterQueryCache(m.InterQueryBuiltinCacheConfig()),
	}

	// Register Authorization Server
	ext_authz_v3.RegisterAuthorizationServer(plugin.server, plugin)
	ext_authz_v2.RegisterAuthorizationServer(plugin.server, &envoyExtAuthzV2Wrapper{v3: plugin})

	m.RegisterCompilerTrigger(plugin.compilerUpdated)

	// Register reflection service on gRPC server
	if cfg.EnableReflection {
		reflection.Register(plugin.server)
	}

	m.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})

	return plugin
}

// Config represents the plugin configuration.
type Config struct {
	Addr             string `json:"addr"`
	Query            string `json:"query"` // Deprecated: Use Path instead
	Path             string `json:"path"`
	DryRun           bool   `json:"dry-run"`
	EnableReflection bool   `json:"enable-reflection"`
	parsedQuery      ast.Body
	ProtoDescriptor  string `json:"proto-descriptor"`
	protoSet         *protoregistry.Files
}

type envoyExtAuthzGrpcServer struct {
	cfg                    Config
	server                 *grpc.Server
	manager                *plugins.Manager
	preparedQuery          *rego.PreparedEvalQuery
	preparedQueryDoOnce    *sync.Once
	interQueryBuiltinCache iCache.InterQueryCache
}

type envoyExtAuthzV2Wrapper struct {
	v3 *envoyExtAuthzGrpcServer
}

func (p *envoyExtAuthzGrpcServer) Start(ctx context.Context) error {
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
	go p.listen()
	return nil
}

func (p *envoyExtAuthzGrpcServer) Stop(ctx context.Context) {
	p.server.Stop()
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
}

func (p *envoyExtAuthzGrpcServer) Reconfigure(ctx context.Context, config interface{}) {
	return
}

func (p *envoyExtAuthzGrpcServer) compilerUpdated(txn storage.Transaction) {
	p.preparedQueryDoOnce = new(sync.Once)
}

func (p *envoyExtAuthzGrpcServer) listen() {

	// The listener is closed automatically by Serve when it returns.
	l, err := net.Listen("tcp", p.cfg.Addr)
	if err != nil {
		logrus.WithField("err", err).Fatal("Unable to create listener.")
	}

	logrus.WithFields(logrus.Fields{
		"addr":              p.cfg.Addr,
		"query":             p.cfg.Query,
		"path":              p.cfg.Path,
		"dry-run":           p.cfg.DryRun,
		"enable-reflection": p.cfg.EnableReflection,
	}).Info("Starting gRPC server.")

	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateOK})

	if err := p.server.Serve(l); err != nil {
		logrus.WithField("err", err).Fatal("Listener failed.")
	}

	logrus.Info("Listener exited.")
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
}

// Check is envoy.service.auth.v3.Authorization/Check
func (p *envoyExtAuthzGrpcServer) Check(ctx context.Context, req *ext_authz_v3.CheckRequest) (*ext_authz_v3.CheckResponse, error) {
	resp, stop, err := p.check(ctx, req)
	if code := stop(); resp != nil && code != nil {
		resp.Status = code
	}
	return resp, err
}

func (p *envoyExtAuthzGrpcServer) check(ctx context.Context, req interface{}) (*ext_authz_v3.CheckResponse, func() *rpc_status.Status, error) {
	var err error
	start := time.Now()

	result := evalResult{}
	result.metrics = metrics.New()
	result.metrics.Timer(metrics.ServerHandler).Start()
	result.decisionID, err = uuid4()
	if err != nil {
		logrus.WithField("err", err).Error("Unable to generate decision ID.")
		return nil, func() *rpc_status.Status { return nil }, err
	}
	logEntry := logrus.WithField("decision-id", result.decisionID)

	var input map[string]interface{}

	stop := func() *rpc_status.Status {
		result.metrics.Timer(metrics.ServerHandler).Stop()
		logErr := p.log(ctx, input, &result, err)
		if logErr != nil {
			return &rpc_status.Status{
				Code:    int32(code.Code_UNKNOWN),
				Message: logErr.Error(),
			}
		}
		return nil
	}

	if ctx.Err() != nil {
		err = errors.Wrap(ctx.Err(), "check request timed out before query execution")
		return nil, stop, err
	}

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
			return nil, stop, err
		}
		path = req.GetAttributes().GetRequest().GetHttp().GetPath()
		body = req.GetAttributes().GetRequest().GetHttp().GetBody()
		headers = req.GetAttributes().GetRequest().GetHttp().GetHeaders()
		rawBody = req.GetAttributes().GetRequest().GetHttp().GetRawBody()
		version = v3Info
	case *ext_authz_v2.CheckRequest:
		bs, err = json.Marshal(req)
		if err != nil {
			return nil, stop, err
		}
		path = req.GetAttributes().GetRequest().GetHttp().GetPath()
		body = req.GetAttributes().GetRequest().GetHttp().GetBody()
		headers = req.GetAttributes().GetRequest().GetHttp().GetHeaders()
		version = v2Info
	}

	err = util.UnmarshalJSON(bs, &input)
	if err != nil {
		return nil, stop, err
	}
	input["version"] = version

	parsedPath, parsedQuery, err := getParsedPathAndQuery(path)
	if err != nil {
		return nil, stop, err
	}

	input["parsed_path"] = parsedPath
	input["parsed_query"] = parsedQuery

	parsedBody, isBodyTruncated, err := getParsedBody(logEntry, headers, body, rawBody, parsedPath, p.cfg.protoSet)
	if err != nil {
		return nil, stop, err
	}

	input["parsed_body"] = parsedBody
	input["truncated_body"] = isBodyTruncated

	inputValue, err := ast.InterfaceToValue(input)
	if err != nil {
		return nil, stop, err
	}

	err = p.eval(ctx, inputValue, &result)
	if err != nil {
		return nil, stop, err
	}

	resp := &ext_authz_v3.CheckResponse{}

	switch decision := result.decision.(type) {
	case bool:
		status := int32(code.Code_PERMISSION_DENIED)
		if decision {
			status = int32(code.Code_OK)
		}

		resp.Status = &rpc_status.Status{Code: status}

	case map[string]interface{}:
		status, err := getResponseStatus(decision)
		if err != nil {
			return nil, stop, errors.Wrap(err, "failed to get response status")
		}

		resp.Status = &rpc_status.Status{Code: status}

		responseHeaders, err := getResponseHeaders(decision)
		if err != nil {
			return nil, stop, errors.Wrap(err, "failed to get response headers")
		}

		if status == int32(code.Code_OK) {
			resp.HttpResponse = &ext_authz_v3.CheckResponse_OkResponse{
				OkResponse: &ext_authz_v3.OkHttpResponse{
					Headers: responseHeaders,
				},
			}
		} else {
			body, err := getResponseBody(decision)
			if err != nil {
				return nil, stop, errors.Wrap(err, "failed to get response body")
			}

			httpStatus, err := getResponseHTTPStatus(decision)
			if err != nil {
				return nil, stop, errors.Wrap(err, "failed to get response http status")
			}

			deniedResponse := &ext_authz_v3.DeniedHttpResponse{
				Headers: responseHeaders,
				Body:    body,
				Status:  httpStatus,
			}

			resp.HttpResponse = &ext_authz_v3.CheckResponse_DeniedResponse{
				DeniedResponse: deniedResponse,
			}
		}

	default:
		err = fmt.Errorf("illegal value for policy evaluation result: %T", decision)
		return nil, stop, err
	}

	logrus.WithFields(logrus.Fields{
		"query":               p.cfg.parsedQuery.String(),
		"dry-run":             p.cfg.DryRun,
		"decision":            result.decision,
		"err":                 err,
		"txn":                 result.txnID,
		"metrics":             result.metrics.All(),
		"total_decision_time": time.Since(start),
	}).Debug("Returning policy decision.")

	// If dry-run mode, override the Status code to unconditionally Allow the request
	// DecisionLogging should reflect what "would" have happened
	if p.cfg.DryRun {
		if resp.Status.Code != int32(code.Code_OK) {
			resp.Status = &rpc_status.Status{Code: int32(code.Code_OK)}
			resp.HttpResponse = &ext_authz_v3.CheckResponse_OkResponse{
				OkResponse: &ext_authz_v3.OkHttpResponse{},
			}
		}
	}

	return resp, stop, nil
}

func (p *envoyExtAuthzGrpcServer) eval(ctx context.Context, input ast.Value, result *evalResult, opts ...func(*rego.Rego)) error {

	err := storage.Txn(ctx, p.manager.Store, storage.TransactionParams{}, func(txn storage.Transaction) error {

		var err error

		result.revision, err = getRevision(ctx, p.manager.Store, txn)
		if err != nil {
			return err
		}

		result.txnID = txn.ID()

		logrus.WithFields(logrus.Fields{
			"input":   input,
			"query":   p.cfg.parsedQuery.String(),
			"dry-run": p.cfg.DryRun,
			"txn":     result.txnID,
		}).Debug("Executing policy query.")

		err = p.constructPreparedQuery(txn, result.metrics, opts)
		if err != nil {
			return err
		}

		rs, err := p.preparedQuery.Eval(
			ctx,
			rego.EvalParsedInput(input),
			rego.EvalTransaction(txn),
			rego.EvalMetrics(result.metrics),
			rego.EvalInterQueryBuiltinCache(p.interQueryBuiltinCache),
		)

		if err != nil {
			return err
		} else if len(rs) == 0 {
			return fmt.Errorf("undefined decision")
		} else if len(rs) > 1 {
			return fmt.Errorf("multiple evaluation results")
		}

		result.decision = rs[0].Expressions[0].Value
		return nil
	})

	return err
}

func (p *envoyExtAuthzGrpcServer) constructPreparedQuery(txn storage.Transaction, m metrics.Metrics, opts []func(*rego.Rego)) error {
	var err error
	var pq rego.PreparedEvalQuery

	p.preparedQueryDoOnce.Do(func() {
		opts = append(opts,
			rego.Metrics(m),
			rego.ParsedQuery(p.cfg.parsedQuery),
			rego.Compiler(p.manager.GetCompiler()),
			rego.Store(p.manager.Store),
			rego.Transaction(txn),
			rego.Runtime(p.manager.Info))

		r := rego.New(opts...)

		pq, err = r.PrepareForEval(context.Background())
		p.preparedQuery = &pq
	})

	return err
}

func (p *envoyExtAuthzGrpcServer) log(ctx context.Context, input interface{}, result *evalResult, err error) error {
	plugin := logs.Lookup(p.manager)
	if plugin == nil {
		return nil
	}

	info := &server.Info{
		Timestamp: time.Now(),
		Input:     &input,
	}

	if p.cfg.Query != "" {
		info.Query = p.cfg.Query
	}

	if p.cfg.Path != "" {
		info.Path = p.cfg.Path
	}

	info.Revision = result.revision
	info.DecisionID = result.decisionID
	info.Metrics = result.metrics

	if err != nil {
		switch err.(type) {
		case *storage.Error, *ast.Error, ast.Errors:
			break
		case *topdown.Error:
			if topdown.IsCancel(err) {
				err = &topdown.Error{
					Code:    topdown.CancelErr,
					Message: "context deadline reached during query execution",
				}
			}
		default:
			// Wrap errors that may not serialize to JSON well (e.g., fmt.Errorf, etc.)
			err = &internalError{Message: err.Error()}
		}
		info.Error = err
	} else {
		var x interface{}
		if result != nil {
			x = result.decision
		}
		info.Results = &x
	}

	return plugin.Log(ctx, info)
}

// getResponseStatus returns the status of the evaluation.
// The status is determined by the "allowed" key in the evaluation
// result and is represented as a boolean value. If the key is missing, an
// error will be returned.
func getResponseStatus(result map[string]interface{}) (int32, error) {
	status := int32(code.Code_PERMISSION_DENIED)

	var decision, ok bool
	var val interface{}

	if val, ok = result["allowed"]; !ok {
		return 0, fmt.Errorf("unable to determine evaluation result due to missing \"allowed\" key")
	}

	if decision, ok = val.(bool); !ok {
		return 0, fmt.Errorf("type assertion error")
	}

	if decision {
		status = int32(code.Code_OK)
	}

	return status, nil
}

func getResponseHeaders(result map[string]interface{}) ([]*ext_core_v3.HeaderValueOption, error) {
	var ok bool
	var val interface{}

	responseHeaders := []*ext_core_v3.HeaderValueOption{}

	if val, ok = result["headers"]; !ok {
		return responseHeaders, nil
	}

	takeResponseHeaders := func(headers map[string]interface{}) ([]*ext_core_v3.HeaderValueOption, error) {
		responseHeaders := []*ext_core_v3.HeaderValueOption{}
		for key, value := range headers {
			var headerVal string
			if headerVal, ok = value.(string); !ok {
				return nil, fmt.Errorf("type assertion error")
			}
			headerValue := &ext_core_v3.HeaderValue{
				Key:   key,
				Value: headerVal,
			}
			headerValueOption := &ext_core_v3.HeaderValueOption{
				Header: headerValue,
			}
			responseHeaders = append(responseHeaders, headerValueOption)
		}
		return responseHeaders, nil
	}

	switch val := val.(type) {
	case []interface{}:
		for _, vval := range val {
			headers, ok := vval.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("type assertion error")
			}

			responseHeadersToAppend, err := takeResponseHeaders(headers)
			if err != nil {
				return nil, err
			}
			responseHeaders = append(responseHeaders, responseHeadersToAppend...)
		}

	case map[string]interface{}:
		responseHeadersToUse, err := takeResponseHeaders(val)
		if err != nil {
			return nil, err
		}
		responseHeaders = responseHeadersToUse

	default:
		return nil, fmt.Errorf("type assertion error")
	}

	return responseHeaders, nil
}

func getResponseBody(result map[string]interface{}) (string, error) {
	var ok bool
	var val interface{}
	var body string

	if val, ok = result["body"]; !ok {
		return "", nil
	}

	if body, ok = val.(string); !ok {
		return "", fmt.Errorf("type assertion error")
	}

	return body, nil
}

func getResponseHTTPStatus(result map[string]interface{}) (*ext_type_v3.HttpStatus, error) {
	var ok bool
	var val interface{}
	var statusCode json.Number

	status := &ext_type_v3.HttpStatus{
		Code: ext_type_v3.StatusCode(ext_type_v3.StatusCode_Forbidden),
	}

	if val, ok = result["http_status"]; !ok {
		return status, nil
	}

	if statusCode, ok = val.(json.Number); !ok {
		return nil, fmt.Errorf("type assertion error")
	}

	httpStatusCode, err := statusCode.Int64()
	if err != nil {
		return nil, fmt.Errorf("error converting JSON number to int: %v", err)
	}

	if _, ok := ext_type_v3.StatusCode_name[int32(httpStatusCode)]; !ok {
		return nil, fmt.Errorf("Invalid HTTP status code %v", httpStatusCode)
	}

	status.Code = ext_type_v3.StatusCode(int32(httpStatusCode))

	return status, nil
}

func uuid4() (string, error) {
	bs := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, bs)
	if n != len(bs) || err != nil {
		return "", err
	}
	bs[8] = bs[8]&^0xc0 | 0x80
	bs[6] = bs[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", bs[0:4], bs[4:6], bs[6:8], bs[8:10], bs[10:]), nil
}

func getRevision(ctx context.Context, store storage.Store, txn storage.Transaction) (string, error) {
	value, err := store.Read(ctx, txn, revisionPath)
	if err != nil {
		if storage.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}
	revision, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("bad revision")
	}
	return revision, nil
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

			err := util.Unmarshal([]byte(body), &data)
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
		}
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

func stringPathToDataRef(s string) (r ast.Ref) {
	result := ast.Ref{ast.DefaultRootDocument}
	result = append(result, stringPathToRef(s)...)
	return result
}

func stringPathToRef(s string) (r ast.Ref) {
	if len(s) == 0 {
		return r
	}

	p := strings.Split(s, "/")
	for _, x := range p {
		if x == "" {
			continue
		}

		i, err := strconv.Atoi(x)
		if err != nil {
			r = append(r, ast.StringTerm(x))
		} else {
			r = append(r, ast.IntNumberTerm(i))
		}
	}
	return r
}

type internalError struct {
	Message string `json:"message"`
}

func (e *internalError) Error() string {
	return e.Message
}

// Check is envoy.service.auth.v2.Authorization/Check
func (p *envoyExtAuthzV2Wrapper) Check(ctx context.Context, req *ext_authz_v2.CheckRequest) (*ext_authz_v2.CheckResponse, error) {
	var stop func() *rpc_status.Status
	respV2 := &ext_authz_v2.CheckResponse{}
	respV3, stop, err := p.v3.check(ctx, req)
	defer func() {
		if code := stop(); code != nil {
			respV2.Status = code
		}
	}()

	if err != nil {
		return nil, err
	}
	respV2 = v2Response(respV3)
	return respV2, nil
}

func v2Response(respV3 *ext_authz_v3.CheckResponse) *ext_authz_v2.CheckResponse {
	respV2 := ext_authz_v2.CheckResponse{
		Status: respV3.Status,
	}
	switch http3 := respV3.HttpResponse.(type) {
	case *ext_authz_v3.CheckResponse_OkResponse:
		hdrs := http3.OkResponse.GetHeaders()
		respV2.HttpResponse = &ext_authz_v2.CheckResponse_OkResponse{
			OkResponse: &ext_authz_v2.OkHttpResponse{
				Headers: v2Headers(hdrs),
			}}
	case *ext_authz_v3.CheckResponse_DeniedResponse:
		hdrs := http3.DeniedResponse.GetHeaders()
		respV2.HttpResponse = &ext_authz_v2.CheckResponse_DeniedResponse{
			DeniedResponse: &ext_authz_v2.DeniedHttpResponse{
				Headers: v2Headers(hdrs),
				Status:  v2Status(http3.DeniedResponse.Status),
				Body:    http3.DeniedResponse.Body,
			}}
	}
	return &respV2
}

func v2Headers(hdrs []*ext_core_v3.HeaderValueOption) []*ext_core_v2.HeaderValueOption {
	hdrsV2 := make([]*ext_core_v2.HeaderValueOption, len(hdrs))
	for i, hv := range hdrs {
		hdrsV2[i] = &ext_core_v2.HeaderValueOption{
			Header: &ext_core_v2.HeaderValue{
				Key:   hv.GetHeader().Key,
				Value: hv.GetHeader().Value,
			},
		}
	}
	return hdrsV2
}

func v2Status(s *ext_type_v3.HttpStatus) *ext_type_v2.HttpStatus {
	return &ext_type_v2.HttpStatus{
		Code: ext_type_v2.StatusCode(s.Code),
	}
}
