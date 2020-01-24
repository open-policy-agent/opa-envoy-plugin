// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	ctx "golang.org/x/net/context"

	ext_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	ext_authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	ext_type "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/plugins/logs"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/server"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/code"
	rpc_status "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const defaultAddr = ":9191"
const defaultPath = "istio/authz/allow"
const defaultDryRun = false
const defaultEnableReflection = false

var revisionPath = storage.MustParsePath("/system/bundle/manifest/revision")

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

	return &cfg, nil
}

// New returns a Plugin that implements the Envoy ext_authz API.
func New(m *plugins.Manager, cfg *Config) plugins.Plugin {

	plugin := &envoyExtAuthzGrpcServer{
		manager:             m,
		cfg:                 *cfg,
		server:              grpc.NewServer(),
		preparedQueryDoOnce: new(sync.Once),
	}

	// Register Authorization Server
	ext_authz.RegisterAuthorizationServer(plugin.server, plugin)

	m.RegisterCompilerTrigger(plugin.compilerUpdated)

	// Register reflection service on gRPC server
	if cfg.EnableReflection {
		reflection.Register(plugin.server)
	}

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
}

type envoyExtAuthzGrpcServer struct {
	cfg                 Config
	server              *grpc.Server
	manager             *plugins.Manager
	preparedQuery       *rego.PreparedEvalQuery
	preparedQueryDoOnce *sync.Once
}

func (p *envoyExtAuthzGrpcServer) Start(ctx context.Context) error {
	go p.listen()
	return nil
}

func (p *envoyExtAuthzGrpcServer) Stop(ctx context.Context) {
	p.server.Stop()
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

	if err := p.server.Serve(l); err != nil {
		logrus.WithField("err", err).Fatal("Listener failed.")
	}

	logrus.Info("Listener exited.")
}

func (p *envoyExtAuthzGrpcServer) Check(ctx ctx.Context, req *ext_authz.CheckRequest) (resp *ext_authz.CheckResponse, err error) {
	start := time.Now()
	var input map[string]interface{}
	var result *evalResult

	defer func() {
		logErr := p.log(ctx, input, result, err)
		if logErr != nil {
			resp = &ext_authz.CheckResponse{
				Status: &rpc_status.Status{
					Code:    int32(code.Code_UNKNOWN),
					Message: logErr.Error(),
				},
			}
		}
	}()

	bs, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	err = util.UnmarshalJSON(bs, &input)
	if err != nil {
		return nil, err
	}

	parsedPath, parsedQuery, err := getParsedPathAndQuery(req)
	if err != nil {
		return nil, err
	}

	input["parsed_path"] = parsedPath
	input["parsed_query"] = parsedQuery

	parsedBody, err := getParsedBody(req)
	if err != nil {
		return nil, err
	}

	input["parsed_body"] = parsedBody

	inputValue, err := ast.InterfaceToValue(input)
	if err != nil {
		return nil, err
	}

	result, err = p.eval(ctx, inputValue)
	if err != nil {
		return nil, err
	}

	resp = &ext_authz.CheckResponse{}

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
			return nil, errors.Wrap(err, "failed to get response status")
		}

		resp.Status = &rpc_status.Status{Code: status}

		responseHeaders, err := getResponseHeaders(decision)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get response headers")
		}

		if status == int32(code.Code_OK) {
			resp.HttpResponse = &ext_authz.CheckResponse_OkResponse{
				OkResponse: &ext_authz.OkHttpResponse{
					Headers: responseHeaders,
				},
			}
		} else {
			body, err := getResponseBody(decision)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get response body")
			}

			httpStatus, err := getResponseHTTPStatus(decision)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get response http status")
			}

			deniedResponse := &ext_authz.DeniedHttpResponse{
				Headers: responseHeaders,
				Body:    body,
				Status:  httpStatus,
			}

			resp.HttpResponse = &ext_authz.CheckResponse_DeniedResponse{
				DeniedResponse: deniedResponse,
			}
		}

	default:
		err = fmt.Errorf("illegal value for policy evaluation result: %T", decision)
		return nil, err
	}

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.WithFields(logrus.Fields{
			"query":               p.cfg.parsedQuery.String(),
			"dry-run":             p.cfg.DryRun,
			"decision":            result.decision,
			"err":                 err,
			"txn":                 result.txnID,
			"metrics":             result.metrics.All(),
			"total_decision_time": time.Since(start),
		}).Debug("Returning policy decision.")
	}

	// If dry-run mode, override the Status code to unconditionally Allow the request
	// DecisionLogging should reflect what "would" have happened
	if p.cfg.DryRun {
		if resp.Status.Code != int32(code.Code_OK) {
			resp.Status = &rpc_status.Status{Code: int32(code.Code_OK)}
			resp.HttpResponse = &ext_authz.CheckResponse_OkResponse{
				OkResponse: &ext_authz.OkHttpResponse{},
			}
		}
	}

	return resp, nil
}

func (p *envoyExtAuthzGrpcServer) eval(ctx context.Context, input ast.Value, opts ...func(*rego.Rego)) (*evalResult, error) {
	result := &evalResult{}
	result.metrics = metrics.New()
	result.metrics.Timer(metrics.ServerHandler).Start()

	err := storage.Txn(ctx, p.manager.Store, storage.TransactionParams{}, func(txn storage.Transaction) error {

		var err error

		result.revision, err = getRevision(ctx, p.manager.Store, txn)
		if err != nil {
			return err
		}

		result.decisionID, err = uuid4()
		if err != nil {
			return err
		}

		result.txnID = txn.ID()

		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.WithFields(logrus.Fields{
				"input":   input,
				"query":   p.cfg.parsedQuery.String(),
				"dry-run": p.cfg.DryRun,
				"txn":     result.txnID,
			}).Debug("Executing policy query.")
		}

		err = p.constructPreparedQuery(txn, result.metrics, opts)
		if err != nil {
			return err
		}

		rs, err := p.preparedQuery.Eval(
			ctx,
			rego.EvalParsedInput(input),
			rego.EvalTransaction(txn),
			rego.EvalMetrics(result.metrics),
		)

		result.metrics.Timer(metrics.ServerHandler).Stop()

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

	return result, err
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
		Error:     err,
	}

	if p.cfg.Query != "" {
		info.Query = p.cfg.Query
	}

	if p.cfg.Path != "" {
		info.Path = p.cfg.Path
	}

	if result != nil {
		info.Revision = result.revision
		info.DecisionID = result.decisionID
		info.Metrics = result.metrics
	}

	if err == nil {
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

func getResponseHeaders(result map[string]interface{}) ([]*ext_core.HeaderValueOption, error) {
	var ok bool
	var val interface{}
	var headers map[string]interface{}

	responseHeaders := []*ext_core.HeaderValueOption{}

	if val, ok = result["headers"]; !ok {
		return responseHeaders, nil
	}

	if headers, ok = val.(map[string]interface{}); !ok {
		return nil, fmt.Errorf("type assertion error")
	}

	for key, value := range headers {
		var headerVal string
		if headerVal, ok = value.(string); !ok {
			return nil, fmt.Errorf("type assertion error")
		}

		headerValue := &ext_core.HeaderValue{
			Key:   key,
			Value: headerVal,
		}

		headerValueOption := &ext_core.HeaderValueOption{
			Header: headerValue,
		}

		responseHeaders = append(responseHeaders, headerValueOption)
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

func getResponseHTTPStatus(result map[string]interface{}) (*ext_type.HttpStatus, error) {
	var ok bool
	var val interface{}
	var statusCode json.Number

	status := &ext_type.HttpStatus{
		Code: ext_type.StatusCode(ext_type.StatusCode_Forbidden),
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

	if _, ok := ext_type.StatusCode_name[int32(httpStatusCode)]; !ok {
		return nil, fmt.Errorf("Invalid HTTP status code %v", httpStatusCode)
	}

	status.Code = ext_type.StatusCode(int32(httpStatusCode))

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

func getParsedPathAndQuery(req *ext_authz.CheckRequest) ([]interface{}, map[string]interface{}, error) {
	path := req.GetAttributes().GetRequest().GetHttp().GetPath()

	unescapedPath, err := url.PathUnescape(path)
	if err != nil {
		return nil, nil, err
	}

	parsedURL, err := url.Parse(unescapedPath)
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

func getParsedBody(req *ext_authz.CheckRequest) (map[string]interface{}, error) {
	body := req.GetAttributes().GetRequest().GetHttp().GetBody()
	headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()

	data := make(map[string]interface{})

	if val, ok := headers["content-type"]; ok {
		if strings.Contains(val, "application/json") {
			err := util.Unmarshal([]byte(body), &data)
			if err != nil {
				return nil, err
			}
		}
	}

	return data, nil
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
