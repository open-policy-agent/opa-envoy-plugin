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
	"strings"
	"time"

	ctx "golang.org/x/net/context"

	ext_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	ext_authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	ext_type "github.com/envoyproxy/go-control-plane/envoy/type"
	google_rpc "github.com/gogo/googleapis/google/rpc"
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
	"google.golang.org/grpc"
)

const defaultAddr = ":9191"
const defaultQuery = "data.istio.authz.allow"
const defaultDryRun = false

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
		Addr:   defaultAddr,
		Query:  defaultQuery,
		DryRun: defaultDryRun,
	}

	if err := util.Unmarshal(bs, &cfg); err != nil {
		return nil, err
	}

	parsedQuery, err := ast.ParseBody(cfg.Query)
	if err != nil {
		return nil, err
	}

	cfg.parsedQuery = parsedQuery

	return &cfg, nil
}

// New returns a Plugin that implements the Envoy ext_authz API.
func New(m *plugins.Manager, cfg *Config) plugins.Plugin {

	plugin := &envoyExtAuthzGrpcServer{
		manager: m,
		cfg:     *cfg,
		server:  grpc.NewServer(),
	}

	ext_authz.RegisterAuthorizationServer(plugin.server, plugin)

	return plugin
}

// Config represents the plugin configuration.
type Config struct {
	Addr        string `json:"addr"`
	Query       string `json:"query"`
	DryRun      bool   `json:"dry-run"`
	parsedQuery ast.Body
}

type envoyExtAuthzGrpcServer struct {
	cfg     Config
	server  *grpc.Server
	manager *plugins.Manager
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

func (p *envoyExtAuthzGrpcServer) listen() {

	// The listener is closed automatically by Serve when it returns.
	l, err := net.Listen("tcp", p.cfg.Addr)
	if err != nil {
		logrus.WithField("err", err).Fatalf("Unable to create listener.")
	}

	logrus.WithFields(logrus.Fields{
		"addr":    p.cfg.Addr,
		"query":   p.cfg.Query,
		"dry-run": p.cfg.DryRun,
	}).Infof("Starting gRPC server.")

	if err := p.server.Serve(l); err != nil {
		logrus.WithField("err", err).Fatalf("Listener failed.")
	}

	logrus.Info("Listener exited.")
}

func (p *envoyExtAuthzGrpcServer) Check(ctx ctx.Context, req *ext_authz.CheckRequest) (*ext_authz.CheckResponse, error) {
	start := time.Now()

	bs, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	var input map[string]interface{}

	err = util.UnmarshalJSON(bs, &input)
	if err != nil {
		return nil, err
	}

	input["parsed_path"] = getParsedPath(req)

	inputValue, err := ast.InterfaceToValue(input)
	if err != nil {
		return nil, err
	}

	result, err := p.eval(ctx, inputValue)
	if err != nil {
		return nil, err
	}

	resp := &ext_authz.CheckResponse{}

	switch decision := result.decision.(type) {
	case bool:
		status := int32(google_rpc.PERMISSION_DENIED)
		if decision {
			status = int32(google_rpc.OK)
		}

		resp.Status = &google_rpc.Status{Code: status}

	case map[string]interface{}:
		status, err := getResponseStatus(decision)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get response status")
		}

		resp.Status = &google_rpc.Status{Code: status}

		responseHeaders, err := getResponseHeaders(decision)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get response headers")
		}

		if status == int32(google_rpc.OK) {
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

			resp.HttpResponse = &ext_authz.CheckResponse_DeniedResponse{
				DeniedResponse: &ext_authz.DeniedHttpResponse{
					Headers: responseHeaders,
					Body:    body,
					Status:  httpStatus,
				},
			}
		}

	default:
		return nil, fmt.Errorf("illegal value for policy evaluation result: %T", decision)
	}

	err = p.log(ctx, input, result, err)

	if err != nil {
		resp := &ext_authz.CheckResponse{
			Status: &google_rpc.Status{
				Code:    int32(google_rpc.UNKNOWN),
				Message: err.Error(),
			},
		}
		return resp, nil
	}

	logrus.WithFields(logrus.Fields{
		"query":               p.cfg.Query,
		"dry-run":             p.cfg.DryRun,
		"decision":            result.decision,
		"err":                 err,
		"txn":                 result.txnID,
		"metrics":             result.metrics.All(),
		"total_decision_time": time.Since(start),
	}).Info("Returning policy decision.")

	// If dry-run mode, override the Status code to unconditionally Allow the request
	// DecisionLogging should reflect what "would" have happened
	if p.cfg.DryRun {
		if resp.Status.Code != int32(google_rpc.OK) {
			resp.Status = &google_rpc.Status{Code: int32(google_rpc.OK)}
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

		logrus.WithFields(logrus.Fields{
			"input":   input,
			"query":   p.cfg.Query,
			"dry-run": p.cfg.DryRun,
			"txn":     result.txnID,
		}).Infof("Executing policy query.")

		opts = append(opts,
			rego.Metrics(result.metrics),
			rego.ParsedQuery(p.cfg.parsedQuery),
			rego.ParsedInput(input),
			rego.Compiler(p.manager.GetCompiler()),
			rego.Store(p.manager.Store),
			rego.Transaction(txn),
			rego.Runtime(p.manager.Info))

		rs, err := rego.New(opts...).Eval(ctx)

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

func (p *envoyExtAuthzGrpcServer) log(ctx context.Context, input interface{}, result *evalResult, err error) error {
	plugin := logs.Lookup(p.manager)
	if plugin == nil {
		return nil
	}

	info := &server.Info{
		Revision:   result.revision,
		DecisionID: result.decisionID,
		Timestamp:  time.Now(),
		Query:      p.cfg.Query,
		Input:      &input,
		Error:      err,
		Metrics:    result.metrics,
	}

	if err == nil {
		var x interface{} = result.decision
		info.Results = &x
	}

	return plugin.Log(ctx, info)
}

// getResponseStatus returns the status of the evaluation.
// The status is determined by the "allowed" key in the evaluation
// result and is represented as a boolean value. If the key is missing, an
// error will be returned.
func getResponseStatus(result map[string]interface{}) (int32, error) {
	status := int32(google_rpc.PERMISSION_DENIED)

	var decision, ok bool
	var val interface{}

	if val, ok = result["allowed"]; !ok {
		return 0, fmt.Errorf("unable to determine evaluation result due to missing \"allowed\" key")
	}

	if decision, ok = val.(bool); !ok {
		return 0, fmt.Errorf("type assertion error")
	}

	if decision {
		status = int32(google_rpc.OK)
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

	status := &ext_type.HttpStatus{}

	if val, ok = result["http_status"]; !ok {
		return nil, nil
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

func getParsedPath(req *ext_authz.CheckRequest) []interface{} {
	path := req.GetAttributes().GetRequest().GetHttp().GetPath()
	parsedPath := strings.Split(strings.TrimLeft(path, "/"), "/")
	parsedPathInterface := make([]interface{}, len(parsedPath))
	for i, v := range parsedPath {
		parsedPathInterface[i] = v
	}
	return parsedPathInterface
}
