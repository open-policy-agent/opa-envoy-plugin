// Copyright 2019 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package internal

import (
	"testing"

	ext_authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/code"

	"github.com/open-policy-agent/opa/v1/util"
)

func BenchmarkCheck(b *testing.B) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		b.Fatal(err)
	}

	server := testAuthzServer(nil)
	ctx := b.Context()

	b.ResetTimer()
	for range b.N {
		output, err := server.Check(ctx, &req)
		if err != nil {
			b.Fatal(err)
		}
		if output.Status.Code != int32(code.Code_OK) {
			b.Fatal("Expected request to be allowed but got:", output)
		}
	}
}

func BenchmarkCheck_withCustomLogger(b *testing.B) {
	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		b.Fatal(err)
	}

	server := testAuthzServer(nil, withCustomLogger(&testPlugin{}))
	ctx := b.Context()

	b.ResetTimer()
	for range b.N {
		output, err := server.Check(ctx, &req)
		if err != nil {
			b.Fatal(err)
		}
		if output.Status.Code != int32(code.Code_OK) {
			b.Fatal("Expected request to be allowed but got:", output)
		}
	}
}
