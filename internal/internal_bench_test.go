// Copyright 2019 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package internal

import (
	"context"
	"testing"

	ext_authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	google_rpc "github.com/gogo/googleapis/google/rpc"
	"github.com/open-policy-agent/opa/util"
)

func BenchmarkCheck(b *testing.B) {

	var req ext_authz.CheckRequest
	if err := util.Unmarshal([]byte(exampleAllowedRequest), &req); err != nil {
		panic(err)
	}

	server := testAuthzServer(&testPlugin{}, false)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		output, err := server.Check(ctx, &req)
		if err != nil {
			b.Fatal(err)
		}
		if output.Status.Code != int32(google_rpc.OK) {
			b.Fatal("Expected request to be allowed but got:", output)
		}
	}
}
