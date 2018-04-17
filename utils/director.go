// Copyright 2018 The OPA Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package utils

import (
	"fmt"
	"strings"

	"github.com/mwitkow/grpc-proxy/proxy"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// MixerAddress Istio Mixer address
const MixerAddress string = "istio-mixer.istio-system:9091"

// GetDirector dials the appropriate backend based on the incoming request
func GetDirector() func(context.Context, string) (context.Context, *grpc.ClientConn, error) {

	return func(ctx context.Context, fullMethodName string) (context.Context, *grpc.ClientConn, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		// Copy the inbound metadata explicitly.
		outCtx, _ := context.WithCancel(ctx)
		outCtx = metadata.NewOutgoingContext(outCtx, md.Copy())

		if ok {
			// Forward the "Report" call to Istio Mixer
			if strings.HasPrefix(fullMethodName, "/istio.mixer.v1.Mixer/Report") {
				logrus.WithFields(logrus.Fields{}).Infof("Report Call received")

				conn, err := grpc.DialContext(ctx, MixerAddress, grpc.WithCodec(proxy.Codec()), grpc.WithInsecure())
				if err != nil {
					fmt.Println("Backend Dialing Error: ", err)
				}
				defer conn.Close()
				return outCtx, conn, err
			}
		}
		return nil, nil, grpc.Errorf(codes.Unimplemented, "Unknown method")
	}
}
