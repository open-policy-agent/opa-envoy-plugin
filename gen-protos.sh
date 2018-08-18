#!/usr/bin/env bash

set -e

function join() {
    local IFS=$1
    shift
    echo "$*"
}

ENVOY_API="vendor/github.com/envoyproxy/data-plane-api"

PROTOC_MAPPINGS=(
    "Menvoy/api/v2/core/address.proto=github.com/envoyproxy/data-plane-api/envoy/api/v2/core"
    "Menvoy/api/v2/core/base.proto=github.com/envoyproxy/data-plane-api/envoy/api/v2/core"
    "Menvoy/type/http_status.proto=github.com/envoyproxy/data-plane-api/envoy/type"
	"Mgogoproto/gogo.proto=github.com/gogo/protobuf/gogoproto"
	"Mgoogle/protobuf/any.proto=github.com/gogo/protobuf/types"
	"Mgoogle/protobuf/duration.proto=github.com/gogo/protobuf/types"
	"Mgoogle/protobuf/struct.proto=github.com/gogo/protobuf/types"
	"Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types"
	"Mgoogle/protobuf/wrappers.proto=github.com/gogo/protobuf/types"
    "Mgoogle/rpc/status.proto=github.com/gogo/googleapis/google/rpc"
)

PROTOC_IMPORTS=" \
    -I $ENVOY_API \
    -I vendor/github.com/gogo/protobuf/protobuf \
    -I vendor/github.com/gogo/protobuf \
    -I vendor/github.com/gogo/googleapis \
    -I vendor/github.com/lyft/protoc-gen-validate"

echo "Building envoy core protos"
protoc \
    $PROTOC_IMPORTS \
    $ENVOY_API/envoy/api/v2/core/address.proto \
    $ENVOY_API/envoy/api/v2/core/base.proto \
    --gogofast_out=plugins=grpc,$(join ',' ${PROTOC_MAPPINGS[@]}):$ENVOY_API

echo "Building envoy type protos"
protoc \
    $PROTOC_IMPORTS \
    $ENVOY_API/envoy/type/http_status.proto \
    --gogofast_out=plugins=grpc,$(join ',' ${PROTOC_MAPPINGS[@]}):$ENVOY_API

echo "Building ext_authz protos"
protoc \
    $PROTOC_IMPORTS \
    $ENVOY_API/envoy/service/auth/v2alpha/*.proto \
    --gogofast_out=plugins=grpc,$(join ',' ${PROTOC_MAPPINGS[@]}):$ENVOY_API
