# Envoy and gRPC example

The docker-compose.yaml file defines three services:
1. testsrv, a gRPC server used for testing, created by [fullstorydev](https://github.com/fullstorydev/grpcui/tree/master/testing/cmd/testsvr)
2. opa-envoy-plugin, equipped with the descriptor set for testsrv
3. Envoy, configured to use opa-envoy-plugin as ext_authz service, using the v3 API,
   and including the request payloads _as bytes_:
   ```yaml
   - name: envoy.ext_authz
     typed_config:
       '@type': type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
       transport_api_version: V3
       failure_mode_allow: false
       grpc_service:
         envoy_grpc:
           cluster_name: opa-envoy
       with_request_body:
         allow_partial_message: true
         max_request_bytes: 1024
         pack_as_bytes: true
   ```

After spinning them up with `docker compose up`, they can be exercised
using a gRPC client.

This is an example invocation using `grpcurl`:

```interactive
$ grpcurl -plaintext -protoset testsrv.pb 127.0.0.1:51051 test.KitchenSink/Ping
{

}
$ grpcurl -plaintext -protoset testsrv.pb 127.0.0.1:51051 test.KitchenSink/Exchange
ERROR:
  Code: PermissionDenied
  Message:
$ grpcurl -d @ -plaintext -protoset testsrv.pb 127.0.0.1:51051 test.KitchenSink/Exchange < message.json
{
  "person": {
    "id": "123",
    "name": "alice",
    "parent": {
      "id": "122",
      "name": "bob"
    }
  },
  "state": "AWAITING_INPUT",
  "neededNumA": 1.23,
  "neededNumB": 1.23,
  "opaqueId": "asdf",
  "wk": {
    "now": "2020-12-02T09:48:42.118723Z",
    "period": "30s",
    "neat": {
      "@type": "googleapis.com/google.protobuf.StringValue",
      "value": "Hithere"
    },
    "object": {
        "foo": "bar"
      },
    "value": "string",
    "list": [
        "zero",
        "one",
        "infinity"
      ],
    "bytes": "AAAA",
    "string": "abcd",
    "bool": true,
    "double": 0.12,
    "float": 0.12,
    "smallInt": 1,
    "bigInt": "2",
    "smallId": 100,
    "bigId": "101"
  }
}
```

The policy used in this example, `policy.rego`, is quite artificial, but allows us
to show how different protobuf fields are going to look like when made available to
OPA. The service definition used can be found in `testsrv/test.proto`.
