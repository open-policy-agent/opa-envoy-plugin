# opa-envoy-plugin

[![Build Status](https://github.com/open-policy-agent/opa-envoy-plugin/workflows/Post%20Merge/badge.svg?branch=master)](https://github.com/open-policy-agent/opa-envoy-plugin/actions) [![Go Report Card](https://goreportcard.com/badge/github.com/open-policy-agent/opa-envoy-plugin)](https://goreportcard.com/report/github.com/open-policy-agent/opa-envoy-plugin)

This repository contains an extended version of OPA (**OPA-Envoy**) that allows you to enforce OPA policies with Envoy.

## Issue Management
Use [OPA GitHub Issues](https://github.com/open-policy-agent/opa/issues) to request features or file bugs.

## Examples with Envoy-based service meshes

The OPA-Envoy plugin can be deployed with Envoy-based service meshes such as:

* [Istio](./examples/istio)

## Overview

OPA-Envoy extends OPA with a gRPC server that implements the [Envoy External
Authorization
API](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter.html).
You can use this version of OPA to enforce fine-grained, context-aware access
control policies with Envoy _without_ modifying your microservice.

## How does it work?

In addition to the Envoy sidecar, your application pods will include an OPA
sidecar. When Envoy receives API requests destined for your
microservice, it checks with OPA to decide if the request should be allowed.

Evaluating policies locally with Envoy is preferable because it
avoids introducing a network hop (which has implications on performance and
availability) in order to perform the authorization check.

![arch](./docs/arch.png)

> The example below shows how to run OPA-Envoy in a Kubernetes environment. OPA-Envoy can be deployed outside of
> Kubernetes as well. For example, it can be co-located next to a running Envoy using `docker-compose`.

## Quick Start

This section assumes you are testing with Envoy v1.10.0 or later.

1. Start Minikube.

    ```bash
    minikube start
    ```

1. Install OPA-Envoy.

    ```bash
    kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/opa-envoy-plugin/master/quick_start.yaml
    ```

    The `quick_start.yaml` manifest defines the following resources:

    * A ConfigMap containing an Envoy configuration with an External Authorization Filter to direct authorization checks to the OPA-Envoy sidecar.
    See `kubectl get configmap proxy-config` for details.

    * OPA configuration file, and an OPA policy into ConfigMaps in the namespace where the app will be deployed, e.g., `default`.

    * A Deployment consisting an example Go application with OPA-Envoy and Envoy sidecars. The sample app provides information
    about employees in a company and exposes APIs to `get` and `create` employees. More information about the app
    can be found [here](https://github.com/ashutosh-narkar/go-test-server). The deployment also includes an init container that
    installs iptables rules to redirect all container traffic through the Envoy proxy sidecar. More information can be
    found [here](https://github.com/open-policy-agent/contrib/tree/master/envoy_iptables).

1. Make the application accessible outside the cluster.

    ```bash
    kubectl expose deployment example-app --type=NodePort --name=example-app-service --port=8080
    ```

1. Set the `SERVICE_URL` environment variable to the service’s IP/port.

    **minikube**:

    ```bash
    export SERVICE_PORT=$(kubectl get service example-app-service -o jsonpath='{.spec.ports[?(@.port==8080)].nodePort}')
    export SERVICE_HOST=$(minikube ip)
    export SERVICE_URL=$SERVICE_HOST:$SERVICE_PORT
    echo $SERVICE_URL
    ```

    **minikube (example)**:

    ```bash
    192.168.99.100:31380
    ```

1. Exercise the sample OPA policy.

    For convenience, we’ll want to store Alice’s and Bob’s tokens in environment variables.

    ```bash
    export ALICE_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiZ3Vlc3QiLCJzdWIiOiJZV3hwWTJVPSIsIm5iZiI6MTUxNDg1MTEzOSwiZXhwIjoxNjQxMDgxNTM5fQ.K5DnnbbIOspRbpCr2IKXE9cPVatGOCBrBQobQmBmaeU"
    export BOB_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiJZbTlpIiwibmJmIjoxNTE0ODUxMTM5LCJleHAiOjE2NDEwODE1Mzl9.WCxNAveAVAdRCmkpIObOTaSd0AJRECY2Ch2Qdic3kU8"
    ```

    Check that `Alice` can get employees **but cannot** create one.

    ```bash
    curl -i -H "Authorization: Bearer "$ALICE_TOKEN"" http://$SERVICE_URL/people
    curl -i -H "Authorization: Bearer "$ALICE_TOKEN"" -d '{"firstname":"Charlie", "lastname":"OPA"}' -H "Content-Type: application/json" -X POST http://$SERVICE_URL/people
    ```

   Check that `Bob` can get employees and also create one.

   ```bash
    curl -i -H "Authorization: Bearer "$BOB_TOKEN"" http://$SERVICE_URL/people
    curl -i -H "Authorization: Bearer "$BOB_TOKEN"" -d '{"firstname":"Charlie", "lastname":"Opa"}' -H "Content-Type: application/json" -X POST http://$SERVICE_URL/people
    ```

   Check that `Bob` **cannot** create an employee with the same firstname as himself.

   ```bash
    curl -i  -H "Authorization: Bearer "$BOB_TOKEN"" -d '{"firstname":"Bob", "lastname":"Rego"}' -H "Content-Type: application/json" -X POST http://$SERVICE_URL/people
    ```


## Configuration

To deploy OPA-Envoy include the following container in your Kubernetes Deployments:

```yaml
containers:
- image: openpolicyagent/opa:0.26.0-envoy
  imagePullPolicy: IfNotPresent
  name: opa-envoy
  volumeMounts:
  - mountPath: /config
    name: opa-envoy-config
  args:
  - run
  - --server
  - --addr=localhost:8181
  - --diagnostic-addr=0.0.0.0:8282
  - --config-file=/config/config.yaml
  livenessProbe:
    httpGet:
      path: /health?plugins
      port: 8282
  readinessProbe:
    httpGet:
      path: /health?plugins
      port: 8282
```

The OPA-Envoy configuration file should be volume mounted into the container. Add the following volume to your Kubernetes Deployments:

```yaml
volumes:
- name: opa-envoy-config
  configMap:
    name: opa-envoy-config
```

The OPA-Envoy plugin supports the following configuration fields:


| Field                                               | Required | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `plugins["envoy_ext_authz_grpc"].addr`              | No       | Set listening address of Envoy External Authorization gRPC server. This must match the value configured in the Envoy config. Default: `:9191`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `plugins["envoy_ext_authz_grpc"].path`              | No       | Specifies the hierarchical policy decision path. The policy decision can either be a `boolean` or an `object`. If boolean, `true` indicates the request should be allowed and `false` indicates the request should be denied. If the policy decision is an object, it **must** contain the `allowed` key set to either `true` or `false` to indicate if the request is allowed or not respectively. It can optionally contain a `headers` field to send custom headers to the downstream client or upstream. An optional `body` field can be included in the policy decision to send a response body data to the downstream client. Also an optional `http_status` field can be included to send a HTTP response status code to the downstream client other than `403 (Forbidden)`. Default: `envoy/authz/allow`. |
| `plugins["envoy_ext_authz_grpc"].dry-run`           | No       | Configures the Envoy External Authorization gRPC server to unconditionally return an `ext_authz.CheckResponse.Status` of `google_rpc.Status{Code: google_rpc.OK}`. Default: `false`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `plugins["envoy_ext_authz_grpc"].enable-reflection` | No       | Enables gRPC server reflection on the Envoy External Authorization gRPC server. Default: `false`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `plugins["envoy_ext_authz_grpc"].proto-descriptor`  | No       | Set the path to a pb that enables the capability to decode the raw body to the parsed body. Default: turns this capability off.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

If the configuration does not specify the `path` field, `envoy/authz/allow` will be considered as the default policy
decision path. `data.envoy.authz.allow` will be the name of the policy decision to query in the default case.

The `dry-run` parameter is provided to enable you to test out new policies. You can set `dry-run: true` which will
unconditionally allow requests. Decision logs can be monitored to see what "would" have happened. This is especially
useful for initial integration of OPA or when policies undergo large refactoring.

The `enable-reflection` parameter registers the Envoy External Authorization gRPC server with reflection. After enabling
server reflection, a command line tool such as [grpcurl](https://github.com/fullstorydev/grpcurl) can be used to invoke
RPC methods on the gRPC server. See [gRPC Server Reflection Usage](#grpc-server-reflection-usage) section for more details.

Providing a file containing a protobuf descriptor set allows the plugin to decode gRPC message payloads.
So far, only unary methods using uncompressed protobuf-encoded payloads are supported.
The protoset can be generated using `protoc`, e.g. `protoc --descriptor_set_out=protoset.pb --include_imports`.

Note that gRPC message payload decoding is only available [using the v3 API](#envoy-xds-v2-and-v2).
See [`examples/grpc`](examples/grpc) for an example setup using Envoy, a gRPC service, and opa-envoy-plugin examining the
request payloads.

An example of a rule that returns an object that not only indicates if a request is allowed or not but also provides
optional response headers, body and HTTP status that can be sent to the downstream client or upstream can be seen below
in the [Example Policy with Object Response](#example-policy-with-object-response) section.

### Example Bundle Configuration

In the [Quick Start](#quick-start) section an OPA policy is loaded via a volume-mounted ConfigMap. For production
deployments, we recommend serving policy [Bundles](http://www.openpolicyagent.org/docs/bundles.html) from a remote HTTP server.

Using the configuration shown below, OPA will download a sample bundle from [https://www.openpolicyagent.org](https://www.openpolicyagent.org).
The sample bundle contains the exact same policy that was loaded into OPA via the volume-mounted ConfigMap. More details
about this policy can be found in the [Example Policy](#example-policy) section.

**config.yaml**:

```yaml
services:
  - name: controller
    url: https://www.openpolicyagent.org
bundles:
  envoy/authz:
    service: controller
plugins:
  envoy_ext_authz_grpc:
    addr: :9191
    path: envoy/authz/allow
    dry-run: false
    enable-reflection: false
```

You can download the bundle and inspect it yourself:

```bash
mkdir example && cd example
curl -s -L https://www.openpolicyagent.org/bundles/envoy/authz | tar xzv
```

In this way OPA can periodically download bundles of policy from an external server and hence loading the policy via a
volume-mounted ConfigMap would not be required. The `readinessProbe` to `GET /health?bundles` ensures that the `opa-envoy`
container becomes ready after the bundles are activated.

## Example Policy

The following OPA policy is used in the [Quick Start](#quick-start) section above. This policy restricts access to the
`/people` endpoint exposed by our sample app:

* alice is granted a **guest** role and can perform a `GET` request to `/people`.
* bob is granted an **admin** role and can perform a `GET` and `POST` request to /people.

The policy also restricts an `admin` user, in this case `bob` from creating an employee with the same `firstname` as himself.

The policy uses the `io.jwt.decode_verify` builtin function to parse and verify the JWT containing information
about the user making the request.

```rego
package envoy.authz

import input.attributes.request.http as http_request

default allow = false

token = {"valid": valid, "payload": payload} {
    [_, encoded] := split(http_request.headers.authorization, " ")
    [valid, _, payload] := io.jwt.decode_verify(encoded, {"secret": "secret"})
}

allow {
    is_token_valid
    action_allowed
}

is_token_valid {
  token.valid
  now := time.now_ns() / 1000000000
  token.payload.nbf <= now
  now < token.payload.exp
}

action_allowed {
  http_request.method == "GET"
  token.payload.role == "guest"
  glob.match("/people*", [], http_request.path)
}

action_allowed {
  http_request.method == "GET"
  token.payload.role == "admin"
  glob.match("/people*", [], http_request.path)
}

action_allowed {
  http_request.method == "POST"
  token.payload.role == "admin"
  glob.match("/people", [], http_request.path)
  lower(input.parsed_body.firstname) != base64url.decode(token.payload.sub)
}
```

### Example Input

The `input` value defined for your policy will resemble the JSON below:

```json
{
  "attributes": {
    "source": {
      "address": {
        "socketAddress": {
          "address": "172.17.0.1",
          "portValue": 61402
        }
      }
    },
    "destination": {
      "address": {
        "socketAddress": {
          "address": "172.17.06",
          "portValue": 8000
        }
      }
    },
    "request": {
      "time": "2020-11-20T09:47:47.722473Z",
      "http": {
        "id":"13519049518330544501",
        "method": "POST",
        "headers": {
          ":authority":"192.168.99.206:30164",
          ":method":"POST",
          ":path":"/people?lang=en",
          "accept": "*/*",
          "authorization":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiJZbTlpIiwibmJmIjoxNTE0ODUxMTM5LCJleHAiOjE2NDEwODE1Mzl9.WCxNAveAVAdRCmkpIObOTaSd0AJRECY2Ch2Qdic3kU8",
          "content-length":"41",
          "content-type":"application/json",
          "user-agent":"curl/7.54.0",
          "x-forwarded-proto":"http",
          "x-request-id":"7bca5c86-bf55-432c-b212-8c0f1dc999ec"
        },
        "host":"192.168.99.206:30164",
        "path":"/people?lang=en",
        "protocol":"HTTP/1.1",
        "body":"{\"firstname\":\"Charlie\", \"lastname\":\"Opa\"}",
        "size":41
      }
    },
    "metadataContext": {}
  },
  "parsed_body":{"firstname": "Charlie", "lastname": "Opa"},
  "parsed_path":["people"],
  "parsed_query": {"lang": ["en"]},
  "truncated_body": false,
  "version": {
    "encoding":"protojson",
    "ext_authz":"v3"
  }
}
```
Note that this is the input [using the v3 API](#envoy-xds-v2-and-v2).

<details><summary>See here for an example of v2 input</summary>

```json
{
  "attributes":{
     "source":{
        "address":{
           "Address":{
              "SocketAddress":{
                 "PortSpecifier":{
                    "PortValue":61402
                 },
                 "address":"172.17.0.1"
              }
           }
        }
     },
     "destination":{
        "address":{
           "Address":{
              "SocketAddress":{
                 "PortSpecifier":{
                    "PortValue":8000
                 },
                 "address":"172.17.0.6"
              }
           }
        }
     },
     "request":{
        "http":{
           "id":"13519049518330544501",
           "method":"POST",
           "headers":{
              ":authority":"192.168.99.206:30164",
              ":method":"POST",
              ":path":"/people?lang=en",
              "accept":"*/*",
              "authorization":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiJZbTlpIiwibmJmIjoxNTE0ODUxMTM5LCJleHAiOjE2NDEwODE1Mzl9.WCxNAveAVAdRCmkpIObOTaSd0AJRECY2Ch2Qdic3kU8",
              "content-length":"41",
              "content-type":"application/json",
              "user-agent":"curl/7.54.0",
              "x-forwarded-proto":"http",
              "x-request-id":"7bca5c86-bf55-432c-b212-8c0f1dc999ec"
           },
           "host":"192.168.99.206:30164",
           "path":"/people?lang=en",
           "protocol":"HTTP/1.1",
           "body":"{\"firstname\":\"Charlie\", \"lastname\":\"Opa\"}",
           "size":41
        }
     }
  },
  "parsed_body":{"firstname": "Charlie", "lastname": "Opa"},
  "parsed_path":["people"],
  "parsed_query": {"lang": ["en"]},
  "truncated_body": false,
  "version": {
    "encoding":"encoding/json",
    "ext_authz":"v2"
  }
}
```
</details>

The `parsed_path` field in the input is generated from the `path` field in the HTTP request which is included in the
Envoy External Authorization `CheckRequest` message type. This field provides the request path as a string array which
can help policy authors perform pattern matching on the HTTP request path. The below sample policy allows anyone to
access the path `/people`.

```rego
package envoy.authz

default allow = false

allow {
   input.parsed_path = ["people"]
}
```

The `parsed_query` field in the input is also generated from the `path` field in the HTTP request. This field provides
the HTTP url query as a map of string array. The below sample policy allows anyone to access the path
`/people?lang=en&id=1&id=2`.

```rego
package envoy.authz

default allow = false

allow {
   input.parsed_path = ["people"]
   input.parsed_query.lang = ["en"]
   input.parsed_query.id = ["1", "2"]
}
```

The `parsed_body` field in the input is generated from the `body` field in the HTTP request which is included in the
Envoy External Authorization `CheckRequest` message type. This field contains the deserialized JSON request body which
can then be used in a policy as shown below.

```rego
package envoy.authz

default allow = false

allow {
   input.parsed_body.firstname == "Charlie"
   input.parsed_body.lastname == "Opa"
}
```

The `truncated_body` field in the input represents if the HTTP request body is truncated. The body is considered to be
truncated, if the value of the `Content-Length` header exceeds the size of the request body.


## Example Policy with Object Response

The `allow` rule in the below policy when queried generates an `object` that provides the status of the request
(ie. `allowed` or `denied`) along with some headers, body data and HTTP status which will be included in the response
that is sent back to the downstream client or upstream.

```rego
package envoy.authz

default allow = {
  "allowed": false,
  "headers": {"x-ext-auth-allow": "no"},
  "body": "Unauthorized Request",
  "http_status": 301
}

allow = response {
  input.attributes.request.http.method == "GET"
  response := {
    "allowed": true,
    "headers": {"x-ext-auth-allow": "yes"}
  }
}
```

The following policy shows how to generate an object response with the headers set as an array of values.
The example policy restricts access to the `/admin` path and the `POST` method.

```ruby
package envoy.authz

default allow = {
  "allowed": true,
  "http_status": 200
}

allow = response {
  count(disallowlist) > 0
  response := {
    "allowed": false,
    "body": "Unauthorized Request",
    "http_status": 400,
    "headers": disallowlist
  }
}

disallowlist[reason] {
  input.attributes.request.http.method == "POST"
  reason = {"why": "POST method is not allowed"}
}


disallowlist[reason] {
  input.attributes.request.http.path == "/admin"
  reason = {"why": "/admin path is not allowed"}
}
```

Below is a sample input to the policy:

```json
{
  "attributes": {
    "request": {
      "http": {
        "method": "POST",
        "path": "/admin"
      }
    }
  }
}
```

The following is the response generated by the policy given the above input:

```json
{
  "allowed": false,
  "body": "Unauthorized Request",
  "headers": [
    {
      "why": "/admin path is not allowed"
     },
     {
      "why": "POST method is not allowed"
     }
  ],
  "http_status": 400
}
```

## Example with JWT payload passed from Envoy

Envoy can be configured to pass validated JWT payload data into the `ext_authz` filter with `metadata_context_namespaces`
and `payload_in_metadata`.

### Example Envoy Configuration

```yaml
http_filters:
- name: envoy.filters.http.jwt_authn
  typed_config:
  "@type": type.googleapis.com/envoy.config.filter.http.jwt_authn.v2alpha.JwtAuthentication
  providers:
    example:
      payload_in_metadata: verified_jwt
      <...>
- name: envoy.ext_authz
  config:
    metadata_context_namespaces:
    - envoy.filters.http.jwt_authn
    <...>
```

### Example OPA Input

This will result in something like the following dictionary being added to `input.attributes` (some common fields have
been excluded for brevity):

```
  "metadata_context": {
    "filter_metadata": {
      "envoy.filters.http.jwt_authn": {
        "verified_jwt": {
          "email": "alice@example.com",
          "exp": 1569026124,
          "name": "Alice"
        }
      }
    }
  }
```

### Example OPA Policy

This JWT data can be accessed in OPA policy like this:

```rego
jwt_payload = input.attributes.metadata_context.filter_metadata["envoy.filters.http.jwt_authn"].verified_jwt

allow {
  jwt_payload.email == "alice@example.com"
}
```

## Envoy xDS v2 and v2

This plugin exposes both versions. For v3 requests, the [specified JSON mapping for protobuf](https://developers.google.com/protocol-buffers/docs/proto3#json)
is used for making the incoming `envoy.service.auth.v3.CheckRequest` available in `input`.
It differs from the encoding
used for v2 requests:

In v3, all keys are lower camelcase. Also, needless nesting of oneof values is removed.

For example, source address data that looks like this in v2,
```
"source": {
  "address": {
    "Address": {
      "SocketAddress": {
        "PortSpecifier": {
          "PortValue": 59052
        },
        "address": "127.0.0.1"
      }
    }
  }
}
```

becomes, in v3,
```
"source": {
  "address": {
    "socketAddress": {
      "address": "127.0.0.1",
      "portValue": 59052
    }
  }
}
```

The following table shows the rego code for common data, in v2 and v3:


| information         |  rego v2 | rego v3 |
|---------------------|----------|---------|
| source address      | `input.attributes.source.address.Address.SocketAddress.address` | `input.attributes.source.address.socketAddress.address`|
| source port         | `input.attributes.source.address.Address.SocketAddress.PortSpecifier.PortValue` | `input.attributes.source.address.socketAddress.portValue`|
| destination address | `input.attributes.destination.address.Address.SocketAddress.address` | `input.attributes.destination.address.socketAddress.address`|
| destination port    | `input.attributes.destination.address.Address.SocketAddress.PortSpecifier.PortValue` | `input.attributes.destination.address.socketAddress.portValue`|
| dynamic metadata    | `input.attributes.metadata_context.filter_metadata` | `input.attributes.metadataContext.filterMetadata` |

Due to those differences, it's important to know which version is used when writing policies.
Thus this information is passed into the OPA evaluation under `input.version`, where you'll either
find, for v2,

```rego
input.version == { "ext_authz": "v2", "encoding": "encoding/json" }
```

or, for v3,

```rego
input.version == { "ext_authz": "v3", "encoding": "protojson" }
```

This information can also be used to create policies that are compatible with both versions and
encodings.

To have Envoy use the v3 version of the service, it will need to be configured to do so.
The http_filters entry should look like this (minimal version):
```yaml
http_filters:
- name: envoy.ext_authz
  typed_config:
    '@type': type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    grpc_service:
      google_grpc: # or envoy_grpc
        target_uri: "127.0.0.1:9191"
```

Note that further settings are required to have (raw) request bodies forwarded to the ext authz
service.

For the use in Istio, _at least_ Istio 1.7.0 is **required** to use a v3 ExtAuthz filter, [see
the 1.7.0 release notes](https://istio.io/latest/news/releases/1.7.x/announcing-1.7/upgrade-notes/#envoyfilter-syntax-change) for details.
<!-- NOTE(sr): https://github.com/istio/istio/commit/e0e53ee9190049a0126490f3b9b59cb3f3210620 -->

When using grpcurl (see below) you can choose with which version to interact.

## gRPC Server Reflection Usage

This section provides examples of interacting with the Envoy External Authorization gRPC server using the `grpcurl` tool.

* List all services exposed by the server

  ```bash
  $ grpcurl -plaintext localhost:9191 list
  ```

  Output:

  ```bash
  envoy.service.auth.v2.Authorization
  envoy.service.auth.v3.Authorization
  grpc.reflection.v1alpha.ServerReflection
  ```

* Invoke a v3 Check RPC on the server

  ```bash
  $ grpcurl -plaintext -d '
  {
    "attributes": {
      "request": {
        "http": {
          "method": "GET",
          "path": "/api/v1/products"
        }
      }
    }
  }' localhost:9191 envoy.service.auth.v3.Authorization/Check
  ```

  Output:

  ```
  {
    "status": {

    },
    "okResponse": {
      "headers": [
        {
          "header": {
            "key": "x-ext-auth-allow",
            "value": "yes"
          }
        }
      ]
    }
  }
  ```

## Dependencies

Dependencies are managed with [Modules](https://github.com/golang/go/wiki/Modules).
If you need to add or update dependencies, modify the `go.mod` file or
use `go get`. More information is available [here](https://github.com/golang/go/wiki/Modules#how-to-upgrade-and-downgrade-dependencies).
Finally commit all changes to the repository.
