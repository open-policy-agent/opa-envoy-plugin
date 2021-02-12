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

```rego
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

## Envoy xDS v2 and v3

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

## Performance

This section provides some performance benchmarks that give an idea of the overhead of using the OPA-Envoy plugin.

### Test Setup

The setup uses the same example Go application that's described in the [Quick Start](#quick-start) section above. Below
are some more details about the setup:

* Platform: Minikube
* Kubernetes Version: 1.18.6
* Envoy Version: 1.10.0
* OPA-Envoy Version: 0.26.0-envoy

### Benchmarks

The benchmark result below provides the percentile distribution of the latency observed by sending *100 requests/sec*
to the sample application. Each request makes a `GET` call to the `/people` endpoint exposed by the application.

The graph shows the latency distribution when the load test is performed under the following conditions:

1. **App Only**

In this case, the graph documents the latency distribution observed when requests are
sent directly to the application ie. no Envoy and OPA in the request path. This scenario is depicted by the
`blue` curve.

2. **App and Envoy**

In this case, the distribution is with [Envoy External
Authorization
API](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter.html) disabled. This means
OPA is not included in the request path but Envoy is. This scenario is depicted by the `red` curve.

3. **App, Envoy and OPA (NOP policy)**

In the case, we will see the latency observed with [Envoy External
Authorization
API](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter.html) enabled. This means
Envoy will make a call to OPA on every incoming request. The graph explores the effect of loading the below NOP policy into
OPA. This scenario is depicted by the `green` curve.

```rego
package envoy.authz

default allow = true
```

4. **App, Envoy and OPA (RBAC policy)**

In the case, we will see the latency observed with [Envoy External
Authorization
API](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter.html) enabled and
explore the effect of loading the following RBAC policy into OPA. This scenario is depicted by the `yellow` curve.

```rego
package envoy.authz

import input.attributes.request.http as http_request

default allow = false

allow {
    roles_for_user[r]
    required_roles[r]
}

roles_for_user[r] {
    r := user_roles[user_name][_]
}

required_roles[r] {
    perm := role_perms[r][_]
    perm.method = http_request.method
    perm.path = http_request.path
}

user_name = parsed {
    [_, encoded] := split(http_request.headers.authorization, " ")
    [parsed, _] := split(base64url.decode(encoded), ":")
}

user_roles = {
    "alice": ["guest"],
    "bob": ["admin"]
}

role_perms = {
    "guest": [
        {"method": "GET",  "path": "/people"},
    ],
    "admin": [
        {"method": "GET",  "path": "/people"},
    ],
}
```

![hist_100](./docs/hist_google_grpc_100.png)

The above four scenarios are replicated to measure the latency distribution now by sending *1000 requests/sec*
to the sample application. The following graph captures this result.

![hist_1000](./docs/hist_google_grpc_1000.png)

#### OPA Benchmarks

The table below captures the `gRPC Server Handler` and `OPA Evaluation` time with [Envoy External
Authorization
API](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter.html) enabled and the
`RBAC` policy described above loaded into OPA. All values are in microseconds.

##### OPA Evaluation

`OPA Evaluation` is the time taken to evaluate the policy.

| Number of Requests per sec | 75% | 90% | 95% | 99% | 99.9% | 99.99% | Mean | Median |
|:--------------------------:|:---:|:---:|:---:|:---:|:-----:|:------:|:----:|:------:|
| 10 | 467.122 | 571.028 | 579.272 | 579.272 | 579.272 | 579.272 | 437.282 | 437.367 |
| 100 | 374.714 | 439.620 | 502.146 | 736.478 | 737.025 | 737.025 | 326.840 | 307.902 |
| 1000 | 251.582 | 386.282 | 526.037 | 1513.457 | 5627.604 | 5629.248 | 269.490 | 202.471 |
| 2000 | 223.174 | 463.464 | 1461.558 | 3456.464 | 8251.585 | 8289.024 | 345.520 | 168.145 |
| 3000 | 253.609 | 660.672 | 2171.718 | 6878.808 | 149920.172 | 152030.931 | 800.997 | 163.617 |
| 4000 | 266.848 | 625.534 | 1957.568 | 18970.466 | 152209.408 | 153406.983 | 1010.549 | 162.288 |
| 5000 | 302.344 | 1153.263 | 2283.017 | 6149.344 | 131990.115 | 132097.885 | 984.640 | 170.703 |

##### gRPC Server Handler

`gRPC Server Handler` is the total time taken to prepare the input for the policy, evaluate the policy (`OPA Evaluation`)
and prepare the result.

| Number of Requests per sec | 75% | 90% | 95% | 99% | 99.9% | 99.99% | Mean | Median |
|:--------------------------:|:---:|:---:|:---:|:---:|:-----:|:------:|:----:|:------:|
| 10 | 919.938 | 1156.589 | 1181.885 | 1181.885 | 1181.885 | 1181.885 | 766.204 | 732.136 |
| 100 | 681.010 | 777.223 | 857.337 | 1543.975 | 1544.085 | 1544.085 | 580.151 | 541.035 |
| 1000 | 430.083 | 622.528 | 1070.177 | 3000.366 | 6792.175 | 6793.221 | 461.363 | 346.520 |
| 2000 | 386.011 | 992.878 | 2292.579 | 5387.087 | 8935.611 | 8951.691 | 552.703 | 274.954 |
| 3000 | 458.886 | 2169.441 | 4609.724 | 48793.693 | 296123.974 | 299798.509 | 2364.095 | 270.948 |
| 4000 | 523.895 | 3168.597 | 8197.937 | 127324.217 | 210427.167 | 212126.793 | 3990.733 | 274.938 |
| 5000 | 556.581 | 2442.139 | 3943.508 | 9178.572 | 303796.678 | 309531.296 | 1283.640 | 294.794 |

In the analysis so far, the gRPC client used in Envoy's External authorization filter configuration is the [Google C++ gRPC client](https://github.com/grpc/grpc).
The following graph displays the latency distribution for the same four conditions described previously (ie. *App Only*,
*App and Envoy*, *App, Envoy and OPA (NOP policy)* and *App, Envoy and OPA (RBAC policy)*) by sending *100 requests/sec*
to the sample application but now using Envoy’s in-built gRPC client.

![hist_100_envoy](./docs/hist_envoy_grpc_100.png)

The below graph captures the latency distribution when *1000 requests/sec* are sent to the sample application and
Envoy’s in-built gRPC client is used.

![hist_1000_envoy](./docs/hist_envoy_grpc_1000.png)

The following graphs show the latency distribution for the *App, Envoy and OPA (NOP policy)* and *App, Envoy and OPA (RBAC policy)*
condition and plot the latencies seen by using the Google C++ gRPC client and Envoy’s in-built gRPC client in the
External authorization filter configuration. The first graph is when *100 requests/sec* are sent to the application
while the second one for *1000 requests/sec*.

![hist_100_google_vs_envoy](./docs/hist_google_vs_envoy_grpc_100.png)

![hist_1000_google_vs_envoy](./docs/hist_google_vs_envoy_grpc_1000.png)

### Debugging Performance Issues

This section provides some pointers that could assist in debugging performance issues encountered while using the
OPA-Envoy plugin.

#### Benchmarking Queries

The `opa bench` command evaluates a Rego query multiple times and reports metrics. You can also profile your polices using
`opa eval` to understand expression evaluation time. More information on improving policy performance can be found [here](https://www.openpolicyagent.org/docs/latest/policy-performance/).

#### Analyzing Decision Logs

The OPA-Envoy plugin logs every decision that it makes. These logs contain lots of useful information including metrics like
gRPC server handler time and Rego query evaluation time which can help in measuring the OPA-Envoy plugin's performance.
To enable local console logging of decisions see [this](https://www.openpolicyagent.org/docs/latest/management/#local-decision-logs).

#### Envoy External Authorization Filter Configuration

Envoy's External authorization gRPC service configuration uses either Envoy’s in-built gRPC client, or the Google C++ gRPC client.
From the results above, lower latency numbers are seen while using Envoy’s gRPC client versus Google's. Experimenting
with the gRPC service configuration may help in improving performance.

The filter configuration also has a `status_on_error` field that can be used to indicate a network error between the filter
and the OPA-Envoy plugin. The default status on such an error is HTTP `403 Forbidden`. Changing the default value of this
field will help uncover potential network issues as `403 Forbidden` is also generated when a request is denied.

## Dependencies

Dependencies are managed with [Modules](https://github.com/golang/go/wiki/Modules).
If you need to add or update dependencies, modify the `go.mod` file or
use `go get`. More information is available [here](https://github.com/golang/go/wiki/Modules#how-to-upgrade-and-downgrade-dependencies).
Finally commit all changes to the repository.
