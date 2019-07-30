# opa-istio-plugin

[![Build Status](https://travis-ci.org/open-policy-agent/opa-istio-plugin.svg?branch=master)](https://travis-ci.org/open-policy-agent/opa-istio-plugin) [![Go Report Card](https://goreportcard.com/badge/github.com/open-policy-agent/opa-istio-plugin)](https://goreportcard.com/report/github.com/open-policy-agent/opa-istio-plugin)

This repository contains an extended version of OPA (**OPA-Istio**) that allows you to enforce OPA
policies at the Istio Proxy layer.

## Issue Management
Use [OPA GitHub Issues](https://github.com/open-policy-agent/opa/issues) to request features or file bugs.

## Overview

OPA-Istio extends OPA with a gRPC server that implements the [Envoy External
Authorization
API](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/ext_authz_filter).
You can use this version of OPA to enforce fine-grained, context-aware access
control policies at the Istio Proxy layer without modifying your microservice.

## How does it work?

In addition to the Istio Proxy/Envoy sidecar, your application pods will include an OPA
sidecar. When Istio Proxy receives API requests destined for your
microservice, it checks with OPA to decide if the request should be allowed.

Evaluating policies locally at the Istio Proxy layer is preferable because it
avoids introducing a network hop (which has implications on performance and
availability) in order to perform the authorization check.

![arch](./docs/arch.png)

## Quick Start

This section assumes you are testing with Istio v1.1.0 or later.

This section assumes you have Istio deployed on top of Kubernetes. See Istio's [Quick Start](https://istio.io/docs/setup/kubernetes/install/kubernetes/) page to get started.

1. Install OPA-Istio.

    ```bash
    kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/opa-istio-plugin/master/quick_start.yaml
    ```

    The `quick_start.yaml` manifest defines the following resources:

    * External Authorization Filter to direct authorization checks to the OPA-Istio sidecar. See `kubectl -n istio-system get envoyfilter ext-authz` for details.

    * Kubernetes namespace (`opa-istio`) for OPA-Istio control plane components.

    * Kubernetes admission controller in the `opa-istio` namespace that automatically injects the OPA-Istio sidecar into pods in namespaces labelled with `opa-istio-injection=enabled`.

    * OPA configuration file and an OPA policy into ConfigMaps in the namespace where the app will be deployed, e.g., `default`.

1. Enable automatic injection of the Istio Proxy and OPA-Istio sidecars in the namespace where the app will be deployed, e.g., `default`.

    ```bash
    kubectl label namespace default opa-istio-injection="enabled"
    kubectl label namespace default istio-injection="enabled"
    ```

1. Deploy the BookInfo application and make it accessible outside the cluster.

    ```bash
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/master/samples/bookinfo/platform/kube/bookinfo.yaml
    ```

    ```bash
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/master/samples/bookinfo/networking/bookinfo-gateway.yaml
    ```

1. Set the `GATEWAY_URL` environment variable in your shell to the public
IP/port of the Istio Ingress gateway.

    **minikube**:

    ```bash
    export INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].nodePort}')
    export INGRESS_HOST=$(minikube ip)
    export GATEWAY_URL=$INGRESS_HOST:$INGRESS_PORT
    echo $GATEWAY_URL
    ```

    **minikube (example)**:

    ```bash
    192.168.99.100:31380
    ```

    For other platforms see the [Istio documentation on determining ingress IP and ports.](https://istio.io/docs/tasks/traffic-management/ingress/#determining-the-ingress-ip-and-ports)

1. Exercise the sample policy. Check that **alice** can access `/productpage` **BUT NOT** `/api/v1/products`.

    ```bash
    curl --user alice:password -i http://$GATEWAY_URL/productpage
    curl --user alice:password -i http://$GATEWAY_URL/api/v1/products
    ```

1. Exercise the sample policy. Check that **bob** can access `/productpage` **AND** `/api/v1/products`.

    ```bash
    curl --user bob:password -i http://$GATEWAY_URL/productpage
    curl --user bob:password -i http://$GATEWAY_URL/api/v1/products
    ```

## Configuration

To deploy OPA-Istio include the following container in your Kubernetes Deployments:

```yaml
containers:
- image: openpolicyagent/opa:0.12.1-istio
  imagePullPolicy: IfNotPresent
  name: opa-istio
  volumeMounts:
  - mountPath: /config
    name: opa-istio-config
  args:
  - run
  - --server
  - --config-file=/config/config.yaml
```

The OPA-Istio configuration file should be volume mounted into the container. Add the following volume to your Kubernetes Deployments:

```yaml
volumes:
- name: opa-istio-config
  configMap:
    name: opa-istio-config
```

The OPA-Istio plugin supports the following configuration fields:

| Field | Required | Description |
| --- | --- | --- |
| `plugins["envoy_ext_authz_grpc"].addr` | No | Set listening address of Envoy External Authorization gRPC server. This must match the value configured in the Envoy Filter resource. Default: `:9191`. |
| `plugins["envoy_ext_authz_grpc"].query` | No | Specifies the name of the policy decision to query. The policy decision can either be a `boolean` or an `object`. If boolean, `true` indicates the request should be allowed and `false` indicates the request should be denied. If the policy decision is an object, it **must** contain the `allowed` key set to either `true` or `false` to indicate if the request is allowed or not respectively. It can optionally contain a `headers` field to send custom headers to the downstream client or upstream. An optional `body` field can be included in the policy decision to send a response body data to the downstream client. Also an optional `http_status` field can be included to send a HTTP response status code to the downstream client other than `403 (Forbidden)`. Default: `data.istio.authz.allow`.|
| `plugins["envoy_ext_authz_grpc"].dry-run` | No | Configures the Envoy External Authorization gRPC server to unconditionally return an `ext_authz.CheckResponse.Status` of `google_rpc.Status{Code: google_rpc.OK}`. Default: `false`. |

If the configuration does not specify the `query` field, `data.istio.authz.allow` will be considered as the default name of the policy decision to query.

The `dry-run` parameter is provided to enable you to test out new policies. You can set `dry-run: true` which will unconditionally allow requests. Decision logs can be monitored to see what "would" have happened. This is especially useful for initial integration of OPA or when policies undergo large refactoring.

An example of a rule that returns an object that not only indicates if a request is allowed or not but also provides optional response headers, body and HTTP status that can be sent to the downstream client or upstream can be seen below in the [Example Policy with Object Response](#example-policy-with-object-response) section.

In the [Quick Start](#quick-start) section an OPA policy is loaded via a volume-mounted ConfigMap. For production deployments, we recommend serving policy [Bundles](http://www.openpolicyagent.org/docs/bundles.html) from a remote HTTP server. For example:

**config.yaml**:

```yaml
services:
  - name: default
    url: https://example.com                           # replace with your bundle service base URL
    credentials:                                       # replace with your bundle service credentials
      bearer:
        scheme: "Bearer"
        token: "BrXpzQ2cHXV06H0-8xSe79agaTiM5wPurYGS"
bundle:
  name: istio/authz
  service: bundle_service
plugins:
    envoy_ext_authz_grpc:
        addr:    :9191
        query:   data.istio.authz.allow
        dry-run: false
```

## Example Policy

The following OPA policy is used in the [Quick Start](#quick-start) section above. This policy restricts access to the BookInfo such that:

* Alice is granted a __guest__ role and can access the `/productpage` frontend BUT NOT the `/v1/api/products` backend.
* Bob is granted an __admin__ role and can access the `/productpage` frontend AND the `/v1/api/products` backend.

```ruby
package istio.authz

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
        {"method": "GET",  "path": "/productpage"},
    ],
    "admin": [
        {"method": "GET",  "path": "/productpage"},
        {"method": "GET",  "path": "/api/v1/products"},
    ],
}
```

### Example Input

The `input` value defined for your policy will resemble the JSON below:

```json
{
  "parsed_path": ["api", "v1", "products"],
  "attributes": {
    "source": {
      "address": {
        "Address": {
          "SocketAddress": {
            "address": "172.17.0.10",
            "PortSpecifier": {
              "PortValue": 36472
            }
          }
        }
      }
    },
    "destination": {
      "address": {
        "Address": {
          "SocketAddress": {
            "address": "172.17.0.17",
            "PortSpecifier": {
              "PortValue": 9080
            }
          }
        }
      }
    },
    "request": {
      "http": {
        "id": "13359530607844510314",
        "method": "GET",
        "headers": {
          ":authority": "192.168.99.100:31380",
          ":method": "GET",
          ":path": "/api/v1/products",
          "accept": "*/*",
          "authorization": "Basic YWxpY2U6cGFzc3dvcmQ=",
          "content-length": "0",
          "user-agent": "curl/7.54.0",
          "x-b3-sampled": "1",
          "x-b3-spanid": "537f473f27475073",
          "x-b3-traceid": "537f473f27475073",
          "x-envoy-internal": "true",
          "x-forwarded-for": "172.17.0.1",
          "x-forwarded-proto": "http",
          "x-istio-attributes": "Cj4KE2Rlc3RpbmF0aW9uLnNlcnZpY2USJxIlcHJvZHVjdHBhZ2UuZGVmYXVsdC5zdmMuY2x1c3Rlci5sb2NhbApPCgpzb3VyY2UudWlkEkESP2t1YmVybmV0ZXM6Ly9pc3Rpby1pbmdyZXNzZ2F0ZXdheS02Nzk5NWM0ODZjLXFwOGpyLmlzdGlvLXN5c3RlbQpBChdkZXN0aW5hdGlvbi5zZXJ2aWNlLnVpZBImEiRpc3RpbzovL2RlZmF1bHQvc2VydmljZXMvcHJvZHVjdHBhZ2UKQwoYZGVzdGluYXRpb24uc2VydmljZS5ob3N0EicSJXByb2R1Y3RwYWdlLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwKKgodZGVzdGluYXRpb24uc2VydmljZS5uYW1lc3BhY2USCRIHZGVmYXVsdAopChhkZXN0aW5hdGlvbi5zZXJ2aWNlLm5hbWUSDRILcHJvZHVjdHBhZ2U=",
          "x-request-id": "92a6c0f7-0250-944b-9cfc-ae10cbcedd8e"
        },
        "path": "/api/v1/products",
        "host": "192.168.99.100:31380",
        "protocol": "HTTP/1.1"
      }
    }
  }
}
```

The `parsed_path` field in the input is generated from the `path` field in the HTTP request which is included in the Envoy External Authorization `CheckRequest` message type. This field provides the request path as a string array which can help policy authors perform pattern matching on the HTTP request path. The below sample policy allows anyone to access the path `/api/v1/products`.

```ruby
package istio.authz

default allow = false

allow {
   input.parsed_path = ["api", "v1", "products"]
}
```

## Example Policy with Object Response

The `allow` rule in the below policy when queried generates an `object` that provides the status of the request (ie. `allowed` or `denied`) alongwith some headers, body data and HTTP status which will be included in the response that is sent back to the downstream client or upstream.

```ruby
package istio.authz

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

## Dependencies

Dependencies are managed with [dep](https://golang.github.io/dep/).
If you need to add or update dependencies, modify the `Gopkg.toml` file and
then use the `dep ensure` command. Finally commit all changes to the
repository.
