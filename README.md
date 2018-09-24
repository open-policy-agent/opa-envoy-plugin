# opa-istio-plugin

[![Build Status](https://travis-ci.org/open-policy-agent/opa-istio-plugin.svg?branch=master)](https://travis-ci.org/open-policy-agent/opa-istio-plugin) [![Go Report Card](https://goreportcard.com/badge/github.com/open-policy-agent/opa-istio-plugin)](https://goreportcard.com/report/github.com/open-policy-agent/opa-istio-plugin)

This repository contains an extended version of OPA (**OPA-Istio**) that allows you to enforce OPA
policies at the Istio Proxy layer.

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

This section assumes you are testing with Istio v1.0.0 or later.

This section assumes you have Istio deployed on top of Kubernetes. See Istio's [Quick Start](https://istio.io/docs/setup/kubernetes/quick-start.html) page to get started.

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
- image: openpolicyagent/opa:0.9.2-istio
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
| `plugins["envoy.ext_authz.grpc"].addr` | No | Set listening address of Envoy External Authorization gRPC server. This must match the value configured in the Envoy Filter resource. Default: `:9191`. |
| `plugins["envoy.ext_authz.grpc"].query` | No | Specifies the name of the policy decision to query. The policy decision must be return a `boolean` value. `true` indicates the request should be allowed and `false` indicates the request should be denied. Default: `data.istio.authz.allow`. |

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
    envoy.ext_authz.grpc:
        addr: :9191
        query: data.istio.authz.allow
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

## Dependencies

Dependencies are managed with [Glide](https://github.com/Masterminds/glide).
If you need to add or update dependencies, modify the `glide.yaml` file and
then run `glide update --strip-vendor` and then commit all changes to the
repository. You will need to have Glide v0.13 or newer installed.

If you update any of the gRPC, protobuf, or
`github.com/envoyproxy/data-plane-api` dependencies, you should regenerate
the Go code that depends on them by running `gen-protos.sh` in this directory.