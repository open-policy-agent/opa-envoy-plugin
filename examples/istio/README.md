## Overview

OPA-Envoy extends OPA with a gRPC server that implements the [Envoy External
Authorization
API](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter.html).
You can use this version of OPA to enforce fine-grained, context-aware access
control policies at the Istio Proxy layer without modifying your microservice.

## How does it work?

In addition to the Istio Proxy/Envoy sidecar, your application pods will include an OPA
sidecar. When Istio Proxy receives API requests destined for your
microservice, it checks with OPA to decide if the request should be allowed.

Evaluating policies locally at the Istio Proxy layer is preferable because it
avoids introducing a network hop (which has implications on performance and
availability) in order to perform the authorization check.

![arch](./arch.png)

See Istio's [External Authoriation](https://istio.io/latest/docs/tasks/security/authorization/authz-custom/) documentation and [Better External Authorization
](https://istio.io/latest/blog/2021/better-external-authz/) blog post for more information about the Istio configuration.

## Quick Start

This section assumes you are testing with Istio v1.9.0 or later. (Support for CUSTOM AuthorizationPolicies is required.)

This section installs Istio using the [Istio operator](https://istio.io/latest/docs/setup/install/operator/) on top of Kubernetes.

1. Install Istio operator

   ```bash
   kubectl create namespace istio-system  # Not needed with Istio v1.10+, created by operator automatically
   istioctl operator init
   ```

   Create the IstioOperator resource to create the Istio control plane. The configuration includes an `envoyExtAuthzGrpc` extension provider named `opa-istio` for performing external authorization.

   ```bash
   kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/opa-envoy-plugin/main/examples/istio/istiooperator.yaml
   ```

   Wait for Istio to finish installing. The following command should show `HEALTHY`:

   ```bash
   kubectl get -n istio-system istiooperator istiocontrolplane -o 'jsonpath={.status.status}{"\n"}'
   ```

1. Install OPA-Envoy.

    ```bash
    kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/opa-envoy-plugin/main/examples/istio/quick_start.yaml
    ```

    The `quick_start.yaml` manifest defines the following resources:

    * Kubernetes namespace (`opa-istio`) for OPA-Envoy control plane components.

    * A localhost `external-authz-grpc-local` ServiceEntry which is referenced by the `envoyExtAuthzGrpc` extension provider.

    * Kubernetes admission controller in the `opa-istio` namespace that automatically injects the OPA-Envoy sidecar into pods in namespaces labelled with `opa-istio-injection=enabled`.

    * OPA configuration file and an OPA policy into ConfigMaps in the namespace where the app will be deployed, e.g., `default`.

1. Enable automatic injection of the Istio Proxy and OPA-Envoy sidecars in the namespace where the app will be deployed, e.g., `default`.

    ```bash
    kubectl label namespace default opa-istio-injection="enabled"
    kubectl label namespace default istio-injection="enabled"
    ```

1.  Create an CUSTOM AuthorizationPolicy that references the `opa-istio` provider in the namespace where the app will be deployed, e.g., `default`.

    This sample policy sends all requests through OPA (an empty rule is used), but the rules can be customized to use OPA for only some requests.

    ```bash
    kubectl apply -n default -f https://raw.githubusercontent.com/open-policy-agent/opa-envoy-plugin/main/examples/istio/authz.yaml
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
## Controlling the injection policy at the pod level

If you want to control the injection policy at the pod level, set the `sidecar.opa-istio.io/inject` label to `false` on the pod.
An example of the updated admission controller configuration is shown below:
```yaml
objectSelector:
  matchExpressions:
  - key: sidecar.opa-istio.io/inject
    operator: NotIn
    values:
    - "false"
```

## Example Bundle Configuration

In the [Quick Start](#quick-start) section an OPA policy is loaded via a volume-mounted ConfigMap. For production deployments,
we recommend serving policy [Bundles](http://www.openpolicyagent.org/docs/bundles.html) from a remote HTTP server.

Using the configuration shown below, OPA will download a sample bundle from [https://www.openpolicyagent.org](https://www.openpolicyagent.org).
The sample bundle contains the exact same policy that was loaded into OPA via the volume-mounted ConfigMap. More details
about this policy can be found in the [Example Policy](#example-policy) section.

**config.yaml**:

```yaml
services:
  - name: controller
    url: https://www.openpolicyagent.org
bundles:
  istio/authz:
    service: controller
plugins:
    envoy_ext_authz_grpc:
        addr: :9191
        path: istio/authz/allow
        dry-run: false
        enable-reflection: false
```

You can download the bundle and inspect it yourself:

```bash
mkdir example && cd example
curl -s -L https://www.openpolicyagent.org/bundles/istio/authz | tar xzv
```

> To allow OPA to access the sample bundle from [https://www.openpolicyagent.org](https://www.openpolicyagent.org), create a `ServiceEntry` as shown below:
> ```bash
> $ kubectl apply -f - <<EOF
> apiVersion: networking.istio.io/v1alpha3
> kind: ServiceEntry
> metadata:
>   name: opa-bundle
> spec:
>   hosts:
>    - www.openpolicyagent.org
>   ports:
>   - number: 443
>     name: https
>     protocol: HTTPS
>   resolution: DNS
>   location: MESH_EXTERNAL
>EOF
>```

In this way OPA can periodically download bundles of policy from an external server and hence loading the policy via a
volume-mounted ConfigMap would not be required. The `readinessProbe` to `GET /health?bundles` ensures that the
OPA-Envoy sidecar container becomes ready after the bundles are activated.

## Example Policy

The following OPA policy is used in the [Quick Start](#quick-start) section above. This policy restricts access to the BookInfo such that:

* Alice is granted a __guest__ role and can access the `/productpage` frontend BUT NOT the `/v1/api/products` backend.
* Bob is granted an __admin__ role and can access the `/productpage` frontend AND the `/v1/api/products` backend.

```ruby
package istio.authz

import input.attributes.request.http as http_request
import input.parsed_path

default allow = false

allow {
    roles_for_user[r]
    required_roles[r]
}

# allow health checks of the opa sidecar
allow {
    parsed_path[0] == "health"
    http_request.method == "GET"
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
  "parsed_query": {"lang": ["en"]},
  "parsed_body":  {"id": "ext1", "name": "opa_authz"},
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
          ":path": "/api/v1/products?lang=en",
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
        "path": "/api/v1/products?lang=en",
        "host": "192.168.99.100:31380",
        "protocol": "HTTP/1.1",
        "body": "{\"id\": \"ext1\", \"name\": \"opa_authz\"}"
      }
    }
  }
}
```

The `parsed_path` field in the input is generated from the `path` field in the HTTP request which is included in the
Envoy External Authorization `CheckRequest` message type. This field provides the request path as a string array which
can help policy authors perform pattern matching on the HTTP request path. The below sample policy allows anyone to access the path `/api/v1/products`.

```ruby
package istio.authz

default allow = false

allow {
   input.parsed_path = ["api", "v1", "products"]
}
```

The `parsed_query` field in the input is also generated from the `path` field in the HTTP request. This field provides
the HTTP url query as a map of string array. The below sample policy allows anyone to access the path `/api/v1/products?lang=en&id=1&id=2`.


```ruby
package istio.authz

default allow = false

allow {
   input.parsed_path = ["api", "v1", "products"]
   input.parsed_query.lang = ["en"]
   input.parsed_query.id = ["1", "2"]
}
```

The `parsed_body` field in the input is generated from the `body` field in the HTTP request which is included in the
Envoy External Authorization `CheckRequest` message type. This field contains the deserialized JSON request body
which can then be used in a policy as shown below.

```ruby
package istio.authz

default allow = false

allow {
   input.parsed_body.id == "ext1"
   input.parsed_body.name == "opa_authz"
}
```
