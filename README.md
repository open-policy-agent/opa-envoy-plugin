# opa-istio-plugin

[![Build Status](https://travis-ci.org/open-policy-agent/opa-istio-plugin.svg?branch=master)](https://travis-ci.org/open-policy-agent/opa-istio-plugin) [![Go Report Card](https://goreportcard.com/badge/github.com/open-policy-agent/opa-istio-plugin)](https://goreportcard.com/report/github.com/open-policy-agent/opa-istio-plugin)

This repository contains an extended version of OPA (**OPA-Istio**) that allows you to enforce OPA
policies at the Istio Proxy layer.

## Overview

OPA-Istio extends OPA with a gRPC server that implements the [Istio Check
API](https://github.com/istio/api/blob/master/mixer/v1/service.proto#L52). You can use this version of OPA to enforce fine-grained, context-aware access control policies **at the Istio Proxy layer without modifying your
microservice.**

## How does it work?

In addition to the Istio Proxy sidecar, your application pods will include an
OPA sidecar. When Istio Proxy receives API requests destined for your
microservice, it checks with OPA to decide if the request should be allowed.

Evaluating policies locally at the Istio Proxy layer is preferable because it
avoids introducing a network hop (which has implications on performance and
availability) in order to perform the authorization check.

![arch](./docs/arch.png)

To integrate with Istio Proxy, OPA-Istio implements the Istio Check API. In
the future, OPA-Istio may be configured to forward Check calls to Istio's
Mixer component in addition to performing evaluation locally. This way check
decisions from Istio's Mixer component could be combined locally at the proxy
layer.

## Quick Start

This section assumes you have Istio deployed on top of Kubernetes. See Istio's [Quick Start](https://istio.io/docs/setup/kubernetes/quick-start.html) page to get started.

1. Install OPA-Istio.

    ```bash
    kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/opa-istio-plugin/master/quick_start.yaml
    ```

    The `quick_start.yaml` manifest defines the following resources:

    * Kubernetes namespace (`opa-istio`) for OPA-Istio control plane components.

    * Kubernetes admission controller into the `opa-istio` namespace that automatically injects the OPA-Istio sidecar into pods in namespaces labelled with `enable-opa-istio-injection`.

    * OPA configuration file and an OPA policy into ConfigMaps in the namespace where the app will be deployed, e.g., `default`.

1. Update [Istio's `mesh` config](https://istio.io/docs/reference/config/istio.mesh.v1alpha1.html#MeshConfig) to use OPA. The `mesh` config controls which endpoint Istio Proxy queries for authorization checks.

    **Istio v0.6 and higher**:

    ```bash
    kubectl -n istio-system \
        replace configmap istio \
        -f <(kubectl -n istio-system get configmap istio -o yaml \
                | sed 's/mixerCheckServer: .*/mixerCheckServer: localhost:50051/g')
    ```

    **Istio v0.5 and lower**:

    ```bash
    kubectl -n istio-system \
        replace configmap istio \
        -f <(kubectl -n istio-system get configmap istio -o yaml \
                | sed 's/mixerAddress: .*/mixerAddress: localhost:50051/g')
    ```

    **Restart Istio Pilot**:

    ```bash
    kubectl -n istio-system \
        delete pod $(kubectl get pod -n istio-system -l istio=pilot -o jsonpath='{.items[].metadata.name}')
    ```

    > Istio Pilot must be restarted for the `mesh` config update to take affect. This is a known issue. See [Istio #1449](https://github.com/istio/istio/issues/1449#issuecomment-368059202) for more details.

1. Enable OPA injection on the namespace where the app will be deployed, e.g., `default`.

    ```bash
    kubectl label namespace default enable-opa-istio-injection="true"
    ```

1. Deploy the BookInfo application.

    ```bash
    kubectl apply -f <(istioctl kube-inject --debug -f https://raw.githubusercontent.com/istio/istio/master/samples/bookinfo/kube/bookinfo.yaml)
    ```

    > **NOTE:** This command assumes you have `istioctl` in your path. You can find `istioctl` under the `<ISTIO_INSTALL_DIR>/bin` directory.

1. Exercise the sample policy. Check that **alice** can access `/productpage` **BUT NOT** `/api/v1/products`.

    ```bash
    curl --user alice:password  -o /dev/null -s -w "%{http_code}\n" http://<INGRESS_IP_PORT>/productpage
    200
    ```

    ```bash
    curl --user alice:password  -o /dev/null -s -w "%{http_code}\n" http://<INGRESS_IP_PORT>/api/v1/products
    403
    ```

1. Exercise the sample policy. Check that **bob** can access `/productpage` **AND** `/api/v1/products`.

    ```bash
    curl --user bob:password  -o /dev/null -s -w "%{http_code}\n" http://<INGRESS_IP_PORT>/productpage
    200
    ```

    ```bash
    curl --user bob:password  -o /dev/null -s -w "%{http_code}\n" http://<INGRESS_IP_PORT>/api/v1/products
    200
    ```

## Configuration

To deploy OPA-Istio include the following container in your Kubernetes Deployments:

```yaml
containers:
- image: openpolicyagent/opa:0.8.0-dev-istio
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
| `plugins.istio_policy_server.plugin_addr` | No | Specifies listening address for the plugin's gRPC server. The port must match the one used in Istio's `mesh` config. Example: `:50051`. Default: `:50051`. |
| `plugins.istio_policy_server.policy_query` | No | Specifies the name of the policy decision to query. Example: `data.istio.authz.allow`. Default: `data.istio.authz.allow`. |

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
    istio_policy_server:
        plugin_addr: :50051
        policy_query: data.istio.authz.allow
```

## Example Policy

The following OPA policy is used in the [Quick Start](#quick-start) section above. This policy restricts access to the BookInfo such that:

* Alice is granted a __guest__ role and can access the `/productpage` frontend BUT NOT the `/v1/api/products` backend.
* Bob is granted an __admin__ role and can access the `/productpage` frontend AND the `/v1/api/products` backend.


```ruby
package istio.authz

# HTTP API request
import input as http_api

# user-role assignments
user_roles = {
    "alice": ["guest"],
    "bob": ["admin"]
}

# role-permissions assignments
role_perms = {
    "guest":    [{"method": "GET",  "path": "/productpage"}],
    "admin":    [{"method": "GET",  "path": "/productpage"},
                 {"method": "GET",  "path": "/api/v1/products"}]
}


# logic that implements RBAC
default allow = false

allow {
    # get the user
    headers = http_api.request.headers
    auth = headers.authorization
    userAuth = split(auth, " ")
    user_pass = base64url.decode(userAuth[1])
    user_parts = split(user_pass, ":")
    user = user_parts[0]

    # lookup the list of roles for the user
    roles = user_roles[user]
    # for each role in that list
    r = roles[_]
    # lookup the permissions list for role r
    permissions = role_perms[r]
    # for each permission
    p = permissions[_]
    # check if the permission granted to r matches the user's request
    {"method": http_api.request.method, "path": http_api.request.path} = p
}
```

## Dependencies

Dependencies are managed with [Glide](https://github.com/Masterminds/glide).
If you need to add or update dependencies, modify the `glide.yaml` file and
then run `glide update --strip-vendor` and then commit all changes to the
repository. You will need to have Glide v0.13 or newer installed.
