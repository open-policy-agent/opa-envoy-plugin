# Using OPA with Gloo Edge

* [Gloo Edge](https://docs.solo.io/gloo-edge/latest/)
* [OPA](https://www.openpolicyagent.org/docs/latest/envoy-authorization/)

`Gloo Edge` is `Envoy` based API Gateway that provides K8S CRD to manage `Envoy` config for performing traffic management and routing.

`Gloo Edge` allows to leverage `Envoy` [External Authorization](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter.html)
introducing concept of [Custom Auth server](https://docs.solo.io/gloo-edge/master/guides/security/auth/custom_auth/).

The purpose of this tutorial is to show how OPA could be used with `Gloo Edge` to apply security policies for upstream services.

This document assumes you have avialable K8S cluster available and have understand of `Gloo Edge` routing basics,
i.e. `Upstream`, `VirtualService` resources.

For local development one could use [Minikube](https://minikube.sigs.k8s.io/docs/) or [K3D](https://k3d.io/).

This guide was tested on local [k3d](https://k3d.io/) and [kOps](https://github.com/kubernetes/kops) based cluster in AWS.

Required software

* [Helm](https://helm.sh/docs/intro/install/)
* [Kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
* [curl](https://curl.se/download.html)

## TL;DR

Execute `./setup.sh`, the script will setup everything
and run sample tests to prove that setup worked.

## Setup and configure Gloo Edge

```bash
$ helm repo add gloo https://storage.googleapis.com/solo-public-helm
$ helm upgrade -i -n gloo-system --create-namespace gloo gloo/gloo
$ kubectl config set-context $(kubectl config current-context) --namespace=gloo-system
```

Ensure all pods are running using `kubectl get pod` command.

For simplification port-forwarding will be used. Open another console and execute.

```bash
$ kubectl port-forward deployment/gateway-proxy 8080:8080
```

Let's test that Gloo works properly.
We're going to create sample [VirtualService](https://docs.solo.io/gloo-edge/latest/introduction/architecture/concepts/#virtual-services)
that forwards requests to http://httpbin.org.

In initial console run

```bash
$ curl -XGET -Is localhost:8080/get | head -n 1
HTTP/1.1 200 OK

$ http -XPOST -Is localhost:8080/post | head -n1
HTTP/1.1 200 OK
```

## Setup OPA-Envoy

K8S `Service` is required to create a DNS record and create Gloo `Upstream` object.
Since name of the service port is `grpc` - `Gloo` will understand that traffic should be routed using HTTP2 protocol.

Together with OPA container we will deploy simple REGO policy, that only aceepts GET requests and denies all other HTTP methods.

```
package envoy.authz
import input.attributes.request.http as http_request

default allow = false

allow {
    action_allowed
}

action_allowed {
  http_request.method == "GET"
}
```

Execute command below to deploy OPA and ensure all pods are running using `kubectl get pod` command.

```bash
$ kubectl apply -f opa.yaml
```

## Enable OPA as Custom Auth server in Gloo Edge

First of all we should enable `ext_authz` in embedded `Envoy` by applying such values to Gloo Edge Helm chart.

```yaml
global:
  extensions:
    extAuth:
      extauthzServerRef:
        name: gloo-system-opa-9191
        namespace: gloo-system
```

To apply it, run this command

```bash
$ helm upgrade -i -n gloo-system --create-namespace -f gloo.yaml gloo gloo/gloo
```

Then, we should configure `Gloo Edge` routes to perform authorization via configured `ext_auth` before regular processing

Let's create file `vs-patch.yaml` with content

```yaml
spec:
  virtualHost:
    options:
      extauth:
        customAuth: {}
```

and apply the patch to our `VirtualService` by calling

```bash
$ kubectl patch vs httpbin --type=merge -p "$(cat vs-patch.yaml)"
```

## Check External Authorization via Gloo Edge

After patch application, let's verify that `ext_authz` works properly,
executing the same HTTP requests that we used before to check if routing worked.

We expect that GET requests are passing through and all other methods are denied.

```bash
$ curl -XGET -Is localhost:8080/get | head -n 1
HTTP/1.1 200 OK

$ http -XPOST -Is localhost:8080/post | head -n1
HTTP/1.1 403 Forbidden
```

Also, OPA decision logs could be checked to debug Gloo request and OPA results.

```bash
$ kubectl logs deployment/opa
```
