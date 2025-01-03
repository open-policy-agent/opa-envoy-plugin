## Overview

[Gloo Edge](https://docs.solo.io/gloo-edge/latest/) is an Envoy based API Gateway that provides a Kubernetes CRD
to manage Envoy configuration for performing traffic management and routing.

`Gloo Edge` allows creation of a [Custom External Auth Service](https://docs.solo.io/gloo-edge/master/guides/security/auth/custom_auth/)
that implements the Envoy spec for an [External Authorization Server](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter.html).

The purpose of this tutorial is to show how OPA could be used with Gloo Edge to apply security policies for upstream services.

## Prerequisites

This tutorial requires Kubernetes 1.14 or later. To run the tutorial locally, we recommend using [minikube](https://minikube.sigs.k8s.io/docs/start/) in
version v1.0+ with Kubernetes 1.14+.

The tutorial also requires [Helm](https://helm.sh/docs/intro/install/) to install Gloo Edge on a Kubernetes cluster.

## TL;DR

Execute `./setup.sh`, the script will set up everything and run sample tests to prove that the setup worked.

## Steps

### Start Minikube

```bash
minikube start
```

### Setup and configure Gloo Edge

```bash
helm repo add gloo https://storage.googleapis.com/solo-public-helm
helm upgrade --install --namespace gloo-system --create-namespace gloo gloo/gloo
kubectl config set-context $(kubectl config current-context) --namespace=gloo-system
```

Ensure all pods are running using `kubectl get pod` command.

### Create Virtual Service and Upstream

[Virtual Services](https://docs.solo.io/gloo-edge/latest/introduction/architecture/concepts/#virtual-services) define a
set of route rules, security configuration, rate limiting, transformations, and other core routing capabilities
supported by Gloo Edge.

[Upstreams](https://docs.solo.io/gloo-edge/latest/introduction/architecture/concepts/#upstreams) define destinations for routes.

Save the configuration as **vs.yaml**.

```yaml
apiVersion: gloo.solo.io/v1
kind: Upstream
metadata:
  name: httpbin
spec:
  static:
    hosts:
      - addr: httpbin.org
        port: 80
---
apiVersion: gateway.solo.io/v1
kind: VirtualService
metadata:
  name: httpbin
spec:
  virtualHost:
    domains:
      - '*'
    routes:
      - matchers:
         - prefix: /
        routeAction:
          single:
            upstream:
              name: httpbin
              namespace: gloo-system
        options:
          autoHostRewrite: true
```

```bash
kubectl apply -f vs.yaml
```

### Test Gloo

For simplification port-forwarding will be used. Open another terminal and execute.

```bash
kubectl port-forward deployment/gateway-proxy 8080:8080
```

The `VirtualService` created in the previous step forwards requests to [http://httpbin.org](http://httpbin.org).

Let's test that Gloo works properly by running the below commands in the first terminal.

```bash
curl -XGET -Is localhost:8080/get | head -n 1
HTTP/1.1 200 OK

curl http -XPOST -Is localhost:8080/post | head -n1
HTTP/1.1 200 OK
```

### Define a OPA policy

The following OPA policy only allows `GET` requests.

**policy.rego**

```rego
package envoy.authz

import input.attributes.request.http as http_request

default allow = false

allow if {
    action_allowed
}

action_allowed if {
  http_request.method == "GET"
}
```

Store the policy in Kubernetes as a Secret.

```bash
kubectl create secret generic opa-policy --from-file policy.rego
```

### Setup OPA-Envoy

Create a deployment as shown below and save it in **deployment.yaml**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opa
  labels:
    app: opa
spec:
  replicas: 1
  selector:
    matchLabels:
      app: opa
  template:
    metadata:
      labels:
        app: opa
    spec:
      containers:
        - name: opa
          image: openpolicyagent/opa:0.26.0-envoy
          volumeMounts:
            - readOnly: true
              mountPath: /policy
              name: opa-policy
          args:
            - "run"
            - "--server"
            - "--addr=0.0.0.0:8181"
            - "--set=plugins.envoy_ext_authz_grpc.addr=0.0.0.0:9191"
            - "--set=plugins.envoy_ext_authz_grpc.query=data.envoy.authz.allow"
            - "--set=decision_logs.console=true"
            - "--ignore=.*"
            - "/policy/policy.rego"
      volumes:
        - name: opa-policy
          secret:
            secretName: opa-policy
```

```bash
kubectl apply -f deployment.yaml
```

Ensure all pods are running using `kubectl get pod` command.

Next, define a Kubernetes `Service` for OPA-Envoy. This is required to create a DNS record and thereby create
a Gloo `Upstream` object.

**service.yaml**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: opa
spec:
  selector:
    app: opa
  ports:
    - name: grpc
      protocol: TCP
      port: 9191
      targetPort: 9191
```

> Note: Since the name of the service port is `grpc`, `Gloo` will understand that traffic should be routed using HTTP2 protocol.

```bash
kubectl apply -f service.yaml
```

### Configure Gloo Edge to use OPA

To use OPA as a custom auth server, we need to add the `extauth` attribute as describe below:

**gloo.yaml**

```yaml
global:
  extensions:
    extAuth:
      extauthzServerRef:
        name: gloo-system-opa-9191
        namespace: gloo-system
```

To apply it, run the following command:

```bash
helm upgrade --install --namespace gloo-system --create-namespace -f gloo.yaml gloo gloo/gloo
```

Then, configure Gloo Edge routes to perform authorization via configured `extauth` before regular processing.

**vs-patch.yaml**

```yaml
spec:
  virtualHost:
    options:
      extauth:
        customAuth: {}
```

Then apply the patch to our `VirtualService` as shown below:

```bash
kubectl patch vs httpbin --type=merge --patch "$(cat vs-patch.yaml)"
```

### Exercise the OPA policy

After the patch is applied, let's verify that OPA allows only allows `GET` requests.

```bash
curl -XGET -Is localhost:8080/get | head -n 1
HTTP/1.1 200 OK

curl http -XPOST -Is localhost:8080/post | head -n1
HTTP/1.1 403 Forbidden
```

Check OPA's decision logs to view the inputs received by OPA from Gloo Edge and the results generated by OPA.

```bash
$ kubectl logs deployment/opa
```
