## Overview

[Envoy Gateway](https://gateway.envoyproxy.io/) (EG) is the community-built, open-standards, Envoy-based ingress controller.

Envoy proxies can defer to an external system for authorization (aka authz, access control) decisions.
Envoy Gateway's control plane allows easy configuration of this feature, enabling your Envoy ingress proxies to use any external authz system which implements Envoy's `[ext_authz](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto)` protocol.

OPA's _opa-envoy-plugin_ is precisely one such system, and this guide will show you how to configure Envoy Gateway to integrate with an OPA instance running this plugin.

## Prerequisites

You will need a Kubernetes cluster with Envoy Gateway installed.
Basic familiarity with OPA and Rego is assumed.

This section will briefly show you how to run a local cluster and perform a default install of Envoy Gateway.
These are not production-grade systems and are only for example purposes, but will get you started.

### Kubernetes Cluster

Ensure [Minikube](https://minikube.sigs.k8s.io/docs/) is installed.

```bash
minikube start
```

### Envoy Gateway

Ensure [Helm](https://helm.sh/) in installed.

```bash
helm install eg oci://docker.io/envoyproxy/gateway-helm --version v1.0.0 -n envoy-gateway-system --create-namespace
```

## Example App an EG config

We'll use httpbin as an example service to protect using OPA policy.

```bash
kubectl apply -f https://raw.githubusercontent.com/istio/istio/master/samples/httpbin/httpbin.yaml
```

First, configure EG with a template for how to deploy gateways.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: eg
spec:
  controllerName: gateway.envoyproxy.io/gatewayclass-controller
```

> Note: where you see a YAML file like this, save it to your machine and apply it to the cluster with `kubectl apply -f <filename.yaml>`

Now we'll configure EG to deploy a gateway of proxies listening on port 80.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: mygateway
spec:
  gatewayClassName: eg
  listeners:
    - name: http
      protocol: HTTP
      port: 80
```

Lastly, we'll send all traffic that hits port 80 on that gateway to our httpbin Pod.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: httpbin
spec:
  parentRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: mygateway
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - group: ""
          kind: Service
          name: httpbin
          port: 8000
```

### Test

Get access to the gateway Pods by port-forwarding.
This command blocks, so in another terminal:

```bash
SVC=$(kubectl get svc -n envoy-gateway-system -l app.kubernetes.io/name=envoy -l gateway.envoyproxy.io/owning-gateway-name=mygateway -l gateway.envoyproxy.io/owning-gateway-namespace=default -o name)
kubectl port-forward -n envoy-gateway-system $SVC 8080:80
```

We can now test that httpbin is running correctly, and that EG is correctly forwarding requests to and from it:

```bash
curl -i localhost:8080/get
```

You should see the response headers, and a JSON document from httpbin which echos back the parameters of our request.
If this is all present and correct, we can move on to setting up OPA as an external authorization system.

## Install and Configure OPA

For this demo example, we'll be deploying our OPA Rego policy in a Secret and mounting that as a volume into the OPA Pod.
This is again not a production-grade setup, but will work for a demo.
Because of this, we need to deploy the Secret first, so that the Pod can mount it at startup.

### OPA Policy

This example policy allows only requests to the `/headers` path.
Save it to your local machine as `policy.rego` (this name is important)

```rego
package envoy.authz

import input.attributes.request.http as http_request

default allow = false

allow {
    action_allowed
}

action_allowed {
    http_request.path == "/headers"
}
```

We'll now deploy that file to Kubernetes as a Secret resource.

```bash
kubectl create secret generic opa-policy --from-file policy.rego
```

### OPA Server + Envoy Plugin

The following resources will run an OPA daemon, with the Envoy `ext_authz` API plugin pre-configured.
They also expose it as a Service within the cluster.
Note how the Deployment mounts in our Rego policy.

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
          image: openpolicyagent/opa:0.62.1-envoy-5-rootless
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
---
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

### Apply OPA Policy-Enforcement to httpbin

Now we can tell EG to call out to that OPA service for auth decisions when clients request the httpbin service.

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: httpbin-opa-authz
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: httpbin
  extAuth:
    grpc:
      backendRef:
        name: opa
        port: 9191
```

### Test

We should now see that requests to the previously-working `/get` path are rejected as unauthorized:

```bash
curl -i localhost:8080/get
```

However we can still access the `/headers` path, which is within policy:

```bash
curl -i localhost:8080/headers
```

If you wish to dive further in, you can see OPA's logs of its authz decisions:

```bash
kubectl logs deployment/opa | jq
```
