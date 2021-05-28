# opa-envoy-plugin

[![Build Status](https://github.com/open-policy-agent/opa-envoy-plugin/workflows/Post%20Merge/badge.svg?branch=master)](https://github.com/open-policy-agent/opa-envoy-plugin/actions) [![Go Report Card](https://goreportcard.com/badge/github.com/open-policy-agent/opa-envoy-plugin)](https://goreportcard.com/report/github.com/open-policy-agent/opa-envoy-plugin)

This repository contains an extended version of OPA (**OPA-Envoy**) that allows you to enforce OPA policies with Envoy.

## Issue Management
Use [OPA GitHub Issues](https://github.com/open-policy-agent/opa/issues) to request features or file bugs.

## Examples with Envoy-based service meshes

The OPA-Envoy plugin can be deployed with Envoy-based service meshes such as:

* [Istio](./examples/istio)
* [Gloo Edge](./examples/gloo-edge)

## Overview

OPA-Envoy extends OPA with a gRPC server that implements the [Envoy External
Authorization
API](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter.html).
You can use this version of OPA to enforce fine-grained, context-aware access
control policies with Envoy _without_ modifying your microservice.

More information about the OPA-Envoy plugin including performance benchmarks, debugging tips, detailed usage examples
can be found [here](https://www.openpolicyagent.org/docs/edge/envoy-introduction/).

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
- image: openpolicyagent/opa:0.29.2-envoy
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

### Example Bundle Configuration

In the [Quick Start](#quick-start) section an OPA policy is loaded via a volume-mounted ConfigMap. For production
deployments, we recommend serving policy [Bundles](http://www.openpolicyagent.org/docs/bundles.html) from a remote HTTP server.

Using the configuration shown below, OPA will download a sample bundle from [https://www.openpolicyagent.org](https://www.openpolicyagent.org).
The sample bundle contains the exact same policy that was loaded into OPA via the volume-mounted ConfigMap.

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

## Dependencies

Dependencies are managed with [Modules](https://github.com/golang/go/wiki/Modules).
If you need to add or update dependencies, modify the `go.mod` file or
use `go get`. More information is available [here](https://github.com/golang/go/wiki/Modules#how-to-upgrade-and-downgrade-dependencies).
Finally commit all changes to the repository.
