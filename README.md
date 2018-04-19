# OPA-Istio Plugin

[![Build Status](https://travis-ci.org/ashutosh-narkar/opa-istio-plugin.svg?branch=master)](https://travis-ci.org/ashutosh-narkar/opa-istio-plugin) [![Go Report Card](https://goreportcard.com/badge/github.com/ashutosh-narkar/opa-istio-plugin)](https://goreportcard.com/report/github.com/ashutosh-narkar/opa-istio-plugin)

This repository contains the OPA-Istio plugin that extends OPA with a
gRPC API which implements Istio Mixer's _Check_ API. 

## Overview

This plugin extends OPA with a gRPC API that allows OPA to enforce policy
decisions at the Istio Proxy layer. You can use this plugin to enforce
fine-grained API access control policies without modifying microservices
that run on top of Istio.

## How does it work?

Using this plugin, your microservice pods will include an OPA sidecar in
addition to the Istio Proxy. When Istio Proxy receives an API request
destined for your microservice, it checks with OPA (locally)
to see if the request should be allowed.

This plugin enables distributed enforcement of OPA policies. All policy
evaluation is done locally in the sidecar next to your microservice.
Evaluating policies locally reduces the latency introduced into the
request path and improves the overall availability for your microservice
because policy decisions are not subject to network partitions.

![arch](./docs/arch.png)

To integrate with Istio Proxy, the plugin implements the Istio Check API.
In the future, the plugin may be configured to forward Check calls to
Istio's Mixer component in addition to performing evaluation locally.
This way check decisions from Istio's Mixer component could be combined
locally at the proxy layer.

## Install Istio

**Any existing Istio installation needs to be removed to run the OPA-Istio**
**plugin. The plugin relies on a custom Istio config map which is needed for the**
**proper working on the demo. Istio is working on adding watchers to track**
**changes in the config map. See [this](https://github.com/istio/istio/issues/1449) for details.**

Install Istio's core components:
```bash
kubectl apply -f config/install/istio.yaml
```

Istio's installation config file has been modified to include changes as
described below.

The following field is valid for Istio v0.6.0 and higher.

The _mixerCheckServer_ field in Istio's configMap is modified to point 
to the plugin instead of Istio Mixer. 
The default listening port of the plugin is 50051. So the  _mixerCheckServer_ 
field is:

```bash
mixerCheckServer: localhost:50051
```

If using Istio 0.5.1, update the _mixerAddress_ field:
```bash
mixerAddress: localhost:50051
```

Below is the Istio mesh config. Notice the value of the _mixerCheckServer_
field is the plugin's address. This demo uses Istio 0.7.1.

```bash
################################
# Istio configMap cluster-wide
################################
apiVersion: v1
kind: ConfigMap
metadata:
  name: istio
  namespace: istio-system
data:
  mesh: |-
    mtlsExcludedServices: ["kubernetes.default.svc.cluster.local"]
    disablePolicyChecks: false
    enableTracing: true

    mixerCheckServer: localhost:50051
    mixerReportServer: istio-mixer.istio-system:15004

    rdsRefreshDelay: 1s

    defaultConfig:
      connectTimeout: 10s

      configPath: "/etc/istio/proxy"
      binaryPath: "/usr/local/bin/envoy"

      serviceCluster: istio-proxy

      drainDuration: 45s
      parentShutdownDuration: 1m0s

      proxyAdminPort: 15000

      zipkinAddress: zipkin.istio-system:9411

      statsdUdpAddress: istio-mixer.istio-system:9125
---
```

## Install Bookinfo App
```bash
kubectl apply -f config/demo/bookinfo.yaml
```

Below is the app deployment section to include the plugin as a sidecar container.

```yaml
 - image: openpolicyagent/opa:0.8.0-dev-istio
   imagePullPolicy: IfNotPresent
   name: opa-istio-plugin
   volumeMounts:
   - mountPath: /config       // volume to mount the plugin config
     name: plugin-config
   args:
   - "run"
   - "--server"
   - "--addr=:8182"
   - "--config-file=/config/config.yaml"    // Config file for OPA and the plugin
   - "--log-level=debug"

 volumes:
 - name: plugin-config
   configMap:
     name: opa-istio-plugin-config
     items:
     - key: config_istio.yaml
       path: config.yaml
```

More information about the _Bookinfo_ app such as the different services that
make up the app can be found [here](https://istio.io/docs/guides/bookinfo.html)

Below is an example of the config file used by OPA and the plugin

```yaml
// Plugin config
plugins:
  istio_policy_server:
    plugin_addr: ":50052"                     // gRPC server listening port
    policy_query: "data.istio.authz.allow"    // OPA policy query
```

If external services (ie. services outside Istio cluster) need to be contacted,
an _Istio Egress Rule_ need to be configured. For more information on how this
can be done see [this](https://istio.io/docs/tasks/traffic-management/egress.html).

For a complete example of the plugin config see _sample_config.yaml_.

The plugin container gets its runtime configuration using Config Maps. A config map
called _opa-istio-plugin-config_ is  created using plugin config similar to _sample_config.yaml_
and referenced in the Bookinfo App config file _config/demo/bookinfo.yaml_.

For more information on creating and using Config Maps see [this](https://cloud.google.com/kubernetes-engine/docs/concepts/configmap).

## Example: API Authorization

This example shows how HTTP API authorization can be enforced in the _BookInfo_
app. In the policy shown below, _alice_ who has a _guest_ role can access the path _/productpage_
while _bob_ who has a _admin_ role can access the path _/productpage_ and _/api/v1/products_.

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

## Example Queries

__Check that “alice” can access “/productpage” but not “/api/v1/products”__
```bash
curl --user alice:password  -o /dev/null -s -w "%{http_code}\n" http://<INGRESS_IP_PORT>/productpage
200

curl --user alice:password  -o /dev/null -s -w "%{http_code}\n" http://<INGRESS_IP_PORT>/api/v1/products
403
```

__Check that “bob” can access “/productpage” and “/api/v1/products”__
```bash
curl --user bob:password  -o /dev/null -s -w "%{http_code}\n" http://<INGRESS_IP_PORT>/productpage
200

curl --user bob:password  -o /dev/null -s -w "%{http_code}\n" http://<INGRESS_IP_PORT>/api/v1/products
200
```

## Dependencies

[Glide](https://github.com/Masterminds/glide) is a command line tool used for
dependency management. You must have Glide installed in order to add new
dependencies or update existing dependencies. If you are not changing
dependencies you do not have to install Glide, all of the dependencies are
contained in the vendor directory.

Update `glide.yaml` if you are adding a new dependency and then run:

```bash
glide update --strip-vendor
```

This assumes you have Glide v0.13 or newer installed.
