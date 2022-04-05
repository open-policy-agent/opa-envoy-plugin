# Proxy Init

This directory contains the Istio proxy init script and a Dockerfile for
building an image for the init container that installs iptables rules to
redirect all container traffic through the Envoy proxy sidecar.

Ports can be whitelisted to bypass the envoy proxy by using the `-w`
parameter with a comma separated list of ports. This is useful for
application health checks that should go directly to a service.

This container used to live in
[open-policy-agent/contrib](https://github.com/open-policy-agent/contrib).
