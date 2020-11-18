#!/usr/bin/env bash
# Script to create a Kubernetes cluster using kind and deploy Istio on top of it

set -e
set -x

GOARCH=$(go env GOARCH)
GOOS=$(go env GOOS)
KIND_VERSION=0.4.0
ISTIO_VERSION=1.7.0

# Download and install kind
curl -L https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-${GOOS}-${GOARCH} --output kind && chmod +x kind && sudo mv kind /usr/local/bin/

# Create kind cluster
if [ -z $(kind get clusters) ]; then
    kind create cluster
fi

# Get kubeconfig
export KUBECONFIG="$(kind get kubeconfig-path --name=kind)"

# Download and install kubectl
curl -LO \
https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/${GOOS}/${GOARCH}/kubectl && chmod +x ./kubectl && sudo mv kubectl /usr/local/bin/

# Download and install Istio
curl -L https://git.io/getLatestIstio | ISTIO_VERSION=${ISTIO_VERSION} sh - && mv istio-${ISTIO_VERSION} /tmp
cd /tmp/istio-${ISTIO_VERSION}
bin/istioctl install -y --set profile=demo
kubectl -n istio-system wait --for=condition=available --timeout=600s --all deployment
