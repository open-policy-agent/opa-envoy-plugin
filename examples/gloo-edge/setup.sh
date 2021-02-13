#!/bin/bash
set -e
set -m

helm repo add gloo https://storage.googleapis.com/solo-public-helm
helm upgrade -i -n gloo-system --create-namespace gloo gloo/gloo
kubectl config set-context $(kubectl config current-context) --namespace=gloo-system

kubectl apply -f vs.yaml
kubectl apply -f opa.yaml

helm upgrade -i -n gloo-system --create-namespace -f gloo.yaml gloo gloo/gloo
kubectl patch vs httpbin --type=merge -p "$(cat vs-patch.yaml)"

sleep 10

kubectl port-forward deployment/gateway-proxy 8080:8080 &

sleep 2
echo
echo "Starting tests"
echo

echo "Sending allowed request: "
curl -XGET -Is localhost:8080/get | head -n 1
echo
echo "Sending restricted request: "
curl -XPOST -Is localhost:8080/post | head -n 1
echo
echo "Press CTRL+C to exit"

fg 1
