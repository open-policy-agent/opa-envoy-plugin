#!/usr/bin/env bats

load helper

BATS_TESTS_DIR=test/bats/tests
WAIT_TIME=60
SLEEP_TIME=1

@test "deploy Istio control plane with operator" {
  run kubectl apply -f examples/istio/istiooperator.yaml
  assert_success

  cmd='[[ $(kubectl get -n istio-system istiooperator istiocontrolplane -o "jsonpath={.status.status}") == "HEALTHY" ]]'
  wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"
  assert_success
}

@test "install OPA-Envoy" {
  run kubectl apply -f examples/istio/quick_start.yaml
  assert_success
}

@test "label default namespace for Istio Proxy and OPA-Envoy sidecar injection" {
  run kubectl label namespace default opa-istio-injection="enabled"
  assert_success

  run kubectl label namespace default istio-injection="enabled"
  assert_success
}

@test "add AuthorizationPolicy to default namespace for external authorization" {
  run kubectl apply -n default -f examples/istio/authz.yaml
  assert_success
}

@test "deploy Bookinfo app" {
  run kubectl apply -f https://raw.githubusercontent.com/istio/istio/master/samples/bookinfo/platform/kube/bookinfo.yaml
  assert_success

  cmd="kubectl wait --for=condition=available --timeout=60s --all deployment"
  wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"
  assert_success
}

@test "make Bookinfo app accessible from outside the cluster" {
  run kubectl apply -f https://raw.githubusercontent.com/istio/istio/master/samples/bookinfo/networking/bookinfo-gateway.yaml
  assert_success
}

@test "alice can access /productpage" {
  host="$(docker_ip 'kind-control-plane')"
  port="$(ingress_port)"

  echo "$host"
  echo "$port"

  cmd="docker exec kind-control-plane curl --connect-timeout 30 --max-time 60 --retry 10 --retry-delay 0 --retry-max-time 600 \
  --retry-connrefused --user alice:password -s -o /dev/null -w "%{http_code}" http://"$host":"$port"/productpage"

  result=`$cmd`
  echo "result: $result"
  [ "$result" == 200 ]
}

@test "alice cannot access /api/v1/products" {
  host="$(docker_ip 'kind-control-plane')"
  port="$(ingress_port)"

  echo "$host"
  echo "$port"

  cmd="docker exec kind-control-plane curl --connect-timeout 30 --max-time 60 --retry 10 --retry-delay 0 --retry-max-time 600 \
  --retry-connrefused --user alice:password -s -o /dev/null -w "%{http_code}" http://"$host":"$port"/api/v1/products"

  result=`$cmd`
  echo "result: $result"
  [ "$result" == 403 ]
}

@test "bob can access /productpage" {
  host="$(docker_ip 'kind-control-plane')"
  port="$(ingress_port)"

  echo "$host"
  echo "$port"

  cmd="docker exec kind-control-plane curl --connect-timeout 30 --max-time 60 --retry 10 --retry-delay 0 --retry-max-time 600 \
  --retry-connrefused --user bob:password -s -o /dev/null -w "%{http_code}" http://"$host":"$port"/api/v1/products"

  result=`$cmd`
  echo "result: $result"
  [ "$result" == 200 ]
}

@test "bob can access /api/v1/products" {
  host="$(docker_ip 'kind-control-plane')"
  port="$(ingress_port)"

  echo "$host"
  echo "$port"

  cmd="docker exec kind-control-plane curl --connect-timeout 30 --max-time 60 --retry 10 --retry-delay 0 --retry-max-time 600 \
  --retry-connrefused --user bob:password -s -o /dev/null -w "%{http_code}" http://"$host":"$port"/api/v1/products"

  result=`$cmd`
  echo "result: $result"
  [ "$result" == 200 ]
}