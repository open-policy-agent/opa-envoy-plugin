# Envoy External Authz and UNIX Domain Socket (UDS) example

This tutorial shows how Envoy’s External authorization filter can be used with OPA as an authorization service. The
OPA-Envoy plugin is configured to listen on a UNIX Domain Socket.

This section assumes you are testing with Kubernetes v1.20 or later.
## Steps

### 1. Start Minikube

```bash
minikube start
```

### 2. Install OPA-Envoy.

```bash
kubectl apply -f quick_start.yaml
```

The `quick_start.yaml` manifest defines the following resources:

 * A ConfigMap containing an Envoy configuration with an External Authorization Filter to direct authorization
checks to the OPA-Envoy sidecar. It uses the Google C++ gRPC client to specify the UDS for the OPA-Envoy container.
See `kubectl get configmap proxy-config` for details.

* OPA configuration file, and an OPA policy into ConfigMaps in the namespace where the app will be deployed, e.g., `default`.

* A Deployment consisting an example Go application with OPA-Envoy and Envoy sidecars.

* An `emptyDir` volume called `opa-socket` that the OPA-Envoy and Envoy containers share.

### 3. Make the application accessible outside the cluster.

```bash
kubectl expose deployment example-app --type=NodePort --name=example-app-service --port=8080
```

### 4. Set the `SERVICE_URL` environment variable to the service’s IP/port.

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

### 5. Exercise the sample OPA policy.

For convenience, we’ll want to store Alice’s token in environment variables.

```bash
export ALICE_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiZ3Vlc3QiLCJzdWIiOiJZV3hwWTJVPSIsIm5iZiI6MTUxNDg1MTEzOSwiZXhwIjoxNjQxMDgxNTM5fQ.K5DnnbbIOspRbpCr2IKXE9cPVatGOCBrBQobQmBmaeU"
```

Check that `Alice` can get employees **but cannot** create one.

```bash
curl -i -H "Authorization: Bearer "$ALICE_TOKEN"" http://$SERVICE_URL/people
curl -i -H "Authorization: Bearer "$ALICE_TOKEN"" -d '{"firstname":"Charlie", "lastname":"OPA"}' -H "Content-Type: application/json" -X POST http://$SERVICE_URL/people
```
