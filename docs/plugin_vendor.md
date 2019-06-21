##  Instructions to load the OPA-Istio plugin using `vendored` OPA:

1. Build the OPA-Istio binary.
   
   ```bash
   make build
   ```

2. Build the OPA-Istio plugin.

    ```bash
    make build-plugin
    ```

3. Create a configuration file.

    ```yaml
    plugins:
        envoy.ext_authz.grpc:
            addr: :9191
            query: data.istio.authz.allow
    ```

4. Run OPA-Istio

    ```bash
    opa_istio --plugin-dir=. run --server --config-file=config.yaml
    ```
