##  Instructions to build the OPA-Istio plugin as a Go plugin:

1. Clone OPA in your `GOPATH`.

   ```bash
   git clone git@github.com:open-policy-agent/opa.git
   ```

2. Clone the OPA-Istio plugin in your `GOPATH`.

    ```bash
    git clone git@github.com:open-policy-agent/opa-istio-plugin.git
    ```

3. Remove the vendored OPA directory.

    ```bash
    cd $GOPATH/src/github.com/open-policy-agent/opa-istio-plugin
    rm -rf vendor/github.com/open-policy-agent
    ```

4. Build the plugin.

    ```bash
    make build-plugin
    ```

5. Create a configuration file.

    ```yaml
    plugins:
        envoy_ext_authz_grpc:
            addr:    :9191
            query:   data.istio.authz.allow
            dry-run: false
    ```

6. Run OPA

    ```bash
    opa --plugin-dir=. run --server --config-file=config.yaml
    ```

## To re-vendor OPA:

   ```bash
   cd $GOPATH/src/github.com/open-policy-agent/opa-istio-plugin

   dep ensure
   ```

