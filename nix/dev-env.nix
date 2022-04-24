{ pkgs }:
with pkgs;

buildEnv {
  name = "opa-envoy-plugin-dev-env";
  paths = [
    # Go dev env:
    # - Compiler
    # - VS Code tools (https://github.com/golang/vscode-go#tools)
    # - Nix build tool (https://www.tweag.io/blog/2021-03-04-gomod2nix/)
    go gopls delve go-tools go-outline
    # NOTE. delve includes dlv-dap; go-tools = staticcheck
    gomod2nix
  ];
}
