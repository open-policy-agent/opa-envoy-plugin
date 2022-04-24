{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    nixie.url = "github:c0c0n3/nixie";
    gomod2nix.url = "github:tweag/gomod2nix";
  };

  outputs = { self, nixpkgs, nixie, gomod2nix }:
  let
    output = nixie.lib.flakes.mkOutputSetForCoreSystems nixpkgs;
    devEnv = { system, sysPkgs, ...}: {
      defaultPackage.${system} = with sysPkgs; buildEnv {
        name = "opa-dev-env";
        paths = [
          # Go dev env:
          # - Compiler
          # - VS Code tools (https://github.com/golang/vscode-go#tools)
          # - Nix build tool (https://www.tweag.io/blog/2021-03-04-gomod2nix/)
          go gopls delve go-tools go-outline
          # NOTE. delve includes dlv-dap; go-tools = staticcheck
          gomod2nix.defaultPackage.${system}
        ];
      };
    };
  in
    output devEnv;
}
