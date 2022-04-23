{
  inputs = {
    nixie.url = "github:c0c0n3/nixie";
    gomod2nix.url = "github:tweag/gomod2nix";
    nixpkgs.follows = "nixie/nixpkgs";
  };

  outputs = { self, nixpkgs, nixie, gomod2nix }:
  let
    output = nixie.lib.flakes.mkOutputSetForCoreSystems nixpkgs;
    devEnv = { system, sysPkgs, ...}: {
      defaultPackage.${system} = with sysPkgs; buildEnv {
        name = "opa-dev-env";
        paths = [
            go
            gomod2nix.defaultPackage.${system}
        ];
      };
    };
  in
    output devEnv;
}
