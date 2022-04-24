{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    nixie.url = "github:c0c0n3/nixie";
    gomod-2-nix.url = "github:tweag/gomod2nix";
  };

  outputs = { self, nixpkgs, nixie, gomod-2-nix }:
  let
    # Nixie flake builder.
    output = nixie.lib.flakes.mkOutputSetForCoreSystems nixpkgs;

    flake = { system, sysPkgs, ...}:
    let
      # Add gomod2nix tool and go pkg builder (buildGoApplication) to the
      # base Nix pkgs.
      pkgs = import nixpkgs {
        system = system;
        overlays = [ gomod-2-nix.overlay ];
      };
    in {
      packages.${system} = {
        # Make the dev env the default pkg so `nix shell` will give you
        # an env with all the dev tools in it.
        # NOTE. Setting devShells.${system}.default doesn't seem to work
        # with `nix shell`. It's probably for `nix develop`, but this
        # gives you a shell packed with lots of Nix extras you won't need.
        default = pkgs.callPackage ./dev-env.nix { inherit pkgs; };
        opa-envoy-plugin = pkgs.callPackage ./opa-envoy-plugin.nix {
          inherit pkgs;
        };
      };
    };
  in
    output flake;
}
