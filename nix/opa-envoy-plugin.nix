# NOTE this package is still a work in progress!
{ pkgs }:
pkgs.buildGoApplication {
  pname = "opa-envoy-plugin";
  version = "0.1.0";
  src = ../.;
  modules = ../gomod2nix.toml;                  # (1)
  # subPackages = [ ../cmd/opa-envoy-plugin ];  # (2)
}
# NOTE
# 1. Go deps. Everytime you add a new Go module, you've got to remember
#    to run `gomod2nix` from the root dir to regenerate `gomod2nix.toml`.
# 2. Build target. Not sure how to tackle this. At the moment it looks
#    like every subdir gets built, but if I add the `subPackages` attr,
#    then I get an error---try running `nix build .#opa-envoy-plugin`.
#    In both cases, the result dir doesn't contain any files though!
# 3. Build flags. To be added. See Makefile.
# 4. Code gen. Not sure how to tackle this. Probably the approach should
#    be similar to deps where we've got to remember to run `go generate`
#    beforehand and commit the generated files to the repo?
