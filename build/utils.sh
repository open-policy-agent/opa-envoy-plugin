#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset

function opa-envoy-plugin::go_packages() {
    for pkg in $(go list ./.../ 2>/dev/null); do
        echo $pkg
    done
}

function opa-envoy-plugin::go_files_in_package() {
    dir=$(go list -f '{{ .Dir }}' $1)
    for file in $(go list -f '{{ join .GoFiles "\n" }}' $1); do
        echo  $dir/$file
    done
    for file in $(go list -f '{{ join .TestGoFiles "\n" }}' $1); do
        echo $dir/$file
    done
}

