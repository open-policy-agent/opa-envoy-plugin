#!/usr/bin/env bash

OPA_ISTIO_DIR=$(
    dir=$(dirname "${BASH_SOURCE}")/..
    cd "$dir"
    pwd
)
source $OPA_ISTIO_DIR/build/utils.sh


function opa-istio-plugin::check_lint() {
    exec 5>&1
    exit_code=0
    for pkg in $(opa-istio-plugin::go_packages); do
        __output=$(golint $pkg | tee >(cat - >&5))
        if [ ! -z "$__output" ]; then
            exit_code=1
        fi
    done
    exit $exit_code
}

opa-istio-plugin::check_lint
