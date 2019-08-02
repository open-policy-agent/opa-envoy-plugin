#!/usr/bin/env bash

OPA_ISTIO_DIR=$(dirname "${BASH_SOURCE}")/..
source $OPA_ISTIO_DIR/build/utils.sh

function opa-istio-plugin::check_fmt() {
    exec 5>&1
    exit_code=0
    for pkg in $(opa-istio-plugin::go_packages); do
        for file in $(opa-istio-plugin::go_files_in_package $pkg); do
            __diff=$(gofmt -d $file | tee >(cat - >&5))
            if [ ! -z "$__diff" ]; then
                exit_code=1
            fi
        done
    done
    exit $exit_code
}

opa-istio-plugin::check_fmt
