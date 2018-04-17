#!/usr/bin/env bash

OPA_ISTIO_DIR=$(
    dir=$(dirname "${BASH_SOURCE}")/..
    cd "$dir"
    pwd
)
source $OPA_ISTIO_DIR/build/utils.sh

function opa-istio-plugin::check_vet() {
    exec 5>&1
    rc=0
    exit_code=0
    for pkg in $(opa-istio-plugin::go_packages); do
        go vet $pkg || rc=$?
        if [[ $rc != 0 ]]; then
            exit_code=1
        fi
    done
    exit $exit_code
}

opa-istio-plugin::check_vet
