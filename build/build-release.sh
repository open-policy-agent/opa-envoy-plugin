#!/usr/bin/env bash
# Script to build OPA-Envoy releases. Assumes execution environment is golang Docker container.

set -e

OPA_ENVOY_DIR=/go/src/github.com/open-policy-agent/opa-envoy-plugin
BUILD_DIR=$OPA_ENVOY_DIR/build

usage() {
    echo "build-release.sh --output-dir=<path>"
    echo "                 --source-url=<git-url>"
    echo "                 [--version=<mj.mn.pt>]"
}

for i in "$@"; do
    case $i in
    --source-url=*)
        SOURCE_URL="${i#*=}"
        shift
        ;;
    --output-dir=*)
        OUTPUT_DIR="${i#*=}"
        shift
        ;;
    --version=*)
        VERSION="${i#*=}"
        shift
        ;;
    *)
        usage
        exit 1
        ;;
    esac
done

if [ -z "$OUTPUT_DIR" ]; then
    usage
    exit 1
elif [ -z "$SOURCE_URL" ]; then
    usage
    exit 1
fi

build_release() {
    make build-all-platforms RELEASE_DIR="${OUTPUT_DIR}"
}

clone_repo() {
    git config --system --add safe.directory '*'
    git clone $SOURCE_URL /go/src/github.com/open-policy-agent/opa-envoy-plugin
    cd /go/src/github.com/open-policy-agent/opa-envoy-plugin
    if [ -n "$VERSION" ]; then
        git checkout v${VERSION}
    fi
}

main() {
    clone_repo
    build_release
}

main
