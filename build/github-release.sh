#!/usr/bin/env bash
# Script to draft and edit OPA-Envoy GitHub releases. Assumes execution environment is Github Action runner.

set -x

usage() {
    echo "github-release.sh [--asset-dir=<path>] [--tag=<git tag>]"
    echo "    Default --asset-dir is $PWD and --tag $TAG_NAME "
}

TAG_NAME=${TAG_NAME}
ASSET_DIR=${PWD:-"./"}

for i in "$@"; do
    case $i in
    --asset-dir=*)
        ASSET_DIR="${i#*=}"
        shift
        ;;
    --tag=*)
        TAG_NAME="${i#*=}"
        shift
        ;;
    *)
        usage
        exit 1
        ;;
    esac
done

# Collect a list of opa-envoy binaries
ASSETS=()
for asset in "${ASSET_DIR}"/opa_envoy_*_*; do
    ASSETS+=("$asset")
done

# Prepare the release notes
RELEASE_NOTES="release-notes.md"

# The hub CLI expects the first line to be the title
echo -e "${TAG_NAME}\n" > "${RELEASE_NOTES}"

# Fill in the description
LINE="See the OPA ${TAG_NAME} release notes."
echo -e "${LINE}" >> "${RELEASE_NOTES}"

# Update or create a release on github
if gh release view "${TAG_NAME}" --repo open-policy-agent/opa-envoy-plugin > /dev/null; then
    # Occurs when the tag is created via GitHub UI w/ a release
    gh release upload "${TAG_NAME}" "${ASSETS[@]}" --repo open-policy-agent/opa-envoy-plugin
else
    # Create a draft release
    gh release create "${TAG_NAME}" "${ASSETS[@]}" -F ${RELEASE_NOTES} --draft --title "${TAG_NAME}" --repo open-policy-agent/opa-envoy-plugin
fi
