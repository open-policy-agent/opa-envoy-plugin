#!/usr/bin/env bash
# Script to revendor OPA, Add and Commit changes if needed

set +e
set -x

usage() {
    echo "update-opa-version.sh <VERSION> eg. update-opa-version.sh v0.8.0"
}

# Check if OPA version provided
if [ $# -eq 0 ]
  then
    echo "OPA version not provided"
    usage
    exit 1
fi

# Update the OPA verison in glide.yaml
sed -i "/opa/{N;s/version: .*/version: $1/;}" glide.yaml

# Check if OPA version has changed
git status |  grep  glide.yaml
if [ $? -eq 0 ]; then

  tag=$(echo $1 | cut -c 2-)   # Remove 'v' in Tag. Eg. v0.8.0 -> 0.8.0

  # update plugin image version in README
  sed -i "s/openpolicyagent\/opa:.*/openpolicyagent\/opa:$tag-istio/" README.md

  # update plugin image version in quick_start.yaml
  sed -i "/opa_container/{N;s/openpolicyagent\/opa:.*/openpolicyagent\/opa:$tag-istio\"\,/;}" quick_start.yaml

  # run glide update
  glide up -v

  # add changes
  git add .
fi 
