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

# Update OPA version
env GO111MODULE=on go get github.com/open-policy-agent/opa@$1

# Check if OPA version has changed
git status |  grep  go.mod
if [ $? -eq 0 ]; then

  tag=$(echo $1 | cut -c 2-)   # Remove 'v' in Tag. Eg. v0.8.0 -> 0.8.0

  # update plugin image version in README
  sed -i.bak "s/openpolicyagent\/opa:.*/openpolicyagent\/opa:$tag-istio/" README.md && rm README.md.bak

  # update plugin image version in quick_start.yaml
  sed -i.bak "/opa_container/{N;s/openpolicyagent\/opa:.*/openpolicyagent\/opa:$tag-istio\"\,/;}" quick_start.yaml && rm quick_start.yaml.bak
  sed -i.bak "s/image: openpolicyagent\/opa:.*/image: openpolicyagent\/opa:$tag/" quick_start.yaml quick_start.yaml && rm quick_start.yaml.bak

  # update vendor
  env GO111MODULE=on go mod vendor

  # reverse changes to golang tools
  # Issue: https://github.com/golang/go/issues/25922 and https://github.com/golang/go/issues/30515
  git checkout vendor/golang.org/x/

  # add changes
  git add .
fi 
