#!/usr/bin/env bash
# Script to revendor OPA, Add and Commit changes if needed

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
sed -i '' "/opa/{N;s/version: .*/version: $1/;}" glide.yaml

# Check if OPA version has changed
git diff-index --quiet HEAD --
if [ $? -ne 0 ]; then 
  # run glide update
  glide up -v

  # add and commit changes
  git add . && git commit -s -m "Update OPA version to $1"
fi 
