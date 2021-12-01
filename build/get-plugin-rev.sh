#!/usr/bin/env bash
# Script to get number of commits from the last OPA revendoring

GIT_SHA=$(git log -n 1 --pretty=format:%H -- vendor/github.com/open-policy-agent/opa)
COMMITS=$(git rev-list $GIT_SHA..HEAD --count)

if [ $COMMITS -ne 0 ]; then
  echo "-$COMMITS"
fi
