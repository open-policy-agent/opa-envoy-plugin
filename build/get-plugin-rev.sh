#!/usr/bin/env bash
# Script to get number of commits from the last OPA revendoring

LINE=$(git grep -n "github.com/open-policy-agent/opa " go.mod | awk -F: '{ print $2 }')
GIT_SHA=$(git log -n 1 --pretty=format:%H -L $LINE,$LINE:go.mod | head -1)
COMMITS=$(git rev-list $GIT_SHA..HEAD --count)

if [ $COMMITS -ne 0 ]; then
  echo "-$COMMITS"
fi
