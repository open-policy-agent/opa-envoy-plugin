#!/usr/bin/env bash
# Script to get number of commits from the last OPA revendoring

GIT_SHA=$(git log -n 1 --oneline  --pretty=format:"%h" --author=opa-updater-automation)
COMMITS=$(git rev-list $GIT_SHA..HEAD --count)

if [ $COMMITS -ne 0 ]; then
  echo "-$COMMITS"
fi
