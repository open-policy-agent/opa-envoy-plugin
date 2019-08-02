#!/usr/bin/env bash
# Script to get OPA version from Gopkg.toml. The script removes the
# leading 'v' in the OPA release tag. Example v0.8.0 -> 0.8.0.
# The script also trims whitespaces.

SCRIPT_DIR="$( cd "$(dirname "$0")" ; pwd -P )"
grep -A1 "open-policy-agent/opa" $SCRIPT_DIR/../Gopkg.toml | tail -1 | cut -d'=' -f 2 | xargs | cut -c 2-
