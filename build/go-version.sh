#!/bin/bash

go list -m -f '{{ .GoVersion }}' github.com/open-policy-agent/opa-envoy-plugin
