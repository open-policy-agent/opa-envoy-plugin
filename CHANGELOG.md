# Change Log

All notable changes to this project will be documented in this file. This
project adheres to [Semantic Versioning](http://semver.org/).

## Unreleased

### Fixes

- Support escaped forward-slashes (`\/`) in JSON request bodies (#256, @Dakatan).

  When parsing request bodies of requests with header "Content-Type: application/json",
  opa-envoy-plugin had used a utility method from github.com/open-policy-agent/opa that
  also accepted YAML. This wasn't an intentional feature, and has been removed.

  One side-effect of using that method was that an escaped forward slash, which is
  allowed in the JSON spec (but optional, forward slashes *may* be escaped), wasn't
  parsed properly, leading to a denying policy response when the request may have
  been permissible.
