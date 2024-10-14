# Change Log

All notable changes to this project will be documented in this file. This
project adheres to [Semantic Versioning](http://semver.org/).

## Unreleased

- Refactor creation of prepared queries (#604, @mjungsbluth)
  
  When using the opa-envoy-plugin as a Go library, the interface EvalContext contains a breaking change [#604](https://github.com/open-policy-agent/opa-envoy-plugin/pull/604) that allows users of the library to control all three types of options that can be passed during preparation and evaluation of the underlying Rego query.  

### Fixes

- Support escaped forward-slashes (`\/`) in JSON request bodies (#256, @Dakatan).

  When parsing request bodies of requests with header "Content-Type: application/json",
  opa-envoy-plugin had used a utility method from github.com/open-policy-agent/opa that
  also accepted YAML. This wasn't an intentional feature, and has been removed.

  One side-effect of using that method was that an escaped forward slash, which is
  allowed in the JSON spec (but optional, forward slashes *may* be escaped), wasn't
  parsed properly, leading to a denying policy response when the request may have
  been permissible.
