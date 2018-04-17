# Copyright 2018 The OPA Authors. All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

VERSION := 0.8.0-dev-istio

PACKAGES := $(shell go list ./.../ | grep -v 'vendor')

GO := go
GOARCH := $(shell go env GOARCH)
GOOS := $(shell go env GOOS)
DISABLE_CGO := CGO_ENABLED=0

BIN := opa_istio_$(GOOS)_$(GOARCH)

REPOSITORY := openpolicyagent
IMAGE := $(REPOSITORY)/opa

BUILD_COMMIT := $(shell ./build/get-build-commit.sh)
BUILD_TIMESTAMP := $(shell ./build/get-build-timestamp.sh)
BUILD_HOSTNAME := $(shell ./build/get-build-hostname.sh)

OPA_VENDOR := vendor/github.com/open-policy-agent/opa

LDFLAGS := "-X github.com/open-policy-agent/opa-istio-plugin/$(OPA_VENDOR)/version.Version=$(VERSION) \
	-X github.com/open-policy-agent/opa-istio-plugin/$(OPA_VENDOR)/version.Vcs=$(BUILD_COMMIT) \
	-X github.com/open-policy-agent/opa-istio-plugin/$(OPA_VENDOR)/version.Timestamp=$(BUILD_TIMESTAMP) \
	-X github.com/open-policy-agent/opa-istio-plugin/$(OPA_VENDOR)/version.Hostname=$(BUILD_HOSTNAME)"

GO15VENDOREXPERIMENT := 1
export GO15VENDOREXPERIMENT

.PHONY: all build build-mac build-linux clean check check-fmt check-vet check-lint \
    deps generate image image-quick push push-latest tag-latest test version

######################################################
#
# Development targets
#
######################################################

all: deps build test check

version:
	@echo $(VERSION)

deps:
	@./build/install-deps.sh

generate:
	$(GO) generate

build: generate
	$(DISABLE_CGO) $(GO) build -o $(BIN) -ldflags $(LDFLAGS)

build-mac:
	@$(MAKE) build GOOS=darwin

build-linux:
	@$(MAKE) build GOOS=linux

image:
	@$(MAKE) build-linux
	@$(MAKE) image-quick

image-quick:
	sed -e 's/GOARCH/$(GOARCH)/g' Dockerfile > .Dockerfile_$(GOARCH)
	docker build -t $(IMAGE):$(VERSION) -f .Dockerfile_$(GOARCH) .

push:
	docker push $(IMAGE):$(VERSION)

tag-latest:
	docker tag $(IMAGE):$(VERSION) $(IMAGE):latest

push-latest:
	docker push $(IMAGE):latest

test: generate
	$(DISABLE_CGO) $(GO) test $(PACKAGES)

clean:
	rm -f .Dockerfile_*
	rm -f opa_*_*

check: check-fmt check-vet check-lint

check-fmt:
	./build/check-fmt.sh

check-vet:
	./build/check-vet.sh

check-lint:
	./build/check-lint.sh
