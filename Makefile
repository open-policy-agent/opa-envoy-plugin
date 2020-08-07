# Copyright 2018 The OPA Authors. All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

VERSION := $(shell ./build/get-opa-version.sh)-envoy$(shell ./build/get-plugin-rev.sh)
VERSION_ISTIO := $(shell ./build/get-opa-version.sh)-istio$(shell ./build/get-plugin-rev.sh)

PACKAGES := $(shell go list ./.../ | grep -v 'vendor')

GO := go
GOARCH := $(shell go env GOARCH)
GOOS := $(shell go env GOOS)
DISABLE_CGO := CGO_ENABLED=0

BIN := opa_envoy_$(GOOS)_$(GOARCH)

REPOSITORY := openpolicyagent
IMAGE := $(REPOSITORY)/opa

BUILD_COMMIT := $(shell ./build/get-build-commit.sh)
BUILD_TIMESTAMP := $(shell ./build/get-build-timestamp.sh)
BUILD_HOSTNAME := $(shell ./build/get-build-hostname.sh)

LDFLAGS := "-X github.com/open-policy-agent/opa/version.Version=$(VERSION) \
	-X github.com/open-policy-agent/opa/version.Vcs=$(BUILD_COMMIT) \
	-X github.com/open-policy-agent/opa/version.Timestamp=$(BUILD_TIMESTAMP) \
	-X github.com/open-policy-agent/opa/version.Hostname=$(BUILD_HOSTNAME)"

GO15VENDOREXPERIMENT := 1
export GO15VENDOREXPERIMENT

.PHONY: all build build-mac build-linux clean check check-fmt check-vet check-lint \
    deps deploy-travis generate image image-quick push push-latest tag-latest \
    test test-cluster test-e2e update-opa update-istio-quickstart-version version

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
	$(GO) generate ./...

build: generate
	$(GO) build -o $(BIN) -ldflags $(LDFLAGS) ./cmd/opa-envoy-plugin/...

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
	docker tag $(IMAGE):$(VERSION) $(IMAGE):$(VERSION_ISTIO)

push:
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):$(VERSION_ISTIO)

tag-latest:
	docker tag $(IMAGE):$(VERSION) $(IMAGE):latest-envoy
	docker tag $(IMAGE):$(VERSION) $(IMAGE):latest-istio

push-latest:
	docker push $(IMAGE):latest-envoy
	docker push $(IMAGE):latest-istio

deploy-travis: image-quick push tag-latest push-latest

update-opa:
	@./build/update-opa-version.sh $(TAG)

update-istio-quickstart-version:
	sed -i "/opa_container/{N;s/openpolicyagent\/opa:.*/openpolicyagent\/opa:latest-istio\"\,/;}" examples/istio/quick_start.yaml

test: generate
	$(DISABLE_CGO) $(GO) test -v -bench=. $(PACKAGES)

test-e2e:
	bats -t test/bats/test.bats

test-cluster:
	@./build/install-istio-with-kind.sh

clean:
	rm -f .Dockerfile_*
	rm -f opa_*_*
	rm -f *.so

check: check-fmt check-vet check-lint

check-fmt:
	./build/check-fmt.sh

check-vet:
	./build/check-vet.sh

check-lint:
	./build/check-lint.sh
