# Copyright 2018 The OPA Authors. All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

VERSION_OPA := $(shell ./build/get-opa-version.sh)
VERSION := $(VERSION_OPA)-envoy$(shell ./build/get-plugin-rev.sh)
VERSION_ISTIO := $(VERSION_OPA)-istio$(shell ./build/get-plugin-rev.sh)

PACKAGES := $(shell go list ./.../ | grep -v 'vendor')


CGO_ENABLED ?= 1
WASM_ENABLED ?= 1

# GOPROXY=off: Don't pull anything off the network
# see https://github.com/thepudds/go-module-knobs/blob/master/README.md
GO := CGO_ENABLED=$(CGO_ENABLED) GO111MODULE=on GOFLAGS=-mod=vendor GOPROXY=off go
GOVERSION := $(shell cat ./.go-version)
GOARCH := $(shell go env GOARCH)
GOOS := $(shell go env GOOS)
DISABLE_CGO := CGO_ENABLED=0

BIN := opa_envoy_$(GOOS)_$(GOARCH)

REPOSITORY := openpolicyagent
IMAGE := $(REPOSITORY)/opa

GO_TAGS := -tags=
ifeq ($(WASM_ENABLED),1)
GO_TAGS = -tags=opa_wasm
endif

ifeq ($(shell tty > /dev/null && echo 1 || echo 0), 1)
DOCKER_FLAGS := --rm -it
else
DOCKER_FLAGS := --rm
endif

RELEASE_BUILD_IMAGE := golang:$(GOVERSION)

RELEASE_DIR ?= _release/$(VERSION)

BUILD_COMMIT := $(shell ./build/get-build-commit.sh)
BUILD_TIMESTAMP := $(shell ./build/get-build-timestamp.sh)
BUILD_HOSTNAME := $(shell ./build/get-build-hostname.sh)

LDFLAGS := "-X github.com/open-policy-agent/opa/version.Version=$(VERSION) \
	-X github.com/open-policy-agent/opa/version.Vcs=$(BUILD_COMMIT) \
	-X github.com/open-policy-agent/opa/version.Timestamp=$(BUILD_TIMESTAMP) \
	-X github.com/open-policy-agent/opa/version.Hostname=$(BUILD_HOSTNAME)"

.PHONY: all build build-darwin build-linux build-linux-static build-windows clean check check-fmt check-vet check-lint \
    deploy-ci docker-login generate image image-quick image-static image-quick-static push push-static push-latest \
    push-latest-static tag-latest tag-latest-static test test-cluster test-e2e version

######################################################
#
# Development targets
#
######################################################

all: build test check

version:
	@echo $(VERSION)

generate:
	$(GO) generate ./...

build: generate
	$(GO) build $(GO_TAGS) -o $(BIN) -ldflags $(LDFLAGS) ./cmd/opa-envoy-plugin/...

build-darwin:
	@$(MAKE) build GOOS=darwin

build-linux:
	@$(MAKE) build GOOS=linux

build-linux-static:
	@$(MAKE) build GOOS=linux WASM_ENABLED=0 CGO_ENABLED=0

build-windows:
	@$(MAKE) build GOOS=windows

image:
	@$(MAKE) ci-go-build-linux
	@$(MAKE) image-quick

image-static:
	CGO_ENABLED=0 WASM_ENABLED=0 $(MAKE) ci-go-build-linux-static
	@$(MAKE) image-quick-static

image-quick:
	sed -e 's/GOARCH/$(GOARCH)/g' Dockerfile > .Dockerfile_$(GOARCH)
	docker build -t $(IMAGE):$(VERSION) --build-arg BASE=gcr.io/distroless/cc -f .Dockerfile_$(GOARCH) .
	docker tag $(IMAGE):$(VERSION) $(IMAGE):$(VERSION_ISTIO)

image-quick-static:
	sed -e 's/GOARCH/$(GOARCH)/g' Dockerfile > .Dockerfile_$(GOARCH)
	docker build -t $(IMAGE):$(VERSION)-static --build-arg BASE=gcr.io/distroless/static -f .Dockerfile_$(GOARCH) .
	docker tag $(IMAGE):$(VERSION)-static $(IMAGE):$(VERSION_ISTIO)-static

push:
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):$(VERSION_ISTIO)

push-static:
	docker push $(IMAGE):$(VERSION)-static
	docker push $(IMAGE):$(VERSION_ISTIO)-static

tag-latest:
	docker tag $(IMAGE):$(VERSION) $(IMAGE):latest-envoy
	docker tag $(IMAGE):$(VERSION) $(IMAGE):latest-istio

tag-latest-static:
	docker tag $(IMAGE):$(VERSION)-static $(IMAGE):latest-envoy-static
	docker tag $(IMAGE):$(VERSION)-static $(IMAGE):latest-istio-static

push-latest:
	docker push $(IMAGE):latest-envoy
	docker push $(IMAGE):latest-istio

push-latest-static:
	docker push $(IMAGE):latest-envoy-static
	docker push $(IMAGE):latest-istio-static

docker-login:
	@echo "Docker Login..."
	@echo ${DOCKER_PASSWORD} | docker login -u ${DOCKER_USER} --password-stdin

deploy-ci: docker-login image image-static push tag-latest push-latest push-static tag-latest-static push-latest-static

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

generatepb:
	protoc --proto_path=test/files \
	  --descriptor_set_out=test/files/combined.pb \
	  --include_imports \
	  test/files/example/Example.proto \
	  test/files/book/Book.proto

CI_GOLANG_DOCKER_MAKE := docker run \
        $(DOCKER_FLAGS) \
        -u $(shell id -u):$(shell id -g) \
        -v $(PWD):/src \
        -w /src \
        -e GOCACHE=/src/.go/cache \
        -e CGO_ENABLED=$(CGO_ENABLED) \
        -e WASM_ENABLED=$(WASM_ENABLED) \
        -e TELEMETRY_URL=$(TELEMETRY_URL) \
        golang:$(GOVERSION) \
        make

.PHONY: ci-go-%
ci-go-%:
	$(CI_GOLANG_DOCKER_MAKE) "$*"

.PHONY: release
release:
	docker run $(DOCKER_FLAGS) \
		-v $(PWD)/$(RELEASE_DIR):/$(RELEASE_DIR) \
		-v $(PWD):/_src \
		$(RELEASE_BUILD_IMAGE) \
		/_src/build/build-release.sh --version=$(VERSION) --output-dir=/$(RELEASE_DIR) --source-url=/_src


.PHONY: release-build-linux
release-build-linux: ensure-release-dir
	@$(MAKE) build GOOS=linux CGO_ENABLED=0 WASM_ENABLED=0
	mv opa_envoy_linux_$(GOARCH) $(RELEASE_DIR)/

.PHONY: release-build-darwin
release-build-darwin: ensure-release-dir
	@$(MAKE) build GOOS=darwin CGO_ENABLED=0 WASM_ENABLED=0
	mv opa_envoy_darwin_$(GOARCH) $(RELEASE_DIR)/

.PHONY: release-build-windows
release-build-windows: ensure-release-dir
	@$(MAKE) build GOOS=windows CGO_ENABLED=0 WASM_ENABLED=0
	mv opa_envoy_windows_$(GOARCH) $(RELEASE_DIR)/opa_envoy_windows_$(GOARCH).exe

.PHONY: ensure-release-dir
ensure-release-dir:
	mkdir -p $(RELEASE_DIR)

.PHONY: build-all-platforms
build-all-platforms: release-build-linux release-build-darwin release-build-windows
