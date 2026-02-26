# Copyright 2018 The OPA Authors. All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

VERSION_OPA := $(shell ./build/get-opa-version.sh)
VERSION := $(VERSION_OPA)-envoy$(shell ./build/get-plugin-rev.sh)
VERSION_ISTIO := $(VERSION_OPA)-istio$(shell ./build/get-plugin-rev.sh)

PACKAGES := $(shell go list ./.../)

DOCKER := docker

DOCKER_UID ?= 0
DOCKER_GID ?= 0

CGO_ENABLED ?= 1
WASM_ENABLED ?= 1
GOARCH ?= $(shell go env GOARCH)

DOCKER_RUNNING ?= $(shell docker ps >/dev/null 2>&1 && echo 1 || echo 0)
GOLANGCI_LINT_VERSION := v2.9

GO := CGO_ENABLED=$(CGO_ENABLED) GOARCH=$(GOARCH) GO111MODULE=on go
GOVERSION := $(shell cat ./.go-version)
GOOS := $(shell go env GOOS)
DISABLE_CGO := CGO_ENABLED=0

VARIANT := dynamic
ifeq ($(CGO_ENABLED),0)
	VARIANT = static
endif

BIN := opa_envoy_$(GOOS)_$(GOARCH)_$(VARIANT)

REPOSITORY ?= openpolicyagent
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

# BuildKit is required for automatic platform arg injection (see Dockerfile)
export DOCKER_BUILDKIT := 1

# Supported platforms to include in image manifest lists
DOCKER_PLATFORMS := linux/amd64
DOCKER_PLATFORMS_STATIC := linux/amd64,linux/arm64

######################################################
#
# Development targets
#
######################################################

.PHONY: all
all: build test check

.PHONY: version
version:
	@echo $(VERSION)

.PHONY: generate
generate:
	$(GO) generate ./...

.PHONY: build
build: generate
	$(GO) build $(GO_TAGS) -o $(BIN) -ldflags $(LDFLAGS) ./cmd/opa-envoy-plugin/...

.PHONY: build-darwin
build-darwin:
	@$(MAKE) build GOOS=darwin

.PHONY: build-linux
build-linux: ensure-release-dir ensure-linux-toolchain
	@$(MAKE) build GOOS=linux

.PHONY: build-linux-static
build-linux-static: ensure-release-dir ensure-linux-toolchain
	@$(MAKE) build GOOS=linux WASM_ENABLED=0 CGO_ENABLED=0

.PHONY: ci-build-linux
ci-build-linux:
	$(MAKE) ci-go-build-linux GOARCH=amd64

.PHONY: ci-build-linux-static
ci-build-linux-static:
	$(MAKE) ci-go-build-linux-static GOARCH=arm64
	$(MAKE) ci-go-build-linux-static GOARCH=amd64

.PHONY: build-windows
build-windows:
	@$(MAKE) build GOOS=windows

.PHONY: image
image:
	@$(MAKE) ci-go-build-linux
	@$(MAKE) image-quick

.PHONY: start-builder
start-builder:
	@./build/buildx_workaround.sh

.PHONY: image-quick
image-quick: image-quick-$(GOARCH)

.PHONY: image-quick-%
image-quick-%:
ifneq ($(GOARCH),arm64) # build only static images for arm64
	$(DOCKER) build \
		--platform=linux/$(GOARCH) \
		-t $(IMAGE):$(VERSION) \
		--build-arg BASE=chainguard/glibc-dynamic:latest \
		--build-arg VARIANT=dynamic \
		-f Dockerfile \
		.
endif
	$(DOCKER) build \
		--platform=linux/$(GOARCH) \
		-t $(IMAGE):$(VERSION)-static \
		--build-arg BASE=chainguard/static:latest \
		--build-arg VARIANT=static \
		-f Dockerfile \
		.

.PHONY: push-manifest-list-%
push-manifest-list-%:
	$(DOCKER) buildx build \
		--platform=$(DOCKER_PLATFORMS) \
		--push \
		-t $(IMAGE):$* \
		--build-arg BASE=chainguard/glibc-dynamic:latest \
		--build-arg VARIANT=dynamic \
		-f Dockerfile \
		.
	
	$(DOCKER) buildx build \
		--platform=$(DOCKER_PLATFORMS_STATIC) \
		--push \
		-t $(IMAGE):$*-static \
		--build-arg BASE=chainguard/static:latest \
		--build-arg VARIANT=static \
		-f Dockerfile \
		.

.PHONY: docker-login
docker-login:
	@echo "Docker Login..."
	@echo ${DOCKER_PASSWORD} | $(DOCKER) login -u ${DOCKER_USER} --password-stdin

.PHONY: push-image
push-image: docker-login push-manifest-list-$(VERSION)

.PHONY: deploy-ci
deploy-ci: docker-login ensure-release-dir start-builder ci-build-linux ci-build-linux-static push-manifest-list-latest-istio push-manifest-list-latest-envoy push-manifest-list-$(VERSION) push-manifest-list-$(VERSION_ISTIO)

.PHONY: test
test: generate
	$(DISABLE_CGO) $(GO) test -v -bench=. -benchmem $(PACKAGES)

.PHONY: test-e2e
test-e2e:
	bats -t test/bats/test.bats

.PHONY: test-cluster
test-cluster:
	@./build/install-istio-with-kind.sh

.PHONY: clean
clean:
	rm -f .Dockerfile_*
	rm -f opa_*_*
	rm -f *.so

.PHONY: check
check:
ifeq ($(DOCKER_RUNNING), 1)
	docker run --rm -v $(shell pwd):/app:ro,Z -w /app golangci/golangci-lint:${GOLANGCI_LINT_VERSION} golangci-lint run -v
else
	@echo "Docker not installed or running. Skipping golangci run."
endif

.PHONY: fmt
fmt:
ifeq ($(DOCKER_RUNNING), 1)
	docker run --rm -v $(shell pwd):/app:Z -w /app golangci/golangci-lint:${GOLANGCI_LINT_VERSION} golangci-lint run -v --fix
else
	@echo "Docker not installed or running. Skipping golangci run."
endif

.PHONY: generatepb
generatepb:
	protoc --proto_path=test/files \
	  --descriptor_set_out=test/files/combined.pb \
	  --include_imports \
	  test/files/example/Example.proto \
	  test/files/book/Book.proto

CI_GOLANG_DOCKER_MAKE := $(DOCKER) run \
        $(DOCKER_FLAGS) \
        -u $(DOCKER_UID):$(DOCKER_GID) \
        -v $(PWD):/src \
        -w /src \
        -e GOCACHE=/src/.go/cache \
        -e CGO_ENABLED=$(CGO_ENABLED) \
        -e WASM_ENABLED=$(WASM_ENABLED) \
        -e TELEMETRY_URL=$(TELEMETRY_URL) \
		-e GOARCH=$(GOARCH) \
        golang:$(GOVERSION) \
		make

.PHONY: ensure-linux-toolchain
ensure-linux-toolchain:
ifeq ($(CGO_ENABLED),1)
	$(eval export CC = $(shell GOARCH=$(GOARCH) build/ensure-linux-toolchain.sh))
else
	@echo "CGO_ENABLED=$(CGO_ENABLED). No need to check gcc toolchain."
endif

.PHONY: ci-go-%
ci-go-%:
	$(CI_GOLANG_DOCKER_MAKE) "$*"

.PHONY: tag-latest
tag-latest:
	docker tag $(IMAGE):$(VERSION) $(IMAGE):latest-envoy
	docker tag $(IMAGE):$(VERSION) $(IMAGE):latest-istio

.PHONY: tag-latest-static
tag-latest-static:
	docker tag $(IMAGE):$(VERSION)-static $(IMAGE):latest-envoy-static
	docker tag $(IMAGE):$(VERSION)-static $(IMAGE):latest-istio-static

.PHONY: release
release:
	$(DOCKER) run $(DOCKER_FLAGS) \
		-v $(PWD)/$(RELEASE_DIR):/$(RELEASE_DIR) \
		-v $(PWD):/_src \
		$(RELEASE_BUILD_IMAGE) \
		/_src/build/build-release.sh --version=$(VERSION) --output-dir=/$(RELEASE_DIR) --source-url=/_src

.PHONY: release-build-linux-%
release-build-linux-%: ensure-release-dir
	@$(MAKE) build GOOS=linux GOARCH=$*
	mv opa_envoy_linux_$*_dynamic $(RELEASE_DIR)/opa_envoy_linux_$*

.PHONY: release-build-linux-static-%
release-build-linux-static-%: ensure-release-dir
	@$(MAKE) build GOOS=linux CGO_ENABLED=0 WASM_ENABLED=0 GOARCH=$*
	mv opa_envoy_linux_$*_static $(RELEASE_DIR)/opa_envoy_linux_$*_static

.PHONY: release-build-darwin-%
release-build-darwin-%: ensure-release-dir
	@$(MAKE) build GOOS=darwin GOARCH=$*
	mv opa_envoy_darwin_$*_dynamic $(RELEASE_DIR)/opa_envoy_darwin_$*

.PHONY: release-build-darwin-static-%
release-build-darwin-static-%: ensure-release-dir
	@$(MAKE) build GOOS=darwin CGO_ENABLED=0 WASM_ENABLED=0 GOARCH=$*
	mv opa_envoy_darwin_$*_static $(RELEASE_DIR)/opa_envoy_darwin_$*_static

.PHONY: release-build-windows
release-build-windows: ensure-release-dir
	@$(MAKE) build GOOS=windows CGO_ENABLED=0 WASM_ENABLED=0
	mv opa_envoy_windows_$(GOARCH)_static $(RELEASE_DIR)/opa_envoy_windows_$(GOARCH).exe

.PHONY: ensure-release-dir
ensure-release-dir:
	mkdir -p $(RELEASE_DIR)

.PHONY: build-all-platforms
build-all-platforms: release-build-linux-amd64 release-build-linux-static-amd64 release-build-linux-static-arm64 release-build-darwin-static-amd64 release-build-darwin-static-arm64 release-build-windows
