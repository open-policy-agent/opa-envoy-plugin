REPOSITORY := openpolicyagent/proxy_init
VERSION := v6

.PHONY: all
all: image

.PHONY: build
build: image

.PHONY: image
image:
	docker buildx build --platform=linux/amd64,linux/arm64 -t $(REPOSITORY):latest -t $(REPOSITORY):$(VERSION) .

.PHONY: push
push:
	docker buildx build --push --platform=linux/amd64,linux/arm64 -t $(REPOSITORY):latest -t $(REPOSITORY):$(VERSION) .
