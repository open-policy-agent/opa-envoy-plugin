SHELL:=bash
GRPCURL_IMAGE:=fullstorydev/grpcurl:v1.7.0
GRPCURL=docker run --network=host -i --rm -v $$(pwd)/testsrv.pb:/testsrv.pb $(GRPCURL_IMAGE) \
  -d @ -plaintext -protoset /testsrv.pb 127.0.0.1:51051

all: testsrv.pb testsrv-image test-setup test test-teardown

.PHONY: testsrv-image
testsrv-image:
	docker build -t testsrv testsrv/

testsrv.pb: testsrv/test.proto
	protoc --include_imports -o "$@" "$<"

.PHONY: test-setup
test-setup:
	docker-compose up -d

.PHONY: test-teardown
test-teardown:
	docker-compose logs
	docker-compose down

.PHONY: test
test:
	$(GRPCURL) test.KitchenSink/Ping <<<"{}"
	$(GRPCURL) test.KitchenSink/Exchange < message.json
	if sed s/alice/arno/ message.json | $(GRPCURL) test.KitchenSink/Exchange; then \
	  echo "expected 'Permission Denied'"; exit 1; fi
