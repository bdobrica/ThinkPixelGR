.PHONY: run test unit-test contract-test integration-test fmt-check vet verify check build

run:
	go run ./cmd/thinkpixelgr -config ./configs/config.yaml

test:
	go test ./...

unit-test:
	go test ./cmd/... ./internal/...

contract-test:
	go test ./api ./api/detector/v1

integration-test:
	go test ./integration

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'))" || \
		(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'); exit 1)

vet:
	go vet ./...

verify: fmt-check vet unit-test contract-test integration-test

check:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')
	$(MAKE) verify

build:
	go build -o bin/thinkpixelgr ./cmd/thinkpixelgr
