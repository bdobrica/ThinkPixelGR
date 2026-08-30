.PHONY: run test fmt-check vet verify check build

run:
	go run ./cmd/thinkpixelgr -config ./configs/config.yaml

test:
	go test ./...

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'))" || \
		(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'); exit 1)

vet:
	go vet ./...

verify: fmt-check vet test

check:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')
	$(MAKE) verify

build:
	go build -o bin/thinkpixelgr ./cmd/thinkpixelgr
