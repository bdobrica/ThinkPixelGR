.PHONY: run test check build

run:
	go run ./cmd/thinkpixelgr -config ./configs/config.yaml

test:
	go test ./...

check:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')
	go vet ./...
	go test ./...

build:
	go build -o bin/thinkpixelgr ./cmd/thinkpixelgr
