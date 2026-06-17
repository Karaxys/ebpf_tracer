.PHONY: build test local-vampi smoke-traffic

build:
	mkdir -p bin
	go build -o bin/agent ./cmd/agent
	go build -o bin/worker ./cmd/worker

test:
	go test ./...

local-vampi:
	bash scripts/run-local-vampi.sh

smoke-traffic:
	bash scripts/smoke-vampi-traffic.sh
