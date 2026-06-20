.PHONY: build test local-vampi smoke-traffic smoke-httpbin smoke-juice-shop load-traffic validate-worker-log kafka-outage-drill

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

smoke-httpbin:
	bash scripts/smoke-httpbin-traffic.sh

smoke-juice-shop:
	bash scripts/smoke-juice-shop-traffic.sh

load-traffic:
	bash scripts/load-http-traffic.sh

validate-worker-log:
	bash scripts/validate-worker-log.sh

kafka-outage-drill:
	bash scripts/kafka-outage-drill.sh
