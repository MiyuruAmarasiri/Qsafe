SHELL := /bin/bash

GO_BIN := go
PROJECT := github.com/example/qsafe
BUILD_DIR := dist

.PHONY: all bootstrap tidy test lint build build-gateway build-agent run-gateway run-agent compose-up compose-down clean

all: build

bootstrap:
	@echo ">> Installing toolchain via asdf (if available)"
	@if command -v asdf >/dev/null 2>&1; then asdf install || true; fi
	@echo ">> Enabling direnv"
	@if command -v direnv >/dev/null 2>&1; then direnv allow || true; fi

tidy:
	@echo ">> Ensuring Go modules are tidy"
	$(GO_BIN) mod tidy

test:
	@echo ">> Running unit tests"
	$(GO_BIN) test ./...

lint:
	@echo ">> Formatting Go sources"
	$(GO_BIN) fmt ./...

build: build-gateway build-agent

build-gateway:
	@echo ">> Building gateway binary"
	$(GO_BIN) build -o $(BUILD_DIR)/gateway ./cmd/gateway

build-agent:
	@echo ">> Building agent binary"
	$(GO_BIN) build -o $(BUILD_DIR)/agent ./cmd/agent

run-gateway:
	@echo ">> Starting gateway (CTRL+C to stop)"
	go run ./cmd/gateway --addr=:8443

run-agent:
	@echo ">> Running agent against local gateway"
	go run ./cmd/agent --gateway=http://localhost:8443

compose-up:
	@docker compose -f infra/docker/docker-compose.yml up --build

compose-down:
	@docker compose -f infra/docker/docker-compose.yml down

clean:
	@rm -rf $(BUILD_DIR)
