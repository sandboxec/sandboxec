APP_NAME := sandboxec
BIN_DIR := bin
BIN := $(BIN_DIR)/$(APP_NAME)
GO ?= go
VERSION ?= $(shell git describe --tags --dirty --match 'v*' --always 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || true)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS ?= -s -w \
	-X go.sandbox.ec/sandboxec/internal/cli.AppVersion=$(VERSION) \
	-X go.sandbox.ec/sandboxec/internal/cli.AppBuildCommit=$(COMMIT) \
	-X go.sandbox.ec/sandboxec/internal/cli.AppBuildDate=$(BUILD_DATE)

.PHONY: help build run test test-short test-integration fmt vet tidy install clean

help:
	@echo "Targets:"
	@echo "  make build             Build binary at $(BIN)"
	@echo "  make run ARGS='...'    Run via go run . with optional ARGS"
	@echo "  make test              Run all tests"
	@echo "  make test-short        Run tests in short mode"
	@echo "  make test-integration  Run integration tests only"
	@echo "  make fmt               Format Go code"
	@echo "  make vet               Run go vet"
	@echo "  make tidy              Run go mod tidy"
	@echo "  make install           Install binary to GOPATH/bin"
	@echo "  make clean             Remove build artifacts"

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

build: $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) .

run:
	$(GO) run . $(ARGS)

test:
	$(GO) test -race -v ./...

test-short:
	$(GO) test -short ./...

test-integration:
	$(GO) test -run TestMainIntegration .

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

install:
	$(GO) install -ldflags '$(LDFLAGS)' .

clean:
	rm -rf $(BIN_DIR)
