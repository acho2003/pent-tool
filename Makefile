.PHONY: build run clean test test-ci test-cover test-race install fmt vet lint tidy all

BINARY=xalgorix
BUILD_DIR=./build
VERSION=4.2.9
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

build:
	@echo "Building $(BINARY)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/xalgorix/
	@echo "Built: $(BUILD_DIR)/$(BINARY)"

run:
	go run ./cmd/xalgorix/ $(ARGS)

clean:
	rm -rf $(BUILD_DIR)
	go clean

test:
	go test ./... -v

test-cover:
	go test ./... -cover

test-race:
	go test ./... -race

test-ci:
	go test ./...
	go test ./... -cover
	go test ./... -race
	go vet ./...
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; else echo "staticcheck not installed; skipping"; fi
	node --check internal/web/static/app.js
	go build ./cmd/xalgorix

install: build
	@echo "Installing $(BINARY) to /usr/local/bin..."
	sudo cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	sudo chmod +x /usr/local/bin/$(BINARY)
	@echo "Installed!"

fmt:
	go fmt ./...

vet:
	go vet ./...

lint: fmt vet
	@echo "Lint passed"

tidy:
	go mod tidy

all: tidy lint build
