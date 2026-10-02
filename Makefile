.PHONY: build run clean test test-ci test-cover test-race install fmt vet lint tidy all webui webui-install webui-dev

BINARY=xalgorix
BUILD_DIR=./build
VERSION=4.5.100
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"
# The release image builds with CGO disabled, and the deterministic pipeline
# needs no cgo. Keeping it off here matches Dockerfile and avoids the
# go-m1cpu init crash that gopsutil/v3 pulls in on recent darwin/arm64.
GO=CGO_ENABLED=0 go

webui/node_modules: webui/package.json webui/package-lock.json
	@echo "Installing webui dependencies (locked)..."
	cd webui && npm ci --no-audit --no-fund
	@touch webui/node_modules

webui-install: webui/node_modules

webui: webui/node_modules
	@echo "Building webui (React) → internal/web/static..."
	cd webui && npm run build

webui-dev: webui/node_modules
	cd webui && npm run dev

build: webui
	@echo "Building $(BINARY)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/xalgorix/
	@echo "Built: $(BUILD_DIR)/$(BINARY)"

run:
	$(GO) run ./cmd/xalgorix/ $(ARGS)

clean:
	rm -rf $(BUILD_DIR)
	go clean

test:
	$(GO) test ./... -v

test-cover:
	$(GO) test ./... -cover

test-race:
	go test ./... -race

test-ci:
	$(GO) test ./...
	$(GO) test ./... -cover
	go test ./... -race
	$(GO) vet ./...
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; else echo "staticcheck not installed; skipping"; fi
	$(GO) build ./cmd/xalgorix

install: build
	@echo "Installing $(BINARY) to /usr/local/bin..."
	sudo cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	sudo chmod +x /usr/local/bin/$(BINARY)
	@echo "Installed!"

fmt:
	go fmt ./...

vet:
	$(GO) vet ./...

lint: fmt vet
	@echo "Lint passed"

tidy:
	go mod tidy

all: tidy lint build
