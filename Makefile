# Makefile for whichkey

# Variables
BINARY_NAME := whichkey
MODULE := github.com/roddd/whichkey
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GOBIN := $(shell go env GOBIN)
ifeq ($(GOBIN),)
	GOBIN := $(shell go env GOPATH)/bin
endif

# Build flags
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"

# Go commands
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := gofmt
GOLINT := golangci-lint

# Directories
CMD_DIR := ./cmd/whichkey
BUILD_DIR := ./build

.PHONY: all build install uninstall clean test test-coverage lint fmt tidy mocks help

# Default target
all: lint test build

## Build targets

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

# Build for current platform (quick build without version info)
build-quick:
	@echo "Quick building $(BINARY_NAME)..."
	$(GOBUILD) -o $(BINARY_NAME) $(CMD_DIR)

# Build for multiple platforms
build-all: build-linux build-darwin build-windows

build-linux:
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)

build-darwin:
	@echo "Building for macOS..."
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)

build-windows:
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)

## Install targets

# Install to GOBIN (typically ~/go/bin)
install: build
	@echo "Installing $(BINARY_NAME) to $(GOBIN)..."
	@mkdir -p $(GOBIN)
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(GOBIN)/$(BINARY_NAME)
	@chmod +x $(GOBIN)/$(BINARY_NAME)
	@echo "Installed: $(GOBIN)/$(BINARY_NAME)"
	@echo "Make sure $(GOBIN) is in your PATH"

# Uninstall from GOBIN
uninstall:
	@echo "Uninstalling $(BINARY_NAME) from $(GOBIN)..."
	@rm -f $(GOBIN)/$(BINARY_NAME)
	@echo "Uninstalled"

## Test targets

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race ./...

# Run tests with coverage report (HTML)
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p $(BUILD_DIR)
	$(GOTEST) -v -race -coverprofile=$(BUILD_DIR)/coverage.out ./...
	$(GOCMD) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "Coverage report: $(BUILD_DIR)/coverage.html"

# Show coverage percentage per package
cover:
	@echo "Running tests with coverage summary..."
	@$(GOTEST) -cover ./... | grep -v "no test files"

# Run tests with short flag (skip long-running tests)
test-short:
	@echo "Running short tests..."
	$(GOTEST) -v -short ./...

## Code quality targets

# Run linter
lint:
	@echo "Running linter..."
	@if command -v $(GOLINT) >/dev/null 2>&1; then \
		$(GOLINT) run ./...; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

# Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .
	$(GOCMD) fmt ./...

# Check formatting (for CI)
fmt-check:
	@echo "Checking code format..."
	@test -z "$$($(GOFMT) -l .)" || (echo "Code not formatted. Run 'make fmt'" && exit 1)

## Dependency targets

# Tidy go modules
tidy:
	@echo "Tidying modules..."
	$(GOMOD) tidy

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download

# Update dependencies
deps-update:
	@echo "Updating dependencies..."
	$(GOGET) -u ./...
	$(GOMOD) tidy

## Mock targets

# Generate mocks with mockery
mocks:
	@echo "Generating mocks..."
	@if command -v mockery >/dev/null 2>&1; then \
		mockery --all --dir=./internal --output=./internal/mocks --outpkg=mocks; \
	else \
		echo "mockery not installed. Install with: go install github.com/vektra/mockery/v2@latest"; \
		exit 1; \
	fi

## Utility targets

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(BINARY_NAME)
	@rm -f coverage.out coverage.html
	@$(GOCMD) clean -testcache
	@echo "Cleaned"

# Generate default config file
init-config:
	@echo "Generating default config..."
	@$(BUILD_DIR)/$(BINARY_NAME) -init-config || ./$(BINARY_NAME) -init-config

# Show version info
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"

# Install development tools
tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/vektra/mockery/v2@latest
	@echo "Tools installed"

# Help target
help:
	@echo "Available targets:"
	@echo ""
	@echo "Build:"
	@echo "  build        - Build the binary"
	@echo "  build-quick  - Quick build without version info"
	@echo "  build-all    - Build for all platforms"
	@echo "  install      - Install to GOBIN ($(GOBIN))"
	@echo "  uninstall    - Remove from GOBIN"
	@echo ""
	@echo "Test:"
	@echo "  test          - Run all tests"
	@echo "  test-short    - Run short tests only"
	@echo "  test-coverage - Run tests with coverage report (HTML)"
	@echo "  cover         - Show coverage percentage per package"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint         - Run golangci-lint"
	@echo "  fmt          - Format code"
	@echo "  fmt-check    - Check code formatting"
	@echo ""
	@echo "Dependencies:"
	@echo "  tidy         - Tidy go modules"
	@echo "  deps         - Download dependencies"
	@echo "  deps-update  - Update dependencies"
	@echo ""
	@echo "Utilities:"
	@echo "  mocks        - Generate mocks with mockery"
	@echo "  clean        - Clean build artifacts"
	@echo "  tools        - Install development tools"
	@echo "  version      - Show version info"
	@echo "  help         - Show this help"

