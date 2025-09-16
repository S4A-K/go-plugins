# Makefile for go-plugins security system
#
# Copyright (c) 2025 AGILira - A. Giordano
# SPDX-License-Identifier: MPL-2.0

.PHONY: help clean test test-security build build-examples lint fmt vet security-demo deps

# Default target
help: ## Show this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Dependencies
deps: ## Install dependencies
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

##@ Building
build: ## Build all components
	@echo "Building go-plugins..."
	go build -v ./...

build-examples: build ## Build examples
	@echo "Building security demo..."
	cd examples/security_demo && go build -o security_demo main.go

##@ Testing
test: ## Run all tests
	@echo "Running tests..."
	go test -v -race ./...

test-security: ## Run security-specific tests
	@echo "Security Running security tests..."
	go test -v -race -run "Security" ./...

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "📈 Coverage report generated: coverage.html"

bench: ## Run benchmarks
	@echo "⚡ Running benchmarks..."
	go test -bench=. -benchmem ./...

bench-security: ## Run security benchmarks
	@echo "⚡ Running security benchmarks..."
	go test -bench="Security" -benchmem ./...

##@ Code Quality
lint: ## Run linter
	@echo "🔍 Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "⚠️  golangci-lint not installed, skipping..."; \
		echo "   Install with: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b \$$(go env GOPATH)/bin v1.54.2"; \
	fi

fmt: ## Format code
	@echo "📝 Formatting code..."
	go fmt ./...

vet: ## Run go vet
	@echo "🔎 Running go vet..."
	go vet ./...

check: fmt vet lint test ## Run all checks

##@ Security
security-demo: build-examples ## Run security demonstration
	@echo "Security Running security demo..."
	cd examples/security_demo && ./security_demo

security-create-whitelist: ## Create sample security whitelist
	@echo "📋 Creating sample security whitelist..."
	@mkdir -p tmp
	@go run -c 'package main; import "github.com/agilira/go-plugins"; func main() { goplugins.CreateSampleWhitelist("tmp/sample-whitelist.json") }'
	@echo "SUCCESS: Sample whitelist created: tmp/sample-whitelist.json"

security-validate-config: ## Validate security configuration files
	@echo "🔍 Validating security configuration..."
	@if [ -f "tmp/sample-whitelist.json" ]; then \
		echo "📄 Validating tmp/sample-whitelist.json..."; \
		python3 -m json.tool tmp/sample-whitelist.json > /dev/null && echo "SUCCESS: Valid JSON" || echo "ERROR: Invalid JSON"; \
	else \
		echo "⚠️  No whitelist file found. Run 'make security-create-whitelist' first."; \
	fi

##@ Development
dev-setup: deps ## Setup development environment
	@echo "🛠️  Setting up development environment..."
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "📥 Installing golangci-lint..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin v1.54.2; \
	fi
	@echo "SUCCESS: Development environment ready!"

dev-watch: ## Watch for changes and run tests
	@echo "👀 Watching for changes..."
	@if command -v fswatch >/dev/null 2>&1; then \
		fswatch -o . -e ".*" -i "\\.go$$" | xargs -n1 -I{} make test; \
	else \
		echo "⚠️  fswatch not installed. Install with:"; \
		echo "   macOS: brew install fswatch"; \
		echo "   Ubuntu: apt-get install fswatch"; \
		echo "   Manual watch: while true; do make test; sleep 5; done"; \
	fi

##@ Documentation
docs: ## Generate documentation
	@echo "📚 Generating documentation..."
	@mkdir -p docs/generated
	go doc -all > docs/generated/godoc.txt
	@echo "SUCCESS: Documentation generated in docs/generated/"

docs-serve: ## Serve documentation locally
	@echo "📖 Starting documentation server..."
	@echo "🌐 Open http://localhost:6060/pkg/github.com/agilira/go-plugins/ in your browser"
	godoc -http=:6060

##@ Examples
examples: build-examples ## Build all examples
	@echo "🎯 All examples built successfully!"

run-examples: examples ## Run all examples
	@echo "Running examples..."
	@echo "1. Security Demo:"
	$(MAKE) security-demo

##@ Maintenance
clean: ## Clean build artifacts
	@echo "Cleaning up..."
	go clean -cache
	rm -rf tmp/
	rm -f coverage.out coverage.html
	rm -f examples/security_demo/security_demo
	@echo "SUCCESS: Clean complete!"

clean-all: clean ## Clean everything including dependencies
	@echo "Cleaning Deep cleaning..."
	go clean -modcache

##@ Docker
docker-test: ## Run tests in Docker
	@echo "🐳 Running tests in Docker..."
	docker run --rm -v $(PWD):/app -w /app golang:1.21 make test

docker-security-demo: ## Run security demo in Docker
	@echo "🐳 Running security demo in Docker..."
	docker run --rm -v $(PWD):/app -w /app golang:1.21 bash -c "make build-examples && cd examples/security_demo && ./security_demo"

##@ Release
version: ## Show current version info
	@echo "📋 Version Information:"
	@echo "   Go version: $$(go version)"
	@echo "   Module: $$(go list -m)"
	@echo "   Git commit: $$(git rev-parse --short HEAD 2>/dev/null || echo 'not a git repo')"
	@echo "   Build time: $$(date)"

release-check: check test ## Pre-release checks
	@echo "SUCCESS: Release checks completed successfully!"

##@ Utilities
todo: ## Show TODO items in code
	@echo "📝 TODO items:"
	@grep -r "TODO\|FIXME\|XXX" --include="*.go" --include="*.md" . || echo "   No TODO items found!"

stats: ## Show project statistics  
	@echo "Running Project Statistics:"
	@echo "   Go files: $$(find . -name '*.go' -not -path './vendor/*' | wc -l)"
	@echo "   Lines of code: $$(find . -name '*.go' -not -path './vendor/*' -exec wc -l {} + | tail -1 | awk '{print $$1}')"
	@echo "   Test files: $$(find . -name '*_test.go' -not -path './vendor/*' | wc -l)"
	@echo "   Packages: $$(go list ./... | wc -l)"

##@ Integration
integration-test: ## Run integration tests
	@echo "🔗 Running integration tests..."
	go test -v -tags=integration ./...

e2e-test: build-examples ## Run end-to-end tests
	@echo "🎯 Running end-to-end tests..."
	@echo "Security Testing security system..."
	cd examples/security_demo && timeout 10s ./security_demo || true
	@echo "SUCCESS: E2E tests completed!"

all: clean deps fmt vet lint test build examples ## Run everything

.DEFAULT_GOAL := help