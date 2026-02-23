BINARY     := istio-doctor
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GOFLAGS    := -ldflags "-s -w \
	-X github.com/istio-doctor/pkg/version.Version=$(VERSION) \
	-X github.com/istio-doctor/pkg/version.BuildDate=$(BUILD_DATE) \
	-X github.com/istio-doctor/pkg/version.Commit=$(COMMIT)"

.DEFAULT_GOAL := build

# ────────────────────────────────────────────────────────────────────────────
# Build
# ────────────────────────────────────────────────────────────────────────────
.PHONY: build
build:
	go build $(GOFLAGS) -o bin/$(BINARY) .

.PHONY: install
install:
	go install $(GOFLAGS) .

.PHONY: build-all
build-all: build-linux build-darwin build-windows

.PHONY: build-linux
build-linux:
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o dist/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o dist/$(BINARY)-linux-arm64 .

.PHONY: build-darwin
build-darwin:
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -o dist/$(BINARY)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -o dist/$(BINARY)-darwin-arm64 .

.PHONY: build-windows
build-windows:
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o dist/$(BINARY)-windows-amd64.exe .

# ────────────────────────────────────────────────────────────────────────────
# Development
# ────────────────────────────────────────────────────────────────────────────
.PHONY: run-summary
run-summary: build
	./bin/$(BINARY) summary

.PHONY: run-check
run-check: build
	./bin/$(BINARY) check

.PHONY: fmt
fmt:
	gofmt -w .
	goimports -w .

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: vet
vet:
	go vet ./...

# ────────────────────────────────────────────────────────────────────────────
# Test
# ────────────────────────────────────────────────────────────────────────────
.PHONY: test
test:
	go test ./... -v -race -timeout 60s

.PHONY: test-unit
test-unit:
	go test ./pkg/analyzer/... -v -race

.PHONY: test-integration
test-integration:
	go test ./... -v -tags=integration -race -timeout 300s

.PHONY: test-cover
test-cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# ────────────────────────────────────────────────────────────────────────────
# Docker
# ────────────────────────────────────────────────────────────────────────────
IMAGE ?= ghcr.io/yourorg/istio-doctor
TAG   ?= $(VERSION)

.PHONY: docker-build
docker-build:
	docker build -t $(IMAGE):$(TAG) -t $(IMAGE):latest .

.PHONY: docker-push
docker-push: docker-build
	docker push $(IMAGE):$(TAG)
	docker push $(IMAGE):latest

# ────────────────────────────────────────────────────────────────────────────
# Release
# ────────────────────────────────────────────────────────────────────────────
.PHONY: release
release: test build-all
	@echo "Release $(VERSION) artifacts in ./dist/"

.PHONY: clean
clean:
	rm -rf bin/ dist/ coverage.out coverage.html

# ────────────────────────────────────────────────────────────────────────────
# Cluster shortcuts for development
# ────────────────────────────────────────────────────────────────────────────
.PHONY: dev-trace
dev-trace: build
	@echo "Usage: make dev-trace FROM=payments/pod-xyz TO=payments/orders:8080"
	./bin/$(BINARY) trace --from $(FROM) --to $(TO)

.PHONY: dev-simulate
dev-simulate: build
	@echo "Usage: make dev-simulate FILE=./policy.yaml"
	./bin/$(BINARY) simulate -f $(FILE)

.PHONY: dev-audit
dev-audit: build
	./bin/$(BINARY) audit authz

.PHONY: help
help:
	@echo "istio-doctor Makefile targets:"
	@echo ""
	@echo "  Build:"
	@echo "    build          Build for current platform"
	@echo "    install        Install to GOPATH/bin"
	@echo "    build-all      Cross-compile for linux/darwin/windows"
	@echo ""
	@echo "  Test:"
	@echo "    test           Run all tests"
	@echo "    test-unit      Run unit tests only"
	@echo "    test-cover     Run tests with coverage report"
	@echo ""
	@echo "  Cluster:"
	@echo "    run-summary    Build and run summary against current context"
	@echo "    run-check      Build and run full check"
	@echo "    dev-trace      Trace a traffic path (FROM=ns/pod TO=ns/svc:port)"
	@echo "    dev-simulate   Simulate a policy (FILE=./policy.yaml)"
	@echo "    dev-audit      Audit authz policies"
	@echo ""
	@echo "  Release:"
	@echo "    release        Build release artifacts"
	@echo "    docker-build   Build Docker image"
	@echo ""
	@echo "  Misc:"
	@echo "    fmt            Format code"
	@echo "    lint           Run golangci-lint"
	@echo "    clean          Remove build artifacts"
