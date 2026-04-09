# nullbore-server — local build/test via Docker
#
# This Makefile wraps `go` commands inside an ephemeral golang container so
# you can build and test the server without installing Go on the host.
#
# Caches (build cache + module cache) are persisted under .cache/ in this
# directory — bind-mounted into the container so they inherit host file
# ownership and survive between runs (gitignored). First run downloads
# modules and builds the stdlib; subsequent runs are fast.
#
# Usage:
#   make test         run go test ./...
#   make build        build the linux binary into ./nullbore-server-linux
#   make vet          go vet ./...
#   make fmt          gofmt -w .
#   make fmt-check    fail if anything would change under gofmt
#   make tidy         go mod tidy
#   make shell        interactive shell in the build container
#   make clean        remove built binaries and the .cache directory
#
# Override the Go version with: make GO_IMAGE=golang:1.23 test

DOCKER    ?= docker
GO_IMAGE  ?= golang:1.22

CACHE_DIR  := $(CURDIR)/.cache
GO_BUILD   := $(CACHE_DIR)/go-build
GO_MOD     := $(CACHE_DIR)/go-mod

# Separate cache for `make test-race`. The race detector compiles a
# race-instrumented stdlib that the official golang image doesn't ship
# prebuilt — go test needs to write into GOROOT to do that, which the
# --user flag blocks. So test-race runs as root in the container with
# its own cache, isolated from the user-owned regular cache.
RACE_BUILD := $(CACHE_DIR)/race-go-build
RACE_MOD   := $(CACHE_DIR)/race-go-mod

# Run as the host user so files written into /src (build output, gofmt
# edits, `go mod tidy` updates) end up owned by you, not root.
# HOME=/tmp keeps `go` happy when the uid has no /etc/passwd entry.
DOCKER_RUN = $(DOCKER) run --rm \
	--user $$(id -u):$$(id -g) \
	-e HOME=/tmp \
	-e GOCACHE=/cache/go-build \
	-e GOMODCACHE=/cache/go-mod \
	-v "$(CURDIR)":/src \
	-v "$(GO_BUILD)":/cache/go-build \
	-v "$(GO_MOD)":/cache/go-mod \
	-w /src \
	$(GO_IMAGE)

DOCKER_RUN_IT = $(DOCKER) run --rm -it \
	--user $$(id -u):$$(id -g) \
	-e HOME=/tmp \
	-e GOCACHE=/cache/go-build \
	-e GOMODCACHE=/cache/go-mod \
	-v "$(CURDIR)":/src \
	-v "$(GO_BUILD)":/cache/go-build \
	-v "$(GO_MOD)":/cache/go-mod \
	-w /src \
	$(GO_IMAGE)

# Race detector flavor — runs as root inside the container so it can
# write race-instrumented stdlib into GOROOT. Uses an isolated cache
# (RACE_BUILD/RACE_MOD) so the regular DOCKER_RUN cache stays user-owned.
DOCKER_RUN_RACE = $(DOCKER) run --rm \
	-e HOME=/tmp \
	-e CGO_ENABLED=1 \
	-e GOCACHE=/cache/go-build \
	-e GOMODCACHE=/cache/go-mod \
	-v "$(CURDIR)":/src \
	-v "$(RACE_BUILD)":/cache/go-build \
	-v "$(RACE_MOD)":/cache/go-mod \
	-w /src \
	$(GO_IMAGE)

.PHONY: help build test test-v test-run test-race vet fmt fmt-check tidy shell clean cache-init cache-init-race ci

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

cache-init:
	@mkdir -p $(GO_BUILD) $(GO_MOD)

cache-init-race:
	@mkdir -p $(RACE_BUILD) $(RACE_MOD)

build: cache-init ## Build the linux binary at ./nullbore-server-linux
	$(DOCKER_RUN) sh -c 'CGO_ENABLED=0 go build -ldflags="-s -w" -o nullbore-server-linux ./cmd/server'

test: cache-init ## Run go test ./...
	$(DOCKER_RUN) go test ./...

test-v: cache-init ## Run go test -v ./...
	$(DOCKER_RUN) go test -v ./...

# Run a subset of tests by name regex: make test-run RUN=TestAccountSubdomain
test-run: cache-init ## Run a subset of tests (RUN=<regex>)
	$(DOCKER_RUN) go test -v -run '$(RUN)' ./...

test-race: cache-init-race ## Run go test -race -count=1 (matches CI)
	$(DOCKER_RUN_RACE) go test -race -count=1 -timeout=60s ./...

ci: vet test-race ## Run the same checks CI does (vet + race tests)
	@echo "✅ local CI checks passed"

vet: cache-init ## go vet ./...
	$(DOCKER_RUN) go vet ./...

fmt: cache-init ## gofmt -w .
	$(DOCKER_RUN) gofmt -w .

fmt-check: cache-init ## Fail if gofmt would change anything
	$(DOCKER_RUN) sh -c 'out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "$$out"; exit 1; fi'

tidy: cache-init ## go mod tidy
	$(DOCKER_RUN) go mod tidy

shell: cache-init ## Interactive shell in the build container
	$(DOCKER_RUN_IT) bash

clean: ## Remove built binaries and the .cache directory
	rm -f nullbore-server nullbore-server-linux server
	rm -rf $(CACHE_DIR)
