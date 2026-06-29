.DEFAULT_GOAL := help

GO              := go
CGO_ENABLED     := 0
BIN_DIR         := bin
ARX_DNS         := ./cmd/arx-dns
ARX_TESTER      := ./cmd/arx-tester
LDFLAGS         := -trimpath -ldflags="-s -w"

GOOS_GOARCH_PAIRS := linux/amd64 linux/arm64 windows/amd64 darwin/amd64

UI_SRC := $(shell find ui/src ui/public -type f 2>/dev/null) \
	ui/index.html ui/vite.config.ts ui/package.json ui/pnpm-lock.yaml \
	ui/pnpm-workspace.yaml \
	ui/tsconfig.json ui/tsconfig.app.json ui/tsconfig.node.json ui/components.json

##@ General

help: ## Show this help menu
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_/.-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

clean: ## Remove bin/, ui/dist/, ui/node_modules/, and local binaries
	rm -rf $(BIN_DIR) ui/dist ui/node_modules arx-dns arx-tester

##@ WebUI

ui/dist/index.html: $(UI_SRC) ## Build production WebUI assets (pnpm install && pnpm run build)
	cd ui && pnpm install --frozen-lockfile && pnpm run build

ui/dist: ui/dist/index.html

##@ Local builds

build-core: ## Build arx-dns locally without embedded WebUI (-tags noui)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(LDFLAGS) -tags noui -o arx-dns $(ARX_DNS)

build-full: ui/dist ## Build arx-dns locally with embedded WebUI (-tags webui)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(LDFLAGS) -tags webui -o arx-dns $(ARX_DNS)

build-tester: ## Build arx-tester CLI locally
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(LDFLAGS) -o arx-tester $(ARX_TESTER)

##@ Cross-compilation releases

release-core: ## Cross-compile core arx-dns (no WebUI) for linux, windows, and darwin (amd64, arm64)
	@$(MAKE) --no-print-directory release-core-binaries

release-full: ui/dist ## Cross-compile arx-dns with WebUI for linux, windows, and darwin (amd64, arm64)
	@$(MAKE) --no-print-directory release-full-binaries

release-tester: ## Cross-compile arx-tester for linux, windows, and darwin (amd64, arm64)
	@mkdir -p $(BIN_DIR)
	@set -e; for pair in $(GOOS_GOARCH_PAIRS); do \
		os=$${pair%%/*}; \
		arch=$${pair##*/}; \
		ext=""; \
		[ "$$os" = "windows" ] && ext=".exe"; \
		echo ">> arx-tester-$$os-$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(LDFLAGS) \
			-o $(BIN_DIR)/arx-tester-$$os-$$arch$$ext $(ARX_TESTER); \
	done

.PHONY: release-core-binaries release-full-binaries

release-core-binaries:
	@mkdir -p $(BIN_DIR)
	@set -e; for pair in $(GOOS_GOARCH_PAIRS); do \
		os=$${pair%%/*}; \
		arch=$${pair##*/}; \
		ext=""; \
		[ "$$os" = "windows" ] && ext=".exe"; \
		echo ">> arx-dns-$$os-$$arch (core)"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(LDFLAGS) -tags noui \
			-o $(BIN_DIR)/arx-dns-$$os-$$arch$$ext $(ARX_DNS); \
	done

release-full-binaries:
	@mkdir -p $(BIN_DIR)
	@set -e; for pair in $(GOOS_GOARCH_PAIRS); do \
		os=$${pair%%/*}; \
		arch=$${pair##*/}; \
		ext=""; \
		[ "$$os" = "windows" ] && ext=".exe"; \
		echo ">> arx-dns-$$os-$$arch (full)"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(LDFLAGS) -tags webui \
			-o $(BIN_DIR)/arx-dns-$$os-$$arch$$ext $(ARX_DNS); \
	done

.PHONY: help clean ui/dist build-core build-full build-tester release-core release-full release-tester
