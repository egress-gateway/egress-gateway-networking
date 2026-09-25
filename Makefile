GO ?= go
BASH_BIN := $(shell if test -x /opt/homebrew/bin/bash; then echo /opt/homebrew/bin/bash; else command -v bash; fi)
E2E_ARGS ?=

.PHONY: check fmt e2e e2e-up e2e-test e2e-down e2e-negative
check:
	@test -z "$$(gofmt -l cmd test/e2e enrollment baseline internal)" || { echo 'Run make fmt'; exit 1; }
	@$(BASH_BIN) -c 'for f in install/scripts/*.sh environments/kind/*.sh test/e2e/scripts/*.sh scripts/*.sh; do bash -n "$$f" || exit; done'
	$(GO) run ./internal/versionfiles --check
	$(GO) vet ./...
	$(GO) test -race ./...
	$(GO) build -o bin/networking-e2e ./cmd/networking-e2e

fmt:
	gofmt -w cmd test/e2e enrollment baseline internal

e2e:
	$(GO) run ./cmd/networking-e2e e2e $(E2E_ARGS)

e2e-up:
	$(GO) run ./cmd/networking-e2e up $(E2E_ARGS)

e2e-test:
	$(GO) run ./cmd/networking-e2e test $(E2E_ARGS)

e2e-down:
	$(GO) run ./cmd/networking-e2e down $(E2E_ARGS)

e2e-negative:
	$(GO) run ./cmd/networking-e2e negative $(E2E_ARGS)
