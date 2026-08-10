SHELL := /usr/bin/env bash
CARGO := cargo

.PHONY: hooks pre-commit pre-push check ci build release test clippy fmt fmt-check cli help

# --- Git hooks ---------------------------------------------------------------

hooks: ## Install git hooks (core.hooksPath = .githooks)
	./scripts/install-hooks.sh

pre-commit: ## Run the pre-commit hook manually (fmt + clippy)
	.githooks/pre-commit

pre-push: ## Run the pre-push hook manually (tests + CLI check)
	.githooks/pre-push

# --- Local validation --------------------------------------------------------

fmt: ## Format all workspace code
	$(CARGO) fmt --all

fmt-check: ## Check formatting (no changes)
	$(CARGO) fmt --all -- --check

clippy: ## Lint the workspace
	$(CARGO) clippy --workspace --all-targets -- -D warnings

test: ## Run the full test suite
	$(CARGO) test --workspace

check: fmt-check clippy test ## Full local gate (what a commit + push should pass)

ci: ## Simulate local CI (like ci.yml, no release build)
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	$(CARGO) test --workspace
	$(CARGO) check -p vltr-cli
	$(CARGO) build -p vltr-cli
	./target/debug/vltr completions bash | head -5
	./target/debug/vltr completions zsh | head -5
	./target/debug/vltr completions fish | head -5

# --- Builds ------------------------------------------------------------------

build: ## Debug build of the CLI
	$(CARGO) build -p vltr-cli

release: ## Release build of the CLI (rarely needed locally)
	$(CARGO) build -p vltr-cli --release

cli: ## Run the CLI (e.g. make cli ARGS="status")
	$(CARGO) run -p vltr-cli -- $(ARGS)

help: ## Show all targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'
