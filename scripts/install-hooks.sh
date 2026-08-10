#!/usr/bin/env bash
# Enable git hooks for this repo via core.hooksPath (no symlinks, no husky).
#
# Usage:
#   ./scripts/install-hooks.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
hooks_dir="$root/.githooks"

if [[ ! -d "$hooks_dir" ]]; then
  echo "error: hooks dir not found at $hooks_dir" >&2
  exit 1
fi

git config core.hooksPath .githooks
chmod +x "$hooks_dir"/pre-commit "$hooks_dir"/pre-push

echo "✔ Git hooks installed (core.hooksPath = .githooks)."
echo "  pre-commit → cargo fmt --check + cargo clippy -D warnings"
echo "  pre-push   → cargo test --workspace + cargo check -p vltr-cli"
echo "  Skip (emergency only): git commit --no-verify / git push --no-verify"