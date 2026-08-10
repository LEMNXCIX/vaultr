#!/usr/bin/env bash
# Generate and optionally install shell completions for `vltr`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${VLTR_BIN:-$ROOT/target/debug/vltr}"

if [[ ! -x "$BIN" ]]; then
  echo "Building vltr CLI..."
  cargo build -p vltr-cli --manifest-path "$ROOT/Cargo.toml"
  BIN="$ROOT/target/debug/vltr"
fi

SHELL_NAME="${1:-}"
if [[ -z "$SHELL_NAME" ]]; then
  echo "Usage: $0 <bash|zsh|fish|elvish|powershell>"
  echo "Example: $0 zsh > ~/.zfunc/_vltr"
  exit 1
fi

"$BIN" completions "$SHELL_NAME"
