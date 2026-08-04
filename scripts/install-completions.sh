#!/usr/bin/env bash
# Generate and optionally install shell completions for `secrets`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${SECRETS_BIN:-$ROOT/target/debug/secrets}"

if [[ ! -x "$BIN" ]]; then
  echo "Building secrets CLI..."
  cargo build -p secrets-cli --manifest-path "$ROOT/Cargo.toml"
  BIN="$ROOT/target/debug/secrets"
fi

SHELL_NAME="${1:-}"
if [[ -z "$SHELL_NAME" ]]; then
  echo "Usage: $0 <bash|zsh|fish|elvish|powershell>"
  echo "Example: $0 zsh > ~/.zfunc/_secrets"
  exit 1
fi

"$BIN" completions "$SHELL_NAME"
