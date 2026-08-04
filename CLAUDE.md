# CLAUDE.md

Sigue las instrucciones de [AGENTS.md](AGENTS.md).

Resumen rápido:

- Workspace Rust local-first / zero-knowledge secrets manager
- Capas: cli → core → storage + crypto + models
- CLI antes que GPUI
- No implementar sharing en el MVP
- Tras cambios: `cargo fmt`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`
