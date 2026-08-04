# Code review — prácticas aplicadas

## Correcciones hechas en esta pasada

| Área | Antes | Ahora |
|------|--------|--------|
| KDF | Argon2 vía PHC `hash_password` + pad con ceros | `hash_password_into` raw a `[u8; 32]` |
| RNG | `thread_rng` | `OsRng` para salt/nonce |
| MasterKey | `Zeroizing<Vec<u8>>` | `Zeroizing<[u8; 32]>` (tamaño fijo) |
| Unlock | Cualquier password “abría” | Verifier AEAD `vault-ok` en `vault_meta` |
| Debug de secretos | `DecryptedVariable` derivaba `Debug` | Valor siempre `[redacted]` |
| Sesión `has_session` | Llamaba `load` y **refrescaba TTL** | Solo mira `expires_at` |
| Nombres | Sin validar | `validate_name` en project/key |
| Decrypt | `String` en claro sin zeroize | `Zeroizing<String>` |

## Buenas prácticas ya presentes

- Capas claras: cli → core → storage/crypto/models
- `thiserror` en libs, `anyhow` en binario
- SQLite con `foreign_keys` + WAL
- Zero-knowledge: ciphertext en disco
- Flags `is_readonly` / `allow_export` preparados
- CI: fmt + clippy `-D warnings` + tests

## Mejoras recomendadas (siguiente iteración)

1. **Transacciones** en `import_env` (todo-or-nothing).
2. **Migraciones versionadas** (no solo `CREATE IF NOT EXISTS`).
3. **Constant-time** compare de password en CLI (`subtle`) — helper ya en `crypto::passwords_match`.
4. Endurecer **clippy** `unwrap_used` en código no-test.
5. **Proptest** `DecryptedVariable::value` como `SecretString`.
6. Verificar sesión keyring descifrando el verifier (no solo longitud de clave).
7. Rate-limit / delay suave tras password incorrecta (anti brute-force local).

## Checklist al tocar código

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
