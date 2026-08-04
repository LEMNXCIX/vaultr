# Migraciones de schema

El schema **no** vive hardcodeado en Rust. Cada cambio es un archivo SQL versionado.

## Ubicación canónica

```
crates/storage/migrations/
  001_initial.sql
  002_....sql      # futuros
```

Copia de referencia en la raíz: `migrations/` (mismo contenido; la fuente que usa el binario es la del crate `storage` vía `include_str!`).

## Cómo añadir una migración

1. Crear `crates/storage/migrations/002_descripcion.sql` con el SQL (sin `IF NOT EXISTS` si la migración es de un solo uso).
2. Registrarla en `crates/storage/src/migrations.rs` dentro de `MIGRATIONS`:

```rust
Migration {
    version: 2,
    name: "002_descripcion",
    sql: include_str!("../migrations/002_descripcion.sql"),
},
```

3. **Nunca** editar el SQL de una migración ya publicada; crea la siguiente.

## Comportamiento

Al abrir la DB (`Storage::open` / `open_in_memory`):

1. Crea `schema_migrations` si no existe
2. Si detecta un vault legado (tablas sin filas de migración), marca `001` como aplicada
3. Ejecuta en transacción cada migración pendiente
4. Registra versión + timestamp

En un PC nuevo el vault se crea solo al aplicar `001`. En uno viejo solo corren las que falten.

## Inspección

```bash
vltr status   # (puede mostrar schema version en el futuro)
sqlite3 vault.db "SELECT * FROM schema_migrations;"
```
