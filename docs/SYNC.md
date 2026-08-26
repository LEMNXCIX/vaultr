# Sync (Supabase)

Sincronización opcional del vault local con Supabase (Postgres vía PostgREST).
**Local-first:** la base SQLite es la fuente de verdad y la app funciona 100% offline sin esto.
**Zero-knowledge:** solo se sube ciphertext (`value_encrypted` + `nonce`, XChaCha20-Poly1305).
Ni Supabase ni nosotros podemos leer los valores.

## Esquema del servidor

El SQL vive en `supabase/migrations/0001_init.sql`. Crea las tablas `vaults`,
`projects`, `environments` y `variables` con RLS por `owner_id`.

### Cómo aplicarlo

Opción A — Dashboard:

1. Supabase Dashboard → SQL Editor.
2. Pegar el contenido de `supabase/migrations/0001_init.sql`.
3. Ejecutar.

Opción B — CLI (si usas `supabase db push`):

```bash
supabase link --project-ref <ref>
supabase db push
```

## Configuración

Variables de entorno que consumirá el cliente de sync (futuro):

| Var                  | Descripción                                    |
|----------------------|------------------------------------------------|
| `VAULTR_SUPABASE_URL`   | URL del proyecto (`https://<ref>.supabase.co`) |
| `VAULTR_SUPABASE_KEY`   | Clave publishable/anon (nunca service_role en cliente) |

La autenticación de usuario usa Supabase Auth; el `owner_id` de cada fila se
resuelve con `auth.uid()` y RLS garantiza que solo ves tus filas.

## Qué se sincroniza

- Projects, environments y variables (metadatos + ciphertext).
- Deletes como **tombstones**: `deleted = true` + `version` incrementada.
  Las filas nunca se borran físicamente del server.
- Cursor incremental: columna `updated_at` en el server + `sync_state.last_pull`
  local (tabla `sync_state` en SQLite).
- Dirty tracking local: columna `synced_at` por fila; una fila es "dirty" si
  `synced_at IS NULL OR updated_at > synced_at`.

## Qué NO se sincroniza

- Valores en claro (nunca salen del dispositivo).
- La master key ni el salt del KDF local (el salt del server en `vaults` es
  para el flujo de sharing futuro, no para el unlock local).
- Sesiones / keyring.
- Resolución avanzada de conflictos: gana la versión mayor (`version`),
  último escritor simple.

## Checklist de verificación E2E (manual)

Con tu propio proyecto Supabase:

1. Exporta `VAULTR_SUPABASE_URL` y `VAULTR_SUPABASE_KEY`, y aplica
   `supabase/migrations/0001_init.sql`.
2. Dispositivo A: `vltr login && vltr sync` (sube el vault al remoto).
3. Dispositivo B (o directorio limpio): `vltr bootstrap` + master password →
   `vltr ls` debe mostrar los secretos.
4. Edita una variable en B, `vltr sync`; edita la misma en A, `vltr sync` →
   gana la versión mayor (LWW).
5. `vltr rm` en B, `vltr sync`, luego `vltr sync` en A → la variable
   desaparece en A.

Nota sobre deletes: los borrados se propagan como **tombstones**
(`deleted = true`) y las filas nunca se eliminan físicamente del server; la
limpieza del lado servidor puede requerir un ciclo extra de sync.
