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

Credenciales del cliente de sync, en orden de prioridad:

1. Variables de entorno:

| Var                  | Descripción                                    |
|----------------------|------------------------------------------------|
| `VAULTR_SUPABASE_URL`   | URL del proyecto (`https://<ref>.supabase.co`) |
| `VAULTR_SUPABASE_KEY`   | Clave publishable/anon (nunca service_role en cliente) |

2. Archivo `<data_dir>/sync.json` (útil para cron/scripts donde el entorno no
   es fiable): `{"url":"https://<ref>.supabase.co","key":"sb_publishable_..."}`.
   Crear con permisos 0600.

La autenticación de usuario usa Supabase Auth (email+password):

- `vltr signup` — crea la cuenta. Si el proyecto tiene email-confirmation
  habilitado, GoTrue devuelve el usuario sin tokens: la CLI avisa "confirma tu
  email" y después se usa `vltr login`. Si está deshabilitado, la sesión se
  guarda directamente.
- `vltr login` — inicia sesión (password grant). La sesión (JWT + refresh) se
  guarda en el OS keyring o, si no está disponible, en un archivo local 0600.

El `owner_id` de cada fila se estampa explícitamente desde el JWT (no confiar
en defaults del server) y RLS garantiza que solo ves tus filas.

## Qué se sincroniza

- Projects, environments y variables (metadatos + ciphertext).
- Deletes como **tombstones**: `deleted = true` + `version` incrementada.
  Las filas nunca se borran físicamente del server.
- Cursor incremental: columna `updated_at` en el server + `sync_state.last_pull`
  local (tabla `sync_state` en SQLite).
- Dirty tracking local: columna `synced_at` por fila; una fila es "dirty" si
  `synced_at IS NULL OR updated_at > synced_at`.

## Master key: guard de salt y rotación

La master key se deriva de `password + salt + kdf_params`. Dos dispositivos
solo pueden compartir cifrado si usan el **mismo salt**; por eso `vaults.salt`
(viajando en `vaults`) es el ancla de identidad del vault.

- **Guard de sync:** antes de subir o bajar filas, `vltr sync` compara el salt
  local contra `vaults.salt` remoto. Si difieren (sin marcador pendiente),
  aborta con `RemoteKeyChanged` **sin tocar nada** — nunca se mezclan dos
  dominios de clave en el remoto.
- **Verificador remoto:** `vaults` guarda `verifier_ct`/`verifier_nonce`, el
  ciphertext del mensaje constante `vault-ok` bajo la master key actual. Permite
  probar la contraseña sin depender de que el vault tenga variables: un vault
  vacío rechaza igual una contraseña incorrecta. Los vaults anteriores a la
  migración `0002_key_epoch_verifier` no lo tienen y caen a la verificación por
  muestra de ciphertext; el primer sync los completa, pero solo cuando los
  salts coinciden — el backfill corre únicamente con el guard en verde, nunca
  tras un mismatch. Una fila a medio escribir (con `verifier_ct` pero sin
  `verifier_nonce`, o al revés) no cae a ese fallback: aborta con error
  `RemoteVerifierIncomplete` hasta que alguien complete el par.
- **Key epoch:** `vaults.key_epoch` (y su espejo local, `vault_meta.key_epoch`)
  sube en cada `rekey` y el motivo del último cambio queda en `key_change`
  (`init`, `rekey` o `reset`). El epoch solo se compara cuando los salts
  difieren: un dispositivo cuyo epoch local quedó atrás y cuyo salt ya no
  coincide aborta el sync en vez de pisar el meta remoto con uno viejo, aunque
  tenga un `pending_rekey_salt` válido. Si los salts coinciden, el sync sigue
  adelante sin mirar el epoch — por eso un backup restaurado (salt igual,
  epoch viejo) continúa sincronizando con normalidad.
- **Adopción guiada:** tras ese aborto, `vltr sync` pide la contraseña actual
  del vault remoto, deriva la clave con el salt remoto, la verifica contra el
  verificador remoto si lo hay (o contra un ciphertext de muestra en vaults
  antiguos, el mismo truco que `bootstrap`), re-cifra todas las
  variables locales con la nueva clave, reemplaza `vault_meta` local por el
  remoto y continúa con el sync normal. El pull cursor no se toca.
- **`vltr rekey`** cambia la master password: genera un salt nuevo,
  re-cifra todas las variables (conservando `updated_at` para no distorsionar
  LWW; se marcan dirty con `synced_at = NULL`), actualiza el verificador y
  deja un marcador `pending_rekey_salt` en `sync_state`. El siguiente
  `vltr sync` sube el salt nuevo antes que las filas y limpia el marcador;
  los demás dispositivos ven el abort y pasan por la adopción guiada.
- **Guard en `vltr init`:** si la cuenta ya tiene vault en el server, `init`
  se niega y sugiere `vltr bootstrap` (nunca se bloquea por red caída:
  local-first).
- **Backups:** un backup cifrado creado antes de un `rekey` sigue siendo
  abrible con la **contraseña original** — el header del archivo (`SECRETSBAK01`)
  embebe su propio salt y kdf_params (`crates/core/src/backup.rs`).

## Qué NO se sincroniza

- Valores en claro (nunca salen del dispositivo).
- La master key ni el salt del KDF local. Nota: `bootstrap` usa el salt y los
  `kdf_params` remotos de `vaults` para derivar la clave local; el salt no es
  confidencial.
- El verificador en claro: lo único que llega al server es `vaults.verifier_ct`,
  el mensaje constante `vault-ok` cifrado con la master key. El servidor solo
  ve ciphertext de un valor conocido, igual que en cualquier variable, así que
  el verificador no es un secreto del usuario.
- Sesiones / keyring.
- Resolución avanzada de conflictos: LWW por `updated_at` (gana la fila más
  reciente).

> **Limitación conocida:** la policy de `vaults` es `for all`, así que cualquier
> usuario autenticado de la cuenta puede sobrescribir `salt` y `kdf_params` con
> solo su contraseña de Supabase, sin conocer la master key. El cliente exige la
> contraseña correcta para adoptar o pushear el meta del vault, pero esa es una
> política del cliente, no una garantía del servidor: un atacante con la contraseña
> de la cuenta puede dejar el vault indescifrable. Si además infla `key_epoch`,
> el marcador `pending_rekey_salt` no autoriza nada, el sync aborta y ningún
> `rekey` local escapa de ese aborto: el epoch local sigue por detrás y no hay
> salida desde el cliente. Cerrarlo requiere mover la
> validación al servidor con un rol que la CLI no tiene.

## Checklist de verificación E2E (manual)

Con tu propio proyecto Supabase:

1. Exporta `VAULTR_SUPABASE_URL` y `VAULTR_SUPABASE_KEY`, y aplica
   `supabase/migrations/0001_init.sql` Y `supabase/migrations/0002_key_epoch_verifier.sql`.
2. Dispositivo A: `vltr login && vltr sync` (sube el vault al remoto).
3. Dispositivo B (o directorio limpio): `vltr bootstrap` + master password →
   `vltr ls` debe mostrar los secretos.
4. Edita una variable en B, `vltr sync`; edita la misma en A, `vltr sync` →
   gana la edición más reciente (`updated_at`, LWW).
5. `vltr rm` en B, `vltr sync`, luego `vltr sync` en A → la variable
   desaparece en A.
6. Vault existente sin verificador (creado antes de `0002_key_epoch_verifier`):
   `vltr sync` debe completarse y, al consultar `vaults`, `verifier_ct` debe
   quedar poblado. El backfill reescribe `key_epoch`/`key_change` con valores
   iguales a los del remoto por construcción (la igualdad de salts hoy implica
   igualdad de epochs), no los deja intactos.
7. Con `verifier_ct` poblado: un dispositivo nuevo con la contraseña
   **incorrecta** debe fallar el `vltr bootstrap` aunque el remoto no tenga
   ninguna variable.
8. Tras un `rekey` y un `sync` en A, el `sync` en B debe abortar con
   `RemoteKeyChanged` y adoptar con la contraseña nueva.

Orden de despliegue: un cliente nuevo exige `0002` ya aplicada — sin esas
columnas el primer push del meta falla con `PGRST204` (la CLI lo muestra como
error de conexión). El orden inverso (cliente viejo contra servidor nuevo)
funciona: el cliente viejo simplemente ignora las columnas nuevas.

Nota sobre deletes: los borrados se propagan como **tombstones**
(`deleted = true`) y las filas nunca se eliminan físicamente del server; la
limpieza del lado servidor puede requerir un ciclo extra de sync.
