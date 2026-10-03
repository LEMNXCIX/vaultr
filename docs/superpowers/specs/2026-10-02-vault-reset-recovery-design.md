# Reset y recuperación de master key

**Fecha:** 2026-10-02
**Estado:** diseño aprobado en conversación, pendiente de revisión de este spec
**Ámbito:** `vltr reset`, `vltr recover`, verifier remoto, detección de divergencia por epoch

## Problema

Hoy no existe forma de recuperar el control de un vault cuando se olvida la master
key. `rekey` exige desbloquear con la contraseña actual; `adopt_remote_key` exige la
contraseña del vault remoto. Ambos caminos requieren la clave que se perdió, así que
la pérdida es definitiva.

Peor: la verificación de contraseña contra el remoto es heurística y depende de los
datos del usuario.

- `verify_password_against_remote` (`crates/core/src/sync.rs:497`) no tiene contra qué
  probar en el servidor — `vaults` solo guarda `salt` y `kdf_params`. El cliente baja
  una página de `variables` e intenta descifrar la primera fila.
- Con un vault remoto sin variables, `verify_key_against_sample`
  (`crates/core/src/sync.rs:476`) acepta cualquier contraseña: no hay nada contra qué
  probar y devuelve `Ok(())`.
- Si las filas remotas están cifradas bajo una clave distinta a la que se está
  probando, la verificación falla y el mensaje dice "la contraseña no descifra el
  vault remoto". Una contraseña **correcta** produce un error de contraseña
  **incorrecta**.
- `apply_key_rotation` (`crates/storage/src/lib.rs:195`) marca las variables
  re-cifradas con `synced_at = NULL`, es decir dirty. En el siguiente sync se **suben**.
  Una adopción desde otro dispositivo reintroduce datos que el reset quiso borrar.

En vivo (proyecto Supabase de vaultr, verificado por MCP el 2026-10-02) se confirmó que
la policy de `vaults` es `PERMISSIVE` con `cmd = ALL`: cualquier usuario autenticado de
la cuenta puede sobrescribir `salt` y `kdf_params`. El servidor no exige prueba de
posesión de la clave actual. Toda la restricción actual es política del cliente.

## Objetivos

1. Poder avanzar tras olvidar la master key: reset destructivo explícito, con
   confirmación y sin datos que se sobrescriban por sorpresa en ningún dispositivo.
2. Que la verificación de contraseña sea real e independiente del contenido del vault.
3. Que ninguna contraseña correcta produzca un error de contraseña incorrecta.
4. Que la recuperación de cuenta (password de Supabase) esté disponible desde la CLI.

## No objetivos

- **No** es recuperación de datos. Reset no recupera secretos: la clave perdida nunca
  vuelve, los datos cifrados con ella son irrecuperables. El único camino de
  recuperación de datos sigue siendo un backup previo al rekey
  (`docs/SYNC.md:90-91`). La documentación y la salida de la CLI deben decirlo sin
  ambigüedad.
- **No** se implementa reset de la contraseña de Supabase sin SMTP: se documenta como
  dependencia de despliegue.
- **No** se toca el modelo de datos de dominio ni el schema de proyectos.

## Diseño

### 1. Servidor: verifier y epoch en `vaults`

Migración Supabase `0002_key_epoch_verifier.sql`:

```sql
alter table public.vaults
  add column verifier_ct    text,
  add column verifier_nonce text,
  add column key_epoch      bigint not null default 1,
  add column key_change     text not null default 'init',
  add column key_changed_at timestamptz;

comment on column public.vaults.verifier_ct is
  'ciphertext de VAULT_VERIFIER_MESSAGE bajo la master key actual';
comment on column public.vaults.key_epoch is
  'incremente en cada rekey o reset; permite detectar divergencia';
```

`verifier_ct` es el mensaje constante `VAULT_VERIFIER_MESSAGE` cifrado con la master key
actual. No filtra nada: el servidor solo almacena el ciphertext de un valor constante
conocido. La property zero-knowledge se mantiene.

`key_change` es `'init' | 'rekey' | 'reset'`. Distingue el motivo del cambio para que
otro dispositivo pueda explicarlo. `rekey` **también** incrementa `key_epoch`: sin eso
el epoch no distingue un cambio de contraseña de un reset, y el prompt de la otra PC no
puede decir qué pasó.

Las columnas son nulables / con default para que el despliegue sea compatible con filas
existentes: los vaults previos no tienen verifier y siguen funcionando por el camino de
verificación viejo hasta que un sync lo rellene.

### 2. Cliente: `key_epoch` local

Migración SQLite `003_key_epoch.sql`, registrada en `crates/storage/src/migrations.rs`
(ver `docs/MIGRATIONS.md`): agregar `key_epoch INTEGER NOT NULL DEFAULT 1` a
`vault_meta`. Es el estado contra el que se compara el epoch remoto en el guard de sync.

### 3. Verificación real

`verify_password_against_remote` pasa a descifrar `vaults.verifier_ct` y comparar con
`VAULT_VERIFIER_MESSAGE`.

- Si `verifier_ct` es `NULL` (vault anterior a la migración): fallback a la verificación
  actual por muestra de ciphertext, con su comportamiento actual incluido el
  "aceptar si la muestra está vacía".
- Backfill: cualquier sync o rekey exitoso que detecte `verifier_ct` nulo lo completa con
  una ascentura de `vaults` que no cambia `salt`, `kdf_params` ni `key_epoch`. Los
  vaults nuevos ya lo traen desde el push inicial.

Con esto se cierra el hole de "cualquier contraseña pasa en un vault vacío": un vault
vacío con verifier rechaza la contraseña equivocada, y uno sin verifier mantiene el
comportamiento viejo hasta el primer sync.

### 4. `vltr reset`

Sustituye el caso "olvidé la contraseña". **No requiere unlock**: ése es el punto.

`vltr reset` (online, requiere sesión de sync) · `vltr reset --local` (offline, solo
vault local).

1. **Confirmación.** Imprime qué se pierde y exige tipear `RESET IT` exactamente. Sin
   coincidencia exacta, aborta. Aplica igual si no hay nada que perder.
2. **Nueva clave.** Salt aleatorio de 16 bytes (el tamaño en uso, verificado contra
   `vaults.salt`), mismo `kdf_params` vigente. La master key se deriva de la contraseña
   nueva y ese salt.
3. **Vault local.** Se destruye y se reinicializa: `vault_meta` nuevo (salt nuevo,
   verifier nuevo bajo la clave nueva, `key_epoch` placeholder) y cero filas. Los datos
   locales previos no son recuperables y no se intentan re-cifrar, porque la clave vieja
   no está disponible.

   El `key_epoch` local es un **placeholder**: `meta.key_epoch + 1` sobre su propio valor,
   no `remote + 1`. El valor autoritativo se calcula en el push (paso 5), donde la fila
   remota está a mano: `push_reset` publica `remote.key_epoch + 1`, que es monótono y nunca
   puede bajar el contador del servidor. Esto es lo que permite que `--local` funcione sin
   conexión: no necesita conocer el epoch remoto para nada. Tras un push exitoso el valor
   local converge con el publicado.
4. **Remoto — sin necesitar la clave.** Se bajan las filas remotas y se vuelven a subir
   como **tombstones**: `deleted = true`, `version + 1`, `updated_at` nuevo, y **el
   `value_encrypted` y el `nonce` originales intactos**. Marcar una fila como borrada no
   requiere descifrarla, así que el borrado funciona sin conocer la master key. Es lo que
   hace que el reset sirva justamente cuando la clave se perdió.
5. **Orden de push.** `vaults` primero (salt + verifier + `key_epoch` + `key_change =
   'reset'` + `key_changed_at = now()`), después las filas. El guard de salt ya impide
   que otro dispositivo mezcle dominios durante la ventana, porque ve el salt nuevo y su
   clave vieja no lo deriva.
6. **Marcador.** `pending_local_reset` en `sync_state` se escribe **antes** del push y se
   borra **después** de que el push de filas termine. Si la red se corta, el siguiente
   sync reintenta en vez de dejar el remoto a medias. Mismo patrón que
   `pending_rekey_salt` (`crates/core/src/sync.rs:672`, `:700-706`). El reset borra
   cualquier `pending_rekey_salt` previo: ambos marcadores describen el estado de la
   clave del vault y el reset los subsume a los dos. Nunca hay más de uno activo.

`--local` hace solo el paso 3 y escribe `pending_local_reset`. El próximo sync con red
**termina el borrado él mismo, en silencio y sin prompt**: el guard de salt corre después
del retry, así que al terminar el wipe los salts ya coinciden y resuelve `Proceed`.

> **Nota de implementación (2026-10-02).** Una versión anterior de este spec decía que el
> epoch local era `remote + 1` al resetear, y que tras un `--local` el sync "entraba por el
> flujo de divergencia" de la sección 5. Ambas cosas resultaron incorrectas. Preguntarle al
> autor de un reset por el vault que acaba de crear es un dead-end de UX: el prompt ofrece
> descartar o conservar datos que él mismo acaba de borrar. La implementación terminada usa
> el placeholder local y resuelve el wipe en el mismo sync, sin preguntar nada. El flujo de
> divergencia de la sección 5 queda para el caso real: **otra** PC con el dominio previo.

### 5. Divergencia en otro dispositivo (opción C)

El guard de sync (`salt_action`, `crates/core/src/sync.rs:673`) pasa a considerar el
epoch además del salt. Si `remote.key_epoch > local.key_epoch` con motivo
`key_change = 'reset'`, el sync **se detiene con un error nuevo**
`CoreError::RemoteReset(RemoteResetInfo)` que lleva `key_change`, `key_changed_at` y el
epoch remoto. La CLI lo traduce a un aviso explícito y ofrece tres salidas:

- **a) Descartar local** — se destruye el vault local y se adopta el remoto, que tras un
  reset está vacío. Los dos dispositivos quedan alineados y vacíos.
- **b) Conservar local** — se re-cifran las variables locales con la clave remota
  derivada de la contraseña nueva, y se empujan. Se preserva lo que había en esa PC.
- **c) Cancelar** — no se toca nada; el vault local sigue funcionando con su clave vieja
  y desincronizado. Es el default ante `Enter`.

Si el motivo es `rekey` en lugar de `reset`, se mantiene el flujo de adopción guiada ya
existente, que además ahora verifica contra el verifier en vez de contra una fila de
muestra.

**Precedencia de marcadores.** Solo uno de `pending_rekey_salt` y `pending_local_reset`
puede estar activo a la vez. `reset_local` limpia el marcador de rekey. En el otro
sentido, un `rekey` ejecutado mientras hay un reset pendiente **no** crea su propio
marcador: el reset gana, porque `push_reset` empuja el salt local de todas formas y el
marcador de rekey no aportaría nada. La alternativa —borrar el marcador de reset desde
`rekey`— se descartó: un rekey rotó la clave local pero las filas pre-reset del servidor
siguen cifradas bajo la clave vieja, que **las otras PCs todavía tienen**. Borrar el reset
ahí dejaría datos vivos en el remoto y mandaría a esas PCs al prompt de adopción, que es
justo el callejón sin salida que este prompt evita.

Esta es la pieza que evita la resurrección: hoy la adopción es automática e inmediata
(`crates/cli/src/main.rs:567-582`), así que un dispositivo adopts empuja sus datos viejos
al remoto sin preguntar. Con el prompt, ningún dispositivo reintroduce datos borrados sin
que vos lo decidas.

### 6. `vltr recover` — recuperación de cuenta

Recuperar el password de Supabase, que es la precondición para el reset online.

1. `vltr recover <email>` llama `POST {base}/auth/v1/recover`.
2. Se muestra el aviso: **depende de que el proyecto tenga SMTP configurado.** Si no lo
   tiene, el enlace nunca llega.
3. Se pega el enlace de recuperación; del mismo enlace sale el token y el redirect. El
   cliente llama `PUT {base}/auth/v1/user` con `Authorization: Bearer <token>` y el
   password nuevo, y guarda la sesión resultante con el mismo camino que `login`.

Restricciones a documentar: el correo de la cuenta debe ser entregable, porque
la confirmación de email no se puede recibir en un dominio inexistente.

> **Aclaración (2026-10-03).** Este spec afirmaba, como verificado, que GoTrue
> rechaza el TLD `.test`. **Es cierto**, comprobado el 2026-10-03: `signup` con
> un `.test` nuevo responde `400 Email address "…" is invalid`.
>
> Lo que estaba mal era la conclusión que se derivó: que la cuenta
> `e2e@vaultr.test` no servía. Sí sirve — existe, está confirmada y autentica.
> Fue sembrada por SQL, y por eso nunca pasó por la validación del signup: su
> hash es bcrypt con coste 6, no el 10 por defecto de Supabase. Dos detalles que
> hicieron parecer lo contrario: `signup` sobre un email **existente** devuelve
> `200` con un usuario **fabricado** (anti-enumeración) sin crear ninguna fila, y
> `login` funciona sin tocar nada de eso.
>
> Conclusión operativa: el TLD bloquea **crear cuentas**, no **usar** una ya
> existente. Por eso el checklist corre contra esa cuenta y lo único que no se
> puede ejecutar es el punto 13, que necesita una segunda.

Orden recomendado, y el que la CLI debe sugerir cuando ambas fallen: `vltr recover`
primero, `vltr reset` después.

## Manejo de errores

| Situación | Comportamiento |
|---|---|
| Confirmación incorrecta | Aborta sin tocar nada |
| `reset` sin sesión de sync | Niega; sugiere `--local` o `vltr login` |
| Reset con red caída a mitad del push | `pending_local_reset` sobrevive; el siguiente sync reintenta |
| Password nueva que no descifra el verifier | `InvalidPassword` — imposible por diseño salvo bug, porque el verifier se acaba de derivar con esa clave |
| Otro dispositivo con epoch desfasado | `RemoteReset` → prompt a/b/c; default cancelar |
| Adoptar cuando el remoto quedó vacío | Verificación contra verifier, no contra muestra; funciona |
| `recover` sin SMTP | Mensaje explícito de que el enlace no llegará; no error genérico |

## Zero-knowledge

Nada nuevo sale del dispositivo. `verifier_ct` es el ciphertext de un mensaje constante
conocido, no de un secreto del usuario, así que no expone nada. Las tombstones del reset
conservan el ciphertext original, sin tocarlo ni descifrarlo. El reset sigue moviendo solo
ciphertext.

El riesgo que sí introduce es **destructivo, no de lectura**: un atacante con solo la
password de Supabase ya podía pisar el salt (policy `cmd = ALL`, verificado en vivo), y
con el reset puede además borrarte el vault de forma limpia. El spec no cierra ese hueco
porque cerrarlo exige un cambio de RLS que requeriría un rol de servidor — está fuera de
scope y anotado en docs/SYNC.md como limitación conocida.

## Testing

Unidad (`crates/core/src/sync.rs`, sin HTTP):
- `verify_key_against_sample` y el nuevo `verify_verifier`: clave correcta acepta,
  incorrecta rechaza, verifier ausente cae al fallback, vault vacío con verifier rechaza.
- `salt_action`: epoch atrás, al día, adelantado; `key_change` `rekey` vs `reset`; epoch
  adelantado sin cambio de salt; marcador `pending_local_reset` presente.
- Confirmación: `RESET IT` exacto acepta; `RESET`, `reset it`, `RESET  IT`, vacío rechazan.
- Reset sobre vault no inicializado; reset con epoch remoto ya avanzado.

Integración (Postgres efímero o el proyecto de test):
- reset online borra los secretos vivientes del remoto y el remoto queda sin filas vivas;
- el ciphertext de una tombstone es **byte-idéntico** al original;
- tras el reset, el otro dispositivo recibe `RemoteReset` y las tres salidas funcionan;
- la opción b) preserva los datos locales; la a) los descarta; la c) no toca nada;
- reset con push interrumpido y reintento posterior completa sin perder la fila.

E2E manual (extender el checklist de `docs/SYNC.md`): alta con `signup` real → reset →
segundo dispositivo detecta y elige.

## Rollback

Cliente y servidor se despliegan por separado y ambos son compatibles hacia atrás:

- Cliente viejo contra servidor nuevo: ignora las columnas nuevas; sigue usando la
  verificación por muestra. Funciona.
- Cliente nuevo contra servidor viejo: `verifier_ct` es `NULL`, cae al fallback; el
  epoch remoto se lee como 0 o `NULL` y se interpreta como "sin información", sin
  disparar prompts nuevos.
- La migración es puramente aditiva (`add column`), sin `drop` ni cambio de tipo.
  Revertir es `drop column`, sin pérdida de datos porque las columnas nuevas no son
  leídas por el cliente viejo.

## Archivos tocados

- `supabase/migrations/0002_key_epoch_verifier.sql` (nuevo)
- `crates/storage/migrations/003_key_epoch.sql` (nuevo) + `migrations.rs`
- `crates/storage/src/lib.rs` — reset local, `key_epoch`, tombstone masivo
- `crates/core/src/sync.rs` — verificación por verifier, `salt_action` con epoch,
  `remote_reset`, push de `vaults` extendido, backfill
- `crates/core/src/lib.rs` — `CoreError::RemoteReset`
- `crates/sync/src/lib.rs` / `auth.rs` — columnas de `vaults` en el DTO, `recover`,
  `update_password`
- `crates/cli/src/main.rs` — `Reset`, `Recover`, prompt a/b/c
- `docs/SYNC.md` — flujo, checklist E2E, limitación conocida