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
  sube en cada `rekey` y en cada `reset`, y el motivo del último cambio queda
  en `key_change` (`init`, `rekey` o `reset`). El epoch solo se compara cuando
  los salts difieren: un dispositivo cuyo epoch local quedó atrás y cuyo salt ya
  no coincide aborta el sync en vez de pisar el meta remoto con uno viejo, aunque
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

## Reset: `vltr reset`

`vltr reset` cubre el caso "olvidé la master password": **destruye el vault local
e instala uno vacío bajo una contraseña nueva**. No pide unlock a propósito —
justamente porque puede necesitarlo quien ya no tiene la clave. A partir de ahí
el vault vuelve a estar vacío y utilizable con la contraseña nueva.

**No es una recuperación.** Lo cifrado con la contraseña perdida no se puede
recuperar: las filas anteriores se borran en vez de re-cifrarse, porque la clave
con la que estaban cifradas ya no está para nadie. Lo único que puede salvar esos
datos es un backup hecho **antes del último `vltr rekey`** (ver *Backups* arriba),
que se abre con la contraseña anterior a ese `rekey`.

- **Confirmación:** hay que escribir `RESET IT` exactamente. No se normaliza nada:
  ni mayúsculas, ni espacios, ni lo que venga detrás — solo se quita el fin de
  línea. `reset it`, `RESET  IT` (dos espacios), `RESET IT!` o la línea vacía
  abortan sin tocar nada. Todo lo anterior al prompt es de lectura: ninguna
  escritura, ninguna llamada de red, ninguna sesión guardada.
- **El salt se rota:** 16 bytes aleatorios nuevos (`crypto::generate_salt`) y de
  ellos se deriva la clave nueva; los `kdf_params` vigentes se reutilizan. Ese
  cambio de sal es la señal que hace que los otros dispositivos se den cuenta. Es
  la misma señal que usa `rekey`, así que por el salt, un reset y un cambio de
  contraseña son indistinguibles.
- **`--local` resetea solo este dispositivo.** El remoto no se toca en ese
  momento: el borrado queda pendiente y lo ejecuta el siguiente `vltr sync` con
  red. Es también la salida cuando no hay sesión de sync — un `vltr reset` sin
  sesión se niega y sugiere `vltr login` o `--local`.
- **El borrado remoto no necesita la master key.** Un tombstone es una escritura
  de metadatos: `deleted = true`, `version + 1` y `updated_at` nuevo, con el
  `value_encrypted` y el `nonce` **intactos, byte a byte**. El remoto no se borra
  destruyendo filas, se borra marcándolas, y eso no requiere descifrar nada — que
  es lo que permite resetear un vault cuya clave ya no se tiene. Como en el resto
  del sync, las filas nunca se borran físicamente del server.
- **Publica `key_epoch = remote.key_epoch + 1` con `key_change = 'reset'`.** El
  epoch se calcula al subir, con la fila remota a mano, así que solo puede
  avanzar el contador del servidor: ni un reset ni el reintento de uno
  interrumpido pueden bajarlo. El contador local converge después en el valor
  publicado. `key_change` es lo que distingue "cambié la contraseña" de
  "reseteé el vault"; sin él, el otro dispositivo no podría saber que debe
  preguntar en vez de adoptar.
- **Un fallo remoto no es un reset fallido.** Para cuando el vault local ya es el
  dominio nuevo, el borrado remoto es un segundo paso: si ese paso falla, el
  comando lo dice como lo que es — el reset local se completó, el borrado remoto
  quedó pendiente— y deja el reintento para el próximo `vltr sync`. El marcador
  `pending_local_reset` se escribe antes del push y se borra solo cuando el push
  acaba: un reset interrumpido a mitad del borrado lo termina el siguiente sync,
  que lo ejecuta **antes** del guard de salt — si no, el salt nuevo que acaba de
  instalar este dispositivo chocaría contra el viejo del remoto y el sync
  abortaría para siempre. Si la cuenta no tiene fila en `vaults` es que no hay
  nada que borrar, y eso no se reporta como fallo.

### Divergencia: el remoto se reseteó en otro dispositivo

El guard de sync separa el reset del `rekey`: si los salts difieren y el epoch
remoto está **por delante** con `key_change = 'reset'`, el sync se detiene sin
subir ni bajar nada, la CLI lo explica (con el epoch remoto y cuándo se registró
el cambio) y ofrece tres salidas. Es la pieza que evita la resurrección: la
adopción automática subiría las filas previas al borrado por encima del borrado, y
con ellas volverían al remoto secretos que el reset quiso destruir.

El prompt llega después de que `vltr sync` ya haya desbloqueado el vault local
con su contraseña, así que un dispositivo que perdió su propia clave no llega
hasta aquí: para eso existe el reset.

- **a) Descartar lo local** — se destruye este vault y se adopta el del remoto,
  que tras el reset está vacío: los dos dispositivos quedan alineados y vacíos.
  Pide la master password **del remoto** y la verifica contra su verifier antes
  de borrar nada local, para que una contraseña equivocada no pueda ser lo que
  destruya un vault. No hace falta ninguna clave local: aquí las filas se borran,
  no se re-cifran.
- **b) Conservar lo local** — se re-cifran las variables locales con la clave del
  remoto y se vuelven a subir, así que sobrevive lo que había en esta máquina.
  Necesita la master password del remoto (verificada igual que en a) y el vault
  local desbloqueado, porque lo que se preserva es justamente lo que hay en él. La
  adopción además vuelve a marcar proyectos y entornos para subir: el reset los
  había tombstonado en el server, y sin resubir sus filas el pull siguiente
  ganaría LWW contra ellas y se las llevaría por delante (ver el checklist E2E
  de abajo).
- **c) Cancelar** — no se cambia nada: el vault local sigue funcionando con su
  contraseña actual y simplemente queda desincronizado. **Es el default** ante
  `Enter`, porque es la única de las tres que no pierde nada. Una respuesta que no
  se reconoce vuelve a preguntar en lugar de caer en un default: un typo nunca
  puede acabar descartando un vault.

Tras a) o b) el sync se reintenta **una** vez: para entonces los salts ya
coinciden, así que no puede volver a abortar por lo mismo. Si el remoto cambia otra
vez entre medias (otro reset, otro `rekey`), es un evento nuevo y se reporta en vez
de reintentarse en bucle.

> **Limitación conocida (reset):** el epoch es un contador por niveles, no un
> reloj. Un segundo dispositivo que conserve el dominio de clave anterior al
> reset y lleve un `pending_rekey_salt` válido puede seguir subiendo su salt y sus
> filas por encima del borrado si su `key_epoch` local resulta **igual** al que
> publicó el reset: el guard solo compara con "mayor que", y ante igualdad cae en
> la rama del marcador de rekey. El contador no puede distinguir dos rotaciones
> concurrentes del mismo nivel. Es un residuo del problema de resurrección que el
> prompt de divergencia cierra en el caso normal (epoch remoto adelantado);
> cerrarlo del todo exige una guarda monótona en el servidor, con un rol que la
> CLI no tiene.

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
9. Reset, confirmación errónea: `vltr reset` y escribir `reset it` (y repetir con
   `RESET  IT`, con `RESET IT!` y con la línea vacía) debe abortar con
   `Confirmation phrase does not match. Nothing was changed.`, sin haber escrito
   nada: mismos proyectos, mismo salt en `vault_meta`, ninguna fila tocada.
10. `vltr reset` sin sesión de sync (ni `--local`) se niega y sugiere `vltr login`
    o `--local`, sin tocar nada.
11. Reset completo: `vltr reset` → `RESET IT` → contraseña nueva. Debe terminar
    con el vault local vacío y **sin haber pedido la contraseña anterior en ningún
    momento** (el reset no requiere unlock). En el remoto: `key_epoch` = el
    anterior + 1, `key_change` = `reset`, `key_changed_at` poblado y `salt`
    distinto del anterior; y
    `select count(*) from projects where deleted = false` (con RLS solo ves tus
    filas), lo mismo en `environments` y en `variables`, deben dar **0**. En local,
    `vltr ls` debe mostrar el vault vacío.
12. Ciphertext intacto: guarda el `value_encrypted` y el `nonce` de una variable
    concreta antes del reset; después, esas mismas dos columnas de esa misma fila
    deben salir idénticas — solo cambian `deleted`, `version` y `updated_at`. Un
    reset que re-cifra algo está mal.
13. Cuenta sin vault remoto: en una cuenta nueva (con `vltr signup`/`vltr login`),
    `vltr init` y luego `vltr reset` (online, **sin** `--local`, porque el mensaje
    vive en esa rama) debe completarse y decir que no hay vault remoto que borrar.
    Eso no es un fallo: no había nada que borrar.
14. Reset interrumpido a mitad del borrado: deja el remoto a medias y comprueba
    que el siguiente `vltr sync` lo termina. Vías: `Ctrl-C` sobre el `vltr reset`
    online cuando ya está subiendo filas, o la del marcador, que es más fácil de
    cronometrar — `vltr reset --local` en A (escribe el marcador y no toca el
    remoto) y cortar la red durante el siguiente `vltr sync`. Al restaurar la red,
    el `vltr sync` siguiente debe **terminar el borrado** (0 filas vivas), limpiar
    el marcador y sincronizar sin prompt de divergencia: el mismo sync que termina
    el borrado es el que informa del éxito. Si no se corta a tiempo, el reset se
    habrá completado de sobra; repite el punto 11 con más filas en el remoto para
    tener una ventana más ancha.
15. Segundo dispositivo: el prompt. Con A reseteado y B todavía sincronizado,
    `vltr sync` en B debe detenerse con "El vault remoto se reseteó en otro
    dispositivo (key_epoch N, key_change reset)", **sin subir ni bajar nada**, y
    ofrecer a/b/c. Una respuesta no reconocida (`x`) debe volver a preguntar, y
    `Enter` a secas debe equivaler a cancelar. Cada uno de los puntos 16-19 parte
    de un B recién preparado (repite los puntos 2-3): elegir una opción deja a B
    en el dominio del remoto, así que B ya no sirve para probar la siguiente.
16. Opción a) en B: pide la master password del remoto, borra el vault local de B
    y lo deja en el dominio remoto vacío. Tras el reintento automático, B no debe
    volver a preguntar, `vltr ls` en B sale vacío y el remoto sigue con 0 filas
    vivas. Con la contraseña del remoto **incorrecta** debe fallar sin haber
    borrado nada de B.
17. Opción b) en B: pide la master password del remoto y, tras el reintento, las
    filas de B vuelven a estar en el remoto y `vltr ls` en B las muestra.
18. Opción c) en B: no cambia nada. `vltr ls` sigue funcionando con la contraseña
    anterior de B, el remoto no se toca y el siguiente `vltr sync` vuelve a
    preguntar.
19. **Regresión, opción b) en un dispositivo que ya había sincronizado antes del
    reset.** Prepara B como en los puntos 2-3, con un proyecto, sus entornos y sus
    variables **ya sincronizados**, y elige b). B debe conservar las tres cosas —
    proyecto, entornos y variables— y las filas correspondientes deben quedar
    `deleted = false` en el remoto, resubirtas por encima de las tombstones del
    reset. Este caso estuvo roto: una build anterior solo re-encolaba las
    variables, así que los proyectos y entornos seguían limpios, el push no los
    tocaba, el pull siguiente ganaba LWW contra sus tombstones (más nuevas) y
    `cascade_tombstones` se llevaba a los hijos. El usuario elegía "conservar" y
    recuperaba el vault marcado como borrado: es el fallo que más se pierde en
    silencio, así que hay que repetir este punto tras cualquier cambio en la
    adopción.
20. Backup restaurado después del reset: en un dispositivo restaurado desde un
    backup anterior al reset, `vltr sync` debe dar el prompt de divergencia (no un
    error de contraseña opaco) y la opción b) debe funcionar.

Orden de despliegue: un cliente nuevo exige `0002` ya aplicada — sin esas
columnas el primer push del meta falla con `PGRST204` (la CLI lo muestra como
error de conexión). El orden inverso (cliente viejo contra servidor nuevo)
funciona: el cliente viejo simplemente ignora las columnas nuevas.

Nota sobre deletes: los borrados se propagan como **tombstones**
(`deleted = true`) y las filas nunca se eliminan físicamente del server; la
limpieza del lado servidor puede requerir un ciclo extra de sync.

Nota sobre los puntos de reset (9-20): son **pasos a ejecutar a mano**, no
comprobaciones ya hechas. Los caminos HTTP del reset y del prompt a/b/c
(`push_reset`, `reset_remote`, `discard_local_and_adopt`) no los cubre la suite
unitaria, que solo fija las partes puras: las tombstones, el epoch publicado, las
ramas del guard de salt, el parseo de la confirmación y el de la opción, y el
`reset_vault` de storage. El checklist es la cobertura real de esa parte. Necesitan
además una cuenta de Supabase usable, y contra el proyecto de test de este repo no
se pueden ejecutar: GoTrue rechaza el TLD reservado `.test` en
`e2e@vaultr.test` con `400 email_address_invalid`.
