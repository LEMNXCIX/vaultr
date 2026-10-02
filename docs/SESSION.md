# Sesión (OS keyring + archivo local de respaldo)

Tras `init` o `unlock`, la **master key** se guarda en el **keyring del sistema** con un **TTL de 30 minutos**.

Si el keyring no está disponible (servicio ausente, backend que no persiste, WSL sin `gnome-keyring`, etc.), la CLI escribe la sesión en un **archivo local con permiso `0600`**: `~/.local/share/vaultr/session-<account>.json`, con el mismo TTL y el mismo payload JSON (`{ key_hex, expires_at }`).

Cada uso exitoso de la sesión **renueva** el contador (sliding expiration). Si pasan 30 minutos sin usar la CLI, la sesión caduca y el siguiente comando pide password otra vez. El archivo se borra si expira o está corrupto.

Para pruebas o debug se puede redirigir la ruta del archivo con la variable de entorno `VLTR_SESSION_FILE`.

**Tradeoff:** a diferencia del keyring, la clave descifrada reposa en disco mientras la sesión esté activa (protegida solo por el permiso `0600`), igual que hace `gh auth token`. Es el precio de funcionar sin keyring; usa `vltr lock` cuando termines.

## La sesión es por vault

Cada base de datos tiene su propia sesión. El `account` del keyring se deriva de la ruta del vault: los primeros 16 hex chars del SHA-256 del path absoluto y canonicalizado, sobre el prefijo `master-key-session`. El path en crudo no se guarda, porque los metadatos del keyring los puede leer cualquier proceso con acceso.

Consecuencias:

- `vltr lock` solo borra la sesión del vault actual; los demás vaults siguen desbloqueados.
- `vltr init` sobre una base nueva no pisa la sesión del vault real.
- El archivo de respaldo también es por base (`session-<account>.json`), no un nombre fijo.

Esto aplica **solo a la master key**. La sesión de Supabase es otra cosa: mira abajo.

### Nota de upgrade

Las sesiones creadas por versiones anteriores usaban un `account` global y quedan **huérfanas**: no se pueden reasignar a un vault con seguridad (adivinar a qué base pertenecían podría darle la clave equivocada). Después de actualizar, hay que hacer **`vltr unlock` una vez por vault**. A partir de ahí cada vault tiene su sesión y no se vuelven a pisar entre sí.

## La sesión de Supabase es por cuenta, no por vault

`vltr login` guarda el JWT de Supabase en el keyring con el account fijo `supabase-session`, y el archivo de respaldo es `~/.local/share/vaultr/sync-session.json`. **No lleva sufijo por vault, a propósito.**

Es un credencial de **cuenta**, no de vault: una persona tiene una cuenta de Supabase y un login, y todos sus vaults hablan con el mismo servidor como la misma cuenta. Por eso:

- `vltr login` una vez sirve para todos los vaults de la máquina.
- `vltr logout` cierra la sesión de la cuenta **entera**. Es la semántica correcta: no existe "logout de este vault".

Lo que sí es por vault es la master key, porque dos vaults distintos tienen claves maestras distintas: compartir un slot era el bug (desbloquear el vault A podía darte la clave del vault B).

El guard de `vltr init` —que pregunta al servidor si esta cuenta ya tiene un vault antes de crear uno local— depende de esta sesión de cuenta. Si fuera por base, la base que se está creando no tendría sesión propia, el guard nunca dispararía, e `init` crearía un dominio de clave divergente. La función `sync::init_remote_guard_needed` documenta esa invariante y tiene test.

## Comandos

```bash
vltr unlock    # password + sesión 30 min
vltr lock      # borra la sesión de este vault (keyring y archivo de sesión)
vltr status    # muestra tiempo restante y el backend activo
```

## Parámetros

| Parámetro | Valor |
|-----------|-------|
| TTL | 30 minutos |
| Renovación | En cada `load` exitoso (cualquier comando que use la sesión) |
| Preferencia | OS keyring |
| Fallback | Archivo de sesión local, modo `0600` en Unix |
| Service (keyring) | `dev.secrets-manager.vault` (se conserva para no invalidar sesiones existentes) |
| Account (keyring) | `master-key-session-<hash del path del vault>` (16 hex chars) |
| Payload | JSON `{ key_hex, expires_at }` |
| Ruta (fallback) | `~/.local/share/vaultr/session-<hash del path del vault>.json` (override: `VLTR_SESSION_FILE`) |

Un vault en memoria (tests) no persiste sesión: no hay archivo al cual asociarla.

### Sesión de Supabase

| Parámetro | Valor |
|-----------|-------|
| Ámbito | **Cuenta** (compartida por todos los vaults), no vault |
| Service (keyring) | `dev.secrets-manager.vault` |
| Account (keyring) | `supabase-session` (fijo, sin hash) |
| Ruta (fallback) | `~/.local/share/vaultr/sync-session.json` |
| Se limpia con | `vltr logout` (la cuenta entera) |

## Seguridad

- El vault en disco sigue cifrado.
- La sesión limita la ventana de abuso si dejas el equipo desatendido.
- `vltr lock` elimina la credencial del keyring de este vault y borra su archivo de sesión.
- Sin keyring, el archivo cubre el mismo flujo; si tampoco puede escribirse, la CLI pide password en cada comando y muestra la causa real del fallo.
- En WSL el keyring suele requerir un servicio como `gnome-keyring` ejecutándose dentro de la distribución.
