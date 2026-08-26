# Sesión (OS keyring + archivo local de respaldo)

Tras `init` o `unlock`, la **master key** se guarda en el **keyring del sistema** con un **TTL de 30 minutos**.

Si el keyring no está disponible (servicio ausente, backend que no persiste, WSL sin `gnome-keyring`, etc.), la CLI escribe la sesión en un **archivo local con permiso `0600`**: `~/.local/share/vaultr/session.json`, con el mismo TTL y el mismo payload JSON (`{ key_hex, expires_at }`).

Cada uso exitoso de la sesión **renueva** el contador (sliding expiration). Si pasan 30 minutos sin usar la CLI, la sesión caduca y el siguiente comando pide password otra vez. El archivo se borra si expira o está corrupto.

Para pruebas o debug se puede redirigir la ruta del archivo con la variable de entorno `VLTR_SESSION_FILE`.

**Tradeoff:** a diferencia del keyring, la clave descifrada reposa en disco mientras la sesión esté activa (protegida solo por el permiso `0600`), igual que hace `gh auth token`. Es el precio de funcionar sin keyring; usa `vltr lock` cuando termines.

## Comandos

```bash
vltr unlock    # password + sesión 30 min
vltr lock      # borra sesión de inmediato (keyring y archivo de sesión)
vltr status    # muestra tiempo restante y el backend activo
```

## Parámetros

| Parámetro | Valor |
|-----------|--------|
| TTL | 30 minutos |
| Renovación | En cada `load` exitoso (cualquier comando que use la sesión) |
| Preferencia | OS keyring |
| Fallback | Archivo de sesión local, modo `0600` en Unix |
| Service (keyring) | `dev.secrets-manager.vault` (se conserva para no invalidar sesiones existentes) |
| Account (keyring) | `master-key-session` |
| Payload | JSON `{ key_hex, expires_at }` |
| Ruta (fallback) | `~/.local/share/vaultr/session.json` (override: `VLTR_SESSION_FILE`) |

## Seguridad

- El vault en disco sigue cifrado.
- La sesión limita la ventana de abuso si dejas el equipo desatendido.
- `vltr lock` elimina la credencial del keyring y borra el archivo de sesión.
- Sin keyring, el archivo cubre el mismo flujo; si tampoco puede escribirse, la CLI pide password en cada comando y muestra la causa real del fallo.
- En WSL el keyring suele requerir un servicio como `gnome-keyring` ejecutándose dentro de la distribución.
