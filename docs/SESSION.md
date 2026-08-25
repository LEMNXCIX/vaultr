# Sesión (OS keyring + agente en memoria)

Tras `init` o `unlock`, la **master key** se guarda en el **keyring del sistema** con un **TTL de 30 minutos**.

Si el keyring no está disponible (servicio ausente, backend que no persiste, WSL sin `gnome-keyring`, etc.), la CLI arranca un **agente local en memoria** con el mismo TTL.

Cada uso exitoso de la sesión **renueva** el contador (sliding expiration). Si pasan 30 minutos sin usar la CLI, la sesión caduca y el siguiente comando pide password otra vez.

## Comandos

```bash
vltr unlock    # password + sesión 30 min
vltr lock      # borra sesión de inmediato (keyring y agente)
vltr status    # muestra tiempo restante y el backend activo
```

## Parámetros

| Parámetro | Valor |
|-----------|--------|
| TTL | 30 minutos |
| Renovación | En cada `load` exitoso (cualquier comando que use la sesión) |
| Preferencia | OS keyring |
| Fallback | Agente local en memoria |
| Service (keyring) | `dev.secrets-manager.vault` (se conserva para no invalidar sesiones existentes) |
| Account (keyring) | `master-key-session` |
| Payload (keyring) | JSON `{ key_hex, expires_at }` |
| Transporte (memoria) | loopback local autenticado mediante token aleatorio |
| Coordinación (memoria) | `session-agent.json` con puerto, token y expiración; modo `0600` en Unix |

## Seguridad

- El vault en disco sigue cifrado.
- La sesión limita la ventana de abuso si dejas el equipo desatendido.
- `vltr lock` elimina la credencial del keyring y detiene el agente.
- Sin keyring, el agente cubre el mismo flujo; si tampoco puede iniciarse, la CLI pide password en cada comando.
- En WSL el keyring suele requerir un servicio como `gnome-keyring` ejecutándose dentro de la distribución.
