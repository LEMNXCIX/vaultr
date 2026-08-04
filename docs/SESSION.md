# Sesión (OS keyring + TTL)

Tras `init` o `unlock`, la **master key** se guarda en el keyring del sistema con un **TTL de 30 minutos**.

Cada uso exitoso de la sesión **renueva** el contador (sliding expiration). Si pasan 30 minutos sin usar la CLI, la sesión caduca y el siguiente comando pide password otra vez.

## Comandos

```bash
vltr unlock    # password + sesión 30 min
vltr lock      # borra sesión de inmediato
vltr status    # muestra tiempo restante
```

## Parámetros

| Parámetro | Valor |
|-----------|--------|
| TTL | 30 minutos |
| Renovación | En cada `load` exitoso (cualquier comando que use la sesión) |
| Service | `dev.vltr-manager.vault` |
| Account | `master-key-session` |
| Payload | JSON `{ key_hex, expires_at }` |

## Seguridad

- El vault en disco sigue cifrado.
- La sesión limita la ventana de abuso si dejas el equipo desatendido.
- `vltr lock` o logout del SO eliminan la credencial.
- Sin keyring disponible, la CLI pide password en cada comando.
