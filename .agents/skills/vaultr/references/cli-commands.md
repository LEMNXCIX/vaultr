# CLI — comandos objetivo MVP

Binario: `vltr`

```text
vltr init
vltr unlock
vltr status

vltr project create <name> [--desc TEXT] [--color COLOR]
vltr project list
vltr project delete <name>

vltr env list <project>
vltr env create <project> <name>
vltr env set-default <project> <name>

vltr set <project> <env> <key> [value]
vltr get <project> <env> <key> [--copy]
vltr list <project> <env>
vltr delete <project> <env> <key>

vltr import <project> <env> <path.env>
vltr export <project> <env> [--output path]
vltr apply <project> <env> [--path .env]

vltr search <query> [--project NAME]
vltr backup <path.enc>
vltr restore <path.enc>
```

Prioridad de implementación restante: `import`, `delete`, `search`, `backup`/`restore`, `apply`.
