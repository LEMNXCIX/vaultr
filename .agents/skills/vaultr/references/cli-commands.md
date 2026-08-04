# CLI — comandos objetivo MVP

Binario: `secrets`

```text
secrets init
secrets unlock
secrets status

secrets project create <name> [--desc TEXT] [--color COLOR]
secrets project list
secrets project delete <name>

secrets env list <project>
secrets env create <project> <name>
secrets env set-default <project> <name>

secrets set <project> <env> <key> [value]
secrets get <project> <env> <key> [--copy]
secrets list <project> <env>
secrets delete <project> <env> <key>

secrets import <project> <env> <path.env>
secrets export <project> <env> [--output path]
secrets apply <project> <env> [--path .env]

secrets search <query> [--project NAME]
secrets backup <path.enc>
secrets restore <path.enc>
```

Prioridad de implementación restante: `import`, `delete`, `search`, `backup`/`restore`, `apply`.
