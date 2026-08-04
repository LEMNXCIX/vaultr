# Shell completions

## Generar

```bash
cargo build -p secrets-cli

# Bash
./target/debug/secrets completions bash > /etc/bash_completion.d/secrets
# o
./target/debug/secrets completions bash >> ~/.bashrc

# Zsh
mkdir -p ~/.zfunc
./target/debug/secrets completions zsh > ~/.zfunc/_secrets
# en ~/.zshrc: fpath=(~/.zfunc $fpath) && autoload -Uz compinit && compinit

# Fish
./target/debug/secrets completions fish > ~/.config/fish/completions/secrets.fish

# Elvish / PowerShell
./target/debug/secrets completions elvish
./target/debug/secrets completions powershell
```

Helper:

```bash
./scripts/install-completions.sh zsh > ~/.zfunc/_secrets
```
