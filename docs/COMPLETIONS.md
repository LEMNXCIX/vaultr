# Shell completions

## Generar

```bash
cargo build -p vltr-cli

# Bash
./target/debug/vltr completions bash > /etc/bash_completion.d/vltr
# o
./target/debug/vltr completions bash >> ~/.bashrc

# Zsh
mkdir -p ~/.zfunc
./target/debug/vltr completions zsh > ~/.zfunc/_vltr
# en ~/.zshrc: fpath=(~/.zfunc $fpath) && autoload -Uz compinit && compinit

# Fish
./target/debug/vltr completions fish > ~/.config/fish/completions/vltr.fish

# Elvish / PowerShell
./target/debug/vltr completions elvish
./target/debug/vltr completions powershell
```

Desde PowerShell 7 en Windows, genera el script desde WSL y cárgalo en la
sesión actual:

```powershell
wsl -d archlinux -- bash -lc 'cd ~/Repositories/vaultr && cargo run -- completions powershell' |
  Out-String | Invoke-Expression
```

Helper:

```bash
./scripts/install-completions.sh zsh > ~/.zfunc/_vltr
```
