# sandsh

**sandsh** launches folder-specific sandboxed shells using [bubblewrap](https://github.com/containers/bubblewrap). Each sandbox has its own home folder, and you can configure which files and folders are mounted inside the sandbox, and whether they are read-only or writable.

## Features

- Folder-specific config (`.sandshrc.toml`)
- Global config (`~/.config/sandsh/config.toml`)
- Read-only / writable bind mounts
- No external dependencies (Python 3.11+)

## Installation

```bash
pipx install .
```

## Development Setup

After cloning the repository:

```bash
uv run pre-commit install  # Install pre-commit hooks
```

## Usage

```bash
sandsh           # Launch sandboxed shell
sandsh --dry-run # Preview sandbox config
```

## Example `.sandshrc.toml`

```toml
profile = "python-dev"

bind_mounts = [
  { source = "./data", dest = "/data", mode = "rw" }
]

shell = "/usr/bin/fish"
```
