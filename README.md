# sandsh

**sandsh** launches folder-specific sandboxed shells using [bubblewrap](https://github.com/containers/bubblewrap). Each sandbox has its own home folder, and you can configure which files and folders are mounted inside the sandbox, and whether they are read-only or writable.

## Features

- Profile-based configuration system
- Global config (`~/.config/sandsh/config.toml`) defines sandbox profiles
- Local config (`.sandshrc.toml`) specifies which profile to use
- Read-only / writable bind mounts
- No external dependencies (Python 3.11+)

## Installation

```bash
pipx install .
```

## Getting Started

1. First, create a global config file with default profiles:

   ```bash
   sandsh init --global
   ```

2. Then, in your project directory, create a local config to select which profile to use:

   ```bash
   sandsh init
   ```

3. Now you can launch a sandboxed shell:
   ```bash
   sandsh
   ```

## Development Setup

After cloning the repository:

```bash
uv run pre-commit install  # Install pre-commit hooks
```

## Configuration

### Initialize Configuration Files

Create a global config with default profiles:

```bash
sandsh init --global
```

Create a project-specific config (selects which profile to use):

```bash
sandsh init
```

Use `--force` or `-f` to overwrite existing config files:

```bash
sandsh init --global -f  # Overwrite global config
```

### Configuration Structure

The configuration system uses two types of files:

1. **Global Config** (`~/.config/sandsh/config.toml`):

   - Defines all available sandbox profiles
   - Contains complete settings for each profile
   - Example:

   ```toml
   [profiles.default]
   shell = "/bin/bash"
   network_enabled = true
   bind_mounts = [
     { source = "/usr", dest = "/usr", mode = "ro" },
     # ... other system mounts ...
   ]

   [profiles.restricted]
   shell = "/bin/bash"
   network_enabled = false
   new_session = true
   bind_mounts = [
     # Minimal set of bind mounts
     { source = "/usr", dest = "/usr", mode = "ro" },
     { source = "/bin", dest = "/bin", mode = "ro" },
     { source = "/lib", dest = "/lib", mode = "ro" },
     { source = "/lib64", dest = "/lib64", mode = "ro" },
   ]
   ```

2. **Local Config** (`.sandshrc.toml`):
   - Specifies which profile to use
   - Simple configuration file
   - Example:
   ```toml
   profile = "default"
   ```

sandsh will look for a `.sandshrc.toml` file in the current directory and parent directories until one is found.

## Usage

```bash
sandsh           # Launch sandboxed shell using nearest .sandshrc.toml
sandsh --dry-run # Preview sandbox config
```
