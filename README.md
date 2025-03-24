# sandsh

**sandsh** launches folder-specific sandboxed shells using [bubblewrap](https://github.com/containers/bubblewrap). Each sandbox has its own home folder, and you can configure which files and folders are mounted inside the sandbox, and whether they are read-only or writable.

## Features

- Profile-based configuration system
- Global config (`~/.config/sandsh/config.toml`) defines sandbox profiles
- Local config (`.sandshrc.toml`) specifies which profile to use and any overrides
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

2. Then, in your project directory, create a local config:

   ```bash
   sandsh init
   ```

3. Now you can launch a sandboxed shell:
   ```bash
   sandsh
   ```

## Configuration

### Configuration Structure

The configuration system uses two types of files:

1. **Global Config** (`~/.config/sandsh/config.toml`):
   Defines profiles with complete sandbox configurations. Example:

   ```toml
   [profiles.default]
   shell = "/bin/bash"

   [profiles.default.namespaces]
   unshare_all = true
   network = true  # Enable network access
   disable_userns = false

   [profiles.default.filesystem]
   system_mounts = true  # Enable standard system mounts
   system_ro = true      # Mount system directories as read-only

   [[profiles.default.filesystem.bind_mounts]]
   source = "/home/user/projects"
   dest = "/projects"
   mode = "rw"

   [profiles.default.environment]
   clear_env = true
   preserve_vars = ["TERM", "DISPLAY", "HOME"]
   die_with_parent = true

   [profiles.default.security]
   [profiles.default.security.capabilities]
   drop_all = false
   add = ["CAP_NET_BIND_SERVICE"]

   [profiles.restricted]
   shell = "/bin/bash"

   [profiles.restricted.namespaces]
   unshare_all = true
   network = false  # Disable network access
   disable_userns = true

   [profiles.restricted.filesystem]
   system_mounts = true
   system_ro = true

   [profiles.restricted.environment]
   clear_env = true
   new_session = true  # Better security

   [profiles.restricted.security.capabilities]
   drop_all = true  # Drop all capabilities
   ```

2. **Local Config** (`.sandshrc.toml`):
   Selects a profile and optionally overrides specific settings. Example:

   ```toml
   [sandbox]
   profile = "default"

   # Optional overrides:
   [sandbox.namespaces]
   network = false  # Disable network for this project

   [sandbox.filesystem]
   [[sandbox.filesystem.bind_mounts]]
   source = "./data"
   dest = "/data"
   mode = "ro"

   [sandbox.environment]
   set_vars = { DEBUG = "1" }
   ```

### Configuration Sections

- **namespaces**: Control Linux namespace isolation

  - `unshare_all`: Enable all namespace isolation
  - `network`, `user`, `ipc`, `pid`, `uts`, `cgroup`: Individual namespace controls
  - `uid`, `gid`: Custom user/group IDs
  - `hostname`: Custom hostname

- **filesystem**: Configure filesystem mounts

  - `system_mounts`: Enable standard system mounts
  - `system_ro`: Mount system directories as read-only
  - `bind_mounts`: List of bind mounts
  - `dev_mounts`, `proc_mounts`: Special filesystem mounts
  - `tmpfs_mounts`: Temporary filesystems
  - `overlay_mounts`: Overlay filesystem configurations

- **environment**: Environment and process settings

  - `clear_env`: Start with clean environment
  - `preserve_vars`: Environment variables to preserve
  - `set_vars`: Variables to set
  - `unset_vars`: Variables to unset
  - `new_session`, `die_with_parent`, `as_pid_1`: Process control options

- **security**: Security settings
  - `capabilities`: Linux capabilities configuration
  - `seccomp`: System call filtering
  - `selinux`: SELinux context settings

## Usage

```bash
sandsh           # Launch sandboxed shell using nearest .sandshrc.toml
sandsh --dry-run # Preview sandbox config
sandsh init      # Create local config
sandsh init --force # Force create/overwrite config
sandsh init --global # Create global config
```
