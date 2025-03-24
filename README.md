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
    network = true
    user = true
    ipc = true
    pid = true
    uts = true
    cgroup = true
    disable_userns = false

    [profiles.default.filesystem]
    dev_mounts = ["/dev"]
    proc_mounts = ["/proc"]
    bind_mounts = [
        { source = "/usr", dest = "/usr", mode = "ro" },
        { source = "/bin", dest = "/bin", mode = "ro" },
        { source = "/lib", dest = "/lib", mode = "ro" },
        { source = "/lib64", dest = "/lib64", mode = "ro" },
        { source = "/etc", dest = "/etc", mode = "ro" },
    ]
    tmpfs_mounts = [
        { dest = "/tmp", mode = 0o1777 },
        { dest = "/run", mode = 0o755 },
    ]

    [profiles.default.environment]
    clear_env = true
    preserve_vars = ["TERM", "COLORTERM", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"]
    die_with_parent = true

    [profiles.default.security.seccomp]
    use_tiocsti_protection = true
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
   bind_mounts = [{ source = "./data", dest = "/data", mode = "ro" }]

   [sandbox.environment]
   set_vars = { DEBUG = "1" }
   ```

### Configuration Options

#### Basic Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `shell` | string | `/bin/bash` | Shell to launch in the sandbox |
| `profile` | string | `default` | Profile name to use from global config |

#### Namespace Options (`namespaces` section)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `unshare_all` | bool | `true` | Enable all namespace isolation |
| `user` | bool | `true` | Enable user namespace |
| `user_try` | bool | `false` | Try to enable user namespace |
| `ipc` | bool | `true` | Enable IPC namespace |
| `pid` | bool | `true` | Enable PID namespace |
| `network` | bool | `false` | Enable network namespace |
| `uts` | bool | `true` | Enable UTS namespace |
| `cgroup` | bool | `true` | Enable cgroup namespace |
| `cgroup_try` | bool | `false` | Try to enable cgroup namespace |
| `disable_userns` | bool | `false` | Disable user namespace support |
| `share_net` | bool | `false` | Share network when unshare_all is true |
| `uid` | int | `null` | Custom UID in the sandbox |
| `gid` | int | `null` | Custom GID in the sandbox |
| `hostname` | string | `null` | Custom hostname in the sandbox |

#### Filesystem Options (`filesystem` section)

| Option | Type | Description |
|--------|------|-------------|
| `bind_mounts` | list | List of bind mount configurations |
| `dev_mounts` | list | List of device mount points |
| `proc_mounts` | list | List of procfs mount points |
| `tmpfs_mounts` | list | List of tmpfs mount configurations |
| `mqueue_mounts` | list | List of message queue mount points |
| `overlay_mounts` | list | List of overlay mount configurations |
| `remount_ro` | list | Paths to remount as read-only |

##### Bind Mount Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `source` | string | - | Source path to mount |
| `dest` | string | - | Destination path in sandbox |
| `mode` | string | `"rw"` | Mount mode (`"ro"` or `"rw"`) |
| `create_dest` | bool | `true` | Create destination directory if missing |

##### Tmpfs Mount Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `dest` | string | - | Mount point in sandbox |
| `size` | int | `null` | Size in bytes |
| `mode` | int | `null` | Permission mode (octal) |

#### Environment Options (`environment` section)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `clear_env` | bool | `true` | Start with clean environment |
| `preserve_vars` | list | `[]` | Environment variables to preserve |
| `set_vars` | dict | `{}` | Variables to set |
| `unset_vars` | list | `[]` | Variables to unset |
| `new_session` | bool | `false` | Create new terminal session |
| `die_with_parent` | bool | `true` | Kill sandbox when parent dies |
| `as_pid_1` | bool | `false` | Run shell as PID 1 |

#### Security Options (`security` section)

##### Capabilities (`security.capabilities`)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `drop_all` | bool | `false` | Drop all capabilities |
| `add` | list | `[]` | Capabilities to add |
| `drop` | list | `[]` | Capabilities to drop |

##### Seccomp (`security.seccomp`)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `use_tiocsti_protection` | bool | `true` | Enable TIOCSTI protection |
| `syscall_rules` | list | `[]` | Syscall filtering rules |
| `custom_filter_path` | string | `null` | Path to custom seccomp filter |

##### SELinux (`security.selinux`)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `exec_label` | string | `null` | SELinux exec context |
| `file_label` | string | `null` | SELinux file context |

## Usage

```bash
sandsh           # Launch sandboxed shell using nearest .sandshrc.toml
sandsh --dry-run # Preview sandbox config
sandsh init      # Create local config
sandsh init --force # Force create/overwrite config
sandsh init --global # Create global config
```
