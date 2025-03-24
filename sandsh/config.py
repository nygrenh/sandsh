from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, ClassVar, Protocol, TypeVar, cast, get_args, get_origin

from sandsh.utils import fail, log

try:
    import tomllib
except ImportError:
    fail("Python 3.11+ is required for TOML support.")


CONFIG_FILENAME = ".sandshrc.toml"
GLOBAL_CONFIG_PATH = Path.home() / ".config" / "sandsh" / "config.toml"


# Define a Protocol for dataclass instances
class DataclassProtocol(Protocol):
    # This matches Python's internal dataclass structure
    __dataclass_fields__: ClassVar[dict[str, Any]]


T = TypeVar("T", bound=DataclassProtocol)

# Add near the top with other constants
DEFAULT_BIND_MOUNTS = [
    {"source": "/usr", "dest": "/usr", "mode": "ro"},
    {"source": "/bin", "dest": "/bin", "mode": "ro"},
    {"source": "/lib", "dest": "/lib", "mode": "ro"},
    {"source": "/lib64", "dest": "/lib64", "mode": "ro"},
    {"source": "/etc", "dest": "/etc", "mode": "ro"},
    {"source": "/proc", "dest": "/proc", "mode": "ro"},
    {"source": "/sys", "dest": "/sys", "mode": "ro"},
    {"source": "/var", "dest": "/var", "mode": "ro"},
    {"source": "/run", "dest": "/run", "mode": "ro"},
]

# Replace DEFAULT_CONFIG with separate configs for global and local
DEFAULT_GLOBAL_CONFIG = {
    "profiles": {
        "default": {
            "shell": "/bin/bash",
            "namespaces": {
                "unshare_all": True,
                "network": True,  # Enable network by default
                "user": True,
                "ipc": True,
                "pid": True,
                "uts": True,
                "cgroup": True,
                "disable_userns": False,
            },
            "filesystem": {
                "system_mounts": True,
                "system_ro": True,
                "dev_mounts": ["/dev"],
                "proc_mounts": ["/proc"],
                "tmpfs_mounts": [
                    {"dest": "/tmp", "mode": 0o1777},  # World-writable with sticky bit
                    {"dest": "/run", "mode": 0o755},
                ],
            },
            "environment": {
                "clear_env": True,
                "preserve_vars": ["TERM", "COLORTERM", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"],
                "die_with_parent": True,
            },
            "security": {"seccomp": {"use_tiocsti_protection": True}},
        },
        "restricted": {
            "shell": "/bin/bash",
            "namespaces": {
                "unshare_all": True,
                "network": False,  # Disable network in restricted mode
                "user": True,
                "ipc": True,
                "pid": True,
                "uts": True,
                "cgroup": True,
                "disable_userns": True,
            },
            "filesystem": {
                "system_mounts": True,
                "system_ro": True,
                "dev_mounts": ["/dev"],
                "proc_mounts": ["/proc"],
                "tmpfs_mounts": [
                    {"dest": "/tmp", "mode": 0o1777},
                    {"dest": "/run", "mode": 0o755},
                ],
            },
            "environment": {
                "clear_env": True,
                "preserve_vars": ["TERM", "COLORTERM", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"],
                "die_with_parent": True,
                "new_session": True,  # Better security in restricted mode
            },
            "security": {
                "capabilities": {
                    "drop_all": True  # Drop all capabilities in restricted mode
                },
                "seccomp": {"use_tiocsti_protection": True},
            },
        },
    }
}

DEFAULT_LOCAL_CONFIG = {
    "sandbox": {
        "profile": "default",
        # Other settings can be added here to override the profile
    }
}


@dataclass
class BindMount:
    source: str
    dest: str
    mode: str = "rw"
    create_dest: bool = True

    def __post_init__(self):
        if self.mode not in ("ro", "rw"):
            fail(f"Invalid mode '{self.mode}' for bind mount {self.source} -> {self.dest}")


@dataclass
class TmpfsMount:
    """Configuration for tmpfs mounts"""

    dest: str
    size: int | None = None  # Size in bytes
    mode: int | None = None  # Octal permissions


@dataclass
class OverlayMount:
    """Configuration for overlay mounts"""

    dest: str  # Where to mount the overlay
    sources: list[str] = field(default_factory=list)  # Source directories (overlay-src)
    rw_source: str | None = None  # For writable overlays
    work_dir: str | None = None  # Required for writable overlays
    read_only: bool = False  # Use ro-overlay


@dataclass
class SeccompSyscallRule:
    """Rule for filtering syscalls using seccomp."""

    syscall: str  # Name of the syscall to filter
    action: str = "block"  # "block", "allow", "log", "trace"
    arg_index: int | None = None  # Argument index to check (0-5)
    arg_value: int | None = None  # Value to compare with
    arg_op: str | None = "eq"  # Comparison operation ("eq", "ne", "gt", "lt", etc.)

    def __post_init__(self):
        valid_actions = ["block", "allow", "log", "trace"]
        if self.action not in valid_actions:
            fail(f"Invalid action '{self.action}' in seccomp rule. Valid actions: {valid_actions}")

        if (self.arg_index is not None) != (self.arg_value is not None):
            fail(
                f"Both arg_index and arg_value must be specified together in seccomp rule for {self.syscall}"
            )

        if self.arg_index is not None and not (0 <= self.arg_index <= 5):
            fail(f"arg_index must be between 0 and 5, got {self.arg_index}")


@dataclass
class NamespaceConfig:
    """Configuration for Linux namespaces."""

    unshare_all: bool = False
    user: bool = True
    ipc: bool = True
    pid: bool = True
    network: bool = False  # Default to isolated network
    uts: bool = True
    cgroup: bool = True
    disable_userns: bool = False
    uid: int | None = None
    gid: int | None = None
    hostname: str | None = None


@dataclass
class FilesystemConfig:
    """Configuration for filesystem setup."""

    bind_mounts: list[BindMount] = field(default_factory=list)
    dev_mounts: list[str] = field(default_factory=lambda: ["/dev"])
    proc_mounts: list[str] = field(default_factory=lambda: ["/proc"])
    tmpfs_mounts: list[TmpfsMount] = field(
        default_factory=lambda: [TmpfsMount(dest="/tmp", mode=0o1777)]
    )
    mqueue_mounts: list[str] = field(default_factory=list)
    overlay_mounts: list[OverlayMount] = field(default_factory=list)
    system_mounts: bool = True  # Enable standard system mounts
    system_ro: bool = True  # Mount system directories as read-only


@dataclass
class EnvironmentConfig:
    """Configuration for environment variables and process settings."""

    clear_env: bool = True
    preserve_vars: list[str] = field(
        default_factory=lambda: ["TERM", "COLORTERM", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"]
    )
    set_vars: dict[str, str] = field(default_factory=dict)
    unset_vars: list[str] = field(default_factory=list)
    new_session: bool = False
    die_with_parent: bool = True
    as_pid_1: bool = False


@dataclass
class CapabilityConfig:
    """Configuration for Linux capabilities."""

    add: list[str] = field(default_factory=list)
    drop: list[str] = field(default_factory=list)
    drop_all: bool = False


@dataclass
class SeccompConfig:
    """Configuration for seccomp filters."""

    syscall_rules: list[SeccompSyscallRule] = field(default_factory=list)
    custom_filter_path: str | None = None
    use_tiocsti_protection: bool = True


@dataclass
class SELinuxConfig:
    """Configuration for SELinux contexts."""

    exec_label: str | None = None
    file_label: str | None = None


@dataclass
class SecurityConfig:
    """Configuration for security settings."""

    capabilities: CapabilityConfig = field(default_factory=CapabilityConfig)
    seccomp: SeccompConfig = field(default_factory=SeccompConfig)
    selinux: SELinuxConfig = field(default_factory=SELinuxConfig)


@dataclass
class SandboxConfig:
    """Sandbox configuration with a more logical structure."""

    profile: str | None = None
    shell: str = "/bin/bash"
    namespaces: NamespaceConfig = field(default_factory=NamespaceConfig)
    filesystem: FilesystemConfig = field(default_factory=FilesystemConfig)
    environment: EnvironmentConfig = field(default_factory=EnvironmentConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)


@dataclass
class GlobalConfig:
    """Global configuration that includes default settings and profiles."""

    default_config: SandboxConfig = field(default_factory=SandboxConfig)
    profiles: dict[str, SandboxConfig] = field(default_factory=dict)


@dataclass
class FinalizedSandboxConfig:
    """Configuration with guaranteed non-optional values after merging."""

    # Basic settings
    shell: str  # Shell is required and validated during merging
    profile: str | None = None

    # Configuration objects
    namespaces: NamespaceConfig = field(default_factory=NamespaceConfig)
    filesystem: FilesystemConfig = field(default_factory=FilesystemConfig)
    environment: EnvironmentConfig = field(default_factory=EnvironmentConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)


def parse_dataclass_from_dict(cls: type[T], data: dict[str, Any]) -> T:
    """Parse a dataclass from a dictionary, handling nested dataclasses correctly."""
    kwargs = {}
    for f in fields(cls):
        if f.name not in data:
            continue

        value = data[f.name]
        field_type = f.type

        if isinstance(value, dict) and is_dataclass(field_type):
            if not isinstance(field_type, type):
                field_type = type(field_type)
            kwargs[f.name] = parse_dataclass_from_dict(cast(type[T], field_type), value)
            continue

        if isinstance(value, list):
            origin = get_origin(field_type)
            args = get_args(field_type)

            if origin is list and args and len(args) > 0:
                item_type = args[0]
                if is_dataclass(item_type) and all(isinstance(item, dict) for item in value):
                    parsed_items = []
                    for item in value:
                        if not isinstance(item_type, type):
                            item_type = type(item_type)
                        parsed_items.append(
                            parse_dataclass_from_dict(cast(type[T], item_type), item)
                        )
                    kwargs[f.name] = parsed_items
                    continue

        kwargs[f.name] = value

    return cls(**kwargs)


def load_toml(path: Path) -> dict[str, Any]:
    """Load and parse a TOML file."""
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except Exception as e:
        fail(f"Failed to parse {path.name}: {e}")


def load_local_config(project_dir: Path) -> SandboxConfig | None:
    """Load local sandbox configuration from the project directory or any parent directory.

    Returns None if no config file is found.
    """
    # Start with the project directory
    current_dir = project_dir

    # Check the current directory and all parent directories
    while True:
        path = current_dir / CONFIG_FILENAME
        if path.exists():
            log(f"Found local config at {path}")
            raw = load_toml(path)
            # Extract the sandbox section
            sandbox_config = raw.get("sandbox", {})
            return parse_dataclass_from_dict(SandboxConfig, sandbox_config)

        # Move to parent directory
        parent_dir = current_dir.parent

        # Stop if we've reached the filesystem root
        if parent_dir == current_dir:
            break

        current_dir = parent_dir

    # No config file found in the directory hierarchy
    return None


def load_global_config() -> GlobalConfig:
    """Load the global configuration with profiles."""
    if not GLOBAL_CONFIG_PATH.exists():
        log("No global config found. Using defaults.")
        return GlobalConfig(
            profiles={
                "default": parse_dataclass_from_dict(
                    SandboxConfig, DEFAULT_GLOBAL_CONFIG["profiles"]["default"]
                ),
                "restricted": parse_dataclass_from_dict(
                    SandboxConfig, DEFAULT_GLOBAL_CONFIG["profiles"]["restricted"]
                ),
            }
        )

    raw = load_toml(GLOBAL_CONFIG_PATH)
    global_config = GlobalConfig()

    # Parse profile configurations
    for name, conf in raw.get("profiles", {}).items():
        global_config.profiles[name] = parse_dataclass_from_dict(SandboxConfig, conf)

    if not global_config.profiles:
        fail("Global config must contain at least one profile")

    log(f"Loaded global config from {GLOBAL_CONFIG_PATH}")
    return global_config


def finalize_config(config: SandboxConfig) -> FinalizedSandboxConfig:
    """Convert a merged SandboxConfig to a FinalizedSandboxConfig."""
    if not config.shell:
        fail("Shell must be specified in the configuration")

    return FinalizedSandboxConfig(
        # Basic settings
        shell=config.shell,
        profile=config.profile,
        # Configuration objects
        namespaces=config.namespaces,
        filesystem=config.filesystem,
        environment=config.environment,
        security=config.security,
    )


def merge_configs(local: SandboxConfig, global_conf: GlobalConfig) -> FinalizedSandboxConfig:
    """Merge configurations with precedence: local > profile."""
    profile_name = local.profile or "default"

    if profile_name not in global_conf.profiles:
        fail(f"Profile '{profile_name}' not found in global config.")

    # Start with the specified profile
    profile = global_conf.profiles[profile_name]
    merged = SandboxConfig(
        profile=profile_name,
        shell=local.shell or profile.shell,
        namespaces=NamespaceConfig(
            **{
                f.name: getattr(local.namespaces, f.name) or getattr(profile.namespaces, f.name)
                for f in fields(NamespaceConfig)
            }
        ),
        filesystem=FilesystemConfig(
            **{
                f.name: getattr(local.filesystem, f.name) or getattr(profile.filesystem, f.name)
                for f in fields(FilesystemConfig)
            }
        ),
        environment=EnvironmentConfig(
            **{
                f.name: getattr(local.environment, f.name) or getattr(profile.environment, f.name)
                for f in fields(EnvironmentConfig)
            }
        ),
        security=SecurityConfig(
            capabilities=CapabilityConfig(
                **{
                    f.name: getattr(local.security.capabilities, f.name)
                    or getattr(profile.security.capabilities, f.name)
                    for f in fields(CapabilityConfig)
                }
            ),
            seccomp=SeccompConfig(
                **{
                    f.name: getattr(local.security.seccomp, f.name)
                    or getattr(profile.security.seccomp, f.name)
                    for f in fields(SeccompConfig)
                }
            ),
            selinux=SELinuxConfig(
                **{
                    f.name: getattr(local.security.selinux, f.name)
                    or getattr(profile.security.selinux, f.name)
                    for f in fields(SELinuxConfig)
                }
            ),
        ),
    )

    # Special handling for list and dict fields
    # Filesystem lists
    merged.filesystem.bind_mounts.extend(local.filesystem.bind_mounts)
    merged.filesystem.dev_mounts.extend(local.filesystem.dev_mounts)
    merged.filesystem.proc_mounts.extend(local.filesystem.proc_mounts)
    merged.filesystem.tmpfs_mounts.extend(local.filesystem.tmpfs_mounts)
    merged.filesystem.mqueue_mounts.extend(local.filesystem.mqueue_mounts)
    merged.filesystem.overlay_mounts.extend(local.filesystem.overlay_mounts)

    # Environment variables
    merged.environment.set_vars.update(local.environment.set_vars)
    merged.environment.unset_vars.extend(local.environment.unset_vars)
    merged.environment.preserve_vars.extend(local.environment.preserve_vars)

    # Security lists
    merged.security.capabilities.add.extend(local.security.capabilities.add)
    merged.security.capabilities.drop.extend(local.security.capabilities.drop)
    merged.security.seccomp.syscall_rules.extend(local.security.seccomp.syscall_rules)

    return finalize_config(merged)


def write_default_config(path: Path) -> None:
    """Write the default configuration to the specified path."""
    if path.exists():
        fail(f"Config file already exists at {path}")

    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        from sandsh import toml

        # Use different default configs for global and local
        is_global = path == GLOBAL_CONFIG_PATH
        default_config = DEFAULT_GLOBAL_CONFIG if is_global else DEFAULT_LOCAL_CONFIG

        path.write_text(toml.dumps(default_config))
        log(f"Created {'global' if is_global else 'local'} config at {path}")
    except Exception as e:
        fail(f"Failed to write config file: {e}")
