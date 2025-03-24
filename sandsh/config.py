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

DEFAULT_GLOBAL_CONFIG = """
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

# ---------------------------

[profiles.restricted]
shell = "/bin/bash"

[profiles.restricted.namespaces]
unshare_all = true
network = false
user = true
ipc = true
pid = true
uts = true
cgroup = true
disable_userns = true

[profiles.restricted.filesystem]
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

[profiles.restricted.environment]
clear_env = true
preserve_vars = ["TERM", "COLORTERM", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"]
die_with_parent = true
new_session = true

[profiles.restricted.security]
capabilities.drop_all = true
seccomp.use_tiocsti_protection = true
"""

DEFAULT_LOCAL_CONFIG = """
[sandbox]
profile = "default"
"""


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
    network: bool = False
    uts: bool = True
    cgroup: bool = True
    disable_userns: bool = False
    uid: int | None = None
    gid: int | None = None
    hostname: str | None = None
    user_try: bool = False
    cgroup_try: bool = False
    share_net: bool = False
    userns_fd: int | None = None
    userns2_fd: int | None = None
    pidns_fd: int | None = None
    assert_userns_disabled: bool = False


@dataclass
class ProcessConfig:
    """Configuration for process-related settings."""

    argv0: str | None = None
    lock_files: list[str] = field(default_factory=list)
    sync_fd: int | None = None
    info_fd: int | None = None
    json_status_fd: int | None = None
    block_fd: int | None = None
    userns_block_fd: int | None = None
    level_prefix: bool = False
    args_fds: list[int] = field(default_factory=list)


@dataclass
class FileEntry:
    """Configuration for file creation and manipulation."""

    dest: str
    source_fd: int | None = None  # For file, bind-data, and ro-bind-data operations
    source_path: str | None = None  # For symlink target
    mode: int | None = None  # File permissions
    type: str = "file"  # file, dir, symlink, bind-data, ro-bind-data

    def __post_init__(self):
        valid_types = ["file", "dir", "symlink", "bind-data", "ro-bind-data"]
        if self.type not in valid_types:
            fail(f"Invalid file entry type '{self.type}'. Valid types: {valid_types}")

        if self.type in ["file", "bind-data", "ro-bind-data"] and self.source_fd is None:
            fail(f"source_fd is required for type '{self.type}'")

        if self.type == "symlink" and self.source_path is None:
            fail("source_path (target) is required for symlinks")


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
    remount_ro: list[str] = field(default_factory=list)
    chmod_entries: list[tuple[str, int]] = field(default_factory=list)
    file_entries: list[FileEntry] = field(default_factory=list)
    bind_try: list[BindMount] = field(default_factory=list)
    dev_bind_try: list[BindMount] = field(default_factory=list)
    ro_bind_try: list[BindMount] = field(default_factory=list)
    next_perms: int | None = None  # Affects next filesystem operation
    next_size: int | None = None  # Affects next tmpfs mount


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
    # New field
    additional_filter_fds: list[int] = field(default_factory=list)  # --add-seccomp-fd


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
    shell: str | None = None
    namespaces: NamespaceConfig = field(default_factory=NamespaceConfig)
    filesystem: FilesystemConfig = field(default_factory=FilesystemConfig)
    environment: EnvironmentConfig = field(default_factory=EnvironmentConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    process: ProcessConfig = field(default_factory=ProcessConfig)


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
    process: ProcessConfig = field(default_factory=ProcessConfig)


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


def load_local_config(project_dir: Path) -> SandboxConfig:
    """Load local sandbox configuration from the project directory or any parent directory.

    Returns None if no config file is found.
    """
    # Start with the project directory
    current_dir = project_dir

    # Check the current directory and all parent directories
    while True:
        path = current_dir / CONFIG_FILENAME
        if path.exists():
            raw = load_toml(path)
            # Extract the sandbox section
            sandbox_config = raw.get("sandbox", {})
            return parse_dataclass_from_dict(SandboxConfig, sandbox_config)

        parent_dir = current_dir.parent

        if parent_dir == current_dir:
            break

        current_dir = parent_dir

    fail(
        f"No {CONFIG_FILENAME} found in current directory or any parent directory.\n"
        f"Initialize a configuration file with 'sandsh init'."
    )


def load_global_config() -> GlobalConfig:
    """Load the global configuration with profiles."""
    if not GLOBAL_CONFIG_PATH.exists():
        fail("Global config not found. Please run 'sandsh init --global' to create one.")

    raw = load_toml(GLOBAL_CONFIG_PATH)
    global_config = GlobalConfig()

    for name, conf in raw.get("profiles", {}).items():
        global_config.profiles[name] = parse_dataclass_from_dict(SandboxConfig, conf)

    if not global_config.profiles:
        fail("Global config must contain at least one profile")

    return global_config


def finalize_config(config: SandboxConfig) -> FinalizedSandboxConfig:
    """Convert a merged SandboxConfig to a FinalizedSandboxConfig."""
    if not config.shell:
        fail("Shell must be specified in the configuration")

    return FinalizedSandboxConfig(
        shell=config.shell,
        profile=config.profile,
        namespaces=config.namespaces,
        filesystem=config.filesystem,
        environment=config.environment,
        security=config.security,
        process=config.process,
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
        shell=local.shell if local.shell is not None else profile.shell,
        namespaces=NamespaceConfig(
            **{
                f.name: (
                    getattr(local.namespaces, f.name)
                    if getattr(local.namespaces, f.name) is not None
                    else getattr(profile.namespaces, f.name)
                )
                for f in fields(NamespaceConfig)
            }
        ),
        filesystem=FilesystemConfig(
            **{
                f.name: (
                    getattr(local.filesystem, f.name)
                    if getattr(local.filesystem, f.name) is not None
                    else getattr(profile.filesystem, f.name)
                )
                for f in fields(FilesystemConfig)
            }
        ),
        environment=EnvironmentConfig(
            **{
                f.name: (
                    getattr(local.environment, f.name)
                    if getattr(local.environment, f.name) is not None
                    else getattr(profile.environment, f.name)
                )
                for f in fields(EnvironmentConfig)
            }
        ),
        security=SecurityConfig(
            capabilities=CapabilityConfig(
                **{
                    f.name: (
                        getattr(local.security.capabilities, f.name)
                        if getattr(local.security.capabilities, f.name) is not None
                        else getattr(profile.security.capabilities, f.name)
                    )
                    for f in fields(CapabilityConfig)
                }
            ),
            seccomp=SeccompConfig(
                **{
                    f.name: (
                        getattr(local.security.seccomp, f.name)
                        if getattr(local.security.seccomp, f.name) is not None
                        else getattr(profile.security.seccomp, f.name)
                    )
                    for f in fields(SeccompConfig)
                }
            ),
            selinux=SELinuxConfig(
                **{
                    f.name: (
                        getattr(local.security.selinux, f.name)
                        if getattr(local.security.selinux, f.name) is not None
                        else getattr(profile.security.selinux, f.name)
                    )
                    for f in fields(SELinuxConfig)
                }
            ),
        ),
        process=ProcessConfig(
            **{
                f.name: (
                    getattr(local.process, f.name)
                    if getattr(local.process, f.name) is not None
                    else getattr(profile.process, f.name)
                )
                for f in fields(ProcessConfig)
            }
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

    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        is_global = path == GLOBAL_CONFIG_PATH
        config_str = DEFAULT_GLOBAL_CONFIG if is_global else DEFAULT_LOCAL_CONFIG

        path.write_text(config_str.lstrip())
        log(f"Created {'global' if is_global else 'local'} config at {path}")
    except Exception as e:
        fail(f"Failed to write config file: {e}")
