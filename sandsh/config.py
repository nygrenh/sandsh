from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, ClassVar, Protocol, TypeVar

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
            "bind_mounts": DEFAULT_BIND_MOUNTS,
            "network_enabled": True,
            "clear_env": True,
            "die_with_parent": True,
            "disable_userns": True,
            "unshare_cgroup": True,
            "use_tiocsti_protection": True,
        },
        "restricted": {
            "shell": "/bin/bash",
            "network_enabled": False,
            "new_session": True,
            "bind_mounts": [
                # Minimal set of bind mounts for basic functionality
                {"source": "/usr", "dest": "/usr", "mode": "ro"},
                {"source": "/bin", "dest": "/bin", "mode": "ro"},
                {"source": "/lib", "dest": "/lib", "mode": "ro"},
                {"source": "/lib64", "dest": "/lib64", "mode": "ro"},
            ],
            "clear_env": True,
            "die_with_parent": True,
            "disable_userns": True,
            "unshare_cgroup": True,
            "use_tiocsti_protection": True,
        },
    }
}

DEFAULT_LOCAL_CONFIG = {"profile": "default"}


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
class SeccompSyscallRule:
    """Rule for filtering syscalls using seccomp.

    Examples:
        Block a syscall completely:
            { syscall = "unshare" }

        Block mkdir with specific permissions:
            { syscall = "mkdir", arg_index = 1, arg_value = 0o777 }

        Log all uses of a syscall:
            { syscall = "execve", action = "log" }
    """

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
class SandboxConfig:
    """Core configuration class for sandbox settings.

    All fields are optional with sensible defaults. The shell field is the only one
    that must be set before the sandbox is created, but this is validated at merge time.
    """

    profile: str | None = None
    shell: str | None = None
    bind_mounts: list[BindMount] = field(default_factory=list)
    new_session: bool = False  # Set to true for better security but may have TTY issues
    die_with_parent: bool = True  # Kill sandbox when parent process dies
    network_enabled: bool = True  # By default we enable network
    disable_userns: bool = True  # Prevent creation of new user namespaces (security)
    clear_env: bool = True  # Start with clean environment
    sandbox_uid: int | None = None  # Custom UID in sandbox (None = keep current)
    sandbox_gid: int | None = None  # Custom GID in sandbox (None = keep current)
    hostname: str | None = None  # Custom hostname in sandbox
    unshare_cgroup: bool = True  # Use cgroup namespace isolation
    use_tiocsti_protection: bool = True  # Whether to protect against TIOCSTI
    seccomp_syscall_rules: list[SeccompSyscallRule] = field(
        default_factory=list
    )  # Rules for filtering syscalls
    custom_seccomp_filter: str | None = None  # Path to a pre-compiled seccomp BPF filter file


@dataclass
class GlobalConfig:
    """Global configuration that includes default settings and profiles.

    The default_config contains settings that apply to all sandboxes when not overridden.
    The profiles contains named configurations that can be referenced by local configs.
    """

    default_config: SandboxConfig = field(default_factory=SandboxConfig)
    profiles: dict[str, SandboxConfig] = field(default_factory=dict)


@dataclass
class FinalizedSandboxConfig:
    """Configuration with guaranteed non-optional values after merging."""

    shell: str  # Shell is required and validated during merging
    profile: str | None = None  # Profile remains optional
    bind_mounts: list[BindMount] = field(default_factory=list)
    new_session: bool = False
    die_with_parent: bool = True
    network_enabled: bool = True
    disable_userns: bool = True
    clear_env: bool = True
    sandbox_uid: int | None = None
    sandbox_gid: int | None = None
    hostname: str | None = None
    unshare_cgroup: bool = True
    use_tiocsti_protection: bool = True
    seccomp_syscall_rules: list[SeccompSyscallRule] = field(default_factory=list)
    custom_seccomp_filter: str | None = None
    seccomp_filter_path: str | None = None  # Add this field
    seccomp_rules: list[SeccompSyscallRule] = field(default_factory=list)  # Add this field


def parse_dataclass_from_dict(cls: type[T], data: dict[str, Any]) -> T:
    """Parse a dataclass from a dictionary, handling nested dataclasses correctly."""
    if not is_dataclass(cls):
        raise TypeError(f"Expected dataclass, got {cls}")

    kwargs = {}
    for f in fields(cls):
        if f.name not in data:
            continue

        value = data[f.name]

        # Handle nested dataclasses like BindMount
        if f.name == "bind_mounts" and isinstance(value, list):
            kwargs[f.name] = [BindMount(**item) for item in value]
        elif f.name == "seccomp_syscall_rules" and isinstance(value, list):
            kwargs[f.name] = [SeccompSyscallRule(**item) for item in value]
        else:
            kwargs[f.name] = value

    return cls(**kwargs)  # Remove cast since T is properly bound now


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
    # until we find a config file or reach the filesystem root
    while True:
        path = current_dir / CONFIG_FILENAME
        if path.exists():
            log(f"Found local config at {path}")
            raw = load_toml(path)
            return parse_dataclass_from_dict(SandboxConfig, raw)

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
    """Convert a merged SandboxConfig to a FinalizedSandboxConfig.

    This function performs runtime validation to ensure all required
    fields are present, then converts to the finalized type.
    """
    if config.shell is None:
        fail("Shell must be specified in the configuration")

    return FinalizedSandboxConfig(
        shell=config.shell,  # We know this is not None due to validation
        profile=config.profile,
        bind_mounts=config.bind_mounts,
        new_session=config.new_session,
        die_with_parent=config.die_with_parent,
        network_enabled=config.network_enabled,
        disable_userns=config.disable_userns,
        clear_env=config.clear_env,
        sandbox_uid=config.sandbox_uid,
        sandbox_gid=config.sandbox_gid,
        hostname=config.hostname,
        unshare_cgroup=config.unshare_cgroup,
        use_tiocsti_protection=config.use_tiocsti_protection,
        seccomp_syscall_rules=config.seccomp_syscall_rules,
        custom_seccomp_filter=config.custom_seccomp_filter,
    )


def merge_configs(local: SandboxConfig, global_conf: GlobalConfig) -> FinalizedSandboxConfig:
    """Merge configurations with precedence: local > profile.

    Returns a fully merged FinalizedSandboxConfig with all necessary settings for running a sandbox.
    """
    # Start with the default profile if no profile is specified
    profile_name = local.profile or "default"

    # Check if the profile exists
    if profile_name not in global_conf.profiles:
        fail(f"Profile '{profile_name}' not found in global config.")

    # Start with the specified profile
    profile = global_conf.profiles[profile_name]
    merged = SandboxConfig(**{f.name: getattr(profile, f.name) for f in fields(profile)})
    merged.profile = profile_name

    # Apply local settings, only if they're not the default values
    for f in fields(local):
        if f.name == "profile":
            continue  # We've already handled the profile

        value = getattr(local, f.name)
        default_value = getattr(SandboxConfig(), f.name)

        # Skip field if it's a default value (not explicitly set in local config)
        if value != default_value:
            if f.name == "bind_mounts":
                # Special handling for bind_mounts: we append rather than replace
                setattr(merged, f.name, getattr(merged, f.name) + value)
            elif f.name == "seccomp_syscall_rules":
                # Special handling for seccomp rules: append rather than replace
                setattr(merged, f.name, getattr(merged, f.name) + value)
            else:
                setattr(merged, f.name, value)

    # Validate required fields
    if not merged.shell:
        fail("No shell specified in profile or local config.")

    # Convert to finalized config with non-optional fields
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
