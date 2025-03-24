from dataclasses import dataclass, field
from pathlib import Path

from sandsh.utils import fail, log

try:
    import tomllib
except ImportError:
    fail("Python 3.11+ is required for TOML support.")


CONFIG_FILENAME = ".sandshrc.toml"
GLOBAL_CONFIG_PATH = Path.home() / ".config" / "sandsh" / "config.toml"


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
class SandboxConfig:
    profile: str | None = None
    shell: str | None = None
    bind_mounts: list[BindMount] = field(default_factory=list)
    new_session: bool = False  # Default to false to avoid TTY issues
    die_with_parent: bool = True  # Kill sandbox when parent process dies
    network_enabled: bool = True  # By default we enable network
    disable_userns: bool = True  # Prevent creation of new user namespaces (security)
    clear_env: bool = True  # Start with clean environment
    sandbox_uid: int | None = None  # Custom UID in sandbox (None = keep current)
    sandbox_gid: int | None = None  # Custom GID in sandbox (None = keep current)
    hostname: str | None = None  # Custom hostname in sandbox
    unshare_cgroup: bool = True  # Use cgroup namespace isolation
    use_tiocsti_protection: bool = True  # Whether to protect against TIOCSTI


@dataclass
class GlobalConfig:
    shell: str | None = None
    profiles: dict[str, SandboxConfig] = field(default_factory=dict)


@dataclass
class MergedSandboxConfig:
    """Configuration with guaranteed non-optional values after merging."""

    shell: str
    profile: str | None = None
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


def load_toml(path: Path) -> dict:
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except Exception as e:
        fail(f"Failed to parse {path.name}: {e}")


def load_local_config(project_dir: Path) -> SandboxConfig:
    path = project_dir / CONFIG_FILENAME
    if not path.exists():
        log(f"No local config found at {CONFIG_FILENAME}. Using defaults.")
        return SandboxConfig()
    raw = load_toml(path)
    if "bind_mounts" in raw:
        raw["bind_mounts"] = [BindMount(**bm) for bm in raw["bind_mounts"]]
    log(f"Loaded local config from {path}")
    return SandboxConfig(**raw)


def load_global_config() -> GlobalConfig:
    if not GLOBAL_CONFIG_PATH.exists():
        log("No global config found. Using defaults.")
        return GlobalConfig()
    raw = load_toml(GLOBAL_CONFIG_PATH)
    profiles = {}
    for name, conf in raw.get("profiles", {}).items():
        if "bind_mounts" in conf:
            conf["bind_mounts"] = [BindMount(**bm) for bm in conf["bind_mounts"]]
        profiles[name] = SandboxConfig(**conf)
    log(f"Loaded global config from {GLOBAL_CONFIG_PATH}")
    return GlobalConfig(shell=raw.get("shell"), profiles=profiles)


def merge_configs(local: SandboxConfig, global_conf: GlobalConfig) -> MergedSandboxConfig:
    if local.profile:
        profile = global_conf.profiles.get(local.profile)
        if not profile:
            fail(f"Profile '{local.profile}' not found in global config.")
        shell = local.shell or (profile and profile.shell) or global_conf.shell
        if not shell:
            fail("No shell specified in local, profile, or global config.")
        return MergedSandboxConfig(
            profile=local.profile,
            bind_mounts=(profile.bind_mounts if profile else []) + local.bind_mounts,
            shell=shell,
            new_session=local.new_session,
            die_with_parent=local.die_with_parent,
            network_enabled=local.network_enabled,
            disable_userns=local.disable_userns,
            clear_env=local.clear_env,
            sandbox_uid=local.sandbox_uid,
            sandbox_gid=local.sandbox_gid,
            hostname=local.hostname,
            unshare_cgroup=local.unshare_cgroup,
            use_tiocsti_protection=local.use_tiocsti_protection,
        )

    shell = local.shell or global_conf.shell
    if not shell:
        fail("No shell specified in local or global config.")

    return MergedSandboxConfig(
        shell=shell,
        bind_mounts=local.bind_mounts,
        new_session=local.new_session,
        die_with_parent=local.die_with_parent,
        network_enabled=local.network_enabled,
        disable_userns=local.disable_userns,
        clear_env=local.clear_env,
        sandbox_uid=local.sandbox_uid,
        sandbox_gid=local.sandbox_gid,
        hostname=local.hostname,
        unshare_cgroup=local.unshare_cgroup,
        use_tiocsti_protection=local.use_tiocsti_protection,
    )
