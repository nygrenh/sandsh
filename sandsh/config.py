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


@dataclass
class GlobalConfig:
    shell: str | None = None
    profiles: dict[str, SandboxConfig] = field(default_factory=dict)


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


def merge_configs(local: SandboxConfig, global_conf: GlobalConfig) -> SandboxConfig:
    if local.profile:
        profile = global_conf.profiles.get(local.profile)
        if not profile:
            fail(f"Profile '{local.profile}' not found in global config.")
        shell = local.shell or (profile and profile.shell) or global_conf.shell
        if not shell:
            fail("No shell specified in local, profile, or global config.")
        return SandboxConfig(
            profile=local.profile,
            bind_mounts=(profile.bind_mounts if profile else []) + local.bind_mounts,
            shell=shell,
        )
    if not local.shell:
        local.shell = global_conf.shell
    return local
