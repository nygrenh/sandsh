import hashlib
import os
from pathlib import Path

from sandsh.config import MergedSandboxConfig
from sandsh.utils import log


def build_bind_args(
    config: MergedSandboxConfig, project_dir: Path, sandbox_home: Path
) -> list[str]:
    bind_args: list[str] = []

    # We always need to bind the project directory itself, otherwise we can't chdir to it
    bind_args += ["--bind", str(project_dir), str(project_dir)]

    # Add essential system directories as read-only mounts
    essential_dirs = [
        "/usr",
        "/bin",
        "/lib",
        "/lib64",
        "/etc",
        "/proc",
        "/sys",
        "/var",
        "/run",
    ]

    for dir_path in essential_dirs:
        if os.path.exists(dir_path):
            bind_args += ["--ro-bind", dir_path, dir_path]

    # Add a dev directory with the minimum required devices
    bind_args += ["--dev", "/dev"]

    # Add additional sandbox options from config
    if config.new_session:
        bind_args += ["--new-session"]

    if config.die_with_parent:
        bind_args += ["--die-with-parent"]

    if config.disable_userns:
        bind_args += ["--disable-userns"]

    if config.clear_env:
        bind_args += ["--clearenv"]

    if config.unshare_cgroup:
        bind_args += ["--unshare-cgroup-try"]

    if config.sandbox_uid is not None:
        bind_args += ["--uid", str(config.sandbox_uid)]

    if config.sandbox_gid is not None:
        bind_args += ["--gid", str(config.sandbox_gid)]

    if config.hostname:
        bind_args += ["--hostname", config.hostname]

    for mount in config.bind_mounts:
        src = Path(os.path.expanduser(mount.source)).resolve()
        dest = Path(mount.dest)
        if mount.create_dest:
            if not dest.is_absolute():
                dest = sandbox_home / dest
            dest.parent.mkdir(parents=True, exist_ok=True)
        flag = "--ro-bind" if mount.mode == "ro" else "--bind"
        bind_args += [flag, str(src), str(dest)]

    bind_args += [
        "--tmpfs",
        "/tmp",
    ]

    # Only unshare network if network_enabled is False
    if not config.network_enabled:
        bind_args += ["--unshare-net"]

    bind_args += [
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-user",
        "--chdir",
        str(project_dir),
    ]

    # Only set environment variables after --clearenv if used
    bind_args += [
        "--setenv",
        "HOME",
        str(sandbox_home),
        "--setenv",
        "USER",
        "sandbox",
        "--setenv",
        "SHELL",
        config.shell,
    ]

    return bind_args


def get_sandbox_home(project_dir: Path) -> Path:
    project_name = project_dir.name
    path_hash = hashlib.sha256(str(project_dir.resolve()).encode()).hexdigest()
    hash_prefix = path_hash[:8]
    return Path(os.path.expanduser(f"~/sandsh/{project_name}-{hash_prefix}/home"))


def print_config_preview(config: MergedSandboxConfig, project_dir: Path) -> None:
    sandbox_home = get_sandbox_home(project_dir)
    print("\n[sandsh] DRY RUN: Sandbox Configuration")
    print("========================================")
    print(f"Project Directory : {project_dir}")
    print(f"Sandbox Home      : {sandbox_home}")
    print(f"Shell             : {config.shell}")

    print("\nBind Mounts:")
    for bm in config.bind_mounts:
        print(f"  - {bm.source} -> {bm.dest} ({bm.mode})")
    print("\n[NOTE] This is a dry run. No shell will be launched.\n")


def launch(config: MergedSandboxConfig, project_dir: Path) -> None:
    sandbox_home = get_sandbox_home(project_dir)
    try:
        sandbox_home.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        log(f"Error: Cannot create sandbox home directory at {sandbox_home}")
        raise
    except OSError as e:
        log(f"Error: Failed to create sandbox home directory: {e}")
        raise

    if not sandbox_home.exists():
        log(f"Error: Failed to create sandbox home directory at {sandbox_home}")
        raise RuntimeError("Could not create sandbox home directory")

    args = build_bind_args(config, project_dir, sandbox_home)
    log(f"Launching sandboxed shell: {config.shell}")
    os.execvp("bwrap", ["bwrap"] + args + [config.shell])
