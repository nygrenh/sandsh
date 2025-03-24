import hashlib
import os
from pathlib import Path

from sandsh.config import MergedSandboxConfig
from sandsh.utils import log


def build_bind_args(
    config: MergedSandboxConfig, project_dir: Path, sandbox_home: Path
) -> list[str]:
    bind_args: list[str] = []

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
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-user",
        "--chdir",
        str(project_dir),
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
