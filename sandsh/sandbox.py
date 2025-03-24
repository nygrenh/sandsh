import os
from pathlib import Path

from sandsh.config import SandboxConfig
from sandsh.utils import log


def build_bind_args(config: SandboxConfig, project_dir: Path, sandbox_home: Path) -> list[str]:
    bind_args = []

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
        "--bind",
        str(project_dir),
        str(project_dir),
        "--bind",
        str(sandbox_home),
        str(sandbox_home),
        "--dev-bind",
        "/",
        "/",
        "--ro-bind",
        "/etc",
        "/etc",
        "--proc",
        "/proc",
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


def print_config_preview(config: SandboxConfig, project_dir: Path) -> None:
    sandbox_home = project_dir / ".sandbox-home"
    print("\n[sandsh] DRY RUN: Sandbox Configuration")
    print("========================================")
    print(f"Project Directory : {project_dir}")
    print(f"Sandbox Home      : {sandbox_home}")
    print(f"Shell             : {config.shell}")

    print("\nBind Mounts:")
    for bm in config.bind_mounts:
        print(f"  - {bm.source} -> {bm.dest} ({bm.mode})")
    print("\n[NOTE] This is a dry run. No shell will be launched.\n")


def launch(config: SandboxConfig, project_dir: Path) -> None:
    shell = config.shell
    sandbox_home = project_dir / ".sandbox-home"
    sandbox_home.mkdir(parents=True, exist_ok=True)
    args = build_bind_args(config, project_dir, sandbox_home)
    log(f"Launching sandboxed shell: {shell}")
    os.execvp("bwrap", ["bwrap"] + args + [shell])
