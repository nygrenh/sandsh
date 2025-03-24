import hashlib
import os
from pathlib import Path

from sandsh.config import FinalizedSandboxConfig
from sandsh.seccomp import create_seccomp_filter
from sandsh.utils import log


def build_bind_args(
    config: FinalizedSandboxConfig, project_dir: Path, sandbox_home: Path
) -> list[str]:
    bind_args: list[str] = []

    # We always need to bind the project directory itself
    bind_args += ["--bind", str(project_dir), str(project_dir)]

    # Add a dev directory with the minimum required devices
    bind_args += ["--dev", "/dev"]

    # Process all bind mounts from config
    for mount in config.bind_mounts:
        src = Path(os.path.expanduser(mount.source)).resolve()
        if not src.exists():
            log(f"Warning: Bind mount source does not exist: {src}")
            continue

        dest = Path(mount.dest)
        if mount.create_dest:
            if not dest.is_absolute():
                dest = sandbox_home / dest
            dest.parent.mkdir(parents=True, exist_ok=True)
        flag = "--ro-bind" if mount.mode == "ro" else "--bind"
        bind_args += [flag, str(src), str(dest)]

    # Seccomp filter setup
    temp_dir = None
    filter_path = None

    if config.new_session:
        # If new_session is explicitly enabled, use it
        bind_args += ["--new-session"]
    elif config.use_tiocsti_protection or config.seccomp_rules or config.seccomp_filter_path:
        # Try to create a seccomp filter with all specified rules
        temp_dir, filter_path = create_seccomp_filter(config)
        if filter_path:
            log("Using seccomp filter with custom rules")
        else:
            log("Warning: Failed to create seccomp filter, terminal protection is reduced")
            log("         Consider enabling new_session=true in your config for better security")

    if config.die_with_parent:
        bind_args += ["--die-with-parent"]

    if config.disable_userns:
        bind_args += ["--disable-userns"]

    # Save important environment variables before clearing
    preserved_env = {}
    if config.clear_env:
        important_vars = ["TERM", "COLORTERM", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"]
        for var in important_vars:
            if var in os.environ:
                preserved_env[var] = os.environ[var]

        bind_args += ["--clearenv"]

    if config.unshare_cgroup:
        bind_args += ["--unshare-cgroup-try"]

    if config.sandbox_uid is not None:
        bind_args += ["--uid", str(config.sandbox_uid)]

    if config.sandbox_gid is not None:
        bind_args += ["--gid", str(config.sandbox_gid)]

    if config.hostname:
        bind_args += ["--hostname", config.hostname]

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

    # Environment variables section
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

    # Restore important environment variables after clearing
    for var, value in preserved_env.items():
        bind_args += ["--setenv", var, value]

    # Clean up temp files (now done in launch())
    return bind_args, filter_path  # Return the filter path as well


def get_sandbox_home(project_dir: Path) -> Path:
    project_name = project_dir.name
    path_hash = hashlib.sha256(str(project_dir.resolve()).encode()).hexdigest()
    hash_prefix = path_hash[:8]
    return Path(os.path.expanduser(f"~/sandsh/{project_name}-{hash_prefix}/home"))


def print_config_preview(config: FinalizedSandboxConfig, project_dir: Path) -> None:
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


def launch(config: FinalizedSandboxConfig, project_dir: Path) -> None:
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

    args, seccomp_filter_path = build_bind_args(config, project_dir, sandbox_home)

    log(f"Launching sandboxed shell: {config.shell}")

    # If we have a seccomp filter, use it with fd redirection
    if seccomp_filter_path and os.path.exists(seccomp_filter_path):
        # Use file descriptor 10 for the seccomp filter
        args += ["--seccomp", "10"]

        # Open the file and keep the FD
        seccomp_fd = os.open(seccomp_filter_path, os.O_RDONLY)

        # Duplicate to FD 10 (which bwrap expects)
        os.dup2(seccomp_fd, 10)

        # Start bwrap with FD 10 pointing to our filter
        os.execvp("bwrap", ["bwrap"] + args + [config.shell])
    else:
        # Regular launch without seccomp
        os.execvp("bwrap", ["bwrap"] + args + [config.shell])
