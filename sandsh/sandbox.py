import hashlib
import os
import struct
import tempfile
from contextlib import suppress
from pathlib import Path

from sandsh.config import MergedSandboxConfig
from sandsh.utils import log


def create_tiocsti_seccomp_filter():
    """Create a minimal seccomp filter to block the TIOCSTI ioctl without external dependencies."""
    # TIOCSTI ioctl number (typically 0x5412)
    TIOCSTI = 0x5412
    # ioctl syscall number (typically 16 on x86_64)
    IOCTL_SYSCALL = 16

    # Create a temporary file
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "wb") as f:
        # Simple BPF program structure:
        # 1. Load syscall number
        # 2. Compare with ioctl
        # 3. If not ioctl, allow
        # 4. If ioctl, check second argument against TIOCSTI
        # 5. If TIOCSTI, reject with EPERM
        # 6. Otherwise, allow

        # This is a basic seccomp-bpf program in binary form
        # It's a simplified version that only blocks TIOCSTI

        # Format: (operation, jt, jf, k)
        program = [
            # Load the syscall number
            (0x20, 0, 0, 0x00000000),  # ld [0]
            # Jump if not equal to ioctl (16)
            (0x15, 0, 4, IOCTL_SYSCALL),  # jeq IOCTL_SYSCALL, 0, 4
            # Load the first argument (second register, which holds TIOCSTI code)
            (0x20, 0, 0, 0x00000010),  # ld [16]
            # Jump if not equal to TIOCSTI
            (0x15, 0, 1, TIOCSTI),  # jeq TIOCSTI, 0, 1
            # Return EPERM (Operation not permitted)
            (0x06, 0, 0, 0x00050001),  # ret ERRNO(1)
            # Allow the syscall
            (0x06, 0, 0, 0x7FFF0000),  # ret ALLOW
        ]

        # Write the number of instructions
        f.write(struct.pack("=I", len(program)))

        # Write each instruction
        for op, jt, jf, k in program:
            f.write(struct.pack("=HBBI", op, jt, jf, k))

    return path


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

    # Use seccomp to block TIOCSTI instead of --new-session if available
    seccomp_filter_path = None
    if config.new_session:
        # Default to --new-session for simplicity
        bind_args += ["--new-session"]
    elif config.use_tiocsti_protection:
        try:
            # Try to create a direct seccomp filter
            seccomp_filter_path = create_tiocsti_seccomp_filter()
            if seccomp_filter_path:
                with open(seccomp_filter_path, "rb") as f:
                    seccomp_fd = f.fileno()
                    # Duplicate the file descriptor because execvp will close it
                    seccomp_fd = os.dup(seccomp_fd)
                    bind_args += ["--seccomp", str(seccomp_fd)]
                log("Using seccomp filter to block TIOCSTI ioctl for terminal protection")
            else:
                log("Warning: Failed to create seccomp filter for TIOCSTI protection")
                log("         Your sandbox may be vulnerable to terminal injection attacks")
        except Exception as e:
            log(f"Warning: Failed to set up TIOCSTI protection: {e}")
            log("         Your sandbox may be vulnerable to terminal injection attacks")

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

    # Cleanup temporary file at the end
    if seccomp_filter_path:
        with suppress(Exception):
            os.unlink(seccomp_filter_path)

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
