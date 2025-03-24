import hashlib
import os
from pathlib import Path

from sandsh.config import FinalizedSandboxConfig
from sandsh.seccomp import create_seccomp_filter
from sandsh.utils import log


def build_bind_args(
    config: FinalizedSandboxConfig, project_dir: Path, sandbox_home: Path
) -> tuple[list[str], str | None]:
    bind_args: list[str] = []
    filter_path = None

    # We always need to bind the project directory itself
    bind_args += ["--bind", str(project_dir), str(project_dir)]

    # Handle namespace options
    if config.namespaces.unshare_all:
        bind_args += ["--unshare-all"]
    else:
        # Individual namespace options
        if config.namespaces.user:
            bind_args += ["--unshare-user"]
        if config.namespaces.ipc:
            bind_args += ["--unshare-ipc"]
        if config.namespaces.pid:
            bind_args += ["--unshare-pid"]
        if config.namespaces.network:
            bind_args += ["--unshare-net"]
        if config.namespaces.uts:
            bind_args += ["--unshare-uts"]
        if config.namespaces.cgroup:
            bind_args += ["--unshare-cgroup"]

    # Process filesystem mounts
    if config.filesystem.system_mounts:
        system_mounts = [
            ("/usr", "/usr"),
            ("/bin", "/bin"),
            ("/lib", "/lib"),
            ("/lib64", "/lib64"),
            ("/etc", "/etc"),
        ]
        for src, dest in system_mounts:
            if os.path.exists(src):
                mode = "ro" if config.filesystem.system_ro else "rw"
                bind_args += [f"--{mode}-bind", src, dest]

    # Process all mount types
    for mount in config.filesystem.bind_mounts:
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

    # Handle special mounts
    for dest in config.filesystem.dev_mounts:
        bind_args += ["--dev", dest]

    for dest in config.filesystem.proc_mounts:
        bind_args += ["--proc", dest]

    for dest in config.filesystem.mqueue_mounts:
        bind_args += ["--mqueue", dest]

    # Handle tmpfs mounts
    for mount in config.filesystem.tmpfs_mounts:
        if mount.size is not None:
            bind_args += ["--size", str(mount.size)]
        if mount.mode is not None:
            bind_args += ["--perms", oct(mount.mode)[2:]]
        bind_args += ["--tmpfs", mount.dest]

    # Handle overlay mounts
    for mount in config.filesystem.overlay_mounts:
        for src in mount.sources:
            bind_args += ["--overlay-src", src]

        if mount.read_only:
            bind_args += ["--ro-overlay", mount.dest]
        elif mount.rw_source and mount.work_dir:
            bind_args += ["--overlay", mount.rw_source, mount.work_dir, mount.dest]
        else:
            bind_args += ["--tmp-overlay", mount.dest]

    # Process environment settings
    if config.environment.clear_env:
        bind_args += ["--clearenv"]
        # Preserve specified environment variables
        for var in config.environment.preserve_vars:
            if var in os.environ:
                bind_args += ["--setenv", var, os.environ[var]]

    # Set environment variables
    for name, value in config.environment.set_vars.items():
        bind_args += ["--setenv", name, value]

    # Unset environment variables
    for name in config.environment.unset_vars:
        bind_args += ["--unsetenv", name]

    # Process security settings
    if config.security.capabilities.drop_all:
        bind_args += ["--cap-drop", "ALL"]
    else:
        for cap in config.security.capabilities.add:
            bind_args += ["--cap-add", cap]
        for cap in config.security.capabilities.drop:
            bind_args += ["--cap-drop", cap]

    # Handle SELinux settings
    if config.security.selinux.exec_label:
        bind_args += ["--exec-label", config.security.selinux.exec_label]
    if config.security.selinux.file_label:
        bind_args += ["--file-label", config.security.selinux.file_label]

    # Process settings
    if config.environment.new_session:
        bind_args += ["--new-session"]
    elif config.security.seccomp.use_tiocsti_protection:
        # Try to create a seccomp filter with all specified rules
        temp_dir, filter_path = create_seccomp_filter(config)
        if filter_path:
            log("Using seccomp filter with custom rules")
        else:
            log("Warning: Failed to create seccomp filter, terminal protection is reduced")
            log("         Consider enabling new_session=true in your config for better security")

    if config.environment.die_with_parent:
        bind_args += ["--die-with-parent"]

    if config.namespaces.disable_userns:
        bind_args += ["--disable-userns"]

    if config.environment.as_pid_1:
        bind_args += ["--as-pid-1"]

    # User/Group settings
    if config.namespaces.uid is not None:
        bind_args += ["--uid", str(config.namespaces.uid)]

    if config.namespaces.gid is not None:
        bind_args += ["--gid", str(config.namespaces.gid)]

    if config.namespaces.hostname:
        bind_args += ["--hostname", config.namespaces.hostname]

    # Basic sandbox setup
    bind_args += [
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

    return bind_args, filter_path


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
    print(f"Profile          : {config.profile or 'default'}")

    print("\nNamespace Settings:")
    print(f"  Network        : {'isolated' if config.namespaces.network else 'shared'}")
    print(f"  User Namespace : {'disabled' if config.namespaces.disable_userns else 'enabled'}")

    print("\nBind Mounts:")
    for bm in config.filesystem.bind_mounts:
        print(f"  - {bm.source} -> {bm.dest} ({bm.mode})")

    print("\nSecurity Settings:")
    if config.security.capabilities.drop_all:
        print("  - All capabilities dropped")
    else:
        if config.security.capabilities.add:
            print("  Added capabilities:", ", ".join(config.security.capabilities.add))
        if config.security.capabilities.drop:
            print("  Dropped capabilities:", ", ".join(config.security.capabilities.drop))

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
        args.extend(["--seccomp", "10"])

        # Open the file and keep the FD
        seccomp_fd = os.open(seccomp_filter_path, os.O_RDONLY)

        # Duplicate to FD 10 (which bwrap expects)
        os.dup2(seccomp_fd, 10)

        # Start bwrap with FD 10 pointing to our filter
        os.execvp("bwrap", ["bwrap"] + args + [config.shell])
    else:
        # Regular launch without seccomp
        args.extend([config.shell])
        os.execvp("bwrap", ["bwrap"] + args)
