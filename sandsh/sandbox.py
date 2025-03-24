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
        if config.namespaces.share_net:
            bind_args += ["--share-net"]
    else:
        # Individual namespace options
        if config.namespaces.user_try:
            bind_args += ["--unshare-user-try"]
        elif config.namespaces.user:
            bind_args += ["--unshare-user"]
        if config.namespaces.ipc:
            bind_args += ["--unshare-ipc"]
        if config.namespaces.pid:
            bind_args += ["--unshare-pid"]
        if config.namespaces.network:
            bind_args += ["--unshare-net"]
        if config.namespaces.uts:
            bind_args += ["--unshare-uts"]
        if config.namespaces.cgroup_try:
            bind_args += ["--unshare-cgroup-try"]
        elif config.namespaces.cgroup:
            bind_args += ["--unshare-cgroup"]

    # Handle user namespace FDs
    if config.namespaces.userns_fd is not None:
        bind_args += ["--userns", str(config.namespaces.userns_fd)]
    if config.namespaces.userns2_fd is not None:
        bind_args += ["--userns2", str(config.namespaces.userns2_fd)]
    if config.namespaces.pidns_fd is not None:
        bind_args += ["--pidns", str(config.namespaces.pidns_fd)]

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

    # Handle environment settings
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
            pass
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

    # Process configuration
    if config.process.argv0:
        bind_args += ["--argv0", config.process.argv0]
    for lock_file in config.process.lock_files:
        bind_args += ["--lock-file", lock_file]
    if config.process.sync_fd is not None:
        bind_args += ["--sync-fd", str(config.process.sync_fd)]
    if config.process.info_fd is not None:
        bind_args += ["--info-fd", str(config.process.info_fd)]
    if config.process.json_status_fd is not None:
        bind_args += ["--json-status-fd", str(config.process.json_status_fd)]
    if config.process.block_fd is not None:
        bind_args += ["--block-fd", str(config.process.block_fd)]
    if config.process.userns_block_fd is not None:
        bind_args += ["--userns-block-fd", str(config.process.userns_block_fd)]

    # Handle remount-ro
    for path in config.filesystem.remount_ro:
        bind_args += ["--remount-ro", path]

    # Handle chmod entries
    for path, mode in config.filesystem.chmod_entries:
        bind_args += ["--chmod", oct(mode)[2:], path]

    # Handle file entries with proper perms/size ordering
    for entry in config.filesystem.file_entries:
        # Set size first if needed (only affects tmpfs)
        if config.filesystem.next_size is not None:
            bind_args += ["--size", str(config.filesystem.next_size)]
            config.filesystem.next_size = None

        # Set perms if needed
        if config.filesystem.next_perms is not None:
            bind_args += ["--perms", oct(config.filesystem.next_perms)[2:]]
            config.filesystem.next_perms = None
        elif entry.mode is not None:
            bind_args += ["--perms", oct(entry.mode)[2:]]

        # Handle the actual operation
        if entry.type == "dir":
            bind_args += ["--dir", entry.dest]
        elif entry.type == "file":
            bind_args += ["--file", str(entry.source_fd), entry.dest]
        elif entry.type == "symlink":
            bind_args += ["--symlink", entry.source_path, entry.dest]
        elif entry.type == "bind-data":
            bind_args += ["--bind-data", str(entry.source_fd), entry.dest]
        elif entry.type == "ro-bind-data":
            bind_args += ["--ro-bind-data", str(entry.source_fd), entry.dest]

    # Handle "try" variants of bind mounts
    for mount in config.filesystem.bind_try:
        bind_args += ["--bind-try", mount.source, mount.dest]
    for mount in config.filesystem.dev_bind_try:
        bind_args += ["--dev-bind-try", mount.source, mount.dest]
    for mount in config.filesystem.ro_bind_try:
        bind_args += ["--ro-bind-try", mount.source, mount.dest]

    # Handle process options
    if config.process.level_prefix:
        bind_args += ["--level-prefix"]

    # Handle additional seccomp filters
    for fd in config.security.seccomp.additional_filter_fds:
        bind_args += ["--add-seccomp-fd", str(fd)]

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
    print(f"Shell            : {config.shell}")
    print(f"Profile          : {config.profile or 'default'}")

    print("\nNamespace Settings:")
    if config.namespaces.unshare_all:
        print("  All namespaces enabled")
        if config.namespaces.share_net:
            print("  Network sharing enabled")
    else:
        print(
            f"  User           : {'try' if config.namespaces.user_try else 'enabled' if config.namespaces.user else 'disabled'}"
        )
        print(f"  Network        : {'enabled' if config.namespaces.network else 'disabled'}")
        print(f"  IPC            : {'enabled' if config.namespaces.ipc else 'disabled'}")
        print(f"  PID            : {'enabled' if config.namespaces.pid else 'disabled'}")
        print(f"  UTS            : {'enabled' if config.namespaces.uts else 'disabled'}")
        print(
            f"  Cgroup         : {'try' if config.namespaces.cgroup_try else 'enabled' if config.namespaces.cgroup else 'disabled'}"
        )
    print(f"  User NS        : {'disabled' if config.namespaces.disable_userns else 'enabled'}")

    if any([config.namespaces.userns_fd, config.namespaces.userns2_fd, config.namespaces.pidns_fd]):
        print("\nNamespace FDs:")
        if config.namespaces.userns_fd is not None:
            print(f"  User NS FD     : {config.namespaces.userns_fd}")
        if config.namespaces.userns2_fd is not None:
            print(f"  User NS2 FD    : {config.namespaces.userns2_fd}")
        if config.namespaces.pidns_fd is not None:
            print(f"  PID NS FD      : {config.namespaces.pidns_fd}")

    print("\nFilesystem Settings:")
    if config.filesystem.bind_mounts:
        print("\nBind Mounts:")
        for bm in config.filesystem.bind_mounts:
            print(f"  - {bm.source} -> {bm.dest} ({bm.mode})")

    if config.filesystem.tmpfs_mounts:
        print("\nTmpfs Mounts:")
        for tm in config.filesystem.tmpfs_mounts:
            mode_str = f", mode={oct(tm.mode)[2:]}" if tm.mode else ""
            size_str = f", size={tm.size}" if tm.size else ""
            print(f"  - {tm.dest}{mode_str}{size_str}")

    if config.filesystem.remount_ro:
        print("\nRead-only Remounts:")
        for path in config.filesystem.remount_ro:
            print(f"  - {path}")

    if config.filesystem.chmod_entries:
        print("\nChmod Entries:")
        for path, mode in config.filesystem.chmod_entries:
            print(f"  - {path}: {oct(mode)[2:]}")

    if config.filesystem.file_entries:
        print("\nFile Operations:")
        for entry in config.filesystem.file_entries:
            mode_str = f", mode={oct(entry.mode)[2:]}" if entry.mode else ""
            if entry.type == "dir":
                print(f"  - Create directory: {entry.dest}{mode_str}")
            elif entry.type == "symlink":
                print(f"  - Create symlink: {entry.dest} -> {entry.source_path}")
            else:
                print(f"  - {entry.type}: fd {entry.source_fd} -> {entry.dest}{mode_str}")

    if any(
        [config.filesystem.bind_try, config.filesystem.dev_bind_try, config.filesystem.ro_bind_try]
    ):
        print("\nOptional Bind Mounts:")
        for mount in config.filesystem.bind_try:
            print(f"  - Try bind: {mount.source} -> {mount.dest} ({mount.mode})")
        for mount in config.filesystem.dev_bind_try:
            print(f"  - Try dev-bind: {mount.source} -> {mount.dest} ({mount.mode})")
        for mount in config.filesystem.ro_bind_try:
            print(f"  - Try ro-bind: {mount.source} -> {mount.dest} ({mount.mode})")

    print("\nEnvironment Settings:")
    print(f"  Clear Env      : {'yes' if config.environment.clear_env else 'no'}")
    if config.environment.preserve_vars:
        print("  Preserved Vars :", ", ".join(config.environment.preserve_vars))
    if config.environment.set_vars:
        print("  Set Variables :")
        for name, value in config.environment.set_vars.items():
            print(f"    {name}={value}")
    print(f"  Die w/Parent   : {'yes' if config.environment.die_with_parent else 'no'}")
    print(f"  New Session    : {'yes' if config.environment.new_session else 'no'}")
    print(f"  Run as PID 1   : {'yes' if config.environment.as_pid_1 else 'no'}")

    if any(
        [
            config.process.argv0,
            config.process.lock_files,
            config.process.sync_fd,
            config.process.info_fd,
            config.process.json_status_fd,
            config.process.block_fd,
            config.process.userns_block_fd,
        ]
    ):
        print("\nProcess Settings:")
        if config.process.argv0:
            print(f"  argv[0]        : {config.process.argv0}")
        if config.process.lock_files:
            print("  Lock Files     :", ", ".join(config.process.lock_files))
        if config.process.sync_fd is not None:
            print(f"  Sync FD        : {config.process.sync_fd}")
        if config.process.info_fd is not None:
            print(f"  Info FD        : {config.process.info_fd}")
        if config.process.json_status_fd is not None:
            print(f"  JSON Status FD : {config.process.json_status_fd}")
        if config.process.block_fd is not None:
            print(f"  Block FD       : {config.process.block_fd}")
        if config.process.userns_block_fd is not None:
            print(f"  UserNS Block FD: {config.process.userns_block_fd}")
        if config.process.level_prefix:
            print("  Level Prefix   : enabled")

    print("\nSecurity Settings:")
    if config.security.capabilities.drop_all:
        print("  - All capabilities dropped")
    else:
        if config.security.capabilities.add:
            print("  Added capabilities:", ", ".join(config.security.capabilities.add))
        if config.security.capabilities.drop:
            print("  Dropped capabilities:", ", ".join(config.security.capabilities.drop))

    print(
        f"  Seccomp TIOCSTI: {'enabled' if config.security.seccomp.use_tiocsti_protection else 'disabled'}"
    )

    if config.security.seccomp.syscall_rules:
        print("\nSeccomp Rules:")
        for rule in config.security.seccomp.syscall_rules:
            arg_str = ""
            if rule.arg_index is not None:
                arg_str = f" (arg[{rule.arg_index}] {rule.arg_op} {rule.arg_value})"
            print(f"  - {rule.syscall}: {rule.action}{arg_str}")

    if config.security.seccomp.additional_filter_fds:
        print(
            "  Additional Seccomp Filters:",
            ", ".join(str(fd) for fd in config.security.seccomp.additional_filter_fds),
        )

    if config.process.args_fds:
        print("  Args FDs       :", ", ".join(str(fd) for fd in config.process.args_fds))

    if config.filesystem.next_perms is not None:
        print(f"  Next Perms     : {oct(config.filesystem.next_perms)[2:]}")
    if config.filesystem.next_size is not None:
        print(f"  Next Size      : {config.filesystem.next_size} bytes")

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

    # Print the command in purple with > prefix
    cmd = ["bwrap"] + args + [config.shell]
    print("\033[35m> " + " ".join(cmd) + "\033[0m")

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
