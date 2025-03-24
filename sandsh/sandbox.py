import hashlib
import os
import subprocess
import tempfile
from contextlib import suppress
from pathlib import Path

from sandsh.config import MergedSandboxConfig
from sandsh.utils import log


def generate_seccomp_script(filter_path: str):
    """Generate a seccomp filter using a shell script approach"""
    script_content = """#!/bin/bash
# Generate a minimal seccomp filter to block TIOCSTI ioctl
cat > {filter_path} << EOF
# Simple seccomp filter that blocks TIOCSTI (0x5412) ioctl
# Format: syscall_name, arg_index, arg_value, arg_mask, action
ioctl 1 0x5412 0xffffffff ERRNO(1)
EOF
"""
    script_path = filter_path + ".sh"
    with open(script_path, "w") as f:
        f.write(script_content.format(filter_path=filter_path))

    os.chmod(script_path, 0o755)
    return script_path


def create_seccomp_filter(config: MergedSandboxConfig):
    """Create a seccomp filter with custom rules from config"""
    temp_dir = tempfile.mkdtemp(prefix="sandsh_seccomp_")
    c_file_path = os.path.join(temp_dir, "seccomp_filter.c")
    bin_path = os.path.join(temp_dir, "genfilter")
    filter_path = os.path.join(temp_dir, "seccomp.bpf")

    # If a custom filter path is provided, just use that
    if config.seccomp_filter_path:
        if os.path.exists(config.seccomp_filter_path):
            return None, config.seccomp_filter_path
        else:
            log(
                f"Warning: Specified seccomp filter path {config.seccomp_filter_path} does not exist"
            )

    # Generate C code for the seccomp filter
    rule_lines = []

    # Always add the TIOCSTI protection rule if enabled
    if config.use_tiocsti_protection:
        rule_lines.append("    // Block TIOCSTI ioctl (terminal injection)")
        rule_lines.append("    // TIOCSTI is 0x5412")
        rule_lines.append("    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(1), SCMP_SYS(ioctl), 1,")
        rule_lines.append("                    SCMP_CMP(1, SCMP_CMP_EQ, 0x5412));")

    # Add custom rules from config
    for rule in config.seccomp_rules:
        syscall = rule.syscall

        # Convert rule.action to SCMP_ACT constant
        if rule.action == "block":
            action = "SCMP_ACT_ERRNO(1)"
        elif rule.action == "allow":
            action = "SCMP_ACT_ALLOW"
        elif rule.action == "log":
            action = "SCMP_ACT_LOG"
        elif rule.action == "trace":
            action = "SCMP_ACT_TRACE(1)"
        else:
            action = "SCMP_ACT_ERRNO(1)"  # Default to block

        # Handle rules with and without arguments
        if rule.arg_index is not None and rule.arg_value is not None:
            # Map operator string to SCMP_CMP constant
            op_map = {
                "eq": "SCMP_CMP_EQ",
                "ne": "SCMP_CMP_NE",
                "lt": "SCMP_CMP_LT",
                "le": "SCMP_CMP_LE",
                "gt": "SCMP_CMP_GT",
                "ge": "SCMP_CMP_GE",
                "maskeq": "SCMP_CMP_MASKED_EQ",
            }
            op_str = op_map.get(rule.arg_op, "SCMP_CMP_EQ")

            rule_lines.append(f"    // Custom rule for {syscall}")
            rule_lines.append(f"    seccomp_rule_add(ctx, {action}, SCMP_SYS({syscall}), 1,")
            rule_lines.append(
                f"                    SCMP_CMP({rule.arg_index}, {op_str}, {rule.arg_value}));"
            )
        else:
            # Simple rule that applies to the entire syscall
            rule_lines.append(f"    // Custom rule for {syscall}")
            rule_lines.append(f"    seccomp_rule_add(ctx, {action}, SCMP_SYS({syscall}), 0);")

    # If we have no rules, don't bother creating a filter
    if not rule_lines:
        return None, None

    rules_code = "\n".join(rule_lines)

    # Create a C program that generates a seccomp filter
    with open(c_file_path, "w") as f:
        f.write(f"""
#include <seccomp.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {{
    // Create a seccomp filter context
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {{
        fprintf(stderr, "Failed to initialize seccomp filter\\n");
        return 1;
    }}
    
{rules_code}
    
    // Write the filter to the output file
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {{
        fprintf(stderr, "Failed to open output file\\n");
        seccomp_release(ctx);
        return 1;
    }}
    
    seccomp_export_bpf(ctx, fd);
    close(fd);
    seccomp_release(ctx);
    return 0;
}}
""")

    # Compile and run the filter generator (same as before)
    try:
        compilation_result = subprocess.run(
            ["gcc", "-o", bin_path, c_file_path, "-lseccomp"],
            capture_output=True,
            text=True,
            check=False,
        )

        if compilation_result.returncode != 0:
            log(f"Failed to compile seccomp filter generator: {compilation_result.stderr}")
            return None, None

        run_result = subprocess.run(
            [bin_path, filter_path], capture_output=True, text=True, check=False
        )

        if run_result.returncode != 0:
            log(f"Failed to generate seccomp filter: {run_result.stderr}")
            return None, None

        if os.path.exists(filter_path) and os.path.getsize(filter_path) > 0:
            return temp_dir, filter_path

    except Exception as e:
        log(f"Error creating seccomp filter: {e}")

    # Clean up if failed
    with suppress(Exception):
        if os.path.exists(temp_dir):
            subprocess.run(["rm", "-rf", temp_dir])

    return None, None


def build_bind_args(
    config: MergedSandboxConfig, project_dir: Path, sandbox_home: Path
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
