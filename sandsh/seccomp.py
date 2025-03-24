import os
import subprocess
import tempfile
from contextlib import suppress

from sandsh.config import FinalizedSandboxConfig
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


def create_seccomp_filter(config: FinalizedSandboxConfig) -> tuple[str | None, str | None]:
    """Create a seccomp filter with custom rules from config"""
    temp_dir = tempfile.mkdtemp(prefix="sandsh_seccomp_")
    c_file_path = os.path.join(temp_dir, "seccomp_filter.c")
    bin_path = os.path.join(temp_dir, "genfilter")
    filter_path = os.path.join(temp_dir, "seccomp.bpf")

    # If a custom filter path is provided, just use that
    if config.security.seccomp.custom_filter_path:
        if os.path.exists(config.security.seccomp.custom_filter_path):
            return None, config.security.seccomp.custom_filter_path
        else:
            log(
                f"Warning: Specified seccomp filter path {config.security.seccomp.custom_filter_path} does not exist"
            )

    # Generate C code for the seccomp filter
    rule_lines = []

    # Always add the TIOCSTI protection rule if enabled
    if config.security.seccomp.use_tiocsti_protection:
        rule_lines.append("    // Block TIOCSTI ioctl (terminal injection)")
        rule_lines.append("    // TIOCSTI is 0x5412")
        rule_lines.append("    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(1), SCMP_SYS(ioctl), 1,")
        rule_lines.append("                    SCMP_CMP(1, SCMP_CMP_EQ, 0x5412));")

    # Add custom rules from config
    for rule in config.security.seccomp.syscall_rules:
        syscall = rule.syscall

        # Convert rule.action to SCMP_ACT constant
        action_map: dict[str, str] = {
            "block": "SCMP_ACT_ERRNO(1)",
            "allow": "SCMP_ACT_ALLOW",
            "log": "SCMP_ACT_LOG",
            "trace": "SCMP_ACT_TRACE(1)",
        }
        action = action_map.get(rule.action or "block", "SCMP_ACT_ERRNO(1)")

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
            # Use a default of "eq" if arg_op is None
            op_str = op_map.get(rule.arg_op or "eq", "SCMP_CMP_EQ")

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

    # Compile and run the filter generator
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
