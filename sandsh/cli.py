import argparse
import shutil
from pathlib import Path

from sandsh.config import (
    CONFIG_FILENAME,
    GLOBAL_CONFIG_PATH,
    load_global_config,
    load_local_config,
    merge_configs,
    write_default_config,
)
from sandsh.sandbox import launch, print_config_preview
from sandsh.utils import fail

REQUIRED_PROGRAMS = ["bwrap", "gcc"]


def check_required_programs():
    missing = []
    for program in REQUIRED_PROGRAMS:
        if not shutil.which(program):
            missing.append(program)

    if missing:
        fail(
            f"Required program(s) not found in PATH: {', '.join(missing)}\n"
            "Please install the missing dependencies."
        )


def main() -> None:
    check_required_programs()

    parser = argparse.ArgumentParser(description="Launch a bubblewrap sandbox shell.")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    run_parser = subparsers.add_parser("run", help="Run a sandboxed shell (default)")
    run_parser.add_argument(
        "--dry-run", action="store_true", help="Preview sandbox configuration without launching"
    )

    init_parser = subparsers.add_parser("init", help="Initialize configuration files")
    init_parser.add_argument(
        "--global",
        action="store_true",
        dest="global_",
        help="Create global config instead of local",
    )
    init_parser.add_argument(
        "--force", "-f", action="store_true", help="Overwrite existing config file"
    )

    args = parser.parse_args()

    if not args.command:
        args.command = "run"
        args.dry_run = False

    if args.command == "init":
        path = GLOBAL_CONFIG_PATH if args.global_ else Path.cwd() / CONFIG_FILENAME
        if args.force and path.exists():
            path.unlink()
        write_default_config(path)
        return

    project_dir = Path.cwd()
    local_config = load_local_config(project_dir)
    global_config = load_global_config()
    config = merge_configs(local_config, global_config)

    if args.dry_run:
        print_config_preview(config, project_dir)
    else:
        launch(config, project_dir)
