import argparse
from pathlib import Path

from sandsh.config import load_global_config, load_local_config, merge_configs
from sandsh.sandbox import launch, print_config_preview


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch a bubblewrap sandbox shell.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview sandbox configuration without launching"
    )
    args = parser.parse_args()

    project_dir = Path.cwd()
    local_config = load_local_config(project_dir)
    global_config = load_global_config()
    config = merge_configs(local_config, global_config)

    if args.dry_run:
        print_config_preview(config, project_dir)
    else:
        launch(config, project_dir)
