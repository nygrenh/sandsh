"""Simple TOML writer implementation with no external dependencies."""

from typing import Any


def _format_value(value: Any) -> str:
    """Format a Python value as TOML."""
    if isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, int | float):
        return str(value)
    elif isinstance(value, str):
        return f'"{value}"'
    elif isinstance(value, list):
        items = [
            _format_dict(item) if isinstance(item, dict) else _format_value(item) for item in value
        ]
        return f"[\n  {',\n  '.join(items)}\n]"
    elif isinstance(value, dict):
        return _format_dict(value)
    else:
        raise ValueError(f"Unsupported type for TOML: {type(value)}")


def _format_dict(d: dict) -> str:
    """Format a dictionary as TOML inline table."""
    items = []
    for k, v in d.items():
        items.append(f"{k} = {_format_value(v)}")
    return "{ " + ", ".join(items) + " }"


def dumps(data: dict) -> str:
    """Convert a dictionary to TOML format string."""
    lines = []

    # Handle top-level tables
    for section, content in data.items():
        if not isinstance(content, dict):
            raise ValueError(f"Top-level key '{section}' must be a table (dict)")

        # Write section header
        lines.append(f"[{section}]")

        # Write section content
        for key, value in content.items():
            if isinstance(value, dict):
                # Nested table
                lines.append(f"\n[{section}.{key}]")
                for k, v in value.items():
                    lines.append(f"{k} = {_format_value(v)}")
            else:
                # Regular key-value
                lines.append(f"{key} = {_format_value(value)}")
        lines.append("")  # Empty line between sections

    return "\n".join(lines).strip()
