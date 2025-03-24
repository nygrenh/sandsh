import sys


def log(msg: str) -> None:
    print(f"[sandsh] {msg}")


def warn(msg: str) -> None:
    print(f"[sandsh:warning] {msg}")


def error(msg: str) -> None:
    print(f"[sandsh:error] {msg}", file=sys.stderr)


def fail(msg: str) -> None:
    error(msg)
    sys.exit(1)
