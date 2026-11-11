"""random_bs - a dependency-free local network inventory scanner for Windows."""

from __future__ import annotations

__all__ = ["main"]
__version__ = "0.1.0"


def main() -> int:
    """Console entry point; imported lazily to keep ``python -m`` clean."""
    from .cli import main as cli_main

    return cli_main()
