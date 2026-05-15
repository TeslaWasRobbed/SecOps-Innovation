"""CLI entry point: python -m detection."""

from __future__ import annotations

import sys

from detection.generator import main


if __name__ == "__main__":
    sys.exit(main())
