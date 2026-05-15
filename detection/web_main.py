"""CLI entry point helper for the Detection Workbench."""

from __future__ import annotations

import sys

from detection.web import main


if __name__ == "__main__":
    sys.exit(main())
