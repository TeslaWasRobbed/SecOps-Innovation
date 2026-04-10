#!/usr/bin/env python3
"""Simple launcher for SecOps Innovation Platform"""

import subprocess
import sys

if __name__ == "__main__":
    # Pass all arguments to the main script
    cmd = ["python", "__main__.py"] + sys.argv[1:]
    sys.exit(subprocess.call(cmd))