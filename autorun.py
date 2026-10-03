#!/usr/bin/env python3
"""Entry point: autonomous pentest loop."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from terminator.pentest.runner import main

if __name__ == "__main__":
    raise SystemExit(main())
