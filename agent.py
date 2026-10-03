#!/usr/bin/env python3
"""Entry point: interactive chat agent."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from terminator.agent.loop import main

if __name__ == "__main__":
    main()
