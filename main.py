#!/usr/bin/env python3
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / "src"))

from ghost_firmware_analyzer.cli import run


if __name__ == "__main__":
    raise SystemExit(run())
