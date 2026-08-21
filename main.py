import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from tools.ghost_extension import run
if __name__ == '__main__':
    raise SystemExit(run())
