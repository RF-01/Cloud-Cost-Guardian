import sys
from pathlib import Path

# Import the Lambda like it runs: package `scanner` (from scanner/src) and `common` (from the repo root).
ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT, ROOT / "scanner" / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
