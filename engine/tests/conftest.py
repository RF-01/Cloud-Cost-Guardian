import sys
from pathlib import Path

# Make the repo root importable so tests can `import common.timeline` like the Lambdas do.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
