import sys
from pathlib import Path

# Import the Notify helpers like the Lambda does: handler.py and its notify_*.py modules sit at the zip root.
NOTIFY_SRC = Path(__file__).resolve().parents[1] / "src" / "notify"
if str(NOTIFY_SRC) not in sys.path:
    sys.path.insert(0, str(NOTIFY_SRC))
