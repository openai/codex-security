from __future__ import annotations

import sys
from pathlib import Path

SDK_ROOT = Path(__file__).absolute().parents[1]
SRC_ROOT = SDK_ROOT / "src"

sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(SDK_ROOT))
