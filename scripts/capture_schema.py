import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from main import app


if __name__ == "__main__":
    output = json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"
    (ROOT / "baseline_openapi.json").write_text(output, encoding="utf-8")
