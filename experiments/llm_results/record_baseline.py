import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "experiments" / "llm_results" / "baseline.json"

result = subprocess.run(
    [sys.executable, "-m", "unittest", "discover", "-s", "test", "-v"],
    cwd=ROOT,
    capture_output=True,
    text=True,
)

report = {
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "command": "python -m unittest discover -s test -v",
    "return_code": result.returncode,
    "passed": result.returncode == 0,
    "stdout": result.stdout,
    "stderr": result.stderr,
}

OUTPUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

print(f"Baseline passed: {report['passed']}")
print(f"Return code: {report['return_code']}")
print(f"Saved report: {OUTPUT.relative_to(ROOT)}")

if result.returncode != 0:
    print(result.stderr)
    raise SystemExit(result.returncode)
