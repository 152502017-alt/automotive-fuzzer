"""Experiment A: test an Ollama-generated protocol implementation in isolation."""

import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiments" / "llm_results"
CANDIDATES = OUT / "protocol_candidates"
REPORT = OUT / "protocol_changes.json"
TARGET = ROOT / "someip" / "message.py"

sys.path.insert(0, str(ROOT))
from experiments.llm_provider import OllamaProvider


def strip_fences(text):
    lines = text.strip().splitlines()
    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
    return "\n".join(lines).strip()


def validate_candidate(source):
    tree = ast.parse(source)

    allowed_imports = {"constants", "error", "header"}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.Global, ast.Nonlocal)):
            raise ValueError("Candidate contains a disallowed statement")

        if isinstance(node, ast.ImportFrom):
            if node.level != 1 or node.module not in allowed_imports:
                raise ValueError(
                    f"Disallowed import: {node.module!r}, level={node.level}"
                )

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {
                "eval", "exec", "open", "compile", "__import__",
                "breakpoint", "input",
            }:
                raise ValueError(f"Disallowed call: {node.func.id}")

    return tree


def run_tests(candidate_source):
    with tempfile.TemporaryDirectory(prefix="automotive_fuzzer_candidate_") as tmp:
        workspace = Path(tmp) / "project"

        def ignore(directory, names):
            excluded = {
                ".git", ".venv", "venv", "env", "__pycache__",
                ".pytest_cache",
            }
            if Path(directory).resolve() == ROOT:
                excluded.add("llm_results")
            return [name for name in names if name in excluded]

        shutil.copytree(ROOT, workspace, ignore=ignore)

        candidate_file = workspace / "someip" / "message.py"
        candidate_file.write_text(candidate_source + "\n", encoding="utf-8")

        env = os.environ.copy()
        env["PYTHONPATH"] = str(workspace)
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        return subprocess.run(
            [
                sys.executable, "-m", "unittest",
                "discover", "-s", "test", "-v",
            ],
            cwd=workspace,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    CANDIDATES.mkdir(parents=True, exist_ok=True)

    original_source = TARGET.read_text(encoding="utf-8")
    prompt = f"""
You are proposing a small robustness improvement to a Python SOME/IP parser.
Return the complete replacement source file only, without Markdown fences.
Preserve existing public function signatures and valid-message behavior.
Use only the existing relative imports from constants, error, and header.
Do not add filesystem, network, subprocess, dynamic execution, or OS operations.
Do not claim that tests have passed.

Current source:
{original_source}

Task: propose one small, clearly documented robustness improvement while
preserving existing behavior for valid messages.
"""

    provider = OllamaProvider()
    generated = strip_fences(provider.propose_protocol_patch(prompt))

    candidate = CANDIDATES / "someip" / "message.py"
    candidate.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model": provider.model,
        "target": "someip/message.py",
        "candidate": str(candidate.relative_to(ROOT)),
        "original_modified": False,
        "candidate_syntax_valid": False,
        "candidate_tests_passed": False,
    }

    try:
        validate_candidate(generated)
        compile(generated, str(candidate), "exec")
        report["candidate_syntax_valid"] = True
        candidate.write_text(generated + "\n", encoding="utf-8")

        result = run_tests(generated)
        report["candidate_tests_passed"] = result.returncode == 0
        report["candidate_test_return_code"] = result.returncode
        report["candidate_test_output"] = result.stdout + result.stderr

    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"

    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(f"Candidate syntax valid: {report['candidate_syntax_valid']}")
    print(f"Candidate tests passed: {report['candidate_tests_passed']}")
    print(f"Original source modified: {report['original_modified']}")
    print(f"Candidate saved: {candidate.relative_to(ROOT)}")
    print(f"Report saved: {REPORT.relative_to(ROOT)}")

    if "error" in report:
        print("Error:", report["error"])
    elif not report["candidate_tests_passed"]:
        print("Candidate test output:")
        print(report["candidate_test_output"])


if __name__ == "__main__":
    main()
