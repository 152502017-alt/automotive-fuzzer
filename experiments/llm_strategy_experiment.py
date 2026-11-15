"""Experiment B: evaluate an LLM-proposed fuzzing strategy."""

import ast
import csv
import random
import time
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments.llm_provider import OllamaProvider
from experiments import fuzzing_benchmark as benchmark
from experiments.planted_fault_experiment import is_planted_fault_triggered

OUTPUT = ROOT / "experiments" / "llm_results" / "strategy_comparison.csv"
SEED = 42
BUDGET = 1000

PROMPT = """
Write Python source code only, defining exactly this function:
def generate_candidates(seeds, iterations):

Requirements:
- seeds is a non-empty list of bytes objects.
- Return exactly iterations bytes objects.
- Use only these built-ins: bytes, bytearray, len, range, min, max, int, list.
- Do not use imports, global variables, filesystem, network, subprocess,
  eval, exec, open, compile, or external modules.
- Do not call encode() or assume seeds are strings.
- This experiment targets a SOME/IP Length-field validation defect.
- SOME/IP bytes 4 through 7 contain the big-endian Length field.
- For a packet of total size N, the declared Length should normally be N - 8, but the planted fault requires deliberately incorrect values.
- Generate candidates by changing bytes 4 through 7 to values such as 0, 1, N, N-9, and N+1, where N is the total packet size. The declared Length MUST disagree with N-8.
- Also retain some unchanged or differently mutated seed candidates.
- Derive every candidate from a seed; inputs are bytes, not strings.
- Use only the allowed built-ins listed above.
- No Markdown fences or explanatory text.
"""


def validate_strategy(source):
    source = source.strip()
    lines = source.splitlines()

    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

    source = "\n".join(lines).strip()
    tree = ast.parse(source)

    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "generate_candidates"
    ]
    if len(functions) != 1:
        raise ValueError("Expected exactly one generate_candidates function")

    forbidden = (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)
    if any(isinstance(node, forbidden) for node in ast.walk(tree)):
        raise ValueError("Imports and global state are not allowed")

    forbidden_calls = {"eval", "exec", "open", "compile", "__import__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in forbidden_calls:
                raise ValueError(f"Forbidden call: {node.func.id}")

    return compile(tree, "<llm_strategy>", "exec")

def run_strategy(source, seeds, iterations):
    code = validate_strategy(source)
    namespace = {}
    exec(code, {"__builtins__": {
        "bytes": bytes,
        "bytearray": bytearray,
        "len": len,
        "range": range,
        "min": min,
        "max": max,
        "int": int,
        "list": list,
    }}, namespace)

    candidates = namespace["generate_candidates"](seeds, iterations)

    if not isinstance(candidates, (list, tuple)) or not candidates:
        raise ValueError("Strategy must return a non-empty list or tuple")
    if any(not isinstance(item, bytes) for item in candidates):
        raise ValueError("Every candidate must be bytes")

    # Normalize the output to the same candidate budget as other strategies.
    candidates = list(candidates[:iterations])
    while len(candidates) < iterations:
        candidates.append(candidates[len(candidates) % len(candidates)])

    return candidates



def main():
    seeds = benchmark.someip_seeds()
    strategy_file = ROOT / "experiments" / "llm_results" / "llm_strategy.py"

    if not strategy_file.exists():
        raise FileNotFoundError("Run the LLM strategy generation first.")

    source = strategy_file.read_text(encoding="utf-8")
    trial_seeds = [42, 43, 44, 45, 46]
    rows = []

    for trial in trial_seeds:
        print(f"Running trial seed: {trial}")

        for algorithm in benchmark.ALGORITHMS:
            random.seed(trial)
            generated, _ = benchmark.run_algorithm("someip", algorithm, seeds)

            if algorithm == "stateful":
                generated = [message for seq in generated for message in seq]

            candidates = generated[:BUDGET]
            detections = [
                i + 1 for i, candidate in enumerate(candidates)
                if is_planted_fault_triggered(candidate)
            ]

            rows.append({
                "strategy": algorithm,
                "seed": trial,
                "budget": len(candidates),
                "unique_candidates": len(set(candidates)),
                "planted_fault_detections": len(detections),
                "detection_rate_pct": round(
                    len(detections) / len(candidates) * 100, 2
                ) if candidates else 0,
                "tests_to_first_detection": detections[0] if detections else "",
            })

        # Rotate the seed corpus so each deterministic LLM trial starts
        # from a different seed message.
        offset = (trial - trial_seeds[0]) % len(seeds)
        rotated_seeds = seeds[offset:] + seeds[:offset]

        random.seed(trial)
        candidates = run_strategy(source, rotated_seeds, BUDGET)
        detections = [
            i + 1 for i, candidate in enumerate(candidates)
            if is_planted_fault_triggered(candidate)
        ]

        rows.append({
            "strategy": "llm_generated_ollama",
            "seed": trial,
            "budget": len(candidates),
            "unique_candidates": len(set(candidates)),
            "planted_fault_detections": len(detections),
            "detection_rate_pct": round(
                len(detections) / len(candidates) * 100, 2
            ) if candidates else 0,
            "tests_to_first_detection": detections[0] if detections else "",
        })

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", newline="", encoding="utf-8") as file:
        fields = [
            "strategy", "seed", "budget", "unique_candidates",
            "planted_fault_detections", "detection_rate_pct",
            "tests_to_first_detection",
        ]
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved: {OUTPUT.relative_to(ROOT)}")
    print(f"Trials: {len(trial_seeds)}")
    print(f"Total records: {len(rows)}")


if __name__ == "__main__":
    main()
