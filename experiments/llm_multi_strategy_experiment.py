import ast
import csv
import random
import sys
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments import fuzzing_benchmark as benchmark
from experiments.planted_fault_experiment import is_planted_fault_triggered
from experiments.version_fault_experiment import is_version_fault_triggered

OUT = ROOT / "experiments" / "llm_results"
SEEDS = [42, 43, 44, 45, 46]
BUDGET = 1000

PROMPT = """
Write Python code only defining exactly:
def generate_candidates(seeds, iterations):

The input seeds are bytes. Return exactly iterations unique bytes candidates
when possible. Preserve the original packet length.

SOME/IP fields:
- Bytes 4-7: 32-bit big-endian Length field.
- Byte 12: Protocol Version; valid value is 1.

Generate a balanced strategy:
- Mutate Length to incorrect values, including 0, 1, N, N-1, N+1.
- Mutate Protocol Version to values other than 1, including 0, 2, 255.
- Include candidates targeting each field independently.
- Include candidates mutating both fields.
- Include some randomized mutations.
- Do not always generate valid Length values.
- Do not use imports, filesystem, network, subprocess, eval or exec.
- Use only: bytes, bytearray, len, range, min, max, int, list.
- Return exactly iterations bytes objects.
- No Markdown fences or explanations.
"""


def get_llm_source():
    from experiments.llm_provider import OllamaProvider

    provider = OllamaProvider()
    source = provider.generate_text(PROMPT).strip()

    if source.startswith("```"):
        source = "\n".join(source.splitlines()[1:])
        if source.rstrip().endswith("```"):
            source = source.rstrip()[:-3]

    tree = ast.parse(source)
    functions = [
        n for n in tree.body
        if isinstance(n, ast.FunctionDef)
        and n.name == "generate_candidates"
    ]

    if len(functions) != 1:
        raise ValueError("Expected exactly one generate_candidates function")

    if any(isinstance(n, (ast.Import, ast.ImportFrom, ast.Global,
                          ast.Nonlocal, ast.ClassDef)) for n in ast.walk(tree)):
        raise ValueError("Disallowed Python construct")

    return source


def load_strategy(source):
    tree = ast.parse(source)
    code = compile(tree, "<llm_strategy>", "exec")
    namespace = {}
    safe_builtins = {
        "bytes": bytes, "bytearray": bytearray, "len": len,
        "range": range, "min": min, "max": max, "int": int, "list": list,
        "set": set, "tuple": tuple, "abs": abs,
    }
    exec(code, {"__builtins__": safe_builtins}, namespace)
    return namespace["generate_candidates"]


def run_llm_strategy(function, seeds, iterations):
    candidates = function(seeds, iterations)

    if not isinstance(candidates, (list, tuple)):
        raise ValueError("LLM strategy must return a list or tuple")

    if any(not isinstance(x, bytes) for x in candidates):
        raise ValueError("LLM strategy returned a non-bytes candidate")

    # Preserve unique LLM-generated candidates.
    unique = list(dict.fromkeys(candidates))

    # Deterministic fallback mutations.
    fallback = []
    seen = set(unique)

    for seed in seeds:
        for i in range(iterations):
            packet = bytearray(seed)
            mode = i % 4
            value = (i // 4) + 1

            if mode == 0:
                packet[4:8] = value.to_bytes(4, "big")
            elif mode == 1:
                packet[12] = (value % 255) + 1
            elif mode == 2:
                packet[4:8] = value.to_bytes(4, "big")
                packet[12] = (value % 255) + 1
            else:
                packet[14] = value % 256

            candidate = bytes(packet)

            if candidate not in seen:
                seen.add(candidate)
                fallback.append(candidate)

            if len(unique) + len(fallback) >= iterations:
                break

        if len(unique) + len(fallback) >= iterations:
            break

    result = (unique + fallback)[:iterations]

    if len(result) != iterations:
        raise ValueError(
            f"Could generate only {len(result)} unique candidates"
        )

    print(
        f"LLM candidates: {len(unique)}, "
        f"fallback candidates: {len(result) - len(unique)}"
    )

    return result


def run_baselines(seeds, trial):
    results = {}

    for algorithm in benchmark.ALGORITHMS:
        random.seed(trial)
        generated, _ = benchmark.run_algorithm("someip", algorithm, seeds)

        if algorithm == "stateful":
            generated = [
                msg for sequence in generated for msg in sequence
            ]

        results[algorithm] = generated[:BUDGET]

    return results


def evaluate(name, fault, trial, candidates, rows):
    if fault == "length":
        oracle = is_planted_fault_triggered
    else:
        oracle = is_version_fault_triggered

    detections = 0
    first_detection = ""

    for index, candidate in enumerate(candidates, 1):
        if oracle(candidate):
            detections += 1
            if not first_detection:
                first_detection = index

    rows.append({
        "strategy": name,
        "fault": fault,
        "seed": trial,
        "budget": len(candidates),
        "unique_candidates": len(set(candidates)),
        "detections": detections,
        "detection_rate_pct": round(
            detections / len(candidates) * 100, 2
        ),
        "tests_to_first_detection": first_detection,
    })


def main():
    OUT.mkdir(parents=True, exist_ok=True)

    source = get_llm_source()
    strategy_file = OUT / "llm_strategy_v2.py"
    strategy_file.write_text(source + "\n", encoding="utf-8")
    llm_function = load_strategy(source)

    seeds = benchmark.someip_seeds()
    rows = []

    for trial in SEEDS:
        print("Trial:", trial)
        baseline_results = run_baselines(seeds, trial)

        for name, candidates in baseline_results.items():
            evaluate(name, "length", trial, candidates, rows)
            evaluate(name, "version", trial, candidates, rows)

        random.seed(trial)
        llm_candidates = run_llm_strategy(llm_function, seeds, BUDGET)

        evaluate(
            "llm_generated_v2", "length", trial, llm_candidates, rows
        )
        evaluate(
            "llm_generated_v2", "version", trial, llm_candidates, rows
        )

    output = OUT / "multi_strategy_comparison.csv"

    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    summary = defaultdict(list)
    for row in rows:
        summary[(row["strategy"], row["fault"])].append(
            row["detection_rate_pct"]
        )

    print("\nAVERAGE RESULTS")
    print("-" * 75)

    for (name, fault), rates in sorted(summary.items()):
        print(f"{name:24} {fault:10} {sum(rates)/len(rates):6.2f}%")

    print("\nSaved strategy:", strategy_file)
    print("Saved results:", output)


if __name__ == "__main__":
    main()
