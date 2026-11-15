import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import struct
from someip.message import build_someip_message, parse_someip_message
from someip.message_version_faulty import (
    parse_someip_message as parse_faulty,
)
from someip.error import SomeIPVersionError


def is_version_fault_triggered(data):
    try:
        parse_someip_message(data)
        return False
    except SomeIPVersionError:
        pass
    except Exception:
        return False

    try:
        parse_faulty(data)
        return True
    except Exception:
        return False


def create_version_mutations(seeds, iterations):
    candidates = []

    for seed in seeds:
        for version in range(256):
            candidate = bytearray(seed)
            if len(candidate) >= 16:
                candidate[12] = version
                candidates.append(bytes(candidate))

            if len(candidates) >= iterations:
                return candidates

    return candidates[:iterations]


if __name__ == "__main__":
    valid = build_someip_message(
        service_id=0x1234,
        method_id=0x0001,
        client_id=0x0001,
        session_id=0x0001,
        interface_version=1,
        message_type=0x00,
        return_code=0,
        payload=b"test",
    )

    mutated = bytearray(valid)
    mutated[12] = 2

    print("Original parser rejects:", end=" ")
    try:
        parse_someip_message(bytes(mutated))
        print(False)
    except Exception as exc:
        print(type(exc).__name__)

    print("Faulty parser accepts:", end=" ")
    try:
        parse_faulty(bytes(mutated))
        print(True)
    except Exception as exc:
        print(type(exc).__name__)

    print("Version fault triggered:", is_version_fault_triggered(bytes(mutated)))


def run_benchmark():
    import csv
    import random
    from pathlib import Path
    from experiments import fuzzing_benchmark as benchmark
    from experiments.llm_strategy_experiment import run_strategy

    root = Path(__file__).resolve().parents[1]
    strategy_file = root / "experiments/llm_results/llm_strategy.py"
    output = root / "experiments/llm_results/version_fault_comparison.csv"

    seeds = benchmark.someip_seeds()
    llm_source = strategy_file.read_text()
    rows = []

    for trial in [42, 43, 44, 45, 46]:
        for algorithm in benchmark.ALGORITHMS:
            random.seed(trial)
            generated, _ = benchmark.run_algorithm(
                "someip", algorithm, seeds
            )

            if algorithm == "stateful":
                generated = [
                    message for sequence in generated
                    for message in sequence
                ]

            candidates = generated[:1000]
            detections = sum(
                is_version_fault_triggered(candidate)
                for candidate in candidates
            )

            rows.append({
                "strategy": algorithm,
                "seed": trial,
                "budget": len(candidates),
                "unique_candidates": len(set(candidates)),
                "detections": detections,
                "detection_rate_pct": round(
                    detections / len(candidates) * 100, 2
                ) if candidates else 0,
            })

        random.seed(trial)
        candidates = run_strategy(llm_source, seeds, 1000)
        detections = sum(
            is_version_fault_triggered(candidate)
            for candidate in candidates
        )

        rows.append({
            "strategy": "llm_generated_ollama",
            "seed": trial,
            "budget": len(candidates),
            "unique_candidates": len(set(candidates)),
            "detections": detections,
            "detection_rate_pct": round(
                detections / len(candidates) * 100, 2
            ),
        })

    with output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print("Saved:", output)
    print("Trials:", 5)
    print("Records:", len(rows))


if __name__ == "__main__":
    run_benchmark()
