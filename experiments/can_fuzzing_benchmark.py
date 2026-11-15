import sys
import csv
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from can.can_parser import parse_can_frame, CANValidationError
from can.can_faulty_parser import parse_can_frame_faulty
from can.fuzz_strategies import STRATEGIES


OUTPUT = ROOT / "experiments" / "can_results"
OUTPUT.mkdir(parents=True, exist_ok=True)

BUDGET = 1000
SEEDS = [42, 43, 44, 45, 46]


def serialize(frame):
    return (
        frame["can_id"],
        frame["dlc"],
        frame["data"].hex()
    )


def is_fault_triggered(frame):
    try:
        parse_can_frame(frame)
        return False
    except CANValidationError as error:
        if type(error).__name__ != "CANLengthError":
            return False

    try:
        parse_can_frame_faulty(frame)
        return True
    except CANValidationError:
        return False


def run():
    rows = []

    print("=" * 65)
    print("CAN FUZZING STRATEGY COMPARISON")
    print("=" * 65)

    for strategy_name, strategy_function in STRATEGIES.items():

        for seed in SEEDS:
            print(f"\nStrategy: {strategy_name} | Seed: {seed}")

            start = time.perf_counter()
            metadata = {}

            if strategy_name == "llm_generated":
                candidates, metadata = strategy_function(seed, BUDGET)
            else:
                candidates = strategy_function(seed, BUDGET)

            elapsed = time.perf_counter() - start

            detections = sum(
                1 for frame in candidates
                if is_fault_triggered(frame)
            )

            unique_count = len({
                serialize(frame) for frame in candidates
            })

            detection_rate = detections / len(candidates) * 100

            row = {
                "strategy": strategy_name,
                "seed": seed,
                "budget": len(candidates),
                "unique_candidates": unique_count,
                "detections": detections,
                "detection_rate_pct": round(detection_rate, 2),
                "execution_time_sec": round(elapsed, 4),
                "llm_available": metadata.get("llm_available", ""),
                "llm_proposed_pairs": metadata.get("llm_proposed_pairs", ""),
                "fallback_candidates": metadata.get("fallback_candidates", "")
            }

            rows.append(row)

            print("Candidates:", len(candidates))
            print("Unique:", unique_count)
            print("Detections:", detections)
            print(f"Detection rate: {detection_rate:.2f}%")
            print(f"Generation time: {elapsed:.4f}s")

            if metadata:
                print("LLM metadata:", metadata)

    csv_path = OUTPUT / "can_strategy_comparison.csv"

    with open(csv_path, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    # Summary averaged over five trials
    summary = {}

    for row in rows:
        name = row["strategy"]
        summary.setdefault(name, []).append(row)

    summary_path = OUTPUT / "can_strategy_summary.csv"

    summary_rows = []

    for name, group in summary.items():
        summary_rows.append({
            "strategy": name,
            "trials": len(group),
            "average_budget": round(
                sum(x["budget"] for x in group) / len(group), 2
            ),
            "average_unique_candidates": round(
                sum(x["unique_candidates"] for x in group) / len(group), 2
            ),
            "average_detections": round(
                sum(x["detections"] for x in group) / len(group), 2
            ),
            "average_detection_rate_pct": round(
                sum(x["detection_rate_pct"] for x in group) / len(group), 2
            ),
            "average_execution_time_sec": round(
                sum(x["execution_time_sec"] for x in group) / len(group), 4
            )
        })

    with open(summary_path, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=summary_rows[0].keys())
        writer.writeheader()
        writer.writerows(summary_rows)

    print("\n" + "=" * 65)
    print("AVERAGE RESULTS")
    print("=" * 65)

    for row in summary_rows:
        print(
            f"{row['strategy']:16} "
            f"Detection: {row['average_detection_rate_pct']:6.2f}% "
            f"Unique: {row['average_unique_candidates']:7.2f}"
        )

    print("\nDetailed CSV:", csv_path)
    print("Summary CSV:", summary_path)
    print("Total records:", len(rows))


if __name__ == "__main__":
    run()
