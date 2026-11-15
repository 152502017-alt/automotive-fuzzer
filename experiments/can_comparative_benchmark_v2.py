import sys
import csv
import json
import time
from pathlib import Path
from datetime import datetime
from collections import Counter
from can.can_parser import CANLengthError, CANValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from can.fuzz_strategies import STRATEGIES
from can.can_parser import parse_can_frame, CANValidationError
from can.can_faulty_parser import parse_can_frame_faulty

LLM_RUN = (
    ROOT / "experiments" / "can_results" / "can_llm_v2"
    / "run_20261110_222152_459935"
)

SEEDS = [42, 43, 44, 45, 46]
BUDGET = 1000

BASELINES = [
    "random",
    "boundary",
    "structure",
    "stateful",
    "genetic",
    "ml_guided",
]

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


def serialize(frame):
    return {
        "can_id": frame["can_id"],
        "dlc": frame["dlc"],
        "data_hex": frame["data"].hex()
    }



def evaluate(frames, strategy, seed):
    detections = 0
    mismatches = 0
    correct_rejections = 0
    faulty_acceptances = 0

    for frame in frames:
        dlc = frame["dlc"]
        data = frame["data"]

        if dlc != len(data):
            mismatches += 1

        correct_rejected_for_target_fault = False
        faulty_accepted = False

        try:
            parse_can_frame(frame)
        except CANLengthError:
            correct_rejected_for_target_fault = True
        except CANValidationError:
            correct_rejections += 1

        try:
            parse_can_frame_faulty(frame)
            faulty_accepted = True
        except CANValidationError:
            pass

        if correct_rejected_for_target_fault:
            correct_rejections += 1

        if faulty_accepted:
            faulty_acceptances += 1

        if correct_rejected_for_target_fault and faulty_accepted:
            detections += 1

    unique_candidates = len({
        (f["can_id"], f["dlc"], f["data"]) for f in frames
    })
    unique_length_patterns = len({
        (f["dlc"], len(f["data"])) for f in frames
    })

    return {
        "unique_candidates": unique_candidates,
        "unique_length_patterns": unique_length_patterns,
        "strategy": strategy,
        "seed": seed,
        "total_candidates": len(frames),
        "detections": detections,
        "detection_rate_pct": round(
            detections / len(frames) * 100, 2
        ) if frames else 0,
        "length_mismatches": mismatches,
        "correct_rejections": correct_rejections,
        "faulty_acceptances": faulty_acceptances,
    }


def load_llm_frames(seed):
    path = LLM_RUN / f"seed_{seed}_dataset.json"

    if not path.exists():
        raise FileNotFoundError(path)

    with path.open() as f:
        dataset = json.load(f)

    return [
        {
            "can_id": x["can_id"],
            "dlc": x["dlc"],
            "data": bytes.fromhex(x["data_hex"])
        }
        for x in dataset["frames"]
    ]


def main():
    if not LLM_RUN.exists():
        raise FileNotFoundError(
            f"Saved LLM run not found: {LLM_RUN}"
        )

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    output = (
        ROOT / "experiments" / "can_results"
        / "can_comparison_v2" / f"run_{run_id}"
    )
    output.mkdir(parents=True, exist_ok=False)

    rows = []

    print("=" * 75)
    print("CAN FUZZING COMPARATIVE BENCHMARK V2")
    print("=" * 75)
    print("LLM source:", LLM_RUN)
    print("Budget:", BUDGET)
    print("Seeds:", SEEDS)

    for seed in SEEDS:
        print(f"\n========== SEED {seed} ==========")

        # Reuse the exact saved LLM candidate dataset.
        llm_frames = load_llm_frames(seed)
        result = evaluate(llm_frames, "llm_generated", seed)
        rows.append(result)

        print(
            f"LLM: {result['detections']} detections "
            f"({result['detection_rate_pct']}%)"
        )

        for name in BASELINES:
            print(f"\nGenerating {name}...")

            start = time.perf_counter()
            frames = STRATEGIES[name](seed, BUDGET)
            elapsed = time.perf_counter() - start

            if len(frames) != BUDGET:
                raise RuntimeError(
                    f"{name} generated {len(frames)}, "
                    f"expected {BUDGET}"
                )

            result = evaluate(frames, name, seed)
            result["generation_time_sec"] = round(elapsed, 4)
            rows.append(result)

            dataset_path = output / f"{name}_seed_{seed}.json"
            with dataset_path.open("x") as f:
                json.dump(
                    [serialize(frame) for frame in frames],
                    f
                )

            print(
                f"{name}: {result['detections']} detections "
                f"({result['detection_rate_pct']}%)"
            )

        # Save the LLM evaluation record too.
        llm_path = output / f"llm_generated_seed_{seed}.json"
        with llm_path.open("x") as f:
            json.dump(
                [serialize(frame) for frame in llm_frames],
                f
            )

    detailed_path = output / "comparison_detailed.csv"

    with detailed_path.open("x", newline="") as f:
        writer = csv.DictWriter(f, fieldnames = list(dict.fromkeys(key for row in rows for key in row.keys())))
        writer.writeheader()
        writer.writerows(rows)

    for row in rows:
        row.setdefault("total_candidates", BUDGET)
        row.setdefault("unique_candidates", 0)
        row.setdefault("unique_length_patterns", 0)

    grouped = {}
    for row in rows:
        grouped.setdefault(row["strategy"], []).append(row)

    summary = []

    for name, group in grouped.items():
        summary.append({
            "strategy": name,
            "trials": len(group),
            "total_candidates": sum(x["total_candidates"] for x in group),
            "average_unique_candidates": round(
                sum(x["unique_candidates"] for x in group)
                / len(group), 2
            ),
            "average_unique_length_patterns": round(
                sum(x["unique_length_patterns"] for x in group)
                / len(group), 2
            ),
            "average_detections": round(
                sum(x["detections"] for x in group)
                / len(group), 2
            ),
            "average_detection_rate_pct": round(
                sum(x["detection_rate_pct"] for x in group)
                / len(group), 2
            )
        })

    summary_path = output / "comparison_summary.csv"

    with summary_path.open("x", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=summary[0].keys())
        writer.writeheader()
        writer.writerows(summary)

    print("\n" + "=" * 75)
    print("COMPARATIVE RESULTS")
    print("=" * 75)

    for row in sorted(
        summary,
        key=lambda x: x["average_detection_rate_pct"],
        reverse=True
    ):
        print(
            f"{row['strategy']:16} "
            f"Detection: {row['average_detection_rate_pct']:6.2f}% "
            f"Unique patterns: {row['average_unique_length_patterns']:6.2f}"
        )

    print("\nDetailed CSV:", detailed_path)
    print("Summary CSV:", summary_path)
    print("Saved datasets:", output)


if __name__ == "__main__":
    main()
