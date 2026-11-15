import sys
import csv
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from can.fuzz_strategies import llm_strategy
from can.can_parser import parse_can_frame, CANValidationError
from can.can_faulty_parser import parse_can_frame_faulty

OUTPUT = ROOT / "experiments" / "can_results"
OUTPUT.mkdir(parents=True, exist_ok=True)

SEEDS = [42, 43, 44, 45, 46]
BUDGET = 1000


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


def main():
    rows = []

    print("=" * 70)
    print("LLM CAN PATTERN DIAGNOSTIC")
    print("NOTE: This makes NEW Ollama calls; it does not reproduce old trials.")
    print("=" * 70)

    for seed in SEEDS:
        print(f"\n--- Seed {seed} ---")

        frames, metadata = llm_strategy(seed, BUDGET)

        pair_counts = Counter(
            (frame["dlc"], len(frame["data"]))
            for frame in frames
        )

        mismatch_patterns = {
            pair: count
            for pair, count in pair_counts.items()
            if pair[0] != pair[1]
        }

        matching_patterns = {
            pair: count
            for pair, count in pair_counts.items()
            if pair[0] == pair[1]
        }

        detections = sum(is_fault_triggered(frame) for frame in frames)

        print("LLM available:", metadata["llm_available"])
        print("LLM proposed pairs:", metadata["llm_proposed_pairs"])
        print("Fallback candidates:", metadata["fallback_candidates"])
        print("Generated frames:", len(frames))
        print("Unique (DLC, payload length) patterns:", len(pair_counts))
        print("Mismatching patterns:", mismatch_patterns)
        print("Matching patterns:", matching_patterns)
        print("Mismatching frames:", sum(mismatch_patterns.values()))
        print("Matching frames:", sum(matching_patterns.values()))
        print("Oracle detections:", detections)

        if sum(mismatch_patterns.values()) != detections:
            print("WARNING: Mismatch count and oracle detections differ.")

        rows.append({
            "seed": seed,
            "llm_available": metadata["llm_available"],
            "llm_proposed_pairs": metadata["llm_proposed_pairs"],
            "fallback_candidates": metadata["fallback_candidates"],
            "generated_frames": len(frames),
            "unique_length_patterns": len(pair_counts),
            "mismatching_patterns": len(mismatch_patterns),
            "matching_patterns": len(matching_patterns),
            "mismatching_frames": sum(mismatch_patterns.values()),
            "matching_frames": sum(matching_patterns.values()),
            "oracle_detections": detections,
            "detection_rate_pct": round(detections / len(frames) * 100, 2)
            if frames else 0
        })

    path = OUTPUT / "can_llm_pattern_diagnostic.csv"

    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print("\nDiagnostic CSV:", path)
    print("\nThis diagnostic does not modify your original benchmark results.")


if __name__ == "__main__":
    main()
