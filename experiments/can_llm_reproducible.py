import sys
import csv
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from can.fuzz_strategies import make_frame
from can.can_parser import parse_can_frame, CANValidationError
from can.can_faulty_parser import parse_can_frame_faulty

MODEL = "qwen2.5-coder:7b"
OLLAMA_URL = "http://localhost:11434/api/generate"

SEEDS = [42, 43, 44, 45, 46]
BUDGET = 1000
TEMPERATURE = 0.7

BASE_OUTPUT = ROOT / "experiments" / "can_results" / "can_llm_v2"
BASE_OUTPUT.mkdir(parents=True, exist_ok=True)

PROMPT = """
Generate CAN parser fuzzing test patterns.

We are testing Classical CAN standard data frames.

DLC range: 0 to 8.
Actual payload length range: 0 to 8.

The target is a missing validation check:
DLC must equal actual payload length.

Return ONLY JSON in this format:
{
  "pairs": [[8, 4], [0, 8], [5, 2], [3, 7]]
}

Generate as many diverse DLC and payload-length pairs as possible.
Include both matching and mismatching pairs.
"""


def generate_llm_pairs(seed):
    request_data = {
        "model": MODEL,
        "prompt": PROMPT,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": TEMPERATURE,
            "seed": seed
        }
    }

    encoded = json.dumps(request_data).encode()

    request = urllib.request.Request(
        OLLAMA_URL,
        data=encoded,
        headers={"Content-Type": "application/json"}
    )

    with urllib.request.urlopen(request, timeout=120) as response:
        raw_response = response.read().decode()

    response_object = json.loads(raw_response)
    response_text = response_object.get("response", "{}")
    parsed = json.loads(response_text)

    pairs = []
    for pair in parsed.get("pairs", []):
        if (
            isinstance(pair, list)
            and len(pair) == 2
            and all(
                isinstance(x, int)
                and not isinstance(x, bool)
                and 0 <= x <= 8
                for x in pair
            )
        ):
            pairs.append(tuple(pair))

    if not pairs:
        raise ValueError(
            f"Ollama returned no valid pairs for seed {seed}. "
            "No fallback will be used."
        )

    return pairs, raw_response, response_object


def generate_dataset(seed, run_dir):
    import random

    print(f"\nGenerating candidates for seed {seed}...")

    start = time.perf_counter()

    pairs, raw_response, response_object = generate_llm_pairs(seed)

    rng = random.Random(seed)

    frames = []
    index = 0

    while len(frames) < BUDGET:
        dlc, payload_len = pairs[index % len(pairs)]
        frames.append(make_frame(rng, dlc, payload_len))
        index += 1

    elapsed = time.perf_counter() - start

    dataset = {
        "experiment": "CAN LLM reproducible experiment v2",
        "seed": seed,
        "model": MODEL,
        "temperature": TEMPERATURE,
        "budget": BUDGET,
        "generation_time_sec": round(elapsed, 4),
        "prompt": PROMPT,
        "raw_ollama_response": raw_response,
        "ollama_response_metadata": {
            key: value
            for key, value in response_object.items()
            if key != "response"
        },
        "llm_proposed_pairs": [list(pair) for pair in pairs],
        "fallback_candidates": 0,
        "frames": [
            {
                "can_id": frame["can_id"],
                "dlc": frame["dlc"],
                "data_hex": frame["data"].hex()
            }
            for frame in frames
        ]
    }

    path = run_dir / f"seed_{seed}_dataset.json"

    with path.open("x") as f:
        json.dump(dataset, f, indent=2)

    print("LLM patterns:", len(pairs))
    print("Frames saved:", len(frames))
    print("Dataset:", path)

    return path


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


def evaluate_dataset(path):
    with path.open() as f:
        dataset = json.load(f)

    frames = [
        {
            "can_id": item["can_id"],
            "dlc": item["dlc"],
            "data": bytes.fromhex(item["data_hex"])
        }
        for item in dataset["frames"]
    ]

    pair_counts = Counter(
        (frame["dlc"], len(frame["data"]))
        for frame in frames
    )

    detections = sum(
        is_fault_triggered(frame)
        for frame in frames
    )

    mismatching_patterns = {
        f"{dlc}:{length}": count
        for (dlc, length), count in pair_counts.items()
        if dlc != length
    }

    matching_patterns = {
        f"{dlc}:{length}": count
        for (dlc, length), count in pair_counts.items()
        if dlc == length
    }

    mismatching_frames = sum(mismatching_patterns.values())
    matching_frames = sum(matching_patterns.values())

    if detections != mismatching_frames:
        raise RuntimeError(
            f"Oracle mismatch for seed {dataset['seed']}: "
            f"{detections} detections vs {mismatching_frames} "
            "mismatching frames"
        )

    result = {
        "seed": dataset["seed"],
        "model": dataset["model"],
        "temperature": dataset["temperature"],
        "budget": len(frames),
        "llm_proposed_pairs": len(dataset["llm_proposed_pairs"]),
        "unique_llm_pairs": len({
            tuple(pair) for pair in dataset["llm_proposed_pairs"]
        }),
        "unique_frame_patterns": len(pair_counts),
        "unique_candidates": len({
            (
                frame["can_id"],
                frame["dlc"],
                frame["data"].hex()
            )
            for frame in frames
        }),
        "mismatching_patterns": len(mismatching_patterns),
        "matching_patterns": len(matching_patterns),
        "mismatching_frames": mismatching_frames,
        "matching_frames": matching_frames,
        "detections": detections,
        "detection_rate_pct": round(
            detections / len(frames) * 100, 2
        ),
        "generation_time_sec": dataset["generation_time_sec"]
    }

    return result, mismatching_patterns, matching_patterns


def main():
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    run_dir = BASE_OUTPUT / f"run_{run_id}"
    run_dir.mkdir(parents=True, exist_ok=False)

    print("=" * 75)
    print("CAN LLM REPRODUCIBLE EXPERIMENT V2")
    print("=" * 75)
    print("Model:", MODEL)
    print("Temperature:", TEMPERATURE)
    print("Seeds:", SEEDS)
    print("Budget per seed:", BUDGET)
    print("Run directory:", run_dir)

    result_rows = []

    for seed in SEEDS:
        try:
            dataset_path = generate_dataset(seed, run_dir)
        except Exception as error:
            print(f"\nERROR generating seed {seed}: {error}")
            print("Stopping. Previously saved datasets are preserved.")
            raise

        result, mismatch, matching = evaluate_dataset(dataset_path)
        result_rows.append(result)

        print("\nEvaluation:")
        print("Unique frame patterns:", result["unique_frame_patterns"])
        print("Mismatching patterns:", result["mismatching_patterns"])
        print("Matching patterns:", result["matching_patterns"])
        print("Mismatching frames:", result["mismatching_frames"])
        print("Matching frames:", result["matching_frames"])
        print("Oracle detections:", result["detections"])
        print("Detection rate:", result["detection_rate_pct"], "%")

        pattern_path = run_dir / f"seed_{seed}_patterns.json"
        with pattern_path.open("x") as f:
            json.dump({
                "mismatching_patterns": mismatch,
                "matching_patterns": matching
            }, f, indent=2)

    detailed_path = run_dir / "detailed_results.csv"

    with detailed_path.open("x", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=result_rows[0].keys()
        )
        writer.writeheader()
        writer.writerows(result_rows)

    summary = {
        "trials": len(result_rows),
        "total_candidates": sum(r["budget"] for r in result_rows),
        "average_detection_rate_pct": round(
            sum(r["detection_rate_pct"] for r in result_rows)
            / len(result_rows), 2
        ),
        "average_detections": round(
            sum(r["detections"] for r in result_rows)
            / len(result_rows), 2
        ),
        "average_unique_candidates": round(
            sum(r["unique_candidates"] for r in result_rows)
            / len(result_rows), 2
        ),
        "average_generation_time_sec": round(
            sum(r["generation_time_sec"] for r in result_rows)
            / len(result_rows), 4
        )
    }

    summary_path = run_dir / "summary.json"
    with summary_path.open("x") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 75)
    print("FINAL V2 SUMMARY")
    print("=" * 75)

    for key, value in summary.items():
        print(f"{key}: {value}")

    print("\nSaved datasets and results:")
    print(run_dir)
    print("Detailed CSV:", detailed_path)
    print("Summary JSON:", summary_path)


if __name__ == "__main__":
    main()
