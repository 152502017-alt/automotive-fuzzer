import csv
import random
import time
from pathlib import Path

from experiments import fuzzing_benchmark as benchmark
from someip.message import build_someip_message, parse_someip_message
from someip.error import SomeIPLengthError
from someip.message_faulty import (
    parse_someip_message as parse_faulty,
)

ITERATIONS = 1000
BASE_SEEDS = [42, 43, 44, 45, 46]

OUTPUT = Path("experiments/planted_fault_results.csv")

SEEDS = benchmark.someip_seeds()

ALGORITHMS = [
    "random",
    "boundary",
    "structure",
    "coverage",
    "genetic",
    "stateful",
    "ml_guided",
]


def is_planted_fault_triggered(data):
    """Count only the specific planted length-validation fault."""
    try:
        parse_someip_message(data)
        return False
    except SomeIPLengthError:
        pass
    except Exception:
        # Invalid header or another failure is not this planted fault.
        return False

    try:
        parse_faulty(data)
        return True
    except Exception:
        return False

def flatten_candidates(algorithm, generated):
    """Flatten stateful sequences into individual parser inputs."""
    if algorithm == "stateful":
        return [
            message
            for sequence in generated
            for message in sequence
        ]
    return generated


def main():
    rows = []

    for algorithm in ALGORITHMS:
        for seed in BASE_SEEDS:
            random.seed(seed)

            start_generation = time.perf_counter()

            generated, _ = benchmark.run_algorithm(
                "someip",
                algorithm,
                SEEDS,
            )

            candidates = flatten_candidates(algorithm, generated)

            # Equal budget: at most 1,000 individual messages.
            candidates = candidates[:ITERATIONS]

            generation_seconds = time.perf_counter() - start_generation

            detected = False
            tests_to_detection = ""
            time_to_detection_ms = ""
            triggering_packet_hex = ""

            start_testing = time.perf_counter()

            for test_number, candidate in enumerate(candidates, start=1):
                if is_planted_fault_triggered(candidate):
                    detected = True
                    tests_to_detection = test_number
                    triggering_packet_hex = candidate.hex()
                    time_to_detection_ms = round(
                        (time.perf_counter() - start_testing) * 1000,
                        3,
                    )
                    break

            search_seconds = time.perf_counter() - start_testing

            row = {
                "protocol": "SOME/IP",
                "fault": "declared_actual_length_mismatch_accepted",
                "algorithm": algorithm,
                "seed": seed,
                "budget": ITERATIONS,
                "candidates_tested": (
                    tests_to_detection
                    if detected
                    else len(candidates)
                ),
                "generated_candidates": len(candidates),
                "detected": detected,
                "triggering_packet_hex": triggering_packet_hex,
                "tests_to_detection": tests_to_detection,
                "time_to_detection_ms": time_to_detection_ms,
                "generation_time_seconds": round(generation_seconds, 6),
                "search_time_seconds": round(search_seconds, 6),
            }

            rows.append(row)

            print(
                f"{algorithm:10} seed={seed} "
                f"detected={str(detected):5} "
                f"tests={tests_to_detection or 'N/A':>5} "
                f"time_ms={time_to_detection_ms or 'N/A':>8} "
                f"tested={row['candidates_tested']}"
            )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nTrial results saved to: {OUTPUT}")

    # Summarize detection rate and median tests-to-detection.
    print("\nSummary across five trials:")
    for algorithm in ALGORITHMS:
        group = [r for r in rows if r["algorithm"] == algorithm]
        detections = [r for r in group if r["detected"]]
        test_counts = sorted(
            int(r["tests_to_detection"])
            for r in detections
        )

        if test_counts:
            n = len(test_counts)
            median_tests = (
                test_counts[n // 2]
                if n % 2
                else (test_counts[n // 2 - 1] + test_counts[n // 2]) / 2
            )
            median_text = str(median_tests)
        else:
            median_text = "N/A"

        print(
            f"{algorithm:10} "
            f"detection_rate={len(detections)}/5 "
            f"median_tests_to_detection={median_text}"
        )


if __name__ == "__main__":
    main()