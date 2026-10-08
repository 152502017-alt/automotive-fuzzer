import csv
import time

from experiments.fuzzer import (
    RandomFuzzer,
    BoundaryFuzzer,
    StructureFuzzer,
    GeneticFuzzer,
    CoverageFuzzer,
    MLGUIDEDFuzzer,
)


def run_fuzzer(fuzzer, seed, count=1000):
    start = time.perf_counter()

    results = fuzzer.fuzz(seed, count)

    elapsed = time.perf_counter() - start

    return {
        "strategy": fuzzer.name,
        "tests": len(results),
        "time": elapsed,
        "tests_per_second": (
            len(results) / elapsed if elapsed else 0
        ),
    }


def run_all(seed):
    fuzzers = [
        RandomFuzzer(),
        BoundaryFuzzer(),
        StructureFuzzer(),
        GeneticFuzzer(),
        CoverageFuzzer(),
        MLGUIDEDFuzzer(),
    ]

    rows = []

    for fuzzer in fuzzers:
        rows.append(run_fuzzer(fuzzer, seed))

    with open(
        "experiments/results.csv",
        "w",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=rows[0].keys(),
        )

        writer.writeheader()
        writer.writerows(rows)

    return rows