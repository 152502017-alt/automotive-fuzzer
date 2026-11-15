import random
import json
import urllib.request
import urllib.error


def make_frame(rng, dlc=None, payload_len=None):
    if payload_len is None:
        payload_len = rng.randint(0, 8)
    if dlc is None:
        dlc = rng.randint(0, 8)

    return {
        "can_id": rng.randint(0, 0x7FF),
        "dlc": dlc,
        "data": bytes(rng.randint(0, 255) for _ in range(payload_len))
    }


def random_strategy(seed, budget):
    rng = random.Random(seed)
    return [make_frame(rng) for _ in range(budget)]


def boundary_strategy(seed, budget):
    rng = random.Random(seed)
    values = [-1, 0, 1, 7, 8, 9, 255]
    result = []

    while len(result) < budget:
        dlc = rng.choice(values)
        payload_len = rng.choice(values)
        result.append(make_frame(
            rng,
            dlc=dlc,
            payload_len=max(0, min(8, payload_len))
        ))

    return result


def structure_strategy(seed, budget):
    rng = random.Random(seed)
    result = []

    for _ in range(budget):
        payload_len = rng.randint(0, 8)
        dlc = payload_len if rng.random() < 0.5 else rng.randint(0, 8)
        result.append(make_frame(rng, dlc, payload_len))

    return result


def stateful_strategy(seed, budget):
    rng = random.Random(seed)
    result = []
    current_id = rng.randint(0, 0x7FF)

    for i in range(budget):
        if i % 10 == 0:
            current_id = rng.randint(0, 0x7FF)

        payload_len = rng.randint(0, 8)
        dlc = payload_len if rng.random() < 0.4 else rng.randint(0, 8)

        frame = make_frame(rng, dlc, payload_len)
        frame["can_id"] = current_id
        result.append(frame)

    return result


def coverage_strategy(seed, budget):
    rng = random.Random(seed)
    result = []
    seen = set()

    while len(result) < budget:
        frame = make_frame(rng)
        key = (frame["dlc"], len(frame["data"]))

        if key not in seen:
            seen.add(key)

        result.append(frame)

    return result


def genetic_strategy(seed, budget):
    rng = random.Random(seed)

    population = [
        make_frame(rng) for _ in range(30)
    ]

    result = []

    def fitness(frame):
        return int(frame["dlc"] != len(frame["data"]))

    while len(result) < budget:
        population.sort(key=fitness, reverse=True)

        parent = rng.choice(population[:15])
        child = {
            "can_id": parent["can_id"],
            "dlc": parent["dlc"],
            "data": bytes(parent["data"])
        }

        mutation = rng.choice(["dlc", "payload", "id"])

        if mutation == "dlc":
            child["dlc"] = rng.randint(0, 8)

        elif mutation == "payload":
            length = rng.randint(0, 8)
            child["data"] = bytes(
                rng.randint(0, 255) for _ in range(length)
            )

        else:
            child["can_id"] = rng.randint(0, 0x7FF)

        result.append(child)
        population.append(child)

        if len(population) > 50:
            population = population[-50:]

    return result


def ml_guided_strategy(seed, budget):
    rng = random.Random(seed)
    result = []

    # Simple heuristic-guided mutation.
    # Prioritizes DLC/payload mismatches.
    for i in range(budget):
        payload_len = rng.randint(0, 8)

        if i % 3 == 0:
            dlc = payload_len
        else:
            choices = [x for x in range(9) if x != payload_len]
            dlc = rng.choice(choices)

        result.append(make_frame(rng, dlc, payload_len))

    return result


def llm_strategy(seed, budget):
    rng = random.Random(seed)

    prompt = """
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
"""

    model_candidates = []
    fallback_candidates = []
    model_available = False

    try:
        request_data = json.dumps({
            "model": "qwen2.5-coder:7b",
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.7}
        }).encode()

        request = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=request_data,
            headers={"Content-Type": "application/json"}
        )

        with urllib.request.urlopen(request, timeout=90) as response:
            output = json.loads(response.read().decode())

        response_text = output.get("response", "{}")
        parsed = json.loads(response_text)
        pairs = parsed.get("pairs", [])

        for pair in pairs:
            if (
                isinstance(pair, list)
                and len(pair) == 2
                and all(isinstance(x, int) and 0 <= x <= 8 for x in pair)
            ):
                model_candidates.append(tuple(pair))

        model_available = len(model_candidates) > 0

    except Exception as error:
        print("LLM unavailable:", str(error))

    # Expand model-proposed patterns with different IDs and payloads.
    result = []

    if model_available:
        index = 0
        while len(result) < budget:
            dlc, payload_len = model_candidates[index % len(model_candidates)]
            result.append(make_frame(rng, dlc, payload_len))
            index += 1

    # If Ollama fails, use a clearly labelled deterministic fallback.
    else:
        for i in range(budget):
            payload_len = i % 9
            dlc = (payload_len + 1) % 9
            fallback_candidates.append(
                make_frame(rng, dlc, payload_len)
            )
        result = fallback_candidates

    metadata = {
        "llm_available": model_available,
        "llm_proposed_pairs": len(model_candidates),
        "fallback_candidates": len(fallback_candidates)
    }

    return result, metadata


STRATEGIES = {
    "random": random_strategy,
    "boundary": boundary_strategy,
    "structure": structure_strategy,
    "stateful": stateful_strategy,
    "coverage": coverage_strategy,
    "genetic": genetic_strategy,
    "ml_guided": ml_guided_strategy,
    "llm_generated": llm_strategy
}
