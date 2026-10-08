import csv
import hashlib
import random
import time
from pathlib import Path

from someip.message import build_someip_message, parse_someip_message
from someip.constants import (
    REQUEST,
    RESPONSE,
    PROTOCOL_VERSION,
)

from doip.message import build_doip_message, parse_doip_message
from doip.constants import (
    VEHICLE_IDENTIFICATION_REQUEST,
    ROUTING_ACTIVATION_REQUEST,
    ALIVE_CHECK_REQUEST,
    DIAGNOSTIC_MESSAGE,
)

from fuzzer.doip_state import DoIPStateMachine
from fuzzer.doip_mapper import DoIPMessageMapper
from fuzzer.state_guided import StateGuidedGenerator


ITERATIONS = 1000
RANDOM_SEED = 42

random.seed(RANDOM_SEED)


# ============================================================
# SEEDS
# ============================================================

def someip_seeds():
    request = build_someip_message(
        service_id=0x1234,
        method_id=0x0001,
        client_id=0x0010,
        session_id=0x0001,
        interface_version=1,
        message_type=REQUEST,
        return_code=0x00,
        payload=b"GetSpeed",
    )

    response = build_someip_message(
        service_id=0x1234,
        method_id=0x0001,
        client_id=0x0010,
        session_id=0x0001,
        interface_version=1,
        message_type=RESPONSE,
        return_code=0x00,
        payload=b"Speed:100",
    )

    return [request, response]


def doip_seeds():
    vehicle = build_doip_message(
        VEHICLE_IDENTIFICATION_REQUEST,
        b"",
    )

    routing = build_doip_message(
        ROUTING_ACTIVATION_REQUEST,
        b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    )

    alive = build_doip_message(
        ALIVE_CHECK_REQUEST,
        b"",
    )

    diagnostic = build_doip_message(
        DIAGNOSTIC_MESSAGE,
        b"\x00\x01\x00\x02\x22\xF1\x90",
    )

    return [vehicle, routing, alive, diagnostic]


# ============================================================
# MUTATION HELPERS
# ============================================================

def random_mutation(data):
    data = bytearray(data)

    if not data:
        return bytes([random.randrange(256)])

    for _ in range(random.randint(1, 3)):
        index = random.randrange(len(data))
        data[index] = random.randrange(256)

    return bytes(data)


def boundary_mutation(data):
    data = bytearray(data)

    if not data:
        return b"\x00"

    index = random.randrange(len(data))

    values = [
        0x00,
        0x01,
        0x7F,
        0x80,
        0xFE,
        0xFF,
    ]

    data[index] = random.choice(values)

    if random.random() < 0.15:
        return bytes(data[:-1])

    if random.random() < 0.15:
        return bytes(data) + b"\x00"

    return bytes(data)


def structure_mutation(data):
    data = bytearray(data)

    if len(data) < 8:
        return random_mutation(data)

    # Mutate protocol header fields.
    field = random.choice([
        "first_byte",
        "second_byte",
        "length_byte",
        "header_byte",
    ])

    if field == "first_byte":
        data[0] = random.randrange(256)

    elif field == "second_byte":
        data[1] = random.randrange(256)

    elif field == "length_byte":
        index = random.choice([4, 5, 6, 7])
        data[index] = random.randrange(256)

    else:
        index = random.randrange(min(16, len(data)))
        data[index] ^= random.choice([0x01, 0x10, 0x80, 0xFF])

    return bytes(data)


# ============================================================
# NON-STATEFUL FUZZERS
# ============================================================

def random_fuzzer(seeds, iterations):
    return [
        random_mutation(random.choice(seeds))
        for _ in range(iterations)
    ]


def boundary_fuzzer(seeds, iterations):
    return [
        boundary_mutation(random.choice(seeds))
        for _ in range(iterations)
    ]


def structure_fuzzer(seeds, iterations):
    return [
        structure_mutation(random.choice(seeds))
        for _ in range(iterations)
    ]


def coverage_fuzzer(seeds, iterations):
    corpus = list(seeds)
    results = []

    seen_features = set()

    for _ in range(iterations):
        seed = random.choice(corpus)
        candidate = random_mutation(seed)

        feature = (
            len(candidate),
            sum(candidate) % 256,
            max(candidate) if candidate else 0,
            min(candidate) if candidate else 0,
        )

        results.append(candidate)

        if feature not in seen_features:
            seen_features.add(feature)
            corpus.append(candidate)

    return results


def genetic_fuzzer(seeds, iterations):
    population = list(seeds)
    results = []

    while len(results) < iterations:
        parent1 = random.choice(population)
        parent2 = random.choice(population)

        if len(parent1) > 1 and len(parent2) > 1:
            cut1 = random.randrange(1, len(parent1))
            cut2 = random.randrange(1, len(parent2))

            child = parent1[:cut1] + parent2[cut2:]
        else:
            child = parent1

        child = random_mutation(child)

        population.append(child)
        results.append(child)

        if len(population) > 100:
            population.pop(0)

    return results[:iterations]


# ============================================================
# STATEFUL / SEQUENCE-AWARE FUZZER
# ============================================================

def stateful_fuzzer(seeds, iterations, protocol):
    """
    Generate protocol message sequences.

    DoIP uses the state-guided generator.
    SOME/IP keeps the existing sequence-aware implementation
    until a dedicated SOME/IP state model is available.
    """

    if protocol != "doip":
        sequences = []

        for _ in range(iterations):
            length = random.randint(
                1,
                min(4, len(seeds) + 2),
            )

            sequence = []

            for _ in range(length):
                sequence.append(
                    random_mutation(random.choice(seeds))
                )

            sequences.append(sequence)

        return sequences

    from fuzzer.state_guided import StateGuidedGenerator

    generator = StateGuidedGenerator()

    # Existing valid DoIP seed messages.
    #
    # These are templates because several payload types belong
    # to the same protocol event.
    templates = {
        0x0001: seeds[0],  # Vehicle Identification Request
        0x0002: seeds[0],
        0x0003: seeds[0],
        0x0004: seeds[0],

        0x0005: seeds[1],  # Routing Activation Request
        0x0006: seeds[1],

        0x0007: seeds[2],  # Alive Check Request
        0x0008: seeds[2],

        0x8001: seeds[3],  # Diagnostic Message
        0x8002: seeds[3],
        0x8003: seeds[3],
    }

    sequences = []

    for _ in range(iterations):
        result = generator.generate(
            length=random.randint(1, 6)
        )

        sequence = []

        for payload_type in result.sequence.payload_types():
            template = templates.get(payload_type)

            if template is not None:
                sequence.append(template)

        if sequence:
            sequences.append(sequence)

    return sequences


# ============================================================
# ML-GUIDED FUZZER
# ============================================================

def feature_vector(data, mutation_id):
    return [
        mutation_id,
        len(data),
        sum(data) % 256,
        max(data) if data else 0,
        min(data) if data else 0,
        data[0] if data else 0,
        data[-1] if data else 0,
    ]


def ml_guided_fuzzer(seeds, iterations, evaluator):
    """
    Prototype ML-guided strategy.

    It uses RandomForest when scikit-learn is available.
    The model learns whether a mutation is likely to produce
    a new/interesting parser behavior.

    This is an experimental ML baseline, not the final RL system.
    """

    try:
        from sklearn.ensemble import RandomForestClassifier
    except ImportError:
        raise RuntimeError(
            "scikit-learn is required for ml_guided. "
            "Install with: python3 -m pip install scikit-learn"
        )

    mutation_functions = [
        random_mutation,
        boundary_mutation,
        structure_mutation,
    ]

    training_x = []
    training_y = []

    results = []

    # Bootstrap data
    for _ in range(min(60, iterations)):
        mutation_id = random.randrange(len(mutation_functions))
        seed = random.choice(seeds)

        candidate = mutation_functions[mutation_id](seed)

        observation = evaluator(candidate)

        reward = int(
            observation["valid"]
            or observation["fault"]
            or observation["new_behavior"]
        )

        training_x.append(
            feature_vector(candidate, mutation_id)
        )

        training_y.append(reward)

        results.append(candidate)

    while len(results) < iterations:

        # Need both classes before training a classifier.
        if len(set(training_y)) < 2:
            mutation_id = random.randrange(
                len(mutation_functions)
            )
        else:
            model = RandomForestClassifier(
                n_estimators=30,
                max_depth=5,
                random_state=RANDOM_SEED,
            )

            model.fit(training_x, training_y)

            candidates = []
            scores = []

            for mutation_id in range(len(mutation_functions)):
                candidate = mutation_functions[mutation_id](
                    random.choice(seeds)
                )

                x = feature_vector(
                    candidate,
                    mutation_id,
                )

                probability = model.predict_proba(
                    [x]
                )[0]

                if len(probability) == 2:
                    score = probability[1]
                else:
                    score = 0.0

                candidates.append(candidate)
                scores.append(score)

            best_index = max(
                range(len(scores)),
                key=lambda i: scores[i],
            )

            mutation_id = best_index
            candidate = candidates[best_index]

        if len(set(training_y)) < 2:
            candidate = mutation_functions[mutation_id](
                random.choice(seeds)
            )

        observation = evaluator(candidate)

        reward = int(
            observation["valid"]
            or observation["fault"]
            or observation["new_behavior"]
        )

        training_x.append(
            feature_vector(candidate, mutation_id)
        )

        training_y.append(reward)

        results.append(candidate)

    return results[:iterations]


# ============================================================
# PROTOCOL EVALUATION
# ============================================================

def evaluate_someip(data):
    try:
        message = parse_someip_message(data)

        message_type = getattr(
            message,
            "message_type",
            "UNKNOWN",
        )

        state = f"MSG_{message_type}"

        behavior = (
            "VALID",
            message_type,
            len(data),
        )

        return {
            "valid": True,
            "fault": False,
            "state": state,
            "transition": None,
            "behavior": behavior,
            "new_behavior": False,
        }

    except Exception as exc:
        return {
            "valid": False,
            "fault": exc.__class__.__name__
            not in {
                "SomeIPHeaderError",
                "SomeIPLengthError",
                "ValueError",
            },
            "state": "REJECTED",
            "transition": None,
            "behavior": (
                "REJECTED",
                exc.__class__.__name__,
            ),
            "new_behavior": False,
        }



def evaluate_doip(data, state_machine):
    try:
        header, payload = parse_doip_message(data)

        # Get payload type from the DoIP header
        payload_type = header.payload_type

        # Record state before processing the message
        state_before = state_machine.current_state

        event = None

        try:
            # Convert DoIP payload type into a state-machine event
            event = DoIPMessageMapper.event_for_payload_type(payload_type)

            # Perform the state transition if this event is valid
            if event is not None and state_machine.can_transition(event):
                state_machine.transition(event)

        except Exception:
            event = None

        # Record state after processing the message
        state_after = state_machine.current_state

        # Record transition only when the state actually changes
        transition = (
            f"{state_before}->{state_after}"
            if state_before != state_after
            else None
        )

        # Record observable behavior
        behavior = (
            "VALID",
            payload_type,
            len(data),
        )

        return {
            "valid": True,
            "fault": False,
            "state": str(state_after),
            "transition": transition,
            "behavior": behavior,
            "new_behavior": False,
        }

    except Exception as exc:
        return {
            "valid": False,
            "fault": exc.__class__.__name__
            not in {
                "DoIPLengthError",
                "DoIPPayloadError",
                "ValueError",
            },
            "state": "REJECTED",
            "transition": None,
            "behavior": (
                "REJECTED",
                exc.__class__.__name__,
            ),
            "new_behavior": False,
        }

# ============================================================
# BENCHMARK
# ============================================================

ALGORITHMS = [
    "random",
    "boundary",
    "structure",
    "stateful",
    "coverage",
    "genetic",
    "ml_guided",
]


def run_algorithm(protocol, algorithm, seeds):
    start = time.perf_counter()

    if algorithm == "random":
        tests = random_fuzzer(seeds, ITERATIONS)

    elif algorithm == "boundary":
        tests = boundary_fuzzer(seeds, ITERATIONS)

    elif algorithm == "structure":
        tests = structure_fuzzer(seeds, ITERATIONS)

    elif algorithm == "coverage":
        tests = coverage_fuzzer(seeds, ITERATIONS)

    elif algorithm == "genetic":
        tests = genetic_fuzzer(seeds, ITERATIONS)

    elif algorithm == "stateful":
        tests = stateful_fuzzer(seeds, ITERATIONS, protocol)

    elif algorithm == "ml_guided":

        evaluator = (
            evaluate_someip
            if protocol == "someip"
            else lambda x: evaluate_doip(
                x,
                DoIPStateMachine(),
            )
        )

        tests = ml_guided_fuzzer(
            seeds,
            ITERATIONS,
            evaluator,
        )

    else:
        raise ValueError(
            f"Unknown algorithm: {algorithm}"
        )

    elapsed = time.perf_counter() - start

    return tests, elapsed


def benchmark(protocol, algorithm, seeds):
    tests, generation_time = run_algorithm(
        protocol,
        algorithm,
        seeds,
    )

    unique_inputs = set()

    valid = 0
    invalid = 0
    faults = 0

    states = set()
    transitions = set()
    behaviors = set()

    for test in tests:

        # A stateful test is a complete message sequence.
        if algorithm == "stateful":
            sequence = test
        else:
            sequence = [test]

        # Every independent test/sequence starts from INITIAL.
        state_machine = (
            DoIPStateMachine()
            if protocol == "doip"
            else None
        )

        for data in sequence:

            unique_inputs.add(
                hashlib.sha256(data).hexdigest()
            )

            if protocol == "someip":
                observation = evaluate_someip(data)
            else:
                observation = evaluate_doip(
                    data,
                    state_machine,
                )

            if observation["valid"]:
                valid += 1
            else:
                invalid += 1

            if observation["fault"]:
                faults += 1

            states.add(
                observation["state"]
            )

            if observation["transition"]:
                transitions.add(
                    observation["transition"]
                )

            behaviors.add(
                observation["behavior"]
            )

    total_messages = sum(
        len(x) if algorithm == "stateful" else 1
        for x in tests
    )

    speed = (
        total_messages / generation_time
        if generation_time > 0
        else 0
    )

    return {
        "protocol": protocol,
        "algorithm": algorithm,
        "tests": len(tests),
        "messages": total_messages,
        "unique_inputs": len(unique_inputs),
        "valid_messages": valid,
        "invalid_messages": invalid,
        "faults": faults,
        "unique_states": len(states),
        "state_transitions": len(transitions),
        "behavior_coverage": len(behaviors),
        "time_seconds": round(
            generation_time,
            6,
        ),
        "tests_per_second": round(
            speed,
            2,
        ),
    }


# ============================================================
# MAIN
# ============================================================

def main():
    results = []

    protocols = {
        "someip": someip_seeds(),
        "doip": doip_seeds(),
    }

    for protocol, seeds in protocols.items():

        for algorithm in ALGORITHMS:

            result = benchmark(
                protocol,
                algorithm,
                seeds,
            )

            results.append(result)

            print(
                f"{protocol:7} "
                f"{algorithm:10} "
                f"tests={result['tests']:5} "
                f"messages={result['messages']:5} "
                f"unique={result['unique_inputs']:5} "
                f"valid={result['valid_messages']:5} "
                f"invalid={result['invalid_messages']:5} "
                f"faults={result['faults']:3} "
                f"states={result['unique_states']:3} "
                f"transitions={result['state_transitions']:3} "
                f"coverage={result['behavior_coverage']:4} "
                f"speed={result['tests_per_second']:.2f}/s"
            )

    output = (
        Path(__file__).resolve().parent
        / "results.csv"
    )

    fields = [
        "protocol",
        "algorithm",
        "tests",
        "messages",
        "unique_inputs",
        "valid_messages",
        "invalid_messages",
        "faults",
        "unique_states",
        "state_transitions",
        "behavior_coverage",
        "time_seconds",
        "tests_per_second",
    ]

    with open(
        output,
        "w",
        newline="",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields,
        )

        writer.writeheader()
        writer.writerows(results)

    print()
    print("Fuzzing comparison completed.")
    print(f"Results saved to {output}")


if __name__ == "__main__":
    main()
