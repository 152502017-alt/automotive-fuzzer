import sys
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from can.can_parser import parse_can_frame, CANValidationError
from can.can_faulty_parser import parse_can_frame_faulty


def is_planted_fault_triggered(frame):
    try:
        parse_can_frame(frame)
        return False
    except CANValidationError as original_error:
        if type(original_error).__name__ != "CANLengthError":
            return False

    try:
        parse_can_frame_faulty(frame)
        return True
    except CANValidationError:
        return False


def generate_testcases(seed=42, count=1000):
    rng = random.Random(seed)
    candidates = []

    for _ in range(count):
        actual_length = rng.randint(0, 8)
        data = bytes(rng.randint(0, 255) for _ in range(actual_length))

        # Generate a DLC that may differ from actual payload length
        dlc = rng.randint(0, 8)

        frame = {
            "can_id": rng.randint(0, 0x7FF),
            "dlc": dlc,
            "data": data
        }

        candidates.append(frame)

    return candidates


def run_experiment():
    testcases = generate_testcases()

    detections = 0

    for frame in testcases:
        if is_planted_fault_triggered(frame):
            detections += 1

    rate = (detections / len(testcases)) * 100

    print("===== CAN PLANTED FAULT EXPERIMENT =====")
    print("Total test cases:", len(testcases))
    print("Fault detections:", detections)
    print("Non-detections:", len(testcases) - detections)
    print(f"Detection rate: {rate:.2f}%")


if __name__ == "__main__":
    run_experiment()
