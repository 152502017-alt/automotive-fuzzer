import csv
import socket
import time
from pathlib import Path

from someip.constants import REQUEST
from someip.message import build_someip_message, parse_someip_message

from experiments.fuzzing_benchmark import (
    random_mutation,
    boundary_mutation,
    structure_mutation,
)

TARGET_IP = "10.128.18.74"
TARGET_PORT = 30490
TEST_CASES = 20
TIMEOUT_SECONDS = 1.0

SEED = build_someip_message(
    service_id=0x1234,
    method_id=0x0001,
    client_id=0x0010,
    session_id=0x0001,
    interface_version=1,
    message_type=REQUEST,
    return_code=0,
    payload=b"GetSpeed",
)

MUTATORS = [
    ("random", random_mutation),
    ("boundary", boundary_mutation),
    ("structure", structure_mutation),
]


def main():
    results_path = Path("experiments/someip_network_results.csv")

    print("SOME/IP network fuzzing experiment")
    print(f"Target: {TARGET_IP}:{TARGET_PORT} (UDP)")
    print(f"Test cases: {TEST_CASES}")
    print("Only the configured Raspberry Pi will be contacted.")
    print()

    responses = 0
    timeouts = 0
    send_errors = 0

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, \
            results_path.open("w", newline="") as csvfile:

        sock.settimeout(TIMEOUT_SECONDS)
        writer = csv.DictWriter(
            csvfile,
            fieldnames=[
                "case", "strategy", "request_hex", "outcome",
                "response_hex", "response_parse", "latency_ms",
            ],
        )
        writer.writeheader()

        for case in range(1, TEST_CASES + 1):
            strategy, mutator = MUTATORS[(case - 1) % len(MUTATORS)]
            packet = mutator(SEED)

            outcome = ""
            response_hex = ""
            response_parse = ""
            latency_ms = ""

            try:
                started = time.monotonic()
                sock.sendto(packet, (TARGET_IP, TARGET_PORT))

                try:
                    response, peer = sock.recvfrom(65535)
                    latency_ms = round(
                        (time.monotonic() - started) * 1000, 3
                    )
                    response_hex = response.hex()

                    if peer[0] != TARGET_IP:
                        outcome = "unexpected_sender"
                    else:
                        try:
                            header, payload = parse_someip_message(response)
                            outcome = "response_received"
                            response_parse = (
                                f"service=0x{header.service_id:04X};"
                                f"method=0x{header.method_id:04X};"
                                f"type=0x{header.message_type:02X};"
                                f"payload={payload!r}"
                            )
                        except Exception as exc:
                            outcome = "unparseable_response"
                            response_parse = type(exc).__name__

                    responses += 1
                    print(
                        f"[{case:02d}] {strategy}: {outcome}; "
                        f"latency={latency_ms} ms"
                    )

                except socket.timeout:
                    outcome = "timeout"
                    timeouts += 1
                    print(f"[{case:02d}] {strategy}: timeout")

            except OSError as exc:
                outcome = "send_error"
                response_parse = f"{type(exc).__name__}: {exc}"
                send_errors += 1
                print(f"[{case:02d}] {strategy}: send error: {exc}")

            writer.writerow({
                "case": case,
                "strategy": strategy,
                "request_hex": packet.hex(),
                "outcome": outcome,
                "response_hex": response_hex,
                "response_parse": response_parse,
                "latency_ms": latency_ms,
            })

            # Keep traffic modest and easy to inspect.
            time.sleep(0.1)

    print("\nExperiment complete")
    print(f"Responses received: {responses}")
    print(f"Timeouts: {timeouts}")
    print(f"Send errors: {send_errors}")
    print(f"Results saved to: {results_path}")


if __name__ == "__main__":
    main()
