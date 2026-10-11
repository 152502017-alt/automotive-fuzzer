import csv
import random
import socket
import time
from pathlib import Path

from doip.constants import (
    ALIVE_CHECK_REQUEST,
    DIAGNOSTIC_MESSAGE,
    ROUTING_ACTIVATION_REQUEST,
    VEHICLE_IDENTIFICATION_REQUEST,
)
from doip.message import (
    AliveCheckRequest,
    DiagnosticMessage,
    RoutingActivationRequest,
    VehicleIdentificationRequest,
    parse_doip_message,
)
from experiments.fuzzing_benchmark import (
    random_mutation,
    boundary_mutation,
    structure_mutation,
)

TARGET_IP = "10.128.18.74"
TARGET_PORT = 13400
TIMEOUT_SECONDS = 1.5
MUTATED_CASES = 12
DELAY_SECONDS = 0.15

RESULTS_FILE = Path("experiments/doip_network_results.csv")


def make_seeds():
    """Build valid DoIP messages using the existing protocol implementation."""
    return [
        ("vehicle_identification", VehicleIdentificationRequest().encode()),
        (
            "routing_activation",
            RoutingActivationRequest(
                source_address=0x0E00,
                activation_type=0x00,
            ).encode(),
        ),
        ("alive_check", AliveCheckRequest().encode()),
        (
            "diagnostic_message",
            DiagnosticMessage(
                source_address=0x0E00,
                target_address=0x0001,
                diagnostic_data=bytes.fromhex("22 F1 90"),
            ).encode(),
        ),
    ]


def receive_exact(sock, size):
    """Receive exactly size bytes, or return None if the peer closes."""
    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data.extend(chunk)

    return bytes(data)


def receive_response(sock):
    """Read one DoIP response using its 8-byte header and length field."""
    header = receive_exact(sock, 8)
    if header is None:
        return None

    payload_length = int.from_bytes(header[4:8], "big")

    # Safety cap: don't try to read an unreasonably large response.
    if payload_length > 65536:
        raise ValueError(f"Response payload too large: {payload_length}")

    payload = receive_exact(sock, payload_length)
    if payload is None:
        return None

    return header + payload


def send_test(packet):
    """Send one packet on a new TCP connection and classify the outcome."""
    start = time.perf_counter()

    try:
        with socket.create_connection(
            (TARGET_IP, TARGET_PORT),
            timeout=TIMEOUT_SECONDS,
        ) as sock:
            sock.settimeout(TIMEOUT_SECONDS)
            sock.sendall(packet)
            response = receive_response(sock)

        elapsed_ms = round((time.perf_counter() - start) * 1000, 3)

        if response is None:
            return "connection_closed", "", elapsed_ms, ""

        try:
            header, _ = parse_doip_message(response)
            response_type = f"0x{header.payload_type:04X}"
            return "response_received", response_type, elapsed_ms, response.hex()
        except Exception as exc:
            return (
                "unparseable_response",
                "",
                elapsed_ms,
                f"{response.hex()} | {type(exc).__name__}: {exc}",
            )

    except socket.timeout:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 3)
        return "timeout", "", elapsed_ms, ""

    except (ConnectionError, OSError) as exc:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 3)
        return "connection_error", "", elapsed_ms, str(exc)

    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 3)
        return "client_error", "", elapsed_ms, f"{type(exc).__name__}: {exc}"


def main():
    random.seed(42)
    seeds = make_seeds()
    tests = []

    # Baseline: verify each valid message type first.
    for name, packet in seeds:
        tests.append((f"baseline_{name}", packet))

    # Mutations: reuse the existing project's mutation strategies.
    strategies = [
        ("random", random_mutation),
        ("boundary", boundary_mutation),
        ("structure", structure_mutation),
    ]

    for index in range(MUTATED_CASES):
        seed_name, seed = seeds[index % len(seeds)]
        strategy_name, mutate = strategies[index % len(strategies)]
        tests.append(
            (
                f"{strategy_name}_{seed_name}",
                mutate(seed),
            )
        )

    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    counts = {}
    print(f"Target: {TARGET_IP}:{TARGET_PORT} (DoIP over TCP)")
    print(f"Total tests: {len(tests)} (4 baseline + {MUTATED_CASES} mutated)")
    print("Starting...\n")

    with RESULTS_FILE.open("w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "test_number",
                "test_name",
                "packet_hex",
                "packet_length",
                "status",
                "response_payload_type",
                "latency_ms",
                "response_or_error",
            ],
        )
        writer.writeheader()

        for number, (name, packet) in enumerate(tests, start=1):
            status, response_type, latency_ms, detail = send_test(packet)
            counts[status] = counts.get(status, 0) + 1

            writer.writerow({
                "test_number": number,
                "test_name": name,
                "packet_hex": packet.hex(),
                "packet_length": len(packet),
                "status": status,
                "response_payload_type": response_type,
                "latency_ms": latency_ms,
                "response_or_error": detail,
            })
            file.flush()

            suffix = f", response={response_type}" if response_type else ""
            print(
                f"[{number:02d}/{len(tests)}] {name}: "
                f"{status}, {latency_ms} ms{suffix}"
            )

            time.sleep(DELAY_SECONDS)

    print("\nSummary:")
    for status, count in sorted(counts.items()):
        print(f"  {status}: {count}")

    print(f"\nResults saved to: {RESULTS_FILE}")


if __name__ == "__main__":
    main()
