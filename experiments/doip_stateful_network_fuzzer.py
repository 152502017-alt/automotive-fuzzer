import csv
import random
import socket
import time
from pathlib import Path

from doip.message import (
    AliveCheckRequest,
    DiagnosticMessage,
    RoutingActivationRequest,
    VehicleIdentificationRequest,
    parse_doip_message,
)
from fuzzer.doip_state import DoIPStateMachine, DoIPEvent

TARGET_IP = "10.128.18.74"
TARGET_PORT = 13400
TIMEOUT = 2.0
NUM_SEQUENCES = 10
MAX_SEQUENCE_LENGTH = 5
RESULTS = Path("experiments/doip_stateful_network_results.csv")


def make_messages():
    return {
        DoIPEvent.VEHICLE_IDENTIFICATION.value:
            lambda: VehicleIdentificationRequest().encode(),
        DoIPEvent.ROUTING_ACTIVATION.value:
            lambda: RoutingActivationRequest(
                source_address=0x0E00,
                activation_type=0x00,
            ).encode(),
        DoIPEvent.ALIVE_CHECK.value:
            lambda: AliveCheckRequest().encode(),
        DoIPEvent.DIAGNOSTIC_MESSAGE.value:
            lambda: DiagnosticMessage(
                source_address=0x0E00,
                target_address=0x0001,
                diagnostic_data=bytes.fromhex("22 F1 90"),
            ).encode(),
    }


def generate_sequence(rng):
    """Generate a message sequence using the existing DoIP state model."""
    machine = DoIPStateMachine()
    builders = make_messages()
    sequence = []

    length = rng.randint(3, MAX_SEQUENCE_LENGTH)

    for _ in range(length):
        available = [
            event for event in machine.available_events()
            if event in builders
        ]
        if not available:
            break

        event = rng.choice(available)
        before = machine.current_state
        packet = builders[event]()
        after = machine.transition(event)

        sequence.append((before, event, after, packet))

    return sequence


def receive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def receive_response(sock):
    header = receive_exact(sock, 8)
    if header is None:
        return None

    length = int.from_bytes(header[4:8], "big")
    if length > 65536:
        raise ValueError(f"Response too large: {length}")

    payload = receive_exact(sock, length)
    if payload is None:
        return None

    return header + payload


def expected_response(event):
    """Return the expected DoIP response payload type for each request."""
    return {
        "VEHICLE_IDENTIFICATION": 0x0004,
        "ROUTING_ACTIVATION": 0x0006,
        "ALIVE_CHECK": 0x0008,
        "DIAGNOSTIC_MESSAGE": 0x8002,
    }.get(event)


def main():
    rng = random.Random(42)
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    counts = {}

    fields = [
        "sequence", "step", "state_before", "event", "state_after",
        "packet_hex", "status", "response_payload_type",
        "latency_ms", "response_or_error",
    ]

    print(f"Target: {TARGET_IP}:{TARGET_PORT}")
    print(f"State-guided sequences: {NUM_SEQUENCES}\n")

    with RESULTS.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for seq_id in range(1, NUM_SEQUENCES + 1):
            sequence = generate_sequence(rng)
            print(f"Sequence {seq_id}: {len(sequence)} message(s)")

            try:
                with socket.create_connection(
                    (TARGET_IP, TARGET_PORT), timeout=TIMEOUT
                ) as sock:
                    sock.settimeout(TIMEOUT)

                    for step, (before, event, after, packet) in enumerate(
                        sequence, start=1
                    ):
                        start = time.perf_counter()
                        status = ""
                        response_type = ""
                        detail = ""

                        try:
                            sock.sendall(packet)
                            response = receive_response(sock)
                            latency = round(
                                (time.perf_counter() - start) * 1000, 3
                            )

                            if response is None:
                                status = "connection_closed"
                                detail = "Peer closed connection"
                            else:
                                header, _ = parse_doip_message(response)
                                response_type = (
                                    f"0x{header.payload_type:04X}"
                                )
                                status = "response_received"
                                detail = response.hex()

                        except socket.timeout:
                            latency = round(
                                (time.perf_counter() - start) * 1000, 3
                            )
                            status = "timeout"
                            detail = "No complete response before timeout"

                        except Exception as exc:
                            latency = round(
                                (time.perf_counter() - start) * 1000, 3
                            )
                            status = "client_error"
                            detail = f"{type(exc).__name__}: {exc}"

                        expected = expected_response(event)
                        if status == "response_received":
                            if response_type != f"0x{expected:04X}":
                                status = "unexpected_response"
                                detail = (
                                    f"Expected 0x{expected:04X}, "
                                    f"received {response_type}; {detail}"
                                )

                        counts[status] = counts.get(status, 0) + 1
                        writer.writerow({
                            "sequence": seq_id,
                            "step": step,
                            "state_before": before,
                            "event": event,
                            "state_after": after,
                            "packet_hex": packet.hex(),
                            "status": status,
                            "response_payload_type": response_type,
                            "latency_ms": latency,
                            "response_or_error": detail,
                        })
                        file.flush()

                        print(
                            f"  [{step}] {event}: {status}"
                            + (f", response={response_type}"
                               if response_type else "")
                        )

                        if status != "response_received":
                            print("  Stopping this sequence after failure.")
                            break

                        time.sleep(0.1)

            except (OSError, socket.timeout) as exc:
                counts["connection_error"] = (
                    counts.get("connection_error", 0) + 1
                )
                print(f"  Connection error: {exc}")

            time.sleep(0.2)

    print("\nSummary:")
    for status, count in sorted(counts.items()):
        print(f"  {status}: {count}")
    print(f"\nCSV saved to: {RESULTS}")


if __name__ == "__main__":
    main()
