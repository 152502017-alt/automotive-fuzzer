import socket

from someip.udp import SomeIPUDP
from someip.message import build_someip_message, parse_someip_message
from someip.constants import REQUEST


def main():

    target_ip = "127.0.0.1"
    target_port = 30490

    message = build_someip_message(
        service_id=0x1234,
        method_id=0x0001,
        client_id=0x0010,
        session_id=0x0001,
        interface_version=1,
        message_type=REQUEST,
        return_code=0x00,
        payload=b"GetSpeed",
    )

    transport = SomeIPUDP(timeout=3.0)

    print("================================")
    print("       SOME/IP UDP CLIENT")
    print("================================")

    print(f"Target : {target_ip}:{target_port}")
    print(f"Packet : {message.hex()}")

    sent = transport.send(message, target_ip, target_port)
    print(f"[+] Sent {sent} bytes")

    try:
        data, address = transport.receive()

        print(f"\n[+] Received {len(data)} bytes from {address}")
        print(f"[+] Raw: {data.hex()}")

        header, payload = parse_someip_message(data)

        print("\nSOME/IP Response")
        print("----------------------------")
        print(f"Service ID : 0x{header.service_id:04X}")
        print(f"Method ID  : 0x{header.method_id:04X}")
        print(f"Client ID  : 0x{header.client_id:04X}")
        print(f"Session ID : 0x{header.session_id:04X}")
        print(f"Message Type: 0x{header.message_type:02X}")
        print(f"Return Code: 0x{header.return_code:02X}")
        print(f"Payload    : {payload!r}")

    except socket.timeout:
        print("[!] No response received within timeout.")

    finally:
        transport.close()


if __name__ == "__main__":
    main()