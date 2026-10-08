from someip.udp import SomeIPUDP
from someip.message import  parse_someip_message
from someip.service import handle_request


def main():

    transport = SomeIPUDP(
        local_ip="127.0.0.1",
        local_port=30490,
    )

    transport.bind()

    print("================================")
    print("       SOME/IP UDP SERVER")
    print("================================")
    print("Listening on 127.0.0.1:30490")
    print()

    try:
        while True:

            data, address = transport.receive()

            print(f"[+] Received {len(data)} bytes")
            print(f"[+] Sender: {address}")
            print(f"[+] Raw: {data.hex()}")

            try:
                header, payload = parse_someip_message(data)

                print("\nSOME/IP Message")
                print("----------------------------")
                print(f"Service ID : 0x{header.service_id:04X}")
                print(f"Method ID  : 0x{header.method_id:04X}")
                print(f"Client ID  : 0x{header.client_id:04X}")
                print(f"Session ID : 0x{header.session_id:04X}")
                print(f"Message Type: 0x{header.message_type:02X}")
                print(f"Payload    : {payload!r}")
                print()

                response = handle_request(header, payload)

                if response is not None:
                    sent = transport.send(
        response,
        address[0],
        address[1],
    )

                print(f"[+] Sent RESPONSE ({sent} bytes) to {address}")
                print(f"[+] Response raw: {response.hex()}")
                print()

            except Exception as error:
                print(f"[!] Invalid SOME/IP message: {error}")

    except KeyboardInterrupt:
        print("\n[+] Server stopped")

    finally:
        transport.close()


if __name__ == "__main__":
    main()