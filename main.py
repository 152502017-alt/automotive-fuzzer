from someip.message import build_someip_message, parse_someip_message
from someip.constants import REQUEST, RESPONSE


request = build_someip_message(
    service_id=0x1234,
    method_id=0x0001,
    client_id=0x0010,
    session_id=0x0001,
    interface_version=1,
    message_type=REQUEST,
    return_code=0x00,
    payload=b"GetSpeed"
)

print("REQUEST")
print(request.hex())

header, payload = parse_someip_message(request)

print("\nParsed REQUEST:")
print(f"Service ID:       0x{header.service_id:04X}")
print(f"Method ID:        0x{header.method_id:04X}")
print(f"Length:           {header.length}")
print(f"Client ID:        0x{header.client_id:04X}")
print(f"Session ID:       0x{header.session_id:04X}")
print(f"Protocol Version: 0x{header.protocol_version:02X}")
print(f"Interface Version:0x{header.interface_version:02X}")
print(f"Message Type:     0x{header.message_type:02X}")
print(f"Return Code:      0x{header.return_code:02X}")
print(f"Payload:          {payload!r}")


response = build_someip_message(
    service_id=header.service_id,
    method_id=header.method_id,
    client_id=header.client_id,
    session_id=header.session_id,
    interface_version=header.interface_version,
    message_type=RESPONSE,
    return_code=0x00,
    payload=b"Speed: 100 km/h"
)

print("\nRESPONSE")
print(response.hex())

response_header, response_payload = parse_someip_message(response)

print("\nParsed RESPONSE:")
print(f"Service ID:       0x{response_header.service_id:04X}")
print(f"Method ID:        0x{response_header.method_id:04X}")
print(f"Message Type:     0x{response_header.message_type:02X}")
print(f"Payload:          {response_payload!r}")