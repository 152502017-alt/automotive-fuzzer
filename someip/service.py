from .constants import REQUEST, RESPONSE
from .message import build_someip_message


GET_SPEED_SERVICE_ID = 0x1234
GET_SPEED_METHOD_ID = 0x0001


def handle_request(header, payload):

    if header.message_type != REQUEST:
        return None

    if header.service_id != GET_SPEED_SERVICE_ID:
        return None

    if header.method_id != GET_SPEED_METHOD_ID:
        return None

    response_payload = b"Speed: 100 km/h"

    return build_someip_message(
        service_id=header.service_id,
        method_id=header.method_id,
        client_id=header.client_id,
        session_id=header.session_id,
        interface_version=header.interface_version,
        message_type=RESPONSE,
        return_code=0x00,
        payload=response_payload,
    )