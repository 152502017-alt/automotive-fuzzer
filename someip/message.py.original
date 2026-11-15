from .constants import PROTOCOL_VERSION
from .error import SomeIPHeaderError, SomeIPLengthError
from .header import SomeIPHeader


def build_someip_message(
    service_id,
    method_id,
    client_id,
    session_id,
    interface_version,
    message_type,
    return_code,
    payload=b"",
):
    """
    Build a SOME/IP message.

    The SOME/IP Length field represents the number of bytes
    following the Length field itself.
    """

    length = 8 + len(payload)

    header = SomeIPHeader(
        service_id=service_id,
        method_id=method_id,
        length=length,
        client_id=client_id,
        session_id=session_id,
        protocol_version=PROTOCOL_VERSION,
        interface_version=interface_version,
        message_type=message_type,
        return_code=return_code,
    )

    return header.encode() + payload


def parse_someip_message(data):
    """Parse a complete SOME/IP message."""

    if len(data) < 16:
        raise SomeIPHeaderError(
            "SOME/IP message must contain at least 16 bytes"
        )

    header = SomeIPHeader.decode(data)

    # SOME/IP Length counts all bytes after the Length field.
    # Minimum:
    #   Request ID                      = 4 bytes
    #   Protocol Version                = 1 byte
    #   Interface Version               = 1 byte
    #   Message Type                    = 1 byte
    #   Return Code                     = 1 byte
    # Therefore minimum Length = 8.
    if header.length < 8:
        raise SomeIPLengthError(
            f"SOME/IP Length field must be at least 8, "
            f"got {header.length}"
        )

    expected_total_length = 8 + header.length

    if len(data) != expected_total_length:
        raise SomeIPLengthError(
            f"Length mismatch: header specifies "
            f"{expected_total_length} bytes, "
            f"received {len(data)} bytes"
        )

    payload = data[16:]

    return header, payload
