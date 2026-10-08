
import struct

from .constants import NOTIFICATION
from .message import build_someip_message, parse_someip_message
from .error import SomeIPError

SD_SERVICE_ID = 0xFFFF
SD_METHOD_ID = 0x8100
SD_CLIENT_ID = 0x0000
SD_MESSAGE_TYPE = NOTIFICATION
SD_RETURN_CODE = 0x00

REBOOT_FLAG_BIT = 0b1000_0000
UNICAST_FLAG_BIT = 0b0100_0000
INITIAL_DATA_FLAG_BIT = 0b0010_0000


class SomeIPSDError(SomeIPError):
    """Raised when an SD message's envelope is malformed (bad flags byte,
    reserved bytes not zero, entries/options length doesn't match the
    actual remaining payload, wrong service/method id, etc.)."""


class SDFlags:
    """The single Flags byte at the start of every SD payload."""

    def __init__(self, reboot: bool = False, unicast: bool = True,
                 initial_data: bool = False):
        self.reboot = reboot
        self.unicast = unicast
        self.initial_data = initial_data

    def encode(self) -> bytes:
        value = 0
        if self.reboot:
            value |= REBOOT_FLAG_BIT
        if self.unicast:
            value |= UNICAST_FLAG_BIT
        if self.initial_data:
            value |= INITIAL_DATA_FLAG_BIT
        return bytes([value])

    @classmethod
    def decode(cls, byte_value: int) -> "SDFlags":
        return cls(
            reboot=bool(byte_value & REBOOT_FLAG_BIT),
            unicast=bool(byte_value & UNICAST_FLAG_BIT),
            initial_data=bool(byte_value & INITIAL_DATA_FLAG_BIT),
        )

    def __repr__(self):
        return (f"SDFlags(reboot={self.reboot}, unicast={self.unicast}, "
                f"initial_data={self.initial_data})")


def build_sd_message(session_id: int, flags: SDFlags,
                      entries: bytes = b"", options: bytes = b"") -> bytes:
    """Build a complete SD message: SOME/IP header + SD payload.

    entries/options are raw pre-encoded bytes for now -- entry-level
    encoding is not implemented yet, so callers should pass b"" until
    the next checkpoint adds real entries.
    """
    sd_payload = (
        flags.encode()
        + b"\x00\x00\x00"                              # reserved, must be 0
        + struct.pack("!I", len(entries)) + entries
        + struct.pack("!I", len(options)) + options
    )

    return build_someip_message(
        service_id=SD_SERVICE_ID,
        method_id=SD_METHOD_ID,
        client_id=SD_CLIENT_ID,
        session_id=session_id,
        interface_version=1,
        message_type=SD_MESSAGE_TYPE,
        return_code=SD_RETURN_CODE,
        payload=sd_payload,
    )


def parse_sd_message(data: bytes):
    """Parse a complete SD message.

    Returns:
        (header, flags, entries: bytes, options: bytes)

    Raises:
        Whatever parse_someip_message raises (truncated/length/version/
        message-type errors), plus SomeIPSDError for SD-envelope-specific
        problems (wrong Service/Method ID, non-zero reserved bytes,
        entries/options length not matching actual payload size).
    """
    header, payload = parse_someip_message(data)

    if header.service_id != SD_SERVICE_ID or header.method_id != SD_METHOD_ID:
        raise SomeIPSDError(
            f"Not an SD message: service_id=0x{header.service_id:04X}, "
            f"method_id=0x{header.method_id:04X} "
            f"(expected 0x{SD_SERVICE_ID:04X}/0x{SD_METHOD_ID:04X})"
        )

    if len(payload) < 8:
        raise SomeIPSDError(
            f"SD payload too short: {len(payload)} bytes, need at least 8 "
            f"(flags + reserved + entries-length)"
        )

    flags_byte = payload[0]
    reserved = payload[1:4]

    if reserved != b"\x00\x00\x00":
        raise SomeIPSDError(f"SD reserved bytes must be zero, got {reserved.hex()}")

    flags = SDFlags.decode(flags_byte)

    (entries_length,) = struct.unpack("!I", payload[4:8])
    entries_start = 8
    entries_end = entries_start + entries_length

    if entries_end > len(payload):
        raise SomeIPSDError(
            f"Entries length ({entries_length}) exceeds remaining payload "
            f"({len(payload) - entries_start} bytes available)"
        )

    entries = payload[entries_start:entries_end]

    if len(payload) < entries_end + 4:
        raise SomeIPSDError("SD payload truncated before Options-length field")

    (options_length,) = struct.unpack("!I", payload[entries_end:entries_end + 4])
    options_start = entries_end + 4
    options_end = options_start + options_length

    if options_end != len(payload):
        raise SomeIPSDError(
            f"Options length ({options_length}) does not match actual "
            f"remaining payload ({len(payload) - options_start} bytes)"
        )

    options = payload[options_start:options_end]

    return header, flags, entries, options