import struct
from dataclasses import dataclass

from .constants import (
    PROTOCOL_VERSION,
    VALID_MESSAGE_TYPES,
)

from .error import (
    SomeIPHeaderError,
    SomeIPLengthError,
    SomeIPVersionError,
    SomeIPMessageTypeError,
)


HEADER_SIZE = 16


@dataclass
class SomeIPHeader:
    service_id: int
    method_id: int
    length: int
    client_id: int
    session_id: int
    protocol_version: int
    interface_version: int
    message_type: int
    return_code: int

    def encode(self) -> bytes:
        """Serialize the SOME/IP header."""

        self.validate()

        message_id = (
            (self.service_id << 16)
            | self.method_id
        )

        request_id = (
            (self.client_id << 16)
            | self.session_id
        )

        return struct.pack(
            "!I I I B B B B",
            message_id,
            self.length,
            request_id,
            self.protocol_version,
            self.interface_version,
            self.message_type,
            self.return_code,
        )

    @classmethod
    def decode(cls, data: bytes):
        """Deserialize a SOME/IP header."""

        if len(data) < HEADER_SIZE:
            raise SomeIPHeaderError(
                f"Header requires {HEADER_SIZE} bytes, "
                f"got {len(data)}"
            )

        (
            message_id,
            length,
            request_id,
            protocol_version,
            interface_version,
            message_type,
            return_code,
        ) = struct.unpack(
            "!I I I B B B B",
            data[:HEADER_SIZE],
        )

        service_id = (message_id >> 16) & 0xFFFF
        method_id = message_id & 0xFFFF

        client_id = (request_id >> 16) & 0xFFFF
        session_id = request_id & 0xFFFF

        header = cls(
            service_id=service_id,
            method_id=method_id,
            length=length,
            client_id=client_id,
            session_id=session_id,
            protocol_version=protocol_version,
            interface_version=interface_version,
            message_type=message_type,
            return_code=return_code,
        )

        header.validate()

        return header

    def validate(self):
        """Validate SOME/IP header fields."""

        if not 0 <= self.service_id <= 0xFFFF:
            raise SomeIPHeaderError(
                "service_id must fit in 16 bits"
            )

        if not 0 <= self.method_id <= 0xFFFF:
            raise SomeIPHeaderError(
                "method_id must fit in 16 bits"
            )

        if not 0 <= self.length <= 0xFFFFFFFF:
            raise SomeIPLengthError(
                "length must fit in 32 bits"
            )

        if not 0 <= self.client_id <= 0xFFFF:
            raise SomeIPHeaderError(
                "client_id must fit in 16 bits"
            )

        if not 0 <= self.session_id <= 0xFFFF:
            raise SomeIPHeaderError(
                "session_id must fit in 16 bits"
            )

        if not 0 <= self.protocol_version <= 0xFF:
            raise SomeIPHeaderError(
                "protocol_version must fit in 8 bits"
            )

        if not 0 <= self.interface_version <= 0xFF:
            raise SomeIPHeaderError(
                "interface_version must fit in 8 bits"
            )

        if not 0 <= self.message_type <= 0xFF:
            raise SomeIPHeaderError(
                "message_type must fit in 8 bits"
            )

        if not 0 <= self.return_code <= 0xFF:
            raise SomeIPHeaderError(
                "return_code must fit in 8 bits"
            )

        if self.protocol_version != PROTOCOL_VERSION:
            raise SomeIPVersionError(
                f"Unsupported SOME/IP protocol version: "
                f"0x{self.protocol_version:02X}"
            )

        if self.message_type not in VALID_MESSAGE_TYPES:
            raise SomeIPMessageTypeError(
                f"Invalid SOME/IP message type: "
                f"0x{self.message_type:02X}"
            )