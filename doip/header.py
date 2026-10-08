import struct
from dataclasses import dataclass

from .constants import (
    DOIP_HEADER_SIZE,
    DOIP_INVERSE_PROTOCOL_VERSION,
    DOIP_PROTOCOL_VERSION,
    VALID_PAYLOAD_TYPES,
)
from .error import (
    DoIPHeaderError,
    DoIPLengthError,
    DoIPPayloadTypeError,
    DoIPVersionError,
)


@dataclass
class DoIPHeader:
    protocol_version: int
    inverse_protocol_version: int
    payload_type: int
    payload_length: int

    def validate(self):
        if not 0 <= self.protocol_version <= 0xFF:
            raise DoIPHeaderError(
                "Protocol version must fit in one byte"
            )

        if not 0 <= self.inverse_protocol_version <= 0xFF:
            raise DoIPHeaderError(
                "Inverse protocol version must fit in one byte"
            )

        if not 0 <= self.payload_type <= 0xFFFF:
            raise DoIPHeaderError(
                "Payload type must fit in uint16"
            )

        if not 0 <= self.payload_length <= 0xFFFFFFFF:
            raise DoIPLengthError(
                "Payload length must fit in uint32"
            )

        if self.protocol_version != DOIP_PROTOCOL_VERSION:
            raise DoIPVersionError(
                f"Unsupported DoIP protocol version: "
                f"0x{self.protocol_version:02X}"
            )

        expected_inverse = (
            0xFF - self.protocol_version
        )

        if self.inverse_protocol_version != expected_inverse:
            raise DoIPVersionError(
                f"Invalid inverse protocol version: "
                f"expected 0x{expected_inverse:02X}, "
                f"got 0x{self.inverse_protocol_version:02X}"
            )

        if self.payload_type not in VALID_PAYLOAD_TYPES:
            raise DoIPPayloadTypeError(
                f"Unsupported DoIP payload type: "
                f"0x{self.payload_type:04X}"
            )

    def encode(self):
        self.validate()

        return struct.pack(
            "!BBHI",
            self.protocol_version,
            self.inverse_protocol_version,
            self.payload_type,
            self.payload_length,
        )

    @classmethod
    def decode(cls, data):
        if not isinstance(data, bytes):
            raise DoIPHeaderError(
                "DoIP header data must be bytes"
            )

        if len(data) < DOIP_HEADER_SIZE:
            raise DoIPHeaderError(
                f"DoIP header requires {DOIP_HEADER_SIZE} bytes, "
                f"got {len(data)}"
            )

        (
            protocol_version,
            inverse_protocol_version,
            payload_type,
            payload_length,
        ) = struct.unpack(
            "!BBHI",
            data[:DOIP_HEADER_SIZE],
        )

        header = cls(
            protocol_version=protocol_version,
            inverse_protocol_version=inverse_protocol_version,
            payload_type=payload_type,
            payload_length=payload_length,
        )

        header.validate()

        return header
