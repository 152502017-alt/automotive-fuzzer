import struct
from dataclasses import dataclass

from .constants import (
    ALIVE_CHECK_REQUEST,
    ALIVE_CHECK_RESPONSE,
    DIAGNOSTIC_MESSAGE,
    DIAGNOSTIC_MESSAGE_ACK,
    DIAGNOSTIC_MESSAGE_NACK,
    DOIP_HEADER_SIZE,
    DOIP_INVERSE_PROTOCOL_VERSION,
    DOIP_PROTOCOL_VERSION,
    ROUTING_ACTIVATION_REQUEST,
    ROUTING_ACTIVATION_RESPONSE,
    VEHICLE_IDENTIFICATION_REQUEST,
    VEHICLE_IDENTIFICATION_REQUEST_EID,
    VEHICLE_IDENTIFICATION_REQUEST_VIN,
    VEHICLE_IDENTIFICATION_RESPONSE,
)
from .error import DoIPLengthError, DoIPPayloadError
from .header import DoIPHeader


def build_doip_message(payload_type, payload=b""):
    if not isinstance(payload, bytes):
        raise DoIPPayloadError("Payload must be bytes")

    header = DoIPHeader(
        protocol_version=DOIP_PROTOCOL_VERSION,
        inverse_protocol_version=DOIP_INVERSE_PROTOCOL_VERSION,
        payload_type=payload_type,
        payload_length=len(payload),
    )

    return header.encode() + payload


def parse_doip_message(data):
    if not isinstance(data, bytes):
        raise DoIPPayloadError("DoIP message must be bytes")

    if len(data) < DOIP_HEADER_SIZE:
        raise DoIPLengthError(
            f"DoIP message must contain at least "
            f"{DOIP_HEADER_SIZE} bytes"
        )

    header = DoIPHeader.decode(data[:DOIP_HEADER_SIZE])

    expected_length = DOIP_HEADER_SIZE + header.payload_length

    if len(data) != expected_length:
        raise DoIPLengthError(
            f"Length mismatch: header specifies "
            f"{expected_length} total bytes, "
            f"received {len(data)}"
        )

    return header, data[DOIP_HEADER_SIZE:]


@dataclass
class VehicleIdentificationRequest:
    def encode(self):
        return build_doip_message(
            VEHICLE_IDENTIFICATION_REQUEST,
            b"",
        )

    @classmethod
    def decode(cls, data):
        header, payload = parse_doip_message(data)

        if header.payload_type != VEHICLE_IDENTIFICATION_REQUEST:
            raise DoIPPayloadError(
                "Expected Vehicle Identification Request"
            )

        if payload:
            raise DoIPPayloadError(
                "Vehicle Identification Request must have "
                "an empty payload"
            )

        return cls()


@dataclass
class VehicleIdentificationResponse:
    vin: bytes
    logical_address: int
    eid: bytes
    gid: bytes
    further_action: int
    vin_gid_status: int

    PAYLOAD_SIZE = 33

    def validate(self):
        if not isinstance(self.vin, bytes) or len(self.vin) != 17:
            raise DoIPPayloadError(
                "VIN must contain exactly 17 bytes"
            )

        if not 0 <= self.logical_address <= 0xFFFF:
            raise DoIPPayloadError(
                "Logical address must fit in uint16"
            )

        if not isinstance(self.eid, bytes) or len(self.eid) != 6:
            raise DoIPPayloadError(
                "EID must contain exactly 6 bytes"
            )

        if not isinstance(self.gid, bytes) or len(self.gid) != 6:
            raise DoIPPayloadError(
                "GID must contain exactly 6 bytes"
            )

        if not 0 <= self.further_action <= 0xFF:
            raise DoIPPayloadError(
                "Further-action byte must fit in uint8"
            )

        if not 0 <= self.vin_gid_status <= 0xFF:
            raise DoIPPayloadError(
                "VIN/GID status must fit in uint8"
            )

    def encode(self):
        self.validate()

        payload = (
            self.vin
            + struct.pack("!H", self.logical_address)
            + self.eid
            + self.gid
            + bytes([
                self.further_action,
                self.vin_gid_status,
            ])
        )

        return build_doip_message(
            VEHICLE_IDENTIFICATION_RESPONSE,
            payload,
        )

    @classmethod
    def decode(cls, data):
        header, payload = parse_doip_message(data)

        if header.payload_type != VEHICLE_IDENTIFICATION_RESPONSE:
            raise DoIPPayloadError(
                "Expected Vehicle Identification Response"
            )

        if len(payload) != cls.PAYLOAD_SIZE:
            raise DoIPPayloadError(
                f"Vehicle Identification Response must contain "
                f"{cls.PAYLOAD_SIZE} bytes, got {len(payload)}"
            )

        vin = payload[:17]

        logical_address = struct.unpack(
            "!H",
            payload[17:19],
        )[0]

        eid = payload[19:25]
        gid = payload[25:31]
        further_action = payload[31]
        vin_gid_status = payload[32]

        return cls(
            vin=vin,
            logical_address=logical_address,
            eid=eid,
            gid=gid,
            further_action=further_action,
            vin_gid_status=vin_gid_status,
        )


@dataclass
class RoutingActivationRequest:
    source_address: int
    activation_type: int
    reserved: bytes = b"\x00\x00\x00\x00"
    oem_specific: bytes = b"\x00\x00\x00\x00"

    PAYLOAD_SIZE = 11

    def validate(self):
        if not 0 <= self.source_address <= 0xFFFF:
            raise DoIPPayloadError(
                "Source address must fit in uint16"
            )

        if not 0 <= self.activation_type <= 0xFF:
            raise DoIPPayloadError(
                "Activation type must fit in uint8"
            )

        if self.reserved != b"\x00\x00\x00\x00":
            raise DoIPPayloadError(
                "Routing Activation reserved bytes must be zero"
            )

        if not isinstance(self.oem_specific, bytes) or len(
            self.oem_specific
        ) != 4:
            raise DoIPPayloadError(
                "OEM-specific field must contain 4 bytes"
            )

    def encode(self):
        self.validate()

        payload = (
            struct.pack("!HB", self.source_address, self.activation_type)
            + self.reserved
            + self.oem_specific
        )

        return build_doip_message(
            ROUTING_ACTIVATION_REQUEST,
            payload,
        )

    @classmethod
    def decode(cls, data):
        header, payload = parse_doip_message(data)

        if header.payload_type != ROUTING_ACTIVATION_REQUEST:
            raise DoIPPayloadError(
                "Expected Routing Activation Request"
            )

        if len(payload) != cls.PAYLOAD_SIZE:
            raise DoIPPayloadError(
                f"Routing Activation Request must contain "
                f"{cls.PAYLOAD_SIZE} bytes, got {len(payload)}"
            )

        source_address = struct.unpack(
            "!H",
            payload[:2],
        )[0]

        activation_type = payload[2]
        reserved = payload[3:7]
        oem_specific = payload[7:11]

        return cls(
            source_address=source_address,
            activation_type=activation_type,
            reserved=reserved,
            oem_specific=oem_specific,
        )


@dataclass
class RoutingActivationResponse:
    logical_address: int
    source_address: int
    response_code: int
    reserved: bytes = b"\x00\x00\x00\x00"
    oem_specific: bytes = b"\x00\x00\x00\x00"

    PAYLOAD_SIZE = 13

    def validate(self):
        if not 0 <= self.logical_address <= 0xFFFF:
            raise DoIPPayloadError(
                "Logical address must fit in uint16"
            )

        if not 0 <= self.source_address <= 0xFFFF:
            raise DoIPPayloadError(
                "Source address must fit in uint16"
            )

        if not 0 <= self.response_code <= 0xFF:
            raise DoIPPayloadError(
                "Response code must fit in uint8"
            )

        if self.reserved != b"\x00\x00\x00\x00":
            raise DoIPPayloadError(
                "Routing Activation reserved bytes must be zero"
            )

        if not isinstance(self.oem_specific, bytes) or len(
            self.oem_specific
        ) != 4:
            raise DoIPPayloadError(
                "OEM-specific field must contain 4 bytes"
            )

    def encode(self):
        self.validate()

        payload = (
            struct.pack(
                "!HHB",
                self.logical_address,
                self.source_address,
                self.response_code,
            )
            + self.reserved
            + self.oem_specific
        )

        return build_doip_message(
            ROUTING_ACTIVATION_RESPONSE,
            payload,
        )

    @classmethod
    def decode(cls, data):
        header, payload = parse_doip_message(data)

        if header.payload_type != ROUTING_ACTIVATION_RESPONSE:
            raise DoIPPayloadError(
                "Expected Routing Activation Response"
            )

        if len(payload) != cls.PAYLOAD_SIZE:
            raise DoIPPayloadError(
                f"Routing Activation Response must contain "
                f"{cls.PAYLOAD_SIZE} bytes, got {len(payload)}"
            )

        logical_address, source_address, response_code = struct.unpack(
            "!HHB",
            payload[:5],
        )

        return cls(
            logical_address=logical_address,
            source_address=source_address,
            response_code=response_code,
            reserved=payload[5:9],
            oem_specific=payload[9:13],
        )


@dataclass
class AliveCheckRequest:
    def encode(self):
        return build_doip_message(
            ALIVE_CHECK_REQUEST,
            b"",
        )

    @classmethod
    def decode(cls, data):
        header, payload = parse_doip_message(data)

        if header.payload_type != ALIVE_CHECK_REQUEST:
            raise DoIPPayloadError(
                "Expected Alive Check Request"
            )

        if payload:
            raise DoIPPayloadError(
                "Alive Check Request must have an empty payload"
            )

        return cls()


@dataclass
class AliveCheckResponse:
    source_address: int

    PAYLOAD_SIZE = 2

    def validate(self):
        if not 0 <= self.source_address <= 0xFFFF:
            raise DoIPPayloadError(
                "Source address must fit in uint16"
            )

    def encode(self):
        self.validate()

        return build_doip_message(
            ALIVE_CHECK_RESPONSE,
            struct.pack("!H", self.source_address),
        )

    @classmethod
    def decode(cls, data):
        header, payload = parse_doip_message(data)

        if header.payload_type != ALIVE_CHECK_RESPONSE:
            raise DoIPPayloadError(
                "Expected Alive Check Response"
            )

        if len(payload) != cls.PAYLOAD_SIZE:
            raise DoIPPayloadError(
                f"Alive Check Response must contain "
                f"{cls.PAYLOAD_SIZE} bytes, got {len(payload)}"
            )

        return cls(
            source_address=struct.unpack("!H", payload)[0]
        )


@dataclass
class DiagnosticMessage:
    source_address: int
    target_address: int
    diagnostic_data: bytes

    def validate(self):
        if not 0 <= self.source_address <= 0xFFFF:
            raise DoIPPayloadError(
                "Source address must fit in uint16"
            )

        if not 0 <= self.target_address <= 0xFFFF:
            raise DoIPPayloadError(
                "Target address must fit in uint16"
            )

        if not isinstance(self.diagnostic_data, bytes):
            raise DoIPPayloadError(
                "Diagnostic data must be bytes"
            )

    def encode(self):
        self.validate()

        payload = (
            struct.pack(
                "!HH",
                self.source_address,
                self.target_address,
            )
            + self.diagnostic_data
        )

        return build_doip_message(
            DIAGNOSTIC_MESSAGE,
            payload,
        )

    @classmethod
    def decode(cls, data):
        header, payload = parse_doip_message(data)

        if header.payload_type != DIAGNOSTIC_MESSAGE:
            raise DoIPPayloadError(
                "Expected Diagnostic Message"
            )

        if len(payload) < 4:
            raise DoIPPayloadError(
                "Diagnostic Message requires at least "
                "4 payload bytes"
            )

        source_address, target_address = struct.unpack(
            "!HH",
            payload[:4],
        )

        return cls(
            source_address=source_address,
            target_address=target_address,
            diagnostic_data=payload[4:],
        )


@dataclass
class DiagnosticMessageAck:
    source_address: int
    target_address: int
    ack_code: int

    PAYLOAD_SIZE = 5

    def validate(self):
        if not 0 <= self.source_address <= 0xFFFF:
            raise DoIPPayloadError(
                "Source address must fit in uint16"
            )

        if not 0 <= self.target_address <= 0xFFFF:
            raise DoIPPayloadError(
                "Target address must fit in uint16"
            )

        if not 0 <= self.ack_code <= 0xFF:
            raise DoIPPayloadError(
                "ACK code must fit in uint8"
            )

    def encode(self):
        self.validate()

        payload = struct.pack(
            "!HHB",
            self.source_address,
            self.target_address,
            self.ack_code,
        )

        return build_doip_message(
            DIAGNOSTIC_MESSAGE_ACK,
            payload,
        )

    @classmethod
    def decode(cls, data):
        header, payload = parse_doip_message(data)

        if header.payload_type != DIAGNOSTIC_MESSAGE_ACK:
            raise DoIPPayloadError(
                "Expected Diagnostic Message ACK"
            )

        if len(payload) != cls.PAYLOAD_SIZE:
            raise DoIPPayloadError(
                f"Diagnostic Message ACK must contain "
                f"{cls.PAYLOAD_SIZE} bytes, got {len(payload)}"
            )

        source_address, target_address, ack_code = struct.unpack(
            "!HHB",
            payload,
        )

        return cls(
            source_address=source_address,
            target_address=target_address,
            ack_code=ack_code,
        )


@dataclass
class DiagnosticMessageNack:
    source_address: int
    target_address: int
    nack_code: int

    PAYLOAD_SIZE = 5

    def validate(self):
        if not 0 <= self.source_address <= 0xFFFF:
            raise DoIPPayloadError(
                "Source address must fit in uint16"
            )

        if not 0 <= self.target_address <= 0xFFFF:
            raise DoIPPayloadError(
                "Target address must fit in uint16"
            )

        if not 0 <= self.nack_code <= 0xFF:
            raise DoIPPayloadError(
                "NACK code must fit in uint8"
            )

    def encode(self):
        self.validate()

        payload = struct.pack(
            "!HHB",
            self.source_address,
            self.target_address,
            self.nack_code,
        )

        return build_doip_message(
            DIAGNOSTIC_MESSAGE_NACK,
            payload,
        )

    @classmethod
    def decode(cls, data):
        header, payload = parse_doip_message(data)

        if header.payload_type != DIAGNOSTIC_MESSAGE_NACK:
            raise DoIPPayloadError(
                "Expected Diagnostic Message NACK"
            )

        if len(payload) != cls.PAYLOAD_SIZE:
            raise DoIPPayloadError(
                f"Diagnostic Message NACK must contain "
                f"{cls.PAYLOAD_SIZE} bytes, got {len(payload)}"
            )

        source_address, target_address, nack_code = struct.unpack(
            "!HHB",
            payload,
        )

        return cls(
            source_address=source_address,
            target_address=target_address,
            nack_code=nack_code,
        )


def decode_payload(data):
    header, _ = parse_doip_message(data)

    decoders = {
        VEHICLE_IDENTIFICATION_REQUEST:
            VehicleIdentificationRequest,
        VEHICLE_IDENTIFICATION_RESPONSE:
            VehicleIdentificationResponse,
        ROUTING_ACTIVATION_REQUEST:
            RoutingActivationRequest,
        ROUTING_ACTIVATION_RESPONSE:
            RoutingActivationResponse,
        ALIVE_CHECK_REQUEST:
            AliveCheckRequest,
        ALIVE_CHECK_RESPONSE:
            AliveCheckResponse,
        DIAGNOSTIC_MESSAGE:
            DiagnosticMessage,
        DIAGNOSTIC_MESSAGE_ACK:
            DiagnosticMessageAck,
        DIAGNOSTIC_MESSAGE_NACK:
            DiagnosticMessageNack,
    }

    decoder = decoders.get(header.payload_type)

    if decoder is None:
        raise DoIPPayloadError(
            f"No structured decoder for payload type "
            f"0x{header.payload_type:04X}"
        )

    return decoder.decode(data)
