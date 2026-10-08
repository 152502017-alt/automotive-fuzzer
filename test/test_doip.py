import unittest

from doip.constants import (
    ALIVE_CHECK_REQUEST,
    ALIVE_CHECK_RESPONSE,
    DIAGNOSTIC_MESSAGE,
    DIAGNOSTIC_MESSAGE_ACK,
    DIAGNOSTIC_MESSAGE_NACK,
    DOIP_INVERSE_PROTOCOL_VERSION,
    DOIP_PROTOCOL_VERSION,
    ROUTING_ACTIVATION_REQUEST,
    ROUTING_ACTIVATION_RESPONSE,
    VEHICLE_IDENTIFICATION_REQUEST,
    VEHICLE_IDENTIFICATION_RESPONSE,
)
from doip.error import (
    DoIPLengthError,
    DoIPPayloadError,
    DoIPPayloadTypeError,
    DoIPVersionError,
)
from doip.header import DoIPHeader
from doip.message import (
    AliveCheckRequest,
    AliveCheckResponse,
    DiagnosticMessage,
    DiagnosticMessageAck,
    DiagnosticMessageNack,
    RoutingActivationRequest,
    RoutingActivationResponse,
    VehicleIdentificationRequest,
    VehicleIdentificationResponse,
    build_doip_message,
    decode_payload,
    parse_doip_message,
)


class TestDoIPHeader(unittest.TestCase):

    def test_round_trip(self):
        header = DoIPHeader(
            protocol_version=DOIP_PROTOCOL_VERSION,
            inverse_protocol_version=DOIP_INVERSE_PROTOCOL_VERSION,
            payload_type=DIAGNOSTIC_MESSAGE,
            payload_length=10,
        )

        encoded = header.encode()
        decoded = DoIPHeader.decode(encoded)

        self.assertEqual(decoded, header)
        self.assertEqual(
            encoded,
            b"\x04\xfb\x80\x01\x00\x00\x00\x0a",
        )

    def test_rejects_wrong_protocol_version(self):
        with self.assertRaises(DoIPVersionError):
            DoIPHeader(
                protocol_version=0x03,
                inverse_protocol_version=0xFC,
                payload_type=DIAGNOSTIC_MESSAGE,
                payload_length=0,
            ).encode()

    def test_rejects_wrong_inverse_version(self):
        with self.assertRaises(DoIPVersionError):
            DoIPHeader(
                protocol_version=DOIP_PROTOCOL_VERSION,
                inverse_protocol_version=0xFC,
                payload_type=DIAGNOSTIC_MESSAGE,
                payload_length=0,
            ).encode()

    def test_rejects_unknown_payload_type(self):
        with self.assertRaises(DoIPPayloadTypeError):
            DoIPHeader(
                protocol_version=DOIP_PROTOCOL_VERSION,
                inverse_protocol_version=DOIP_INVERSE_PROTOCOL_VERSION,
                payload_type=0x1234,
                payload_length=0,
            ).encode()

    def test_rejects_short_header(self):
        with self.assertRaises(Exception):
            DoIPHeader.decode(b"\x04\xfb\x80")


class TestDoIPMessage(unittest.TestCase):

    def test_empty_payload_round_trip(self):
        message = build_doip_message(
            VEHICLE_IDENTIFICATION_REQUEST,
        )

        header, payload = parse_doip_message(message)

        self.assertEqual(
            header.payload_type,
            VEHICLE_IDENTIFICATION_REQUEST,
        )
        self.assertEqual(payload, b"")

    def test_length_mismatch(self):
        message = build_doip_message(
            DIAGNOSTIC_MESSAGE,
            b"abc",
        )

        with self.assertRaises(DoIPLengthError):
            parse_doip_message(message + b"x")

    def test_truncated_message(self):
        with self.assertRaises(DoIPLengthError):
            parse_doip_message(
                b"\x04\xfb\x80\x01\x00\x00\x00\x05abc"
            )


class TestVehicleIdentification(unittest.TestCase):

    def test_request_round_trip(self):
        message = VehicleIdentificationRequest().encode()

        decoded = VehicleIdentificationRequest.decode(message)

        self.assertIsInstance(
            decoded,
            VehicleIdentificationRequest,
        )

    def test_response_round_trip(self):
        message = VehicleIdentificationResponse(
            vin=b"TESTVIN1234567890",
            logical_address=0x0001,
            eid=b"\x01\x02\x03\x04\x05\x06",
            gid=b"\x10\x11\x12\x13\x14\x15",
            further_action=0x00,
            vin_gid_status=0x00,
        ).encode()

        decoded = VehicleIdentificationResponse.decode(
            message
        )

        self.assertEqual(
            decoded.vin,
            b"TESTVIN1234567890",
        )
        self.assertEqual(
            decoded.logical_address,
            0x0001,
        )
        self.assertEqual(
            decoded.eid,
            b"\x01\x02\x03\x04\x05\x06",
        )
        self.assertEqual(
            decoded.gid,
            b"\x10\x11\x12\x13\x14\x15",
        )

    def test_invalid_vin_length(self):
        with self.assertRaises(DoIPPayloadError):
            VehicleIdentificationResponse(
                vin=b"SHORT",
                logical_address=1,
                eid=b"\x00" * 6,
                gid=b"\x00" * 6,
                further_action=0,
                vin_gid_status=0,
            ).encode()


class TestRoutingActivation(unittest.TestCase):

    def test_request_round_trip(self):
        message = RoutingActivationRequest(
            source_address=0x0E80,
            activation_type=0x00,
        ).encode()

        decoded = RoutingActivationRequest.decode(
            message
        )

        self.assertEqual(
            decoded.source_address,
            0x0E80,
        )
        self.assertEqual(
            decoded.activation_type,
            0x00,
        )

    def test_response_round_trip(self):
        message = RoutingActivationResponse(
            logical_address=0x0001,
            source_address=0x0E80,
            response_code=0x10,
        ).encode()

        decoded = RoutingActivationResponse.decode(
            message
        )

        self.assertEqual(
            decoded.logical_address,
            0x0001,
        )
        self.assertEqual(
            decoded.source_address,
            0x0E80,
        )
        self.assertEqual(
            decoded.response_code,
            0x10,
        )

    def test_request_reserved_bytes_must_be_zero(self):
        with self.assertRaises(DoIPPayloadError):
            RoutingActivationRequest(
                source_address=0x0E80,
                activation_type=0,
                reserved=b"\x01\x00\x00\x00",
            ).encode()


class TestAliveCheck(unittest.TestCase):

    def test_request_round_trip(self):
        message = AliveCheckRequest().encode()

        decoded = AliveCheckRequest.decode(message)

        self.assertIsInstance(
            decoded,
            AliveCheckRequest,
        )

    def test_response_round_trip(self):
        message = AliveCheckResponse(
            source_address=0x0E80,
        ).encode()

        decoded = AliveCheckResponse.decode(
            message
        )

        self.assertEqual(
            decoded.source_address,
            0x0E80,
        )


class TestDiagnosticMessages(unittest.TestCase):

    def test_diagnostic_round_trip(self):
        message = DiagnosticMessage(
            source_address=0x0E80,
            target_address=0x1000,
            diagnostic_data=b"\x22\xF1\x90",
        ).encode()

        decoded = DiagnosticMessage.decode(
            message
        )

        self.assertEqual(
            decoded.source_address,
            0x0E80,
        )
        self.assertEqual(
            decoded.target_address,
            0x1000,
        )
        self.assertEqual(
            decoded.diagnostic_data,
            b"\x22\xF1\x90",
        )

    def test_ack_round_trip(self):
        message = DiagnosticMessageAck(
            source_address=0x1000,
            target_address=0x0E80,
            ack_code=0x00,
        ).encode()

        decoded = DiagnosticMessageAck.decode(
            message
        )

        self.assertEqual(
            decoded.source_address,
            0x1000,
        )
        self.assertEqual(
            decoded.target_address,
            0x0E80,
        )
        self.assertEqual(
            decoded.ack_code,
            0x00,
        )

    def test_nack_round_trip(self):
        message = DiagnosticMessageNack(
            source_address=0x1000,
            target_address=0x0E80,
            nack_code=0x02,
        ).encode()

        decoded = DiagnosticMessageNack.decode(
            message
        )

        self.assertEqual(
            decoded.source_address,
            0x1000,
        )
        self.assertEqual(
            decoded.target_address,
            0x0E80,
        )
        self.assertEqual(
            decoded.nack_code,
            0x02,
        )

    def test_diagnostic_message_requires_addresses(self):
        message = build_doip_message(
            DIAGNOSTIC_MESSAGE,
            b"\x00\x01",
        )

        with self.assertRaises(DoIPPayloadError):
            DiagnosticMessage.decode(message)


class TestGenericDecoder(unittest.TestCase):

    def test_decode_payload(self):
        message = AliveCheckRequest().encode()

        decoded = decode_payload(message)

        self.assertIsInstance(
            decoded,
            AliveCheckRequest,
        )

    def test_decoder_dispatches_diagnostic_message(self):
        message = DiagnosticMessage(
            source_address=0x0E80,
            target_address=0x1000,
            diagnostic_data=b"\x10\x01",
        ).encode()

        decoded = decode_payload(message)

        self.assertIsInstance(
            decoded,
            DiagnosticMessage,
        )


if __name__ == "__main__":
    unittest.main()
