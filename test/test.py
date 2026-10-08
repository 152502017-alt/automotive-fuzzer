import unittest

from someip.message import (
    build_someip_message,
    parse_someip_message,
)

from someip.constants import REQUEST, RESPONSE
from someip.error import (
    SomeIPHeaderError,
    SomeIPLengthError,
    SomeIPVersionError,
    SomeIPMessageTypeError,
)


class TestSomeIP(unittest.TestCase):

    def test_request_encode_decode(self):
        payload = b"GetSpeed"

        message = build_someip_message(
            service_id=0x1234,
            method_id=0x0001,
            client_id=0x0010,
            session_id=0x0001,
            interface_version=1,
            message_type=REQUEST,
            return_code=0x00,
            payload=payload,
        )

        header, parsed_payload = parse_someip_message(message)

        self.assertEqual(header.service_id, 0x1234)
        self.assertEqual(header.method_id, 0x0001)

        self.assertEqual(header.client_id, 0x0010)
        self.assertEqual(header.session_id, 0x0001)

        self.assertEqual(header.protocol_version, 0x01)
        self.assertEqual(header.interface_version, 0x01)

        self.assertEqual(header.message_type, REQUEST)
        self.assertEqual(header.return_code, 0x00)

        self.assertEqual(parsed_payload, payload)


    def test_response_encode_decode(self):
        payload = b"Speed: 100 km/h"

        message = build_someip_message(
            service_id=0x1234,
            method_id=0x0001,
            client_id=0x0010,
            session_id=0x0001,
            interface_version=1,
            message_type=RESPONSE,
            return_code=0x00,
            payload=payload,
        )

        header, parsed_payload = parse_someip_message(message)

        self.assertEqual(header.service_id, 0x1234)
        self.assertEqual(header.method_id, 0x0001)

        self.assertEqual(header.message_type, RESPONSE)
        self.assertEqual(header.return_code, 0x00)

        self.assertEqual(parsed_payload, payload)


    def test_invalid_protocol_version(self):
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

        # Protocol version is byte 12 of the SOME/IP header.
        malformed = (
            message[:12]
            + b"\x02"
            + message[13:]
        )

        with self.assertRaises(SomeIPVersionError):
            parse_someip_message(malformed)


    def test_invalid_message_type(self):
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

        # Message Type is byte 14.
        malformed = (
            message[:14]
            + b"\xFF"
            + message[15:]
        )

        with self.assertRaises(SomeIPMessageTypeError):
            parse_someip_message(malformed)


    def test_length_mismatch(self):
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

        # Replace Length field with an incorrect value.
        malformed = (
            message[:4]
            + b"\x00\x00\x00\xFF"
            + message[8:]
        )

        with self.assertRaises(SomeIPLengthError):
            parse_someip_message(malformed)


    def test_short_message_rejected(self):
        data = b"\x00" * 10 
        with self.assertRaises(SomeIPHeaderError): 
            parse_someip_message(data)

    def test_length_field_too_small(self):
        data = bytearray(
        build_someip_message(
            service_id=0x1234,
            method_id=0x0001,
            client_id=0x0010,
            session_id=0x0001,
            interface_version=1,
            message_type=REQUEST,
            return_code=0x00,
            payload=b"ABC",
        )
    )

    # Length field is at bytes 4-7.
        data[4:8] = (7).to_bytes(4, byteorder="big")

        with self.assertRaises(SomeIPLengthError):
            parse_someip_message(bytes(data))


def test_length_field_too_large(self):
    data = bytearray(
        build_someip_message(
            service_id=0x1234,
            method_id=0x0001,
            client_id=0x0010,
            session_id=0x0001,
            interface_version=1,
            message_type=REQUEST,
            return_code=0x00,
            payload=b"ABC",
        )
    )

    # Increase Length without adding the corresponding payload bytes.
    data[4:8] = (100).to_bytes(4, byteorder="big")

    with self.assertRaises(SomeIPLengthError):
        parse_someip_message(bytes(data))

    
if __name__ == "__main__":
    unittest.main()