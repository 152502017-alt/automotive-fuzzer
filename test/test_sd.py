import unittest

from someip.sd import build_sd_message, parse_sd_message, SDFlags, SomeIPSDError
from someip.constants import NOTIFICATION


class TestSDEnvelope(unittest.TestCase):

    def test_empty_sd_message_round_trip(self):
        flags = SDFlags(reboot=True, unicast=True, initial_data=False)

        message = build_sd_message(session_id=0x0001, flags=flags)

        header, parsed_flags, entries, options = parse_sd_message(message)

        self.assertEqual(header.service_id, 0xFFFF)
        self.assertEqual(header.method_id, 0x8100)
        self.assertEqual(header.message_type, NOTIFICATION)
        self.assertEqual(header.return_code, 0x00)
        self.assertEqual(header.session_id, 0x0001)

        self.assertTrue(parsed_flags.reboot)
        self.assertTrue(parsed_flags.unicast)
        self.assertFalse(parsed_flags.initial_data)

        self.assertEqual(entries, b"")
        self.assertEqual(options, b"")

    def test_rejects_non_sd_service_id(self):
        # A normal, valid, non-SD SOME/IP message should NOT be accepted
        # by parse_sd_message, even though it's a perfectly valid SOME/IP
        # message on its own.
        from someip.message import build_someip_message
        from someip.constants import REQUEST

        not_sd = build_someip_message(
            service_id=0x1234,
            method_id=0x0001,
            client_id=0x0010,
            session_id=0x0001,
            interface_version=1,
            message_type=REQUEST,
            return_code=0x00,
            payload=b"GetSpeed",
        )

        with self.assertRaises(SomeIPSDError):
            parse_sd_message(not_sd)

    def test_rejects_bad_entries_length(self):
        # Tamper the entries-length field to claim more bytes than exist.
        flags = SDFlags()
        message = bytearray(build_sd_message(session_id=0x0001, flags=flags))

        # SD payload starts at byte 16 (after SOME/IP header).
        # Flags(1) + reserved(3) = bytes 16-19, entries-length = bytes 20-23.
        message[20:24] = (99).to_bytes(4, "big")

        with self.assertRaises(SomeIPSDError):
            parse_sd_message(bytes(message))


if __name__ == "__main__":
    unittest.main()