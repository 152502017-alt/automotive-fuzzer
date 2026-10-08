import unittest

from someip.sd_option import (
    IPv4EndpointOption,
    IPv4MulticastOption,
    SomeIPSDOptionError,
    IPV4_ENDPOINT_OPTION,
    IPV4_MULTICAST_OPTION,
    decode_sd_option,
    decode_sd_options,
)


class TestIPv4EndpointOption(unittest.TestCase):

    def test_udp_round_trip(self):
        option = IPv4EndpointOption(
            address="192.168.1.10",
            port=30490,
        )

        decoded = IPv4EndpointOption.decode(
            option.encode()
        )

        self.assertEqual(
            decoded.address,
            "192.168.1.10",
        )

        self.assertEqual(
            decoded.port,
            30490,
        )

    def test_tcp_round_trip(self):
        option = IPv4EndpointOption(
            address="10.0.0.5",
            port=12345,
            protocol=IPv4EndpointOption.PROTOCOL_TCP,
        )

        decoded = IPv4EndpointOption.decode(
            option.encode()
        )

        self.assertEqual(
            decoded.address,
            "10.0.0.5",
        )

        self.assertEqual(
            decoded.port,
            12345,
        )

        self.assertEqual(
            decoded.protocol,
            IPv4EndpointOption.PROTOCOL_TCP,
        )

    def test_known_wire_format(self):
        option = IPv4EndpointOption(
            address="192.168.1.10",
            port=30490,
        )

        self.assertEqual(
            option.encode().hex(),
            "00090400c0a8010a0011771a",
        )

    def test_length_field_is_nine(self):
        option = IPv4EndpointOption(
            address="192.168.1.10",
            port=30490,
        )

        self.assertEqual(
            option.encode()[0:2],
            b"\x00\x09",
        )

    def test_option_type_is_ipv4_endpoint(self):
        option = IPv4EndpointOption(
            address="192.168.1.10",
            port=30490,
        )

        self.assertEqual(
            option.encode()[2],
            IPV4_ENDPOINT_OPTION,
        )

    def test_rejects_invalid_ip(self):
        with self.assertRaises(SomeIPSDOptionError):
            IPv4EndpointOption(
                address="999.999.999.999",
                port=30490,
            )

    def test_rejects_invalid_port(self):
        with self.assertRaises(SomeIPSDOptionError):
            IPv4EndpointOption(
                address="192.168.1.10",
                port=70000,
            )

    def test_rejects_invalid_protocol(self):
        with self.assertRaises(SomeIPSDOptionError):
            IPv4EndpointOption(
                address="192.168.1.10",
                port=30490,
                protocol=0x99,
            )

    def test_rejects_wrong_size(self):
        with self.assertRaises(SomeIPSDOptionError):
            IPv4EndpointOption.decode(
                b"\x00" * 11
            )

        with self.assertRaises(SomeIPSDOptionError):
            IPv4EndpointOption.decode(
                b"\x00" * 13
            )

    def test_rejects_wrong_length_field(self):
        data = bytearray(
            IPv4EndpointOption(
                address="192.168.1.10",
                port=30490,
            ).encode()
        )

        data[1] = 8

        with self.assertRaises(SomeIPSDOptionError):
            IPv4EndpointOption.decode(bytes(data))

    def test_rejects_nonzero_reserved_byte(self):
        data = bytearray(
            IPv4EndpointOption(
                address="192.168.1.10",
                port=30490,
            ).encode()
        )

        data[3] = 0x01

        with self.assertRaises(SomeIPSDOptionError):
            IPv4EndpointOption.decode(bytes(data))

    def test_rejects_nonzero_address_reserved_byte(self):
        data = bytearray(
            IPv4EndpointOption(
                address="192.168.1.10",
                port=30490,
            ).encode()
        )

        data[8] = 0x01

        with self.assertRaises(SomeIPSDOptionError):
            IPv4EndpointOption.decode(bytes(data))


class TestIPv4MulticastOption(unittest.TestCase):

    def test_round_trip(self):
        option = IPv4MulticastOption(
            address="239.255.0.1",
            port=30500,
        )

        decoded = IPv4MulticastOption.decode(
            option.encode()
        )

        self.assertEqual(
            decoded.address,
            "239.255.0.1",
        )

        self.assertEqual(
            decoded.port,
            30500,
        )

    def test_known_wire_format(self):
        option = IPv4MulticastOption(
            address="239.255.0.1",
            port=30500,
        )

        self.assertEqual(
            option.encode().hex(),
            "00091400efff000100117724",
        )

    def test_length_field_is_nine(self):
        option = IPv4MulticastOption(
            address="239.255.0.1",
            port=30500,
        )

        self.assertEqual(
            option.encode()[0:2],
            b"\x00\x09",
        )

    def test_option_type_is_ipv4_multicast(self):
        option = IPv4MulticastOption(
            address="239.255.0.1",
            port=30500,
        )

        self.assertEqual(
            option.encode()[2],
            IPV4_MULTICAST_OPTION,
        )

    def test_rejects_non_multicast_address(self):
        with self.assertRaises(SomeIPSDOptionError):
            IPv4MulticastOption(
                address="192.168.1.10",
                port=30500,
            )

    def test_rejects_invalid_ip(self):
        with self.assertRaises(SomeIPSDOptionError):
            IPv4MulticastOption(
                address="999.999.999.999",
                port=30500,
            )

    def test_rejects_invalid_port(self):
        with self.assertRaises(SomeIPSDOptionError):
            IPv4MulticastOption(
                address="239.255.0.1",
                port=70000,
            )

    def test_rejects_tcp(self):
        with self.assertRaises(SomeIPSDOptionError):
            IPv4MulticastOption(
                address="239.255.0.1",
                port=30500,
                protocol=0x06,
            )

    def test_rejects_wrong_size(self):
        with self.assertRaises(SomeIPSDOptionError):
            IPv4MulticastOption.decode(
                b"\x00" * 11
            )

        with self.assertRaises(SomeIPSDOptionError):
            IPv4MulticastOption.decode(
                b"\x00" * 13
            )

    def test_rejects_wrong_length_field(self):
        data = bytearray(
            IPv4MulticastOption(
                address="239.255.0.1",
                port=30500,
            ).encode()
        )

        data[1] = 8

        with self.assertRaises(SomeIPSDOptionError):
            IPv4MulticastOption.decode(bytes(data))

    def test_rejects_nonzero_reserved_byte(self):
        data = bytearray(
            IPv4MulticastOption(
                address="239.255.0.1",
                port=30500,
            ).encode()
        )

        data[3] = 0x01

        with self.assertRaises(SomeIPSDOptionError):
            IPv4MulticastOption.decode(bytes(data))

    def test_rejects_nonzero_address_reserved_byte(self):
        data = bytearray(
            IPv4MulticastOption(
                address="239.255.0.1",
                port=30500,
            ).encode()
        )

        data[8] = 0x01

        with self.assertRaises(SomeIPSDOptionError):
            IPv4MulticastOption.decode(bytes(data))


class TestSDOptionDecoder(unittest.TestCase):

    def test_decode_endpoint_by_type(self):
        option = IPv4EndpointOption(
            address="192.168.1.10",
            port=30490,
        )

        decoded = decode_sd_option(
            option.encode()
        )

        self.assertIsInstance(
            decoded,
            IPv4EndpointOption,
        )

        self.assertEqual(
            decoded.address,
            "192.168.1.10",
        )

    def test_decode_multicast_by_type(self):
        option = IPv4MulticastOption(
            address="239.255.0.1",
            port=30500,
        )

        decoded = decode_sd_option(
            option.encode()
        )

        self.assertIsInstance(
            decoded,
            IPv4MulticastOption,
        )

        self.assertEqual(
            decoded.address,
            "239.255.0.1",
        )

    def test_rejects_unknown_option_type(self):
        data = bytes.fromhex(
            "000900"
            "000000000000000011"
            "771a"
        )

        with self.assertRaises(
            SomeIPSDOptionError
        ):
            decode_sd_option(data)

    def test_rejects_truncated_option(self):
        with self.assertRaises(
            SomeIPSDOptionError
        ):
            decode_sd_option(
                b"\x00\x09"
            )

    def test_decode_multiple_options(self):
        endpoint = IPv4EndpointOption(
            address="192.168.1.10",
            port=30490,
        )

        multicast = IPv4MulticastOption(
            address="239.255.0.1",
            port=30500,
        )

        data = (
            endpoint.encode()
            + multicast.encode()
        )

        options = decode_sd_options(data)

        self.assertEqual(
            len(options),
            2,
        )

        self.assertIsInstance(
            options[0],
            IPv4EndpointOption,
        )

        self.assertIsInstance(
            options[1],
            IPv4MulticastOption,
        )

    def test_decode_empty_options(self):
        options = decode_sd_options(b"")

        self.assertEqual(
            options,
            [],
        )

    def test_rejects_truncated_second_option(self):
        endpoint = IPv4EndpointOption(
            address="192.168.1.10",
            port=30490,
        )

        multicast = IPv4MulticastOption(
            address="239.255.0.1",
            port=30500,
        )

        data = (
            endpoint.encode()
            + multicast.encode()[:5]
        )

        with self.assertRaises(
            SomeIPSDOptionError
        ):
            decode_sd_options(data)


if __name__ == "__main__":
    unittest.main()