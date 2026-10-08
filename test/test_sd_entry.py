import unittest

from someip.sd_entry import (
    ServiceEntry,
    SomeIPSDEntryError,
    FIND_SERVICE,
    OFFER_SERVICE,
)


class TestServiceEntry(unittest.TestCase):

    def test_offer_service_round_trip(self):
        entry = ServiceEntry(
            entry_type=OFFER_SERVICE,
            index_first_option_run=0,
            index_second_option_run=1,
            number_of_options_1=2,
            number_of_options_2=3,
            service_id=0x1234,
            instance_id=0x0001,
            major_version=1,
            ttl=10,
            minor_version=0x00000002,
        )

        encoded = entry.encode()

        self.assertEqual(len(encoded), 16)

        decoded = ServiceEntry.decode(encoded)

        self.assertEqual(decoded.entry_type, OFFER_SERVICE)
        self.assertEqual(decoded.index_first_option_run, 0)
        self.assertEqual(decoded.index_second_option_run, 1)
        self.assertEqual(decoded.number_of_options_1, 2)
        self.assertEqual(decoded.number_of_options_2, 3)
        self.assertEqual(decoded.service_id, 0x1234)
        self.assertEqual(decoded.instance_id, 0x0001)
        self.assertEqual(decoded.major_version, 1)
        self.assertEqual(decoded.ttl, 10)
        self.assertEqual(decoded.minor_version, 0x00000002)

    def test_find_service_round_trip(self):
        entry = ServiceEntry(
            entry_type=FIND_SERVICE,
            index_first_option_run=0,
            index_second_option_run=0,
            number_of_options_1=0,
            number_of_options_2=0,
            service_id=0x1000,
            instance_id=0x0001,
            major_version=1,
            ttl=0,
            minor_version=0xFFFFFFFF,
        )

        decoded = ServiceEntry.decode(
            entry.encode()
        )

        self.assertEqual(
            decoded.entry_type,
            FIND_SERVICE,
        )
        self.assertEqual(
            decoded.service_id,
            0x1000,
        )
        self.assertEqual(
            decoded.instance_id,
            0x0001,
        )
        self.assertEqual(
            decoded.ttl,
            0,
        )
        self.assertEqual(
            decoded.minor_version,
            0xFFFFFFFF,
        )

    def test_24_bit_ttl(self):
        entry = ServiceEntry(
            entry_type=OFFER_SERVICE,
            index_first_option_run=0,
            index_second_option_run=0,
            number_of_options_1=0,
            number_of_options_2=0,
            service_id=0x1234,
            instance_id=0x0001,
            major_version=1,
            ttl=0xFFFFFF,
            minor_version=0,
        )

        decoded = ServiceEntry.decode(
            entry.encode()
        )

        self.assertEqual(
            decoded.ttl,
            0xFFFFFF,
        )

    def test_rejects_invalid_entry_type(self):
        with self.assertRaises(
            SomeIPSDEntryError
        ):
            ServiceEntry(
                entry_type=0xFF,
                index_first_option_run=0,
                index_second_option_run=0,
                number_of_options_1=0,
                number_of_options_2=0,
                service_id=0x1234,
                instance_id=0x0001,
                major_version=1,
                ttl=10,
                minor_version=0,
            )

    def test_rejects_ttl_above_24_bits(self):
        with self.assertRaises(
            SomeIPSDEntryError
        ):
            ServiceEntry(
                entry_type=OFFER_SERVICE,
                index_first_option_run=0,
                index_second_option_run=0,
                number_of_options_1=0,
                number_of_options_2=0,
                service_id=0x1234,
                instance_id=0x0001,
                major_version=1,
                ttl=0x1000000,
                minor_version=0,
            )

    def test_rejects_wrong_size(self):
        with self.assertRaises(
            SomeIPSDEntryError
        ):
            ServiceEntry.decode(
                b"\x00" * 15
            )

        with self.assertRaises(
            SomeIPSDEntryError
        ):
            ServiceEntry.decode(
                b"\x00" * 17
            )

    def test_find_service_constructor(self):
        entry = ServiceEntry.find_service(
            service_id=0x1234,
            instance_id=0x0001,
            major_version=1,
            minor_version=2,
        )

        self.assertEqual(
            entry.entry_type,
            FIND_SERVICE,
        )
        self.assertEqual(
            entry.service_id,
            0x1234,
        )
        self.assertEqual(
            entry.instance_id,
            0x0001,
        )
        self.assertEqual(
            entry.major_version,
            1,
        )
        self.assertEqual(
            entry.minor_version,
            2,
        )
        self.assertEqual(
            entry.ttl,
            0,
        )

    def test_offer_service_constructor(self):
        entry = ServiceEntry.offer_service(
            service_id=0x1234,
            instance_id=0x0001,
            major_version=1,
            minor_version=2,
            ttl=10,
        )

        self.assertEqual(
            entry.entry_type,
            OFFER_SERVICE,
        )
        self.assertEqual(
            entry.ttl,
            10,
        )

    def test_offer_service_rejects_zero_ttl(self):
        with self.assertRaises(
            SomeIPSDEntryError
        ):
            ServiceEntry.offer_service(
                service_id=0x1234,
                instance_id=0x0001,
                major_version=1,
                minor_version=2,
                ttl=0,
            )

    def test_stop_offer_service(self):
        offer = ServiceEntry.offer_service(
            service_id=0x1234,
            instance_id=0x0001,
            major_version=1,
            minor_version=2,
            ttl=10,
            index_first_option_run=3,
            index_second_option_run=4,
            number_of_options_1=2,
            number_of_options_2=1,
        )

        stop = ServiceEntry.stop_offer_service(
            offer
        )

        self.assertEqual(
            stop.entry_type,
            OFFER_SERVICE,
        )
        self.assertEqual(
            stop.service_id,
            offer.service_id,
        )
        self.assertEqual(
            stop.instance_id,
            offer.instance_id,
        )
        self.assertEqual(
            stop.major_version,
            offer.major_version,
        )
        self.assertEqual(
            stop.minor_version,
            offer.minor_version,
        )

        self.assertEqual(
            stop.index_first_option_run,
            3,
        )
        self.assertEqual(
            stop.index_second_option_run,
            4,
        )
        self.assertEqual(
            stop.number_of_options_1,
            2,
        )
        self.assertEqual(
            stop.number_of_options_2,
            1,
        )

        self.assertEqual(
            stop.ttl,
            0,
        )

    def test_stop_offer_requires_offer_service(self):
        find = ServiceEntry.find_service(
            service_id=0x1234,
            instance_id=0x0001,
            major_version=1,
            minor_version=0,
        )

        with self.assertRaises(
            SomeIPSDEntryError
        ):
            ServiceEntry.stop_offer_service(
                find
            )

    def test_stop_offer_requires_service_entry(self):
        with self.assertRaises(
            SomeIPSDEntryError
        ):
            ServiceEntry.stop_offer_service(
                "not an entry"
            )


if __name__ == "__main__":
    unittest.main()