import unittest

from doip.constants import (
    ALIVE_CHECK_REQUEST,
    DIAGNOSTIC_MESSAGE,
    ROUTING_ACTIVATION_REQUEST,
    VEHICLE_IDENTIFICATION_REQUEST,
)

from fuzzer.doip_mapper import DoIPMessageMapper
from fuzzer.doip_state import DoIPEvent


class TestDoIPMessageMapper(unittest.TestCase):

    def test_vehicle_identification_mapping(self):
        event = DoIPMessageMapper.event_for_payload_type(
            VEHICLE_IDENTIFICATION_REQUEST
        )

        self.assertEqual(
            event,
            DoIPEvent.VEHICLE_IDENTIFICATION.value,
        )

    def test_routing_activation_mapping(self):
        event = DoIPMessageMapper.event_for_payload_type(
            ROUTING_ACTIVATION_REQUEST
        )

        self.assertEqual(
            event,
            DoIPEvent.ROUTING_ACTIVATION.value,
        )

    def test_diagnostic_mapping(self):
        event = DoIPMessageMapper.event_for_payload_type(
            DIAGNOSTIC_MESSAGE
        )

        self.assertEqual(
            event,
            DoIPEvent.DIAGNOSTIC_MESSAGE.value,
        )

    def test_alive_check_mapping(self):
        event = DoIPMessageMapper.event_for_payload_type(
            ALIVE_CHECK_REQUEST
        )

        self.assertEqual(
            event,
            DoIPEvent.ALIVE_CHECK.value,
        )

    def test_unknown_payload_type(self):
        self.assertFalse(
            DoIPMessageMapper.is_supported(0x9999)
        )

        with self.assertRaises(ValueError):
            DoIPMessageMapper.event_for_payload_type(0x9999)

    def test_complete_valid_sequence(self):
        from fuzzer.doip_state import DoIPStateMachine

        machine = DoIPStateMachine()

        sequence = [
            VEHICLE_IDENTIFICATION_REQUEST,
            ROUTING_ACTIVATION_REQUEST,
            DIAGNOSTIC_MESSAGE,
        ]

        for payload_type in sequence:
            event = DoIPMessageMapper.event_for_payload_type(
                payload_type
            )
            machine.transition(event)

        self.assertEqual(
            machine.current_state,
            "DIAGNOSTIC",
        )

    def test_invalid_diagnostic_sequence(self):
        from fuzzer.doip_state import DoIPStateMachine

        machine = DoIPStateMachine()

        event = DoIPMessageMapper.event_for_payload_type(
            DIAGNOSTIC_MESSAGE
        )

        with self.assertRaises(ValueError):
            machine.transition(event)


if __name__ == "__main__":
    unittest.main()
