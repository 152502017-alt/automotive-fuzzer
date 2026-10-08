import unittest

from doip.constants import (
    DIAGNOSTIC_MESSAGE,
    ROUTING_ACTIVATION_REQUEST,
    VEHICLE_IDENTIFICATION_REQUEST,
)

from fuzzer.doip_state import DoIPStateMachine
from fuzzer.sequence import ProtocolSequence


class TestProtocolSequence(unittest.TestCase):

    def test_add_payload_types(self):
        sequence = ProtocolSequence()

        sequence.add_payload_type(VEHICLE_IDENTIFICATION_REQUEST)
        sequence.add_payload_type(ROUTING_ACTIVATION_REQUEST)
        sequence.add_payload_type(DIAGNOSTIC_MESSAGE)

        self.assertEqual(
            sequence.payload_types(),
            [
                VEHICLE_IDENTIFICATION_REQUEST,
                ROUTING_ACTIVATION_REQUEST,
                DIAGNOSTIC_MESSAGE,
            ],
        )

    def test_events_are_generated(self):
        sequence = ProtocolSequence()

        sequence.add_payload_type(VEHICLE_IDENTIFICATION_REQUEST)
        sequence.add_payload_type(ROUTING_ACTIVATION_REQUEST)

        self.assertEqual(
            sequence.events(),
            [
                "VEHICLE_IDENTIFICATION",
                "ROUTING_ACTIVATION",
            ],
        )

    def test_valid_sequence_executes(self):
        sequence = ProtocolSequence()

        sequence.add_payload_type(VEHICLE_IDENTIFICATION_REQUEST)
        sequence.add_payload_type(ROUTING_ACTIVATION_REQUEST)
        sequence.add_payload_type(DIAGNOSTIC_MESSAGE)

        machine = DoIPStateMachine()

        sequence.execute(machine)

        self.assertEqual(
            machine.current_state,
            "DIAGNOSTIC",
        )

    def test_invalid_sequence_is_rejected(self):
        sequence = ProtocolSequence()

        sequence.add_payload_type(DIAGNOSTIC_MESSAGE)

        machine = DoIPStateMachine()

        with self.assertRaises(ValueError):
            sequence.execute(machine)

    def test_empty_sequence(self):
        sequence = ProtocolSequence()
        machine = DoIPStateMachine()

        sequence.execute(machine)

        self.assertEqual(
            machine.current_state,
            "INITIAL",
        )


if __name__ == "__main__":
    unittest.main()
