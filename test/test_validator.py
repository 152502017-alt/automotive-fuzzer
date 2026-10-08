import unittest

from doip.constants import (
    DIAGNOSTIC_MESSAGE,
    ROUTING_ACTIVATION_REQUEST,
    VEHICLE_IDENTIFICATION_REQUEST,
)

from fuzzer.doip_state import DoIPStateMachine
from fuzzer.sequence import ProtocolSequence
from fuzzer.validator import SequenceValidator


class TestSequenceValidator(unittest.TestCase):

    def test_valid_sequence(self):
        sequence = ProtocolSequence()

        sequence.add_payload_type(VEHICLE_IDENTIFICATION_REQUEST)
        sequence.add_payload_type(ROUTING_ACTIVATION_REQUEST)
        sequence.add_payload_type(DIAGNOSTIC_MESSAGE)

        result = SequenceValidator.validate(
            sequence,
            DoIPStateMachine(),
        )

        self.assertTrue(result.valid)
        self.assertEqual(result.final_state, "DIAGNOSTIC")
        self.assertEqual(result.failed_index, -1)
        self.assertEqual(result.error, "")

    def test_diagnostic_before_routing_is_invalid(self):
        sequence = ProtocolSequence()

        sequence.add_payload_type(DIAGNOSTIC_MESSAGE)

        result = SequenceValidator.validate(
            sequence,
            DoIPStateMachine(),
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.failed_index, 0)
        self.assertIn("DIAGNOSTIC_MESSAGE", result.error)

    def test_vehicle_identification_then_diagnostic_is_invalid(self):
        sequence = ProtocolSequence()

        sequence.add_payload_type(VEHICLE_IDENTIFICATION_REQUEST)
        sequence.add_payload_type(DIAGNOSTIC_MESSAGE)

        result = SequenceValidator.validate(
            sequence,
            DoIPStateMachine(),
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.failed_index, 1)

    def test_empty_sequence_is_valid(self):
        sequence = ProtocolSequence()

        result = SequenceValidator.validate(
            sequence,
            DoIPStateMachine(),
        )

        self.assertTrue(result.valid)
        self.assertEqual(result.final_state, "INITIAL")

    def test_valid_sequence_stops_at_correct_state(self):
        sequence = ProtocolSequence()

        sequence.add_payload_type(VEHICLE_IDENTIFICATION_REQUEST)
        sequence.add_payload_type(ROUTING_ACTIVATION_REQUEST)

        result = SequenceValidator.validate(
            sequence,
            DoIPStateMachine(),
        )

        self.assertTrue(result.valid)
        self.assertEqual(result.final_state, "ROUTING_ACTIVE")

    def test_validator_does_not_hide_invalid_transition(self):
        sequence = ProtocolSequence()

        sequence.add_payload_type(DIAGNOSTIC_MESSAGE)

        machine = DoIPStateMachine()

        result = SequenceValidator.validate(
            sequence,
            machine,
        )

        self.assertFalse(result.valid)
        self.assertEqual(machine.current_state, "INITIAL")


if __name__ == "__main__":
    unittest.main()
