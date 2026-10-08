import unittest

from fuzzer.doip_state import DoIPEvent, DoIPState, DoIPStateMachine


class TestDoIPStateMachine(unittest.TestCase):

    def setUp(self):
        self.machine = DoIPStateMachine()

    def test_initial_state(self):
        self.assertEqual(
            self.machine.current_state,
            DoIPState.INITIAL.value,
        )

    def test_vehicle_identification_transition(self):
        state = self.machine.transition(
            DoIPEvent.VEHICLE_IDENTIFICATION.value
        )

        self.assertEqual(
            state,
            DoIPState.VEHICLE_IDENTIFIED.value,
        )

    def test_routing_activation_transition(self):
        self.machine.transition(
            DoIPEvent.VEHICLE_IDENTIFICATION.value
        )

        state = self.machine.transition(
            DoIPEvent.ROUTING_ACTIVATION.value
        )

        self.assertEqual(
            state,
            DoIPState.ROUTING_ACTIVE.value,
        )

    def test_diagnostic_transition(self):
        self.machine.transition(
            DoIPEvent.VEHICLE_IDENTIFICATION.value
        )
        self.machine.transition(
            DoIPEvent.ROUTING_ACTIVATION.value
        )

        state = self.machine.transition(
            DoIPEvent.DIAGNOSTIC_MESSAGE.value
        )

        self.assertEqual(
            state,
            DoIPState.DIAGNOSTIC.value,
        )

    def test_alive_check_keeps_routing_state(self):
        self.machine.transition(
            DoIPEvent.VEHICLE_IDENTIFICATION.value
        )
        self.machine.transition(
            DoIPEvent.ROUTING_ACTIVATION.value
        )

        state = self.machine.transition(
            DoIPEvent.ALIVE_CHECK.value
        )

        self.assertEqual(
            state,
            DoIPState.ROUTING_ACTIVE.value,
        )

    def test_invalid_diagnostic_from_initial_state(self):
        with self.assertRaises(ValueError):
            self.machine.transition(
                DoIPEvent.DIAGNOSTIC_MESSAGE.value
            )

    def test_invalid_routing_activation_from_initial_state(self):
        with self.assertRaises(ValueError):
            self.machine.transition(
                DoIPEvent.ROUTING_ACTIVATION.value
            )

    def test_connection_error_closes_machine(self):
        state = self.machine.transition(
            DoIPEvent.CONNECTION_ERROR.value
        )

        self.assertEqual(
            state,
            DoIPState.CLOSED.value,
        )

    def test_reset_returns_to_initial_state(self):
        self.machine.transition(
            DoIPEvent.CONNECTION_ERROR.value
        )

        state = self.machine.transition(
            DoIPEvent.RESET.value
        )

        self.assertEqual(
            state,
            DoIPState.INITIAL.value,
        )

    def test_history_is_recorded(self):
        self.machine.transition(
            DoIPEvent.VEHICLE_IDENTIFICATION.value
        )
        self.machine.transition(
            DoIPEvent.ROUTING_ACTIVATION.value
        )

        history = self.machine.get_history()

        self.assertEqual(
            history,
            [
                (
                    DoIPState.INITIAL.value,
                    DoIPEvent.VEHICLE_IDENTIFICATION.value,
                    DoIPState.VEHICLE_IDENTIFIED.value,
                ),
                (
                    DoIPState.VEHICLE_IDENTIFIED.value,
                    DoIPEvent.ROUTING_ACTIVATION.value,
                    DoIPState.ROUTING_ACTIVE.value,
                ),
            ],
        )


if __name__ == "__main__":
    unittest.main()
