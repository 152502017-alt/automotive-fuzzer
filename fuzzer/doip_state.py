from enum import Enum

from .state import StateMachine


class DoIPState(str, Enum):
    INITIAL = "INITIAL"
    VEHICLE_IDENTIFIED = "VEHICLE_IDENTIFIED"
    ROUTING_ACTIVE = "ROUTING_ACTIVE"
    DIAGNOSTIC = "DIAGNOSTIC"
    CLOSED = "CLOSED"


class DoIPEvent(str, Enum):
    VEHICLE_IDENTIFICATION = "VEHICLE_IDENTIFICATION"
    ROUTING_ACTIVATION = "ROUTING_ACTIVATION"
    DIAGNOSTIC_MESSAGE = "DIAGNOSTIC_MESSAGE"
    ALIVE_CHECK = "ALIVE_CHECK"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    RESET = "RESET"


class DoIPStateMachine(StateMachine):
    """
    Simplified DoIP behavioral model for stateful fuzzing.

    This model is intentionally separate from the wire-format
    implementation in the doip/ package.

    The state machine describes expected protocol behavior;
    the fuzzer will later use it to generate valid and invalid
    message sequences.
    """

    def __init__(self):
        super().__init__(DoIPState.INITIAL.value)

        self.add_transition(
            DoIPState.INITIAL.value,
            DoIPEvent.VEHICLE_IDENTIFICATION.value,
            DoIPState.VEHICLE_IDENTIFIED.value,
        )

        self.add_transition(
            DoIPState.VEHICLE_IDENTIFIED.value,
            DoIPEvent.ROUTING_ACTIVATION.value,
            DoIPState.ROUTING_ACTIVE.value,
        )

        self.add_transition(
            DoIPState.ROUTING_ACTIVE.value,
            DoIPEvent.DIAGNOSTIC_MESSAGE.value,
            DoIPState.DIAGNOSTIC.value,
        )

        self.add_transition(
            DoIPState.ROUTING_ACTIVE.value,
            DoIPEvent.ALIVE_CHECK.value,
            DoIPState.ROUTING_ACTIVE.value,
        )

        self.add_transition(
            DoIPState.DIAGNOSTIC.value,
            DoIPEvent.DIAGNOSTIC_MESSAGE.value,
            DoIPState.DIAGNOSTIC.value,
        )

        self.add_transition(
            DoIPState.DIAGNOSTIC.value,
            DoIPEvent.ALIVE_CHECK.value,
            DoIPState.DIAGNOSTIC.value,
        )

        self.add_transition(
            DoIPState.INITIAL.value,
            DoIPEvent.CONNECTION_ERROR.value,
            DoIPState.CLOSED.value,
        )

        self.add_transition(
            DoIPState.VEHICLE_IDENTIFIED.value,
            DoIPEvent.CONNECTION_ERROR.value,
            DoIPState.CLOSED.value,
        )

        self.add_transition(
            DoIPState.ROUTING_ACTIVE.value,
            DoIPEvent.CONNECTION_ERROR.value,
            DoIPState.CLOSED.value,
        )

        self.add_transition(
            DoIPState.DIAGNOSTIC.value,
            DoIPEvent.CONNECTION_ERROR.value,
            DoIPState.CLOSED.value,
        )

        self.add_transition(
            DoIPState.CLOSED.value,
            DoIPEvent.RESET.value,
            DoIPState.INITIAL.value,
        )
