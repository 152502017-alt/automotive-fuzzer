from dataclasses import dataclass, field
from typing import List

from .doip_mapper import DoIPMessageMapper
from .state import StateMachine


@dataclass
class SequenceStep:
    payload_type: int
    event: str


@dataclass
class ProtocolSequence:
    """
    Represents an ordered sequence of protocol messages.

    The sequence itself does not send anything over the network.
    It is a model that can later be mutated by the fuzzer.
    """

    steps: List[SequenceStep] = field(default_factory=list)

    def add_payload_type(self, payload_type: int) -> None:
        event = DoIPMessageMapper.event_for_payload_type(payload_type)

        self.steps.append(
            SequenceStep(
                payload_type=payload_type,
                event=event,
            )
        )

    def payload_types(self) -> List[int]:
        return [step.payload_type for step in self.steps]

    def events(self) -> List[str]:
        return [step.event for step in self.steps]

    def execute(self, state_machine: StateMachine) -> None:
        """
        Execute the modeled sequence against a state machine.

        Raises:
            ValueError: if a sequence step is invalid for the
                        current state.
        """
        for step in self.steps:
            state_machine.transition(step.event)
