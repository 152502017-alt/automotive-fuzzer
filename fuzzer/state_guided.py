from dataclasses import dataclass
import random

from doip.constants import VALID_PAYLOAD_TYPES
from .doip_mapper import DoIPMessageMapper
from .doip_state import DoIPStateMachine
from .sequence import ProtocolSequence


@dataclass
class StateGuidedResult:
    sequence: ProtocolSequence
    states: list[str]
    transitions: list[tuple[str, str, str]]


class StateGuidedGenerator:
    """
    Generate valid DoIP message sequences by following the
    currently available protocol-state transitions.

    Internal state-machine events such as RESET and CONNECTION_ERROR
    are ignored because they do not represent normal DoIP payloads.
    """

    def __init__(self, seed: int | None = None):
        self.random = random.Random(seed)

        # One event can correspond to multiple DoIP payload types.
        # Keep all of them instead of collapsing them to one payload.
        self.event_to_payloads: dict[str, list[int]] = {}

        for payload_type in sorted(VALID_PAYLOAD_TYPES):
            try:
                event = DoIPMessageMapper.event_for_payload_type(
                    payload_type
                )
            except (KeyError, ValueError):
                continue

            self.event_to_payloads.setdefault(event, []).append(
                payload_type
            )

    def generate(self, length: int = 5) -> StateGuidedResult:
        if length <= 0:
            raise ValueError("Sequence length must be greater than zero")

        state_machine = DoIPStateMachine()
        sequence = ProtocolSequence()

        states = [state_machine.current_state]
        transitions = []

        for _ in range(length):
            available_events = state_machine.available_events()

            # Keep only events that correspond to actual DoIP payloads.
            valid_events = [
                event
                for event in available_events
                if event in self.event_to_payloads
            ]

            if not valid_events:
                break

            event = self.random.choice(valid_events)

            payload_type = self.random.choice(
                self.event_to_payloads[event]
            )

            previous_state = state_machine.current_state

            next_state = state_machine.transition(event)

            sequence.add_payload_type(payload_type)

            transitions.append(
                (
                    previous_state,
                    event,
                    next_state,
                )
            )

            states.append(next_state)

        return StateGuidedResult(
            sequence=sequence,
            states=states,
            transitions=transitions,
        )


if __name__ == "__main__":
    generator = StateGuidedGenerator(seed=42)

    print("Event -> payload mappings:")
    for event, payloads in generator.event_to_payloads.items():
        formatted = [f"0x{x:04X}" for x in payloads]
        print(f"  {event} -> {formatted}")

    print()

    for i in range(5):
        result = generator.generate(length=6)

        print(f"Sequence {i + 1}")
        print("Payload types:", result.sequence.payload_types())
        print("States:", result.states)
        print("Transitions:")

        for transition in result.transitions:
            print("  ", transition)

        print()
