from dataclasses import dataclass
from typing import List

from .doip_state import DoIPStateMachine
from .sequence import ProtocolSequence


@dataclass
class ValidationResult:
    valid: bool
    final_state: str
    failed_index: int = -1
    error: str = ""


class SequenceValidator:
    """
    Validates a protocol sequence against its state machine.

    The validator does not send packets. It only determines whether
    a sequence follows the modeled protocol state transitions.
    """

    @staticmethod
    def validate(
        sequence: ProtocolSequence,
        state_machine: DoIPStateMachine,
    ) -> ValidationResult:

        for index, step in enumerate(sequence.steps):
            try:
                state_machine.transition(step.event)
            except ValueError as exc:
                return ValidationResult(
                    valid=False,
                    final_state=state_machine.current_state,
                    failed_index=index,
                    error=str(exc),
                )

        return ValidationResult(
            valid=True,
            final_state=state_machine.current_state,
        )
