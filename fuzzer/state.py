from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class Transition:
    source: str
    event: str
    target: str
    action: Optional[Callable[[Any], None]] = None


class StateMachine:
    """
    Generic finite-state-machine engine for protocol fuzzing.

    The protocol-specific state machine will define:
        - states
        - transitions
        - events
        - optional actions

    The fuzzer can later use this engine to generate valid and invalid
    state transitions.
    """

    def __init__(self, initial_state: str):
        self.initial_state = initial_state
        self.current_state = initial_state
        self.transitions: Dict[str, List[Transition]] = {}
        self.history: List[tuple[str, str, str]] = []

    def add_transition(
        self,
        source: str,
        event: str,
        target: str,
        action: Optional[Callable[[Any], None]] = None,
    ) -> None:
        transition = Transition(
            source=source,
            event=event,
            target=target,
            action=action,
        )

        self.transitions.setdefault(source, []).append(transition)

    def available_events(self) -> List[str]:
        """Return events that are valid in the current state."""
        return [
            transition.event
            for transition in self.transitions.get(self.current_state, [])
        ]

    def can_transition(self, event: str) -> bool:
        """Check whether an event is valid in the current state."""
        return any(
            transition.event == event
            for transition in self.transitions.get(self.current_state, [])
        )

    def transition(self, event: str, context: Any = None) -> str:
        """
        Apply an event and move to the next state.

        Raises:
            ValueError: if the event is not valid for the current state.
        """
        for transition in self.transitions.get(self.current_state, []):
            if transition.event == event:
                previous_state = self.current_state

                if transition.action is not None:
                    transition.action(context)

                self.current_state = transition.target

                self.history.append(
                    (
                        previous_state,
                        event,
                        self.current_state,
                    )
                )

                return self.current_state

        raise ValueError(
            f"Invalid event '{event}' in state '{self.current_state}'"
        )

    def reset(self) -> None:
        """Return the state machine to its initial state."""
        self.current_state = self.initial_state
        self.history.clear()

    def get_history(self) -> List[tuple[str, str, str]]:
        """Return a copy of the transition history."""
        return list(self.history)
