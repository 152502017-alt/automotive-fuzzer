from .doip_state import DoIPEvent
from doip.constants import (
    VEHICLE_IDENTIFICATION_REQUEST,
    VEHICLE_IDENTIFICATION_REQUEST_EID,
    VEHICLE_IDENTIFICATION_REQUEST_VIN,
    VEHICLE_IDENTIFICATION_RESPONSE,
    ROUTING_ACTIVATION_REQUEST,
    ROUTING_ACTIVATION_RESPONSE,
    ALIVE_CHECK_REQUEST,
    ALIVE_CHECK_RESPONSE,
    DIAGNOSTIC_MESSAGE,
    DIAGNOSTIC_MESSAGE_ACK,
    DIAGNOSTIC_MESSAGE_NACK,
)


class DoIPMessageMapper:
    """
    Maps DoIP payload types to the events understood by the
    state machine.

    This class does not change the DoIP wire-format implementation.
    It only provides the bridge:

        DoIP payload type -> state-machine event
    """

    PAYLOAD_TO_EVENT = {
        VEHICLE_IDENTIFICATION_REQUEST:
            DoIPEvent.VEHICLE_IDENTIFICATION.value,

        VEHICLE_IDENTIFICATION_REQUEST_EID:
            DoIPEvent.VEHICLE_IDENTIFICATION.value,

        VEHICLE_IDENTIFICATION_REQUEST_VIN:
            DoIPEvent.VEHICLE_IDENTIFICATION.value,

        VEHICLE_IDENTIFICATION_RESPONSE:
            DoIPEvent.VEHICLE_IDENTIFICATION.value,

        ROUTING_ACTIVATION_REQUEST:
            DoIPEvent.ROUTING_ACTIVATION.value,

        ROUTING_ACTIVATION_RESPONSE:
            DoIPEvent.ROUTING_ACTIVATION.value,

        ALIVE_CHECK_REQUEST:
            DoIPEvent.ALIVE_CHECK.value,

        ALIVE_CHECK_RESPONSE:
            DoIPEvent.ALIVE_CHECK.value,

        DIAGNOSTIC_MESSAGE:
            DoIPEvent.DIAGNOSTIC_MESSAGE.value,

        DIAGNOSTIC_MESSAGE_ACK:
            DoIPEvent.DIAGNOSTIC_MESSAGE.value,

        DIAGNOSTIC_MESSAGE_NACK:
            DoIPEvent.DIAGNOSTIC_MESSAGE.value,
    }

    @classmethod
    def event_for_payload_type(cls, payload_type: int) -> str:
        """
        Return the state-machine event associated with a DoIP
        payload type.

        Raises:
            ValueError: if the payload type is not supported by
                        this mapper.
        """
        try:
            return cls.PAYLOAD_TO_EVENT[payload_type]
        except KeyError as exc:
            raise ValueError(
                f"Unsupported DoIP payload type: 0x{payload_type:04X}"
            ) from exc

    @classmethod
    def is_supported(cls, payload_type: int) -> bool:
        """Return True if the payload type is known to the mapper."""
        return payload_type in cls.PAYLOAD_TO_EVENT
