class CANValidationError(Exception):
    pass


class CANIDError(CANValidationError):
    pass


class CANDLCError(CANValidationError):
    pass


class CANLengthError(CANValidationError):
    pass


def parse_can_frame(frame):
    can_id = frame["can_id"]
    dlc = frame["dlc"]
    data = frame["data"]

    # Validate standard 11-bit CAN identifier
    if not isinstance(can_id, int) or isinstance(can_id, bool):
        raise CANIDError("CAN ID must be an integer")

    if not 0 <= can_id <= 0x7FF:
        raise CANIDError("Invalid standard CAN ID")

    # Validate DLC
    if not isinstance(dlc, int) or isinstance(dlc, bool):
        raise CANDLCError("DLC must be an integer")

    if not 0 <= dlc <= 8:
        raise CANDLCError("DLC must be between 0 and 8")

    # Validate payload
    if not isinstance(data, bytes):
        raise CANLengthError("Payload must be bytes")

    if len(data) > 8:
        raise CANLengthError("Classical CAN payload cannot exceed 8 bytes")

    # Correct implementation checks DLC against payload length
    if dlc != len(data):
        raise CANLengthError("DLC does not match payload length")

    return True
