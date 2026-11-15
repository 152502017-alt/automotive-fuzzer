from can.can_parser import CANIDError, CANDLCError, CANLengthError


def parse_can_frame_faulty(frame):
    can_id = frame["can_id"]
    dlc = frame["dlc"]
    data = frame["data"]

    # Same validations as the correct parser
    if not isinstance(can_id, int) or isinstance(can_id, bool):
        raise CANIDError("CAN ID must be an integer")

    if not 0 <= can_id <= 0x7FF:
        raise CANIDError("Invalid standard CAN ID")

    if not isinstance(dlc, int) or isinstance(dlc, bool):
        raise CANDLCError("DLC must be an integer")

    if not 0 <= dlc <= 8:
        raise CANDLCError("DLC must be between 0 and 8")

    if not isinstance(data, bytes):
        raise CANLengthError("Payload must be bytes")

    if len(data) > 8:
        raise CANLengthError("Classical CAN payload cannot exceed 8 bytes")

    # INTENTIONALLY PLANTED BUG:
    # Missing check: dlc == len(data)

    return True
