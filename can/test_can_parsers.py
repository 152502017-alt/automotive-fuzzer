from can.can_parser import parse_can_frame, CANLengthError
from can.can_faulty_parser import parse_can_frame_faulty

valid_frame = {
    "can_id": 0x123,
    "dlc": 4,
    "data": bytes([0x11, 0x22, 0x33, 0x44])
}

faulty_frame = {
    "can_id": 0x123,
    "dlc": 8,
    "data": bytes([0x11, 0x22, 0x33, 0x44])
}

print("===== VALID FRAME =====")
print("Correct parser:", parse_can_frame(valid_frame))
print("Faulty parser:", parse_can_frame_faulty(valid_frame))

print("\n===== MALFORMED FRAME =====")

try:
    parse_can_frame(faulty_frame)
    print("Correct parser: ACCEPTED")
except CANLengthError as error:
    print("Correct parser: REJECTED -", error)

print("Faulty parser:", parse_can_frame_faulty(faulty_frame))
