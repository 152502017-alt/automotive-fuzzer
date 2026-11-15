import can

# Create a virtual CAN bus
bus = can.Bus(
    interface="virtual",
    channel="can_test",
    receive_own_messages=True
)

# Create a standard CAN frame
message = can.Message(
    arbitration_id=0x123,
    data=[0x11, 0x22, 0x33, 0x44],
    is_extended_id=False
)

print("Sending CAN frame...")
bus.send(message)

# Receive the frame
received = bus.recv(timeout=2)

if received:
    print("\nCAN frame received successfully")
    print(f"CAN ID : 0x{received.arbitration_id:X}")
    print(f"DLC    : {received.dlc}")
    print(f"Data   : {received.data.hex(' ').upper()}")
else:
    print("No CAN frame received")

bus.shutdown()
