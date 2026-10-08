import socket
import threading
import unittest

from someip.tcp import SomeIPTCP
from someip.message import (
    build_someip_message,
    parse_someip_message,
)
from someip.constants import REQUEST


class TestSomeIPTCP(unittest.TestCase):

    def test_fragmented_someip_message(self):

        message = build_someip_message(
            service_id=0x1234,
            method_id=0x0001,
            client_id=0x0010,
            session_id=0x0001,
            interface_version=0x01,
            message_type=REQUEST,
            return_code=0x00,
            payload=b"GetSpeed",
        )

        sender, receiver = socket.socketpair()

        transport = SomeIPTCP(timeout=2.0)

        chunks = [
            message[:5],
            message[5:12],
            message[12:],
        ]

        def sender_worker():
            try:
                for chunk in chunks:
                    sender.sendall(chunk)
            finally:
                sender.close()

        thread = threading.Thread(
            target=sender_worker,
            daemon=True,
        )

        thread.start()

        received = transport.receive_message(receiver)

        receiver.close()
        transport.close()

        header, payload = parse_someip_message(received)

        self.assertEqual(
            header.service_id,
            0x1234,
        )

        self.assertEqual(
            header.method_id,
            0x0001,
        )

        self.assertEqual(
            header.client_id,
            0x0010,
        )

        self.assertEqual(
            header.session_id,
            0x0001,
        )

        self.assertEqual(
            header.message_type,
            REQUEST,
        )

        self.assertEqual(
            payload,
            b"GetSpeed",
        )

        thread.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()