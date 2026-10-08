import socket

from .header import SomeIPHeader
from .error import SomeIPHeaderError


class SomeIPTCP:
    def __init__(
        self,
        local_ip="0.0.0.0",
        local_port=0,
        timeout=None,
    ):
        self.local_ip = local_ip
        self.local_port = local_port
        self.timeout = timeout

        self.sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        if timeout is not None:
            self.sock.settimeout(timeout)

    def bind(self):
        self.sock.bind((self.local_ip, self.local_port))

    def listen(self, backlog=5):
        self.sock.listen(backlog)

    def accept(self):
        connection, address = self.sock.accept()

        if self.timeout is not None:
            connection.settimeout(self.timeout)

        return connection, address

    def connect(self, target_ip, target_port):
        self.sock.connect((target_ip, target_port))

    def send(self, data):
        self.sock.sendall(data)

    def receive(self, buffer_size=4096):
        return self.sock.recv(buffer_size)

    def receive_message(self, connection):
        """
        Receive exactly one complete SOME/IP message
        from a TCP byte stream.
        """

        header_data = self._receive_exact(
            connection,
            16,
        )

        if len(header_data) != 16:
            raise SomeIPHeaderError(
                "Incomplete SOME/IP header"
            )

        header = SomeIPHeader.decode(header_data)

        remaining_length = header.length - 8

        if remaining_length < 0:
            raise SomeIPHeaderError(
                "Invalid SOME/IP Length field"
            )

        payload = self._receive_exact(
            connection,
            remaining_length,
        )

        return header_data + payload

    @staticmethod
    def _receive_exact(connection, size):
        data = bytearray()

        while len(data) < size:

            chunk = connection.recv(
                size - len(data)
            )

            if not chunk:
                raise ConnectionError(
                    "TCP connection closed before "
                    "complete SOME/IP message was received"
                )

            data.extend(chunk)

        return bytes(data)

    def close(self):
        self.sock.close()