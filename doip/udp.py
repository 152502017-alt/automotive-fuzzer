import socket

from .constants import DEFAULT_DOIP_PORT


class DoIPUDP:
    def __init__(
        self,
        local_ip="0.0.0.0",
        local_port=DEFAULT_DOIP_PORT,
        timeout=None,
    ):
        self.local_ip = local_ip
        self.local_port = local_port
        self.timeout = timeout

        self.sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        if timeout is not None:
            self.sock.settimeout(timeout)

    def bind(self):
        self.sock.bind(
            (self.local_ip, self.local_port)
        )

    def send(
        self,
        data,
        target_ip,
        target_port=DEFAULT_DOIP_PORT,
    ):
        return self.sock.sendto(
            data,
            (target_ip, target_port),
        )

    def receive(self, buffer_size=65535):
        return self.sock.recvfrom(buffer_size)

    def close(self):
        self.sock.close()
