import socket

DEFAULT_SOMEIP_PORT = 30490


class SomeIPUDP:
    def __init__(
        self,
        local_ip="0.0.0.0",
        local_port=DEFAULT_SOMEIP_PORT,
        timeout=None,
    ):
        self.local_ip = local_ip
        self.local_port = local_port
        self.timeout = timeout

        self.sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        if timeout is not None:
            self.sock.settimeout(timeout)

    def bind(self):
        self.sock.bind((self.local_ip, self.local_port))

    def send(
        self,
        data: bytes,
        target_ip: str,
        target_port: int = DEFAULT_SOMEIP_PORT,
    ):
        return self.sock.sendto(
            data,
            (target_ip, target_port)
        )

    def receive(self, buffer_size=65535):
        data, address = self.sock.recvfrom(buffer_size)
        return data, address

    def close(self):
        self.sock.close()