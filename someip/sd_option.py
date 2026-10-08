import ipaddress
import struct

from .error import SomeIPError


# SOME/IP-SD option types
CONFIGURATION_OPTION = 0x01
LOAD_BALANCING_OPTION = 0x02
IPV4_ENDPOINT_OPTION = 0x04
IPV6_ENDPOINT_OPTION = 0x06
IPV4_MULTICAST_OPTION = 0x14
IPV6_MULTICAST_OPTION = 0x16


class SomeIPSDOptionError(SomeIPError):
    """Raised when a SOME/IP-SD option is invalid."""


class SDOption:
    """Base class for SOME/IP-SD options."""

    def __init__(self, option_type):
        self.option_type = option_type

    def encode(self):
        raise NotImplementedError

    @classmethod
    def decode(cls, data):
        raise NotImplementedError


class IPv4EndpointOption(SDOption):
    """
    SOME/IP-SD IPv4 Endpoint Option.

    Complete wire size = 12 bytes.
    Length field = 0x0009.
    """

    SIZE = 12
    LENGTH = 9

    PROTOCOL_UDP = 0x11
    PROTOCOL_TCP = 0x06

    def __init__(
        self,
        address,
        port,
        protocol=PROTOCOL_UDP,
    ):
        super().__init__(IPV4_ENDPOINT_OPTION)

        self.address = address
        self.port = port
        self.protocol = protocol

        self.validate()

    def validate(self):
        try:
            ipaddress.IPv4Address(self.address)
        except ipaddress.AddressValueError as exc:
            raise SomeIPSDOptionError(
                f"Invalid IPv4 address: {self.address}"
            ) from exc

        if not 0 <= self.port <= 0xFFFF:
            raise SomeIPSDOptionError(
                "Port must fit in uint16"
            )

        if self.protocol not in (
            self.PROTOCOL_UDP,
            self.PROTOCOL_TCP,
        ):
            raise SomeIPSDOptionError(
                f"Unsupported transport protocol: "
                f"0x{self.protocol:02X}"
            )

    def encode(self):
        self.validate()

        address_bytes = ipaddress.IPv4Address(
            self.address
        ).packed

        return struct.pack(
            "!HBB4sBBH",
            self.LENGTH,
            self.option_type,
            0,
            address_bytes,
            0,
            self.protocol,
            self.port,
        )

    @classmethod
    def decode(cls, data):
        if len(data) != cls.SIZE:
            raise SomeIPSDOptionError(
                f"IPv4 Endpoint Option must be exactly "
                f"{cls.SIZE} bytes, got {len(data)}"
            )

        (
            length,
            option_type,
            reserved,
            address_bytes,
            address_reserved,
            protocol,
            port,
        ) = struct.unpack(
            "!HBB4sBBH",
            data,
        )

        if length != cls.LENGTH:
            raise SomeIPSDOptionError(
                f"IPv4 Endpoint Option length must be "
                f"{cls.LENGTH}, got {length}"
            )

        if option_type != IPV4_ENDPOINT_OPTION:
            raise SomeIPSDOptionError(
                f"Expected IPv4 Endpoint Option type "
                f"0x{IPV4_ENDPOINT_OPTION:02X}, "
                f"got 0x{option_type:02X}"
            )

        if reserved != 0:
            raise SomeIPSDOptionError(
                "IPv4 Endpoint Option reserved byte "
                "must be zero"
            )

        if address_reserved != 0:
            raise SomeIPSDOptionError(
                "IPv4 Endpoint Option address reserved byte "
                "must be zero"
            )

        address = str(
            ipaddress.IPv4Address(address_bytes)
        )

        return cls(
            address=address,
            port=port,
            protocol=protocol,
        )

    def __repr__(self):
        protocol = (
            "UDP"
            if self.protocol == self.PROTOCOL_UDP
            else "TCP"
        )

        return (
            "IPv4EndpointOption("
            f"address={self.address!r}, "
            f"port={self.port}, "
            f"protocol={protocol}"
            ")"
        )


class IPv4MulticastOption(SDOption):
    """
    SOME/IP-SD IPv4 Multicast Option.

    Complete wire size = 12 bytes.
    Length field = 0x0009.
    """

    SIZE = 12
    LENGTH = 9

    PROTOCOL_UDP = 0x11

    def __init__(
        self,
        address,
        port,
        protocol=PROTOCOL_UDP,
    ):
        super().__init__(IPV4_MULTICAST_OPTION)

        self.address = address
        self.port = port
        self.protocol = protocol

        self.validate()

    def validate(self):
        try:
            ip = ipaddress.IPv4Address(self.address)
        except ipaddress.AddressValueError as exc:
            raise SomeIPSDOptionError(
                f"Invalid IPv4 address: {self.address}"
            ) from exc

        if not ip.is_multicast:
            raise SomeIPSDOptionError(
                f"IPv4 address is not a multicast address: "
                f"{self.address}"
            )

        if not 0 <= self.port <= 0xFFFF:
            raise SomeIPSDOptionError(
                "Port must fit in uint16"
            )

        if self.protocol != self.PROTOCOL_UDP:
            raise SomeIPSDOptionError(
                "IPv4 Multicast Option currently supports "
                "UDP (0x11) only"
            )

    def encode(self):
        self.validate()

        address_bytes = ipaddress.IPv4Address(
            self.address
        ).packed

        return struct.pack(
            "!HBB4sBBH",
            self.LENGTH,
            self.option_type,
            0,
            address_bytes,
            0,
            self.protocol,
            self.port,
        )

    @classmethod
    def decode(cls, data):
        if len(data) != cls.SIZE:
            raise SomeIPSDOptionError(
                f"IPv4 Multicast Option must be exactly "
                f"{cls.SIZE} bytes, got {len(data)}"
            )

        (
            length,
            option_type,
            reserved,
            address_bytes,
            address_reserved,
            protocol,
            port,
        ) = struct.unpack(
            "!HBB4sBBH",
            data,
        )

        if length != cls.LENGTH:
            raise SomeIPSDOptionError(
                f"IPv4 Multicast Option length must be "
                f"{cls.LENGTH}, got {length}"
            )

        if option_type != IPV4_MULTICAST_OPTION:
            raise SomeIPSDOptionError(
                f"Expected IPv4 Multicast Option type "
                f"0x{IPV4_MULTICAST_OPTION:02X}, "
                f"got 0x{option_type:02X}"
            )

        if reserved != 0:
            raise SomeIPSDOptionError(
                "IPv4 Multicast Option reserved byte "
                "must be zero"
            )

        if address_reserved != 0:
            raise SomeIPSDOptionError(
                "IPv4 Multicast Option address reserved byte "
                "must be zero"
            )

        address = str(
            ipaddress.IPv4Address(address_bytes)
        )

        return cls(
            address=address,
            port=port,
            protocol=protocol,
        )

    def __repr__(self):
        return (
            "IPv4MulticastOption("
            f"address={self.address!r}, "
            f"port={self.port}, "
            f"protocol=UDP"
            ")"
        )


# ----------------------------------------------------------------------
# Generic SD Option Decoder
# ----------------------------------------------------------------------

OPTION_DECODERS = {
    IPV4_ENDPOINT_OPTION: IPv4EndpointOption,
    IPV4_MULTICAST_OPTION: IPv4MulticastOption,
}


def decode_sd_option(data):
    """
    Decode one complete SOME/IP-SD option.

    The option type is read from byte 2 and used to select
    the appropriate option class.
    """

    if not isinstance(data, bytes):
        raise SomeIPSDOptionError(
            "SD option data must be bytes"
        )

    if len(data) < 3:
        raise SomeIPSDOptionError(
            "SD option must contain at least "
            "Length and Type fields"
        )

    option_type = data[2]

    decoder = OPTION_DECODERS.get(
        option_type
    )

    if decoder is None:
        raise SomeIPSDOptionError(
            f"Unsupported SOME/IP-SD option type: "
            f"0x{option_type:02X}"
        )

    return decoder.decode(data)


def decode_sd_options(data):
    """
    Decode a sequence of consecutive SOME/IP-SD options.

    Returns a list of decoded option objects.

    Every option is decoded according to its type and
    exact wire size.
    """

    if not isinstance(data, bytes):
        raise SomeIPSDOptionError(
            "SD options data must be bytes"
        )

    options = []
    offset = 0

    while offset < len(data):

        remaining = len(data) - offset

        if remaining < 3:
            raise SomeIPSDOptionError(
                "Truncated SD option header"
            )

        length = struct.unpack(
            "!H",
            data[offset:offset + 2],
        )[0]

        total_size = 2 + length + 1

        if total_size > remaining:
            raise SomeIPSDOptionError(
                f"SD option exceeds available data: "
                f"need {total_size} bytes, "
                f"have {remaining}"
            )

        option_data = data[
            offset:offset + total_size
        ]

        options.append(
            decode_sd_option(option_data)
        )

        offset += total_size

    return options