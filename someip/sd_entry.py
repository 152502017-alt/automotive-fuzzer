import struct

from .error import SomeIPError


# SOME/IP-SD Service Entry types
FIND_SERVICE = 0x00
OFFER_SERVICE = 0x01


class SomeIPSDEntryError(SomeIPError):
    """Raised when a SOME/IP-SD service entry is invalid."""


class ServiceEntry:
    """
    SOME/IP-SD Service Entry.

    Wire format: exactly 16 bytes.

    Byte 0       Type
    Byte 1       Index First Option Run
    Byte 2       Index Second Option Run
    Byte 3       Number of Options 1/2
    Byte 4-5     Service ID
    Byte 6-7     Instance ID
    Byte 8       Major Version
    Byte 9-11    TTL (24-bit)
    Byte 12-15   Minor Version
    """

    SIZE = 16

    def __init__(
        self,
        entry_type,
        index_first_option_run,
        index_second_option_run,
        number_of_options_1,
        number_of_options_2,
        service_id,
        instance_id,
        major_version,
        ttl,
        minor_version,
    ):
        self.entry_type = entry_type
        self.index_first_option_run = index_first_option_run
        self.index_second_option_run = index_second_option_run
        self.number_of_options_1 = number_of_options_1
        self.number_of_options_2 = number_of_options_2
        self.service_id = service_id
        self.instance_id = instance_id
        self.major_version = major_version
        self.ttl = ttl
        self.minor_version = minor_version

        self.validate()

    def validate(self):
        """Validate fields that are common to all Service Entries."""

        if self.entry_type not in (FIND_SERVICE, OFFER_SERVICE):
            raise SomeIPSDEntryError(
                f"Invalid SD service entry type: 0x{self.entry_type:02X}"
            )

        if not 0 <= self.index_first_option_run <= 0xFF:
            raise SomeIPSDEntryError(
                "Index First Option Run must fit in uint8"
            )

        if not 0 <= self.index_second_option_run <= 0xFF:
            raise SomeIPSDEntryError(
                "Index Second Option Run must fit in uint8"
            )

        if not 0 <= self.number_of_options_1 <= 0x0F:
            raise SomeIPSDEntryError(
                "Number of Options 1 must fit in 4 bits"
            )

        if not 0 <= self.number_of_options_2 <= 0x0F:
            raise SomeIPSDEntryError(
                "Number of Options 2 must fit in 4 bits"
            )

        if not 0 <= self.service_id <= 0xFFFF:
            raise SomeIPSDEntryError(
                "Service ID must fit in uint16"
            )

        if not 0 <= self.instance_id <= 0xFFFF:
            raise SomeIPSDEntryError(
                "Instance ID must fit in uint16"
            )

        if not 0 <= self.major_version <= 0xFF:
            raise SomeIPSDEntryError(
                "Major Version must fit in uint8"
            )

        # TTL is 24-bit.
        if not 0 <= self.ttl <= 0xFFFFFF:
            raise SomeIPSDEntryError(
                "TTL must fit in uint24"
            )

        if not 0 <= self.minor_version <= 0xFFFFFFFF:
            raise SomeIPSDEntryError(
                "Minor Version must fit in uint32"
            )

    def encode(self) -> bytes:
        """Encode the Service Entry into exactly 16 bytes."""

        self.validate()

        option_counts = (
            (self.number_of_options_1 << 4)
            | self.number_of_options_2
        )

        ttl_bytes = self.ttl.to_bytes(
            3,
            byteorder="big",
        )

        return (
            struct.pack(
                "!BBBBHHB",
                self.entry_type,
                self.index_first_option_run,
                self.index_second_option_run,
                option_counts,
                self.service_id,
                self.instance_id,
                self.major_version,
            )
            + ttl_bytes
            + struct.pack(
                "!I",
                self.minor_version,
            )
        )

    @classmethod
    def decode(cls, data: bytes) -> "ServiceEntry":
        """Decode exactly one 16-byte Service Entry."""

        if len(data) != cls.SIZE:
            raise SomeIPSDEntryError(
                f"Service Entry must be exactly 16 bytes, "
                f"got {len(data)}"
            )

        (
            entry_type,
            index_first_option_run,
            index_second_option_run,
            option_counts,
            service_id,
            instance_id,
            major_version,
        ) = struct.unpack(
            "!BBBBHHB",
            data[:9],
        )

        number_of_options_1 = (
            option_counts >> 4
        ) & 0x0F

        number_of_options_2 = (
            option_counts
        ) & 0x0F

        # TTL occupies exactly 3 bytes.
        ttl = int.from_bytes(
            data[9:12],
            byteorder="big",
        )

        # Minor Version occupies exactly 4 bytes.
        minor_version = int.from_bytes(
            data[12:16],
            byteorder="big",
        )

        return cls(
            entry_type=entry_type,
            index_first_option_run=index_first_option_run,
            index_second_option_run=index_second_option_run,
            number_of_options_1=number_of_options_1,
            number_of_options_2=number_of_options_2,
            service_id=service_id,
            instance_id=instance_id,
            major_version=major_version,
            ttl=ttl,
            minor_version=minor_version,
        )

    @classmethod
    def find_service(
        cls,
        service_id,
        instance_id,
        major_version,
        minor_version,
    ):
        """
        Create a FindService entry.

        FindService uses TTL = 0.
        """

        return cls(
            entry_type=FIND_SERVICE,
            index_first_option_run=0,
            index_second_option_run=0,
            number_of_options_1=0,
            number_of_options_2=0,
            service_id=service_id,
            instance_id=instance_id,
            major_version=major_version,
            ttl=0,
            minor_version=minor_version,
        )

    @classmethod
    def offer_service(
        cls,
        service_id,
        instance_id,
        major_version,
        minor_version,
        ttl,
        index_first_option_run=0,
        index_second_option_run=0,
        number_of_options_1=0,
        number_of_options_2=0,
    ):
        """
        Create an OfferService entry.

        A normal OfferService must have a non-zero TTL.
        TTL = 0 is reserved for StopOfferService.
        """

        if ttl == 0:
            raise SomeIPSDEntryError(
                "OfferService TTL must be non-zero; "
                "TTL 0 represents StopOfferService"
            )

        return cls(
            entry_type=OFFER_SERVICE,
            index_first_option_run=index_first_option_run,
            index_second_option_run=index_second_option_run,
            number_of_options_1=number_of_options_1,
            number_of_options_2=number_of_options_2,
            service_id=service_id,
            instance_id=instance_id,
            major_version=major_version,
            ttl=ttl,
            minor_version=minor_version,
        )

    @classmethod
    def stop_offer_service(cls, offered_entry):
        """
        Create a StopOfferService entry from an existing
        OfferService entry.

        All fields are copied from the OfferService except TTL,
        which is set to zero.
        """

        if not isinstance(offered_entry, cls):
            raise SomeIPSDEntryError(
                "offered_entry must be a ServiceEntry"
            )

        if offered_entry.entry_type != OFFER_SERVICE:
            raise SomeIPSDEntryError(
                "StopOfferService must be created from "
                "an OfferService entry"
            )

        return cls(
            entry_type=OFFER_SERVICE,
            index_first_option_run=(
                offered_entry.index_first_option_run
            ),
            index_second_option_run=(
                offered_entry.index_second_option_run
            ),
            number_of_options_1=(
                offered_entry.number_of_options_1
            ),
            number_of_options_2=(
                offered_entry.number_of_options_2
            ),
            service_id=offered_entry.service_id,
            instance_id=offered_entry.instance_id,
            major_version=offered_entry.major_version,
            ttl=0,
            minor_version=offered_entry.minor_version,
        )

    def __repr__(self):
        return (
            "ServiceEntry("
            f"type=0x{self.entry_type:02X}, "
            f"service_id=0x{self.service_id:04X}, "
            f"instance_id=0x{self.instance_id:04X}, "
            f"major_version={self.major_version}, "
            f"ttl={self.ttl}, "
            f"minor_version={self.minor_version}"
            ")"
        )