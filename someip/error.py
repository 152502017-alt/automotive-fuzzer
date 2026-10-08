class SomeIPError(Exception):
    """Base exception for SOME/IP errors."""


class SomeIPHeaderError(SomeIPError):
    """Raised when a SOME/IP header is malformed."""


class SomeIPLengthError(SomeIPHeaderError):
    """Raised when the SOME/IP length field is invalid."""


class SomeIPVersionError(SomeIPHeaderError):
    """Raised when the protocol version is invalid."""


class SomeIPMessageTypeError(SomeIPHeaderError):
    """Raised when the message type is invalid."""