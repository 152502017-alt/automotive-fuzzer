class DoIPError(Exception):
    """Base exception for DoIP errors."""


class DoIPHeaderError(DoIPError):
    """Raised when a DoIP generic header is invalid."""


class DoIPVersionError(DoIPHeaderError):
    """Raised when the DoIP protocol version is invalid."""


class DoIPPayloadTypeError(DoIPHeaderError):
    """Raised when a DoIP payload type is invalid or unsupported."""


class DoIPLengthError(DoIPHeaderError):
    """Raised when the DoIP payload length is invalid."""


class DoIPPayloadError(DoIPError):
    """Raised when a DoIP payload is malformed."""
