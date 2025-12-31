"""Exception classes for OpenBadges Core."""


class OpenBadgesError(Exception):
    """Base exception for all OpenBadges errors."""

    pass


class ValidationError(OpenBadgesError):
    """Raised when credential validation fails."""

    pass


class SigningError(OpenBadgesError):
    """Raised when credential signing fails."""

    pass


class VerificationError(OpenBadgesError):
    """Raised when credential verification fails."""

    pass


class SerializationError(OpenBadgesError):
    """Raised when serialization/deserialization fails."""

    pass


class JWTError(OpenBadgesError):
    """Base exception for JWT operations."""

    pass


class JWTSignatureError(JWTError):
    """Raised when JWT signature verification fails."""

    pass


class JWTExpiredError(JWTError):
    """Raised when JWT has expired."""

    pass


class JWTDecodeError(JWTError):
    """Raised when JWT decoding fails."""

    pass
