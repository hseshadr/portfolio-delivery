"""Concrete failures raised while constructing delivery domain records."""


def diagnostic_error(error_type: type[Exception], message: str) -> Exception:
    """Construct one concrete diagnostic exception while preserving exact text."""

    _require_concrete_exception_type(error_type)
    _require_diagnostic_text(message)
    return error_type(message)


def _require_concrete_exception_type(error_type: object) -> None:
    if not isinstance(error_type, type):
        raise TypeError
    if not issubclass(error_type, Exception):
        raise TypeError
    if error_type is Exception:
        raise TypeError


def _require_diagnostic_text(message: object) -> None:
    if not isinstance(message, str):
        raise TypeError
    if not message:
        raise TypeError


class InvalidIdentityError(ValueError):
    """Raised when an identity field is empty or non-canonical."""


class InvalidDigestError(ValueError):
    """Raised when a digest is not a canonical SHA-256 value."""


class InvalidArtifactPathError(ValueError):
    """Raised when an artifact path is not a safe relative POSIX path."""


class DuplicateArtifactError(ValueError):
    """Raised when more than one artifact claims the same path."""


InvalidIdentity = InvalidIdentityError
InvalidDigest = InvalidDigestError
InvalidArtifactPath = InvalidArtifactPathError
DuplicateArtifact = DuplicateArtifactError
