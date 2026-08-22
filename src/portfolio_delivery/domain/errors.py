"""Concrete failures raised while constructing delivery domain records."""


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
