class KormicError(Exception):
    """Base exception class for all Kormic-related errors."""
    pass

class IdentityError(KormicError):
    """Raised when an agent identity string is malformed or invalid."""
    pass

class CryptographicError(KormicError):
    """Raised during signature generation, verification, or key rotation errors."""
    pass

class PedigreeIntegrityError(KormicError):
    """Raised when pedigree hash chain verification detects tampering or deletion."""
    pass

class VerificationError(KormicError):
    """Raised when verification checks fail (e.g. invalid signature, bad head)."""
    pass

class RevocationError(KormicError):
    """Raised when the epoch or the specific agent has been revoked."""
    pass

class ConfigError(KormicError):
    """Raised when configuration values are malformed or invalid."""
    pass
