"""
OpenBadges Core - A modern Python implementation of OpenBadges 3.0 specification.

This package provides core models and utilities for creating, validating, and verifying
OpenBadges 3.0 credentials compliant with the W3C Verifiable Credentials Data Model v2.0.

Example:
    >>> from openbadges_core import Achievement, OpenBadgeCredential, Profile
    >>> from openbadges_core.crypto import Ed25519Signer
    >>>
    >>> # Create an issuer
    >>> issuer = Profile(
    ...     id="https://example.edu/issuers/1",
    ...     name="Example University"
    ... )
    >>>
    >>> # Create an achievement
    >>> achievement = Achievement(
    ...     id="https://example.edu/achievements/python",
    ...     name="Python Badge",
    ...     description="Python programming badge"
    ... )
"""

from openbadges_core.exceptions import (
    OpenBadgesError,
    SigningError,
    ValidationError,
    VerificationError,
)
from openbadges_core.models.achievement import Achievement, Alignment, Criteria
from openbadges_core.models.credential import (
    AchievementCredential,
    EndorsementCredential,
    OpenBadgeCredential,
)
from openbadges_core.models.profile import Profile
from openbadges_core.models.proof import Evidence, Proof
from openbadges_core.models.subject import AchievementSubject, Result

__version__ = "0.1.0"

__all__ = [
    # Core Models
    "Achievement",
    "OpenBadgeCredential",
    "AchievementCredential",
    "EndorsementCredential",
    "Profile",
    "AchievementSubject",
    # Supporting Models
    "Criteria",
    "Alignment",
    "Result",
    "Proof",
    "Evidence",
    # Exceptions
    "OpenBadgesError",
    "ValidationError",
    "SigningError",
    "VerificationError",
]
