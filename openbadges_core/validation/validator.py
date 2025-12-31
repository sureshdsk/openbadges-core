"""Credential validation logic."""

from datetime import datetime, timezone
from typing import Any

from openbadges_core.exceptions import ValidationError
from openbadges_core.models.credential import OpenBadgeCredential


class CredentialValidator:
    """Validator for OpenBadge credentials."""

    def __init__(self, credential: OpenBadgeCredential):
        """
        Initialize validator with a credential.

        Args:
            credential: The credential to validate
        """
        self.credential = credential
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def validate(self, strict: bool = True) -> bool:
        """
        Validate the credential.

        Args:
            strict: If True, raise ValidationError on any errors.
                   If False, return False but don't raise.

        Returns:
            True if valid, False otherwise

        Raises:
            ValidationError: If strict=True and validation fails
        """
        self.errors = []
        self.warnings = []

        # Check required fields
        self._validate_required_fields()

        # Check types
        self._validate_types()

        # Check dates
        self._validate_dates()

        # Check credential subject
        self._validate_credential_subject()

        # Check issuer
        self._validate_issuer()

        if self.errors:
            error_msg = "\n".join(self.errors)
            if strict:
                raise ValidationError(f"Credential validation failed:\n{error_msg}")
            return False

        return True

    def _validate_required_fields(self) -> None:
        """Validate that required fields are present."""
        if not self.credential.type:
            self.errors.append("Missing required field: type")

        if not self.credential.credential_subject:
            self.errors.append("Missing required field: credentialSubject")

        if not self.credential.issuer:
            self.errors.append("Missing required field: issuer")

    def _validate_types(self) -> None:
        """Validate that required types are present."""
        types = self.credential.type
        if isinstance(types, str):
            types = [types]

        required_types = ["VerifiableCredential", "OpenBadgeCredential"]
        for req_type in required_types:
            if req_type not in types:
                self.errors.append(f"Missing required type: {req_type}")

    def _validate_dates(self) -> None:
        """Validate date fields."""
        now = datetime.now(timezone.utc)

        # Check if credential is not yet valid
        if self.credential.valid_from:
            if self.credential.valid_from > now:
                self.warnings.append(
                    f"Credential not yet valid (validFrom: {self.credential.valid_from})"
                )

        # Check if credential has expired
        expiry = self.credential.valid_until or self.credential.expiration_date
        if expiry:
            if expiry < now:
                self.errors.append(f"Credential has expired (expiry: {expiry})")

        # Check logical date ordering
        if self.credential.valid_from and expiry:
            if self.credential.valid_from > expiry:
                self.errors.append(
                    "validFrom date is after expiration date"
                )

    def _validate_credential_subject(self) -> None:
        """Validate credential subject."""
        subjects = self.credential.credential_subject
        if not isinstance(subjects, list):
            subjects = [subjects]

        for subject in subjects:
            if not hasattr(subject, "achievement") or not subject.achievement:
                self.errors.append("credentialSubject missing required 'achievement' field")

    def _validate_issuer(self) -> None:
        """Validate issuer field."""
        # Issuer can be a URI string or a Profile object
        if not self.credential.issuer:
            self.errors.append("Missing issuer")


def validate_credential(credential: OpenBadgeCredential, strict: bool = True) -> bool:
    """
    Validate an OpenBadge credential.

    Args:
        credential: The credential to validate
        strict: If True, raise ValidationError on failure

    Returns:
        True if valid

    Raises:
        ValidationError: If strict=True and validation fails
    """
    validator = CredentialValidator(credential)
    return validator.validate(strict=strict)
