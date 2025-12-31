"""Unit tests for credential validation."""

from datetime import datetime, timedelta, timezone

import pytest

from openbadges_core.exceptions import ValidationError as OBValidationError
from openbadges_core.validation import CredentialValidator, validate_credential


class TestCredentialValidator:
    """Tests for CredentialValidator class."""

    def test_validate_basic_credential(self, basic_credential):
        """Test validating a basic valid credential."""
        validator = CredentialValidator(basic_credential)
        is_valid = validator.validate(strict=False)

        assert is_valid is True
        assert len(validator.errors) == 0

    def test_validate_detailed_credential(self, detailed_credential):
        """Test validating detailed credential with all features."""
        validator = CredentialValidator(detailed_credential)
        is_valid = validator.validate(strict=False)

        assert is_valid is True
        assert len(validator.errors) == 0

    def test_validate_missing_required_types(self, basic_issuer, basic_subject):
        """Test that model_post_init adds required types automatically."""
        from openbadges_core import OpenBadgeCredential

        # Create credential with partial type list
        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2"],
            type=["SomeCustomType"],  # Missing required types
            issuer=basic_issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=basic_subject,
        )

        # model_post_init should automatically add required types
        assert "VerifiableCredential" in credential.type
        assert "OpenBadgeCredential" in credential.type
        assert "SomeCustomType" in credential.type

        # Validation should pass
        validator = CredentialValidator(credential)
        is_valid = validator.validate(strict=False)
        assert is_valid is True

    def test_validate_missing_issuer(self, basic_subject):
        """Test validation fails when issuer is missing."""
        from openbadges_core import OpenBadgeCredential

        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2"],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=None,  # Missing issuer
            issuance_date=datetime.now(timezone.utc),
            credential_subject=basic_subject,
        )

        validator = CredentialValidator(credential)
        is_valid = validator.validate(strict=False)

        assert is_valid is False
        assert any("issuer" in error.lower() for error in validator.errors)

    def test_validate_subject_without_achievement(self, basic_issuer):
        """Test validation fails when subject is missing achievement."""
        from openbadges_core import AchievementSubject, OpenBadgeCredential
        from pydantic import ValidationError as PydanticValidationError

        # Pydantic will catch None for required field
        # Test that our validator catches missing achievement in subject
        subject = AchievementSubject(
            id="did:example:123",
            achievement=None,  # Missing achievement
        )

        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2"],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=basic_issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=subject,
        )

        validator = CredentialValidator(credential)
        is_valid = validator.validate(strict=False)

        assert is_valid is False
        assert any("achievement" in error.lower() for error in validator.errors)

    def test_validate_expired_credential(self, expired_credential):
        """Test validation fails for expired credential."""
        validator = CredentialValidator(expired_credential)
        is_valid = validator.validate(strict=False)

        assert is_valid is False
        assert any("expired" in error.lower() for error in validator.errors)

    def test_validate_not_yet_valid_credential(self, basic_issuer, basic_subject):
        """Test validation warns for credential not yet valid."""
        from openbadges_core import OpenBadgeCredential

        future = datetime.now(timezone.utc) + timedelta(days=30)

        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2"],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=basic_issuer,
            issuance_date=datetime.now(timezone.utc),
            valid_from=future,  # Not valid yet
            credential_subject=basic_subject,
        )

        validator = CredentialValidator(credential)
        validator.validate(strict=False)

        # Should have warning (not error)
        assert any("not yet valid" in warning.lower() for warning in validator.warnings)

    def test_validate_invalid_date_order(self, basic_issuer, basic_subject):
        """Test validation fails when validFrom is after validUntil."""
        from openbadges_core import OpenBadgeCredential

        now = datetime.now(timezone.utc)

        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2"],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=basic_issuer,
            issuance_date=now,
            valid_from=now + timedelta(days=365),  # After validUntil
            valid_until=now + timedelta(days=30),  # Before validFrom
            credential_subject=basic_subject,
        )

        validator = CredentialValidator(credential)
        is_valid = validator.validate(strict=False)

        assert is_valid is False
        assert any("after" in error.lower() for error in validator.errors)

    def test_strict_mode_raises_exception(self, expired_credential):
        """Test strict mode raises ValidationError on failure."""
        validator = CredentialValidator(expired_credential)

        with pytest.raises(OBValidationError, match="validation failed"):
            validator.validate(strict=True)

    def test_non_strict_mode_returns_false(self, expired_credential):
        """Test non-strict mode returns False on failure."""
        validator = CredentialValidator(expired_credential)
        is_valid = validator.validate(strict=False)

        assert is_valid is False


class TestValidateCredentialFunction:
    """Tests for validate_credential convenience function."""

    def test_validate_valid_credential(self, basic_credential):
        """Test validating valid credential returns True."""
        is_valid = validate_credential(basic_credential, strict=False)
        assert is_valid is True

    def test_validate_valid_credential_strict(self, basic_credential):
        """Test validating valid credential in strict mode."""
        is_valid = validate_credential(basic_credential, strict=True)
        assert is_valid is True

    def test_validate_invalid_credential_strict(self, expired_credential):
        """Test validating invalid credential in strict mode raises."""
        with pytest.raises(OBValidationError):
            validate_credential(expired_credential, strict=True)

    def test_validate_invalid_credential_non_strict(self, expired_credential):
        """Test validating invalid credential in non-strict mode."""
        is_valid = validate_credential(expired_credential, strict=False)
        assert is_valid is False


class TestRequiredTypes:
    """Tests for required type validation."""

    def test_missing_verifiable_credential_type(self, basic_issuer, basic_subject):
        """Test that VerifiableCredential type is required."""
        from openbadges_core import OpenBadgeCredential

        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2"],
            type=["OpenBadgeCredential"],  # Missing VerifiableCredential
            issuer=basic_issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=basic_subject,
        )

        # The model_post_init should add it automatically
        assert "VerifiableCredential" in credential.type

    def test_missing_openbadge_credential_type(self, basic_issuer, basic_subject):
        """Test that OpenBadgeCredential type is required."""
        from openbadges_core import OpenBadgeCredential

        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2"],
            type=["VerifiableCredential"],  # Missing OpenBadgeCredential
            issuer=basic_issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=basic_subject,
        )

        # The model_post_init should add it automatically
        assert "OpenBadgeCredential" in credential.type


class TestSubjectAchievementValidation:
    """Tests for credential subject achievement validation."""

    def test_subject_without_achievement_fails(self, basic_issuer):
        """Test that subject without achievement fails validation."""
        from openbadges_core import AchievementSubject, OpenBadgeCredential

        # Create subject without achievement
        subject = AchievementSubject(
            id="did:example:123",
            achievement=None,  # Missing achievement
        )

        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2"],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=basic_issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=subject,
        )

        validator = CredentialValidator(credential)
        is_valid = validator.validate(strict=False)

        assert is_valid is False
        assert any("achievement" in error.lower() for error in validator.errors)


class TestValidatorErrors:
    """Tests for error collection and reporting."""

    def test_multiple_errors_collected(self, basic_subject):
        """Test that validator collects multiple errors."""
        from openbadges_core import OpenBadgeCredential

        # Create credential with multiple issues
        now = datetime.now(timezone.utc)
        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2"],
            type=[],  # Missing types
            issuer=None,  # Missing issuer
            issuance_date=now,
            valid_from=now + timedelta(days=365),  # Invalid date order
            valid_until=now,
            credential_subject=basic_subject,
        )

        validator = CredentialValidator(credential)
        validator.validate(strict=False)

        # Should have multiple errors
        assert len(validator.errors) >= 3

    def test_errors_are_strings(self, expired_credential):
        """Test that errors are string messages."""
        validator = CredentialValidator(expired_credential)
        validator.validate(strict=False)

        assert len(validator.errors) > 0
        for error in validator.errors:
            assert isinstance(error, str)
            assert len(error) > 0
