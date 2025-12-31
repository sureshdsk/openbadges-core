"""Unit tests for openbadges-core data models."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from openbadges_core.models.achievement import Achievement, Alignment, Criteria
from openbadges_core.models.base import AchievementType, AlignmentTargetType
from openbadges_core.models.credential import OpenBadgeCredential
from openbadges_core.models.profile import Address, Image, Profile
from openbadges_core.models.subject import AchievementSubject, Result


class TestProfileModel:
    """Tests for Profile model."""

    def test_minimal_profile(self):
        """Test creating a minimal profile with only required fields."""
        profile = Profile(
            id="https://example.edu/issuers/1",
        )
        assert profile.id == "https://example.edu/issuers/1"
        assert profile.type == "Profile"

    def test_profile_with_all_fields(self, detailed_issuer):
        """Test profile with all optional fields."""
        assert detailed_issuer.id == "https://example.edu/issuers/dept-cs"
        assert detailed_issuer.name == "Computer Science Department"
        assert detailed_issuer.official_name == "Department of Computer Science, Test University"
        assert detailed_issuer.email == "cs-badges@example.edu"
        assert detailed_issuer.description is not None

    def test_profile_with_address(self):
        """Test profile with postal address."""
        profile = Profile(
            id="https://example.edu/issuers/1",
            name="Test Org",
            address=Address(
                type="Address",
                street_address="123 Main St",
                address_locality="Boston",
                address_region="MA",
                postal_code="02101",
                address_country_code="US",
            ),
        )
        assert profile.address.street_address == "123 Main St"
        assert profile.address.address_locality == "Boston"

    def test_profile_with_image(self):
        """Test profile with image."""
        profile = Profile(
            id="https://example.edu/issuers/1",
            name="Test Org",
            image=Image(
                id="https://example.edu/images/logo.png",
                caption="Organization logo",
            ),
        )
        assert profile.image.id == "https://example.edu/images/logo.png"

    def test_profile_person_fields(self):
        """Test profile with person-specific fields."""
        profile = Profile(
            id="mailto:john.doe@example.com",
            type="Profile",
            given_name="John",
            family_name="Doe",
            additional_name="Q",
            honorific_prefix="Dr.",
            honorific_suffix="PhD",
        )
        assert profile.given_name == "John"
        assert profile.family_name == "Doe"
        assert profile.honorific_prefix == "Dr."


class TestAchievementModel:
    """Tests for Achievement model."""

    def test_minimal_achievement(self):
        """Test creating minimal achievement."""
        achievement = Achievement(
            id="https://example.edu/achievements/1",
            name="Test Achievement",
            description="Test description",
            criteria=Criteria(narrative="Complete the test"),
        )
        assert achievement.id == "https://example.edu/achievements/1"
        assert achievement.name == "Test Achievement"
        assert achievement.type == "Achievement"

    def test_achievement_with_type(self):
        """Test achievement with specific type."""
        achievement = Achievement(
            id="https://example.edu/achievements/1",
            name="Certificate",
            description="Test certificate",
            criteria=Criteria(narrative="Complete requirements"),
            achievement_type=AchievementType.Certificate,
        )
        assert achievement.achievement_type == AchievementType.Certificate

    def test_achievement_with_alignment(self):
        """Test achievement with framework alignment."""
        alignment = Alignment(
            type="Alignment",
            target_name="Test Competency",
            target_url="https://framework.example.org/comp-1",
            target_framework="Test Framework",
            target_type=AlignmentTargetType.Competency,
        )

        achievement = Achievement(
            id="https://example.edu/achievements/1",
            name="Aligned Achievement",
            description="With framework alignment",
            criteria=Criteria(narrative="Complete requirements"),
            alignment=[alignment],
        )

        assert len(achievement.alignment) == 1
        assert achievement.alignment[0].target_name == "Test Competency"

    def test_achievement_with_tags(self):
        """Test achievement with tags."""
        achievement = Achievement(
            id="https://example.edu/achievements/1",
            name="Tagged Achievement",
            description="With tags",
            criteria=Criteria(narrative="Complete requirements"),
            tags=["python", "programming", "beginner"],
        )
        assert len(achievement.tags) == 3
        assert "python" in achievement.tags

    def test_achievement_with_creator(self, basic_issuer):
        """Test achievement with creator profile."""
        achievement = Achievement(
            id="https://example.edu/achievements/1",
            name="Created Achievement",
            description="With creator",
            criteria=Criteria(narrative="Complete requirements"),
            creator=basic_issuer,
        )
        assert achievement.creator == basic_issuer


class TestAchievementSubjectModel:
    """Tests for AchievementSubject model."""

    def test_minimal_subject(self, basic_achievement):
        """Test creating minimal subject."""
        subject = AchievementSubject(
            id="did:example:123",
            achievement=basic_achievement,
        )
        assert subject.id == "did:example:123"
        assert subject.achievement == basic_achievement

    def test_subject_with_results(self, basic_achievement):
        """Test subject with result data."""
        from openbadges_core.models.base import ResultType

        subject = AchievementSubject(
            id="mailto:learner@example.com",
            achievement=basic_achievement,
            result=[
                Result(
                    type="Result",
                    result_type=ResultType.LetterGrade,
                    value="A",
                ),
                Result(
                    type="Result",
                    result_type=ResultType.Percent,
                    value="95",
                ),
            ],
        )
        assert len(subject.result) == 2
        assert subject.result[0].value == "A"
        assert subject.result[1].value == "95"

    def test_subject_with_dates(self, basic_achievement):
        """Test subject with activity dates."""
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 12, 31, tzinfo=timezone.utc)

        subject = AchievementSubject(
            id="did:example:123",
            achievement=basic_achievement,
            activity_start_date=start,
            activity_end_date=end,
        )
        assert subject.activity_start_date == start
        assert subject.activity_end_date == end


class TestOpenBadgeCredentialModel:
    """Tests for OpenBadgeCredential model."""

    def test_minimal_credential(self, basic_issuer, basic_subject):
        """Test creating minimal credential."""
        credential = OpenBadgeCredential(
            context=[
                "https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            ],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=basic_issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=basic_subject,
        )
        assert credential.issuer == basic_issuer
        assert credential.credential_subject == basic_subject
        assert "VerifiableCredential" in credential.type
        assert "OpenBadgeCredential" in credential.type

    def test_credential_auto_adds_required_types(self, basic_issuer, basic_subject):
        """Test that credential automatically adds required types."""
        credential = OpenBadgeCredential(
            context="https://www.w3.org/ns/credentials/v2",
            type="SomeCustomType",
            issuer=basic_issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=basic_subject,
        )
        # model_post_init should add required types
        assert "VerifiableCredential" in credential.type
        assert "OpenBadgeCredential" in credential.type
        assert "SomeCustomType" in credential.type

    def test_credential_with_expiration(self, basic_issuer, basic_subject):
        """Test credential with expiration date."""
        from datetime import timedelta

        now = datetime.now(timezone.utc)
        expiry = now + timedelta(days=365)

        credential = OpenBadgeCredential(
            context=[
                "https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            ],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=basic_issuer,
            issuance_date=now,
            valid_from=now,
            valid_until=expiry,
            credential_subject=basic_subject,
        )
        assert credential.valid_until == expiry

    def test_credential_with_evidence(self, basic_issuer, basic_subject):
        """Test credential with evidence."""
        from openbadges_core.models.proof import Evidence

        evidence = Evidence(
            id="https://example.edu/evidence/123",
            type="Evidence",
            name="Project Portfolio",
            description="Collection of completed projects",
        )

        credential = OpenBadgeCredential(
            context=[
                "https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            ],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=basic_issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=basic_subject,
            evidence=[evidence],
        )
        assert len(credential.evidence) == 1
        assert credential.evidence[0].name == "Project Portfolio"

    def test_credential_with_multiple_subjects(self, basic_issuer, basic_achievement):
        """Test credential with multiple subjects."""
        subject1 = AchievementSubject(
            id="did:example:learner1", achievement=basic_achievement
        )
        subject2 = AchievementSubject(
            id="did:example:learner2", achievement=basic_achievement
        )

        credential = OpenBadgeCredential(
            context=[
                "https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            ],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=basic_issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=[subject1, subject2],
        )
        assert len(credential.credential_subject) == 2


class TestCriteriaModel:
    """Tests for Criteria model."""

    def test_criteria_with_narrative(self):
        """Test criteria with narrative text."""
        criteria = Criteria(narrative="Complete all course modules")
        assert criteria.narrative == "Complete all course modules"

    def test_criteria_with_id(self):
        """Test criteria with URI."""
        criteria = Criteria(
            id="https://example.edu/criteria/course-101",
            narrative="Complete requirements",
        )
        assert criteria.id == "https://example.edu/criteria/course-101"
