"""Pytest configuration and shared fixtures for openbadges-core tests."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from openbadges_core import Achievement, AchievementSubject, OpenBadgeCredential, Profile
from openbadges_core.crypto import Ed25519Signer, RSASigner, Ed25519JWTSigner, RSAJWTSigner, JWTVerifier
from openbadges_core.models.achievement import Alignment, Criteria, ResultDescription
from openbadges_core.models.base import AlignmentTargetType, AchievementType, ResultType
from openbadges_core.models.proof import Evidence
from openbadges_core.models.subject import Result


# ==================== Profile Fixtures ====================


@pytest.fixture
def basic_issuer():
    """Create a basic issuer profile."""
    return Profile(
        id="https://example.edu/issuers/1",
        type="Profile",
        name="Test University",
        email="badges@example.edu",
    )


@pytest.fixture
def detailed_issuer():
    """Create a detailed issuer profile with all fields."""
    return Profile(
        id="https://example.edu/issuers/dept-cs",
        type="Profile",
        name="Computer Science Department",
        official_name="Department of Computer Science, Test University",
        url="https://example.edu/cs",
        email="cs-badges@example.edu",
        description="Leading CS department focused on excellence",
        phone="+1-555-0100",
    )


@pytest.fixture
def learner_profile():
    """Create a learner profile."""
    return Profile(
        id="mailto:learner@example.com",
        type="Profile",
        name="Test Learner",
        email="learner@example.com",
        given_name="Test",
        family_name="Learner",
    )


# ==================== Achievement Fixtures ====================


@pytest.fixture
def basic_achievement(basic_issuer):
    """Create a basic achievement."""
    return Achievement(
        id="https://example.edu/achievements/test-badge",
        type="Achievement",
        name="Test Badge",
        description="A test achievement badge",
        criteria=Criteria(narrative="Complete the test requirements"),
        creator=basic_issuer,
    )


@pytest.fixture
def detailed_achievement(detailed_issuer):
    """Create a detailed achievement with alignments and results."""
    return Achievement(
        id="https://example.edu/achievements/advanced-python",
        type="Achievement",
        name="Advanced Python Certificate",
        description="Certificate for advanced Python programming skills",
        criteria=Criteria(
            narrative="Complete 5 advanced Python projects and pass certification exam with 80% or higher"
        ),
        achievement_type=AchievementType.Certificate,
        creator=detailed_issuer,
        tags=["python", "programming", "advanced"],
        field_of_study="Computer Science",
        credits_available=12.0,
        alignment=[
            Alignment(
                target_name="Python Programming Competency",
                target_url="https://competencies.example.org/python-advanced",
                target_framework="Tech Competency Framework",
                target_code="PY-401",
                target_type=AlignmentTargetType.Competency,
            )
        ],
        result_description=[
            ResultDescription(
                id="https://example.edu/results/grade",
                type="ResultDescription",
                name="Final Grade",
                result_type=ResultType.LetterGrade,
                allowed_value=["A", "A-", "B+", "B", "B-", "C+", "C"],
                required_value="C",
            ),
            ResultDescription(
                id="https://example.edu/results/score",
                type="ResultDescription",
                name="Exam Score",
                result_type=ResultType.Percent,
                value_min="0",
                value_max="100",
                required_value="80",
            ),
        ],
    )


# ==================== Subject Fixtures ====================


@pytest.fixture
def basic_subject(basic_achievement):
    """Create a basic achievement subject."""
    return AchievementSubject(
        id="did:example:learner123",
        type="AchievementSubject",
        achievement=basic_achievement,
    )


@pytest.fixture
def detailed_subject(detailed_achievement):
    """Create a detailed subject with results."""
    return AchievementSubject(
        id="mailto:learner@example.com",
        type="AchievementSubject",
        achievement=detailed_achievement,
        result=[
            Result(
                type="Result",
                result_description="https://example.edu/results/grade",
                result_type=ResultType.LetterGrade,
                value="A",
            ),
            Result(
                type="Result",
                result_description="https://example.edu/results/score",
                result_type=ResultType.Percent,
                value="95",
            ),
        ],
        credits_earned=12.0,
        activity_start_date=datetime(2024, 1, 15, tzinfo=timezone.utc),
        activity_end_date=datetime(2024, 12, 10, tzinfo=timezone.utc),
    )


# ==================== Credential Fixtures ====================


@pytest.fixture
def basic_credential(basic_issuer, basic_subject):
    """Create a basic OpenBadge credential."""
    return OpenBadgeCredential(
        context=[
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ],
        type=["VerifiableCredential", "OpenBadgeCredential"],
        issuer=basic_issuer,
        issuance_date=datetime.now(timezone.utc),
        credential_subject=basic_subject,
        name="Test Badge",
    )


@pytest.fixture
def detailed_credential(detailed_issuer, detailed_subject):
    """Create a detailed credential with all features."""
    now = datetime.now(timezone.utc)
    return OpenBadgeCredential(
        context=[
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ],
        id="https://example.edu/credentials/12345",
        type=["VerifiableCredential", "OpenBadgeCredential"],
        issuer=detailed_issuer,
        issuance_date=now,
        valid_from=now,
        valid_until=now + timedelta(days=365),
        name="Advanced Python Certificate",
        description="Certificate of completion for advanced Python course",
        credential_subject=detailed_subject,
        evidence=[
            Evidence(
                id="https://example.edu/evidence/portfolio-12345",
                type="Evidence",
                name="Project Portfolio",
                description="Portfolio of 5 completed Python projects",
                narrative="Completed projects in data structures, algorithms, web development, ML, and cloud computing",
            )
        ],
    )


@pytest.fixture
def expired_credential(basic_issuer, basic_subject):
    """Create an expired credential for testing validation."""
    past = datetime.now(timezone.utc) - timedelta(days=100)
    return OpenBadgeCredential(
        context=[
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ],
        type=["VerifiableCredential", "OpenBadgeCredential"],
        issuer=basic_issuer,
        issuance_date=past,
        valid_from=past,
        valid_until=past + timedelta(days=30),  # Expired 70 days ago
        credential_subject=basic_subject,
    )


# ==================== Cryptography Fixtures ====================


@pytest.fixture
def ed25519_keypair():
    """Generate an Ed25519 key pair for testing."""
    private_key, public_key = Ed25519Signer.generate_key_pair()
    return private_key, public_key


@pytest.fixture
def rsa_keypair():
    """Generate an RSA key pair for testing."""
    private_key, public_key = RSASigner.generate_key_pair(key_size=2048)
    return private_key, public_key


@pytest.fixture
def ed25519_signer(ed25519_keypair):
    """Create an Ed25519 signer."""
    private_key, _ = ed25519_keypair
    return Ed25519Signer(
        private_key=private_key,
        verification_method="https://example.edu/issuers/1#key-ed25519-1",
    )


@pytest.fixture
def rsa_signer(rsa_keypair):
    """Create an RSA signer."""
    private_key, _ = rsa_keypair
    return RSASigner(
        private_key=private_key,
        verification_method="https://example.edu/issuers/1#key-rsa-1",
    )


# ==================== Test Data Constants ====================


@pytest.fixture
def valid_contexts():
    """Standard valid contexts for OpenBadges 3.0."""
    return [
        "https://www.w3.org/ns/credentials/v2",
        "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
    ]


@pytest.fixture
def valid_types():
    """Standard valid types for OpenBadgeCredential."""
    return ["VerifiableCredential", "OpenBadgeCredential"]


# ==================== JWT Fixtures ====================


@pytest.fixture
def ed25519_jwt_keypair():
    """Generate an Ed25519 key pair for JWT testing."""
    private_key, public_key = Ed25519JWTSigner.generate_key_pair()
    return private_key, public_key


@pytest.fixture
def rsa_jwt_keypair():
    """Generate an RSA key pair for JWT testing."""
    private_key, public_key = RSAJWTSigner.generate_key_pair(key_size=2048)
    return private_key, public_key


@pytest.fixture
def ed25519_jwt_signer(ed25519_jwt_keypair):
    """Create an Ed25519 JWT signer."""
    private_key, _ = ed25519_jwt_keypair
    return Ed25519JWTSigner(private_key=private_key, key_id="key-ed25519-1")


@pytest.fixture
def rsa_jwt_signer(rsa_jwt_keypair):
    """Create an RSA JWT signer."""
    private_key, _ = rsa_jwt_keypair
    return RSAJWTSigner(private_key=private_key, key_id="key-rsa-1")


@pytest.fixture
def ed25519_jwt_verifier(ed25519_jwt_keypair):
    """Create an Ed25519 JWT verifier."""
    _, public_key = ed25519_jwt_keypair
    return JWTVerifier(public_key=public_key, algorithms=["EdDSA"])


@pytest.fixture
def rsa_jwt_verifier(rsa_jwt_keypair):
    """Create an RSA JWT verifier."""
    _, public_key = rsa_jwt_keypair
    return JWTVerifier(public_key=public_key, algorithms=["RS256"])
