"""End-to-end integration tests for complete credential workflows."""

from datetime import datetime, timedelta, timezone

import pytest

from openbadges_core import Achievement, AchievementSubject, OpenBadgeCredential, Profile
from openbadges_core.crypto import Ed25519Signer, RSASigner, verify_credential
from openbadges_core.models.achievement import Criteria
from openbadges_core.models.base import AchievementType
from openbadges_core.serialization import from_json_ld, to_json_ld
from openbadges_core.validation import validate_credential


class TestCompleteCredentialLifecycle:
    """Test complete end-to-end credential workflows."""

    def test_simple_badge_issuance_workflow(self):
        """Test complete workflow: create, sign, serialize, verify."""
        # 1. Create issuer
        issuer = Profile(
            id="https://example.edu/issuers/university",
            name="Example University",
            email="badges@example.edu",
        )

        # 2. Create achievement
        achievement = Achievement(
            id="https://example.edu/achievements/python-101",
            name="Python 101 Completion",
            description="Successfully completed Python fundamentals course",
            criteria=Criteria(narrative="Complete all modules with passing grade"),
            creator=issuer,
        )

        # 3. Create credential subject
        subject = AchievementSubject(
            id="mailto:student@example.com",
            achievement=achievement,
        )

        # 4. Create credential
        credential = OpenBadgeCredential(
            context=[
                "https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            ],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=subject,
            name="Python 101 Completion Badge",
        )

        # 5. Validate before signing
        assert validate_credential(credential, strict=True) is True

        # 6. Generate keys and sign
        private_key, public_key = Ed25519Signer.generate_key_pair()
        signer = Ed25519Signer(
            private_key=private_key,
            verification_method=f"{issuer.id}#key-1",
        )
        signed_credential = signer.sign(credential)

        # 7. Verify signature
        assert verify_credential(signed_credential, public_key) is True

        # 8. Serialize to JSON-LD
        json_ld = to_json_ld(signed_credential)
        assert len(json_ld) > 0

        # 9. Deserialize and verify again
        restored = from_json_ld(json_ld, OpenBadgeCredential)
        assert verify_credential(restored, public_key) is True

    def test_advanced_certificate_with_results(self):
        """Test workflow with grades, evidence, and alignments."""
        from openbadges_core.models.achievement import Alignment
        from openbadges_core.models.base import AlignmentTargetType, ResultType
        from openbadges_core.models.proof import Evidence
        from openbadges_core.models.subject import Result

        # Create detailed issuer
        issuer = Profile(
            id="https://university.edu/cs-dept",
            name="Computer Science Department",
            url="https://university.edu/cs",
        )

        # Create achievement with alignment
        achievement = Achievement(
            id="https://university.edu/achievements/data-science-cert",
            name="Data Science Certificate",
            description="Advanced data science certification",
            criteria=Criteria(
                narrative="Complete 5 projects and exam with 80% minimum"
            ),
            achievement_type=AchievementType.Certificate,
            creator=issuer,
            alignment=[
                Alignment(
                    target_name="Data Science Competency",
                    target_url="https://framework.edu/competencies/ds-301",
                    target_framework="Tech Competency Framework",
                    target_type=AlignmentTargetType.Competency,
                )
            ],
        )

        # Create subject with results
        subject = AchievementSubject(
            id="mailto:scholar@example.com",
            achievement=achievement,
            result=[
                Result(type="Result", result_type=ResultType.LetterGrade, value="A"),
                Result(type="Result", result_type=ResultType.Percent, value="92"),
            ],
            credits_earned=12.0,
        )

        # Create credential with evidence
        credential = OpenBadgeCredential(
            context=[
                "https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            ],
            id="https://university.edu/credentials/cert-2024-001",
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=subject,
            evidence=[
                Evidence(
                    id="https://university.edu/evidence/portfolio-2024-001",
                    type="Evidence",
                    name="Project Portfolio",
                    description="5 completed data science projects",
                )
            ],
        )

        # Sign with RSA
        private_key, public_key = RSASigner.generate_key_pair()
        signer = RSASigner(
            private_key=private_key,
            verification_method=f"{issuer.id}#rsa-key-1",
        )
        signed = signer.sign(credential)

        # Full verification
        assert validate_credential(signed, strict=True) is True
        assert verify_credential(signed, public_key) is True

        # Serialize and round-trip
        json_ld = to_json_ld(signed)
        restored = from_json_ld(json_ld, OpenBadgeCredential)

        # Verify all data preserved
        assert len(restored.credential_subject.result) == 2
        assert len(restored.evidence) == 1
        assert restored.id == credential.id

    def test_multiple_signatures(self):
        """Test credential with multiple proofs (co-signing)."""
        # Create credential
        issuer = Profile(id="https://org.edu/issuer1", name="Organization")
        achievement = Achievement(
            id="https://org.edu/ach1",
            name="Achievement",
            description="Test",
            criteria=Criteria(narrative="Test"),
        )
        subject = AchievementSubject(id="did:example:learner", achievement=achievement)
        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2"],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=subject,
        )

        # Sign with first key
        priv1, pub1 = Ed25519Signer.generate_key_pair()
        signer1 = Ed25519Signer(priv1, "https://org.edu/issuer1#key1")
        signed1 = signer1.sign(credential)
        proof1 = signed1.proof

        # Sign with second key
        priv2, pub2 = Ed25519Signer.generate_key_pair()
        signer2 = Ed25519Signer(priv2, "https://org.edu/issuer2#key2")
        signed2 = signer2.sign(credential)
        proof2 = signed2.proof

        # Manually create credential with both proofs
        credential.proof = [proof1, proof2]

        # Both proofs should be present
        assert len(credential.proof) == 2

    def test_expired_credential_workflow(self):
        """Test that expired credentials fail validation but can still be verified."""
        issuer = Profile(id="https://example.edu/issuer", name="Test")
        achievement = Achievement(
            id="https://example.edu/ach",
            name="Test",
            description="Test",
            criteria=Criteria(narrative="Test"),
        )
        subject = AchievementSubject(id="did:test", achievement=achievement)

        # Create expired credential
        past = datetime.now(timezone.utc) - timedelta(days=100)
        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2"],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=issuer,
            issuance_date=past,
            valid_from=past,
            valid_until=past + timedelta(days=30),  # Expired
            credential_subject=subject,
        )

        # Sign it
        priv, pub = Ed25519Signer.generate_key_pair()
        signer = Ed25519Signer(priv, "https://example.edu/issuer#key")
        signed = signer.sign(credential)

        # Signature should verify (cryptographically valid)
        assert verify_credential(signed, pub) is True

        # But validation should fail (logically expired)
        assert validate_credential(signed, strict=False) is False


class TestSerializationRoundTrips:
    """Test various serialization scenarios."""

    def test_signed_credential_round_trip(self, basic_credential, ed25519_signer, ed25519_keypair):
        """Test that signed credential survives serialization."""
        _, public_key = ed25519_keypair

        # Sign
        signed = ed25519_signer.sign(basic_credential)

        # Serialize
        json_ld = to_json_ld(signed)

        # Deserialize
        restored = from_json_ld(json_ld, OpenBadgeCredential)

        # Should still verify
        assert verify_credential(restored, public_key) is True

    def test_complex_credential_round_trip(self, detailed_credential):
        """Test complex credential preserves all data."""
        json_ld = to_json_ld(detailed_credential)
        restored = from_json_ld(json_ld, OpenBadgeCredential)

        # Check all complex fields preserved
        assert restored.id == detailed_credential.id
        assert len(restored.evidence) == len(detailed_credential.evidence)
        assert (
            len(restored.credential_subject.result)
            == len(detailed_credential.credential_subject.result)
        )


class TestMultipleAlgorithms:
    """Test interoperability between signature algorithms."""

    def test_ed25519_and_rsa_both_work(self, basic_credential):
        """Test that both Ed25519 and RSA can sign/verify same credential."""
        # Ed25519
        ed_priv, ed_pub = Ed25519Signer.generate_key_pair()
        ed_signer = Ed25519Signer(ed_priv, "https://example.edu/key-ed")
        ed_signed = ed_signer.sign(basic_credential)

        assert verify_credential(ed_signed, ed_pub) is True
        assert ed_signed.proof.type == "Ed25519Signature2020"

        # RSA
        rsa_priv, rsa_pub = RSASigner.generate_key_pair()
        rsa_signer = RSASigner(rsa_priv, "https://example.edu/key-rsa")
        rsa_signed = rsa_signer.sign(basic_credential)

        assert verify_credential(rsa_signed, rsa_pub) is True
        assert rsa_signed.proof.type == "RsaSignature2018"


class TestRealWorldScenarios:
    """Test realistic usage scenarios."""

    def test_university_course_completion(self):
        """Simulate university issuing course completion badge."""
        # University setup
        university = Profile(
            id="https://university.edu/issuer",
            name="Example University",
            official_name="Example University, Department of Computer Science",
            url="https://university.edu",
            email="registrar@university.edu",
        )

        # Course achievement
        course = Achievement(
            id="https://university.edu/courses/cs101",
            name="CS101: Introduction to Programming",
            description="Foundational programming course",
            criteria=Criteria(
                narrative="Complete all assignments, participate in labs, and pass final exam"
            ),
            achievement_type=AchievementType.Course,
            credits_available=4.0,
            creator=university,
        )

        # Student
        from openbadges_core.models.base import ResultType
        from openbadges_core.models.subject import Result

        student = AchievementSubject(
            id="mailto:student@example.com",
            achievement=course,
            credits_earned=4.0,
            result=[
                Result(type="Result", result_type=ResultType.LetterGrade, value="B+"),
            ],
            activity_start_date=datetime(2024, 9, 1, tzinfo=timezone.utc),
            activity_end_date=datetime(2024, 12, 15, tzinfo=timezone.utc),
        )

        # Issue credential
        credential = OpenBadgeCredential(
            context=[
                "https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            ],
            id=f"https://university.edu/credentials/{datetime.now().year}/cs101-student",
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=university,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=student,
            name="CS101 Course Completion",
        )

        # Sign and validate
        priv, pub = Ed25519Signer.generate_key_pair()
        signer = Ed25519Signer(priv, f"{university.id}#registrar-key-2024")
        signed = signer.sign(credential)

        assert validate_credential(signed) is True
        assert verify_credential(signed, pub) is True

    def test_professional_certification(self):
        """Simulate professional organization issuing certification."""
        org = Profile(
            id="https://profcert.org/issuer",
            name="Professional Certification Board",
        )

        cert = Achievement(
            id="https://profcert.org/certs/python-advanced",
            name="Advanced Python Developer Certification",
            description="Industry-recognized Python expertise certification",
            criteria=Criteria(
                narrative="Pass written exam (80%+) and complete practical coding assessment"
            ),
            achievement_type=AchievementType.Certification,
        )

        from openbadges_core.models.base import ResultType
        from openbadges_core.models.proof import Evidence
        from openbadges_core.models.subject import Result

        holder = AchievementSubject(
            id="mailto:developer@example.com",
            achievement=cert,
            result=[
                Result(type="Result", result_type=ResultType.Percent, value="94"),
            ],
        )

        credential = OpenBadgeCredential(
            context=[
                "https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            ],
            id="https://profcert.org/credentials/2024/cert-12345",
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=org,
            issuance_date=datetime.now(timezone.utc),
            valid_from=datetime.now(timezone.utc),
            valid_until=datetime.now(timezone.utc) + timedelta(days=365 * 3),  # 3 years
            credential_subject=holder,
            evidence=[
                Evidence(
                    type="Evidence",
                    name="Certification Exam Results",
                    description="Passed with 94%",
                )
            ],
        )

        # Sign and export
        priv, pub = Ed25519Signer.generate_key_pair()
        signer = Ed25519Signer(priv, f"{org.id}#cert-key")
        signed = signer.sign(credential)

        # Export as JSON-LD for recipient
        json_ld = to_json_ld(signed)
        assert "@context" in json_ld
        assert "proof" in json_ld
