"""
Advanced usage example for openbadges-core.

This example demonstrates:
1. Creating achievements with alignments and result descriptions
2. Creating credentials with results and evidence
3. Using different signature algorithms (RSA)
4. Working with embedded achievements
"""

from datetime import datetime, timezone

from openbadges_core import Achievement, AchievementSubject, OpenBadgeCredential, Profile
from openbadges_core.crypto import RSASigner
from openbadges_core.models.achievement import Alignment, Criteria, ResultDescription
from openbadges_core.models.base import AchievementType, AlignmentTargetType, ResultType
from openbadges_core.models.proof import Evidence
from openbadges_core.models.subject import Result
from openbadges_core.serialization import to_json_ld


def main():
    """Run advanced usage example."""

    # Create issuer
    issuer = Profile(
        id="https://example.edu/issuers/cs-dept",
        type="Profile",
        name="Computer Science Department",
        official_name="Department of Computer Science, Example University",
        url="https://example.edu/cs",
        email="cs-badges@example.edu",
    )

    # Create achievement with alignments and result descriptions
    achievement = Achievement(
        id="https://example.edu/achievements/data-science-cert",
        type="Achievement",
        name="Data Science Certificate",
        description="Advanced certification in data science and machine learning",
        criteria=Criteria(
            narrative="Complete 5 projects demonstrating proficiency in data analysis, "
            "machine learning, and statistical modeling. Achieve minimum 85% on final assessment."
        ),
        achievement_type=AchievementType.Certificate,
        creator=issuer,
        tags=["data-science", "machine-learning", "statistics"],
        field_of_study="Computer Science",
        credits_available=12.0,
        # Alignment to external competency framework
        alignment=[
            Alignment(
                target_name="Data Analysis Competency",
                target_url="https://competencies.example.org/data-analysis",
                target_framework="National Competency Framework",
                target_code="DA-301",
                target_type=AlignmentTargetType.Competency,
                target_description="Advanced data analysis and visualization skills",
            )
        ],
        # Define possible results
        result_description=[
            ResultDescription(
                id="https://example.edu/results/final-grade",
                type="ResultDescription",
                name="Final Grade",
                result_type=ResultType.LetterGrade,
                allowed_value=["A", "A-", "B+", "B", "B-", "C+", "C"],
                required_value="C",
            ),
            ResultDescription(
                id="https://example.edu/results/gpa",
                type="ResultDescription",
                name="GPA",
                result_type=ResultType.GradePointAverage,
                value_min="0.0",
                value_max="4.0",
                required_value="2.0",
            ),
        ],
    )

    # Create credential subject with results
    subject = AchievementSubject(
        id="mailto:learner@example.com",
        type="AchievementSubject",
        achievement=achievement,
        # Include actual results achieved
        result=[
            Result(
                type="Result",
                result_description="https://example.edu/results/final-grade",
                result_type=ResultType.LetterGrade,
                value="A",
            ),
            Result(
                type="Result",
                result_description="https://example.edu/results/gpa",
                result_type=ResultType.GradePointAverage,
                value="3.92",
            ),
        ],
        credits_earned=12.0,
        activity_start_date=datetime(2024, 1, 15, tzinfo=timezone.utc),
        activity_end_date=datetime(2024, 12, 10, tzinfo=timezone.utc),
        narrative="Completed all required coursework with distinction, "
        "demonstrating exceptional skills in machine learning and statistical analysis.",
    )

    # Create credential with evidence
    credential = OpenBadgeCredential(
        context=[
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ],
        type=["VerifiableCredential", "OpenBadgeCredential"],
        id="https://example.edu/credentials/12345",
        issuer=issuer,
        issuance_date=datetime(2024, 12, 15, tzinfo=timezone.utc),
        name="Data Science Certificate",
        description="Certificate of completion for advanced data science program",
        credential_subject=subject,
        # Add evidence
        evidence=[
            Evidence(
                id="https://example.edu/evidence/portfolio-12345",
                type="Evidence",
                name="Data Science Portfolio",
                description="Portfolio of 5 completed data science projects",
                narrative="The learner completed projects covering supervised learning, "
                "unsupervised learning, deep learning, time series analysis, "
                "and natural language processing.",
            ),
            Evidence(
                id="https://example.edu/evidence/final-exam-12345",
                type="Evidence",
                name="Final Assessment",
                description="Comprehensive final examination",
                narrative="Achieved 94% on comprehensive final assessment covering all course topics.",
            ),
        ],
    )

    # Sign with RSA
    print("Generating RSA key pair...")
    private_key, public_key = RSASigner.generate_key_pair(key_size=2048)

    print("Signing credential with RSA...")
    signer = RSASigner(
        private_key=private_key,
        verification_method="https://example.edu/issuers/cs-dept#key-rsa-1",
    )
    signed_credential = signer.sign(credential)

    # Serialize
    print("\nCredential JSON-LD:")
    print(to_json_ld(signed_credential))

    print("\n✓ Advanced credential created and signed successfully!")
    print(f"  Credential ID: {signed_credential.id}")
    print(f"  Achievement: {achievement.name}")
    print(f"  Results: {len(subject.result or [])} results recorded")
    print(f"  Evidence: {len(signed_credential.evidence or [])} pieces of evidence")
    print(f"  Signature: {signed_credential.proof.type if signed_credential.proof else 'None'}")


if __name__ == "__main__":
    main()
