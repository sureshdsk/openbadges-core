"""
Basic usage example for openbadges-core.

This example demonstrates:
1. Creating an Achievement definition
2. Creating an OpenBadgeCredential
3. Signing the credential
4. Verifying the signature
5. Serializing to JSON-LD
"""

from datetime import datetime, timedelta, timezone

from openbadges_core import Achievement, AchievementSubject, OpenBadgeCredential, Profile
from openbadges_core.crypto import Ed25519Signer, verify_credential
from openbadges_core.models.achievement import Criteria
from openbadges_core.models.base import AchievementType
from openbadges_core.serialization import to_json_ld
from openbadges_core.validation import validate_credential


def main():
    """Run basic usage example."""

    # 1. Create an issuer profile
    print("Creating issuer profile...")
    issuer = Profile(
        id="https://example.edu/issuers/1",
        type="Profile",
        name="Example University",
        url="https://example.edu",
        email="badges@example.edu",
        description="A leading institution in digital credentials",
    )

    # 2. Create an achievement definition
    print("Creating achievement...")
    achievement = Achievement(
        id="https://example.edu/achievements/python-expert",
        type="Achievement",
        name="Python Expert Badge",
        description="Awarded to learners who have demonstrated expert-level Python programming skills",
        criteria=Criteria(
            narrative="Complete advanced Python projects and pass the expert certification exam"
        ),
        achievement_type=AchievementType.Badge,
        creator=issuer,
        tags=["python", "programming", "expert"],
    )

    # 3. Create a credential subject (the learner)
    print("Creating credential subject...")
    subject = AchievementSubject(
        id="did:example:learner123",
        type="AchievementSubject",
        achievement=achievement,
    )

    # 4. Create the OpenBadgeCredential
    print("Creating credential...")
    credential = OpenBadgeCredential(
        context=[
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ],
        type=["VerifiableCredential", "OpenBadgeCredential"],
        issuer=issuer,
        issuance_date=datetime.now(timezone.utc),
        valid_from=datetime.now(timezone.utc),
        valid_until=datetime.now(timezone.utc) + timedelta(days=365),
        name="Python Expert Badge",
        credential_subject=subject,
    )

    # 5. Validate the credential
    print("Validating credential...")
    is_valid = validate_credential(credential, strict=False)
    print(f"Credential is valid: {is_valid}")

    # 6. Generate a key pair for signing
    print("\nGenerating Ed25519 key pair...")
    private_key, public_key = Ed25519Signer.generate_key_pair()

    # 7. Sign the credential
    print("Signing credential...")
    signer = Ed25519Signer(
        private_key=private_key,
        verification_method="https://example.edu/issuers/1#key-1",
    )
    signed_credential = signer.sign(credential)

    # 8. Verify the signature
    print("Verifying signature...")
    try:
        verify_credential(signed_credential, public_key)
        print("Signature verified successfully!")
    except Exception as e:
        print(f"Verification failed: {e}")

    # 9. Serialize to JSON-LD
    print("\nSerializing to JSON-LD...")
    json_ld = to_json_ld(signed_credential)
    print("\nCredential JSON-LD:")
    print(json_ld)

    # 10. Show proof details
    if signed_credential.proof:
        print("\nProof details:")
        print(f"  Type: {signed_credential.proof.type}")
        print(f"  Created: {signed_credential.proof.created}")
        print(f"  Verification Method: {signed_credential.proof.verification_method}")
        print(f"  Proof Purpose: {signed_credential.proof.proof_purpose}")


if __name__ == "__main__":
    main()
