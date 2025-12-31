"""
Example demonstrating JWT encoding and decoding for OpenBadges credentials.

This example shows how to:
1. Create an OpenBadge credential
2. Encode it as a JWT using Ed25519 or RSA signing
3. Verify and decode the JWT back to a credential
4. Compare JWT vs JSON-LD formats
"""

from datetime import datetime, timedelta, timezone

from openbadges_core import (
    Achievement,
    AchievementSubject,
    OpenBadgeCredential,
    Profile,
)
from openbadges_core.crypto import Ed25519JWTSigner, JWTVerifier, RSAJWTSigner
from openbadges_core.models.achievement import Criteria
from openbadges_core.serialization import from_jwt, to_json_ld, to_jwt


def example_basic_jwt_workflow():
    """Basic example: Create, encode, verify, and decode a credential as JWT."""
    print("=" * 70)
    print("Example 1: Basic JWT Workflow")
    print("=" * 70)

    # Step 1: Create issuer profile
    issuer = Profile(
        id="https://university.edu/issuers/cs-dept",
        type="Profile",
        name="Computer Science Department",
        email="badges@university.edu",
        url="https://university.edu/cs",
    )

    # Step 2: Create achievement definition
    achievement = Achievement(
        id="https://university.edu/badges/python-expert",
        type="Achievement",
        name="Python Expert",
        description="Demonstrates advanced proficiency in Python programming",
        criteria=Criteria(
            narrative="Complete advanced Python course with 90% or higher grade"
        ),
        creator=issuer,
        tags=["python", "programming", "expert"],
    )

    # Step 3: Create credential subject (the learner)
    subject = AchievementSubject(
        id="did:example:learner123",
        type="AchievementSubject",
        achievement=achievement,
    )

    # Step 4: Create the verifiable credential
    now = datetime.now(timezone.utc)
    credential = OpenBadgeCredential(
        context=[
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ],
        id="https://university.edu/credentials/12345",
        type=["VerifiableCredential", "OpenBadgeCredential"],
        issuer=issuer,
        credential_subject=subject,
        issuance_date=now,
        valid_from=now,
        valid_until=now + timedelta(days=365),  # Valid for 1 year
        name="Python Expert Credential",
    )

    # Step 5: Generate Ed25519 key pair for signing
    print("\n1. Generating Ed25519 key pair...")
    private_key, public_key = Ed25519JWTSigner.generate_key_pair()

    # Step 6: Create JWT signer
    signer = Ed25519JWTSigner(private_key, key_id="university-key-2025-01")

    # Step 7: Encode credential as JWT
    print("2. Encoding credential as JWT...")
    jwt_string = to_jwt(credential, signer)
    print(f"   JWT created ({len(jwt_string)} bytes)")
    print(f"   JWT: {jwt_string[:80]}...")

    # Step 8: Create verifier and verify JWT
    print("\n3. Verifying JWT signature...")
    verifier = JWTVerifier(public_key, algorithms=["EdDSA"])
    decoded_credential = from_jwt(jwt_string, verifier)
    print(f"   ✓ Signature verified!")
    print(f"   ✓ Credential ID: {decoded_credential.id}")
    print(f"   ✓ Issued to: {decoded_credential.credential_subject}")

    print("\n✓ Basic JWT workflow completed successfully!\n")
    return jwt_string, decoded_credential


def example_multiple_algorithms():
    """Example showing RSA signing in addition to Ed25519."""
    print("=" * 70)
    print("Example 2: Multiple Signature Algorithms")
    print("=" * 70)

    # Create a simple credential
    issuer = Profile(
        id="https://example.org/issuer",
        type="Profile",
        name="Example Org",
    )

    achievement = Achievement(
        id="https://example.org/badge",
        type="Achievement",
        name="Test Badge",
        description="A test badge",
        criteria=Criteria(narrative="Complete the test"),
        creator=issuer,
    )

    subject = AchievementSubject(id="did:example:user456", achievement=achievement)

    credential = OpenBadgeCredential(
        context=[
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ],
        type=["VerifiableCredential", "OpenBadgeCredential"],
        issuer=issuer,
        credential_subject=subject,
        issuance_date=datetime.now(timezone.utc),
    )

    # Sign with Ed25519
    print("\n1. Signing with Ed25519...")
    ed_private, ed_public = Ed25519JWTSigner.generate_key_pair()
    ed_signer = Ed25519JWTSigner(ed_private, key_id="ed25519-key")
    jwt_ed25519 = to_jwt(credential, ed_signer)
    print(f"   Ed25519 JWT: {len(jwt_ed25519)} bytes")

    # Sign with RSA
    print("\n2. Signing with RSA...")
    rsa_private, rsa_public = RSAJWTSigner.generate_key_pair(key_size=2048)
    rsa_signer = RSAJWTSigner(rsa_private, key_id="rsa-key")
    jwt_rsa = to_jwt(credential, rsa_signer)
    print(f"   RSA JWT: {len(jwt_rsa)} bytes")

    # Verify both
    print("\n3. Verifying both signatures...")
    ed_verifier = JWTVerifier(ed_public, algorithms=["EdDSA"])
    rsa_verifier = JWTVerifier(rsa_public, algorithms=["RS256"])

    decoded_ed = from_jwt(jwt_ed25519, ed_verifier)
    decoded_rsa = from_jwt(jwt_rsa, rsa_verifier)

    print(f"   ✓ Ed25519 signature verified")
    print(f"   ✓ RSA signature verified")
    print(f"   ✓ Both decoded credentials match: {decoded_ed.id == decoded_rsa.id}")

    print("\n✓ Multiple algorithms example completed!\n")


def example_jwt_vs_json_ld():
    """Compare JWT and JSON-LD formats."""
    print("=" * 70)
    print("Example 3: JWT vs JSON-LD Comparison")
    print("=" * 70)

    # Create credential
    issuer = Profile(id="https://example.com/issuer", type="Profile", name="Issuer")
    achievement = Achievement(
        id="https://example.com/badge",
        type="Achievement",
        name="Badge",
        description="A badge",
        criteria=Criteria(narrative="Complete task"),
        creator=issuer,
    )
    subject = AchievementSubject(id="mailto:user@example.com", achievement=achievement)

    credential = OpenBadgeCredential(
        context=[
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ],
        type=["VerifiableCredential", "OpenBadgeCredential"],
        issuer=issuer,
        credential_subject=subject,
        issuance_date=datetime.now(timezone.utc),
    )

    # Generate JWT
    private_key, _ = Ed25519JWTSigner.generate_key_pair()
    signer = Ed25519JWTSigner(private_key)
    jwt_format = to_jwt(credential, signer)

    # Generate JSON-LD
    json_ld_format = to_json_ld(credential)

    print(f"\n1. Size Comparison:")
    print(f"   JWT format:     {len(jwt_format)} bytes")
    print(f"   JSON-LD format: {len(json_ld_format)} bytes")
    print(f"   Difference:     {abs(len(jwt_format) - len(json_ld_format))} bytes")

    print(f"\n2. Format Characteristics:")
    print(f"   JWT:")
    print(f"   - Compact, URL-safe string")
    print(f"   - Self-contained with signature")
    print(f"   - Three parts: header.payload.signature")
    print(f"   - Example: {jwt_format[:60]}...")

    print(f"\n   JSON-LD:")
    print(f"   - Human-readable JSON")
    print(f"   - Linked Data with @context")
    print(f"   - Requires separate signature (proof)")
    print(f"   - First 150 chars:")
    print(f"     {json_ld_format[:150]}...")

    print("\n✓ Format comparison completed!\n")


def example_key_rotation():
    """Example demonstrating key rotation scenario."""
    print("=" * 70)
    print("Example 4: Key Rotation Scenario")
    print("=" * 70)

    # Create credential
    issuer = Profile(id="https://university.edu", type="Profile", name="University")
    achievement = Achievement(
        id="https://university.edu/badge",
        type="Achievement",
        name="Badge",
        description="Badge",
        criteria=Criteria(narrative="Complete"),
        creator=issuer,
    )
    subject = AchievementSubject(id="did:example:student", achievement=achievement)

    credential = OpenBadgeCredential(
        context=[
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ],
        type=["VerifiableCredential", "OpenBadgeCredential"],
        issuer=issuer,
        credential_subject=subject,
        issuance_date=datetime.now(timezone.utc),
    )

    # Old key (2024)
    print("\n1. Using old key (2024)...")
    old_private, old_public = Ed25519JWTSigner.generate_key_pair()
    old_signer = Ed25519JWTSigner(old_private, key_id="univ-key-2024")
    jwt_old = to_jwt(credential, old_signer)

    # Check JWT header for key ID
    import jwt as pyjwt

    header_old = pyjwt.get_unverified_header(jwt_old)
    print(f"   Old JWT kid: {header_old.get('kid')}")

    # New key (2025)
    print("\n2. Using new key (2025)...")
    new_private, new_public = Ed25519JWTSigner.generate_key_pair()
    new_signer = Ed25519JWTSigner(new_private, key_id="univ-key-2025")
    jwt_new = to_jwt(credential, new_signer)

    header_new = pyjwt.get_unverified_header(jwt_new)
    print(f"   New JWT kid: {header_new.get('kid')}")

    # Verify with correct keys
    print("\n3. Verifying with correct keys...")
    old_verifier = JWTVerifier(old_public)
    new_verifier = JWTVerifier(new_public)

    from_jwt(jwt_old, old_verifier)
    from_jwt(jwt_new, new_verifier)

    print(f"   ✓ Old JWT verified with old key")
    print(f"   ✓ New JWT verified with new key")
    print(f"\n   Key rotation allows gradual transition from old to new keys!")

    print("\n✓ Key rotation example completed!\n")


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("OpenBadges JWT Examples")
    print("=" * 70 + "\n")

    # Run all examples
    example_basic_jwt_workflow()
    example_multiple_algorithms()
    example_jwt_vs_json_ld()
    example_key_rotation()

    print("=" * 70)
    print("All examples completed successfully!")
    print("=" * 70)
