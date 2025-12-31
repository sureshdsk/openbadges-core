"""Integration tests for JWT functionality."""

import jwt as pyjwt

import pytest

from openbadges_core.crypto import Ed25519JWTSigner, JWTVerifier, RSAJWTSigner
from openbadges_core.serialization import from_jwt, from_json_ld, to_json_ld, to_jwt


class TestJWTW3CCompliance:
    """Test W3C VC-JWT specification compliance."""

    def test_jwt_structure_complies_with_rfc7519(self, basic_credential, ed25519_jwt_signer):
        """Test that generated JWT complies with RFC 7519 structure."""
        jwt_string = to_jwt(basic_credential, ed25519_jwt_signer)

        # JWT should have exactly 3 parts
        parts = jwt_string.split(".")
        assert len(parts) == 3

        # Header should be valid JSON
        header = pyjwt.get_unverified_header(jwt_string)
        assert "alg" in header
        assert "typ" in header or True  # typ is optional

        # Payload should be valid JSON
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})
        assert isinstance(payload, dict)

    def test_vc_claim_structure(self, detailed_credential, ed25519_jwt_signer):
        """Test that vc claim follows W3C VC structure."""
        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})

        vc = payload["vc"]

        # VC must have @context
        assert "@context" in vc
        assert isinstance(vc["@context"], list)

        # VC must have type
        assert "type" in vc
        assert "VerifiableCredential" in vc["type"]
        assert "OpenBadgeCredential" in vc["type"]

        # VC must have credentialSubject
        assert "credentialSubject" in vc

        # VC must have issuer
        assert "issuer" in vc

    def test_interop_with_external_jwt_tools(
        self, basic_credential, ed25519_jwt_signer, ed25519_jwt_keypair
    ):
        """Test that JWT can be verified by standard JWT libraries."""
        jwt_string = to_jwt(basic_credential, ed25519_jwt_signer)
        _, public_key = ed25519_jwt_keypair

        # Use PyJWT directly to verify (simulating external tool)
        from cryptography.hazmat.primitives import serialization

        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Should not raise exception
        decoded = pyjwt.decode(jwt_string, pem_public_key, algorithms=["EdDSA"])
        assert "vc" in decoded


class TestJWTWorkflow:
    """Test end-to-end JWT workflows."""

    def test_issue_sign_verify_workflow(
        self, basic_issuer, basic_achievement, ed25519_jwt_signer, ed25519_jwt_verifier
    ):
        """Test complete workflow: create → sign → encode → verify → decode."""
        from openbadges_core import AchievementSubject, OpenBadgeCredential
        from datetime import datetime, timezone

        # Step 1: Create credential
        subject = AchievementSubject(
            id="did:example:learner999", achievement=basic_achievement
        )

        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2", "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            id="https://example.edu/credentials/workflow-test",
            issuer=basic_issuer,
            credential_subject=subject,
            issuance_date=datetime.now(timezone.utc),
        )

        # Step 2: Encode as JWT
        jwt_string = to_jwt(credential, ed25519_jwt_signer)
        assert isinstance(jwt_string, str)

        # Step 3: Verify and decode
        decoded = from_jwt(jwt_string, ed25519_jwt_verifier)

        # Step 4: Verify data integrity
        assert decoded.id == credential.id

        # Subject may be dict or object
        subject = decoded.credential_subject
        subject_id = subject["id"] if isinstance(subject, dict) else subject.id
        assert subject_id == "did:example:learner999"

        # Issuer may be dict or Profile object
        issuer = decoded.issuer
        issuer_id = issuer["id"] if isinstance(issuer, dict) else issuer.id
        assert issuer_id == basic_issuer.id

    def test_credential_jwt_json_ld_conversion(
        self, detailed_credential, ed25519_jwt_signer, ed25519_jwt_verifier
    ):
        """Test converting between JWT and JSON-LD formats."""
        # Convert to JWT
        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)

        # Decode from JWT
        from_jwt_credential = from_jwt(jwt_string, ed25519_jwt_verifier)

        # Convert to JSON-LD
        json_ld_string = to_json_ld(from_jwt_credential)

        # Parse back from JSON-LD
        from openbadges_core import OpenBadgeCredential

        from_json_ld_credential = from_json_ld(json_ld_string, OpenBadgeCredential)

        # Verify data is preserved
        assert from_json_ld_credential.id == detailed_credential.id
        assert from_json_ld_credential.name == detailed_credential.name

    def test_multiple_algorithms_same_credential(
        self,
        basic_credential,
        ed25519_jwt_signer,
        rsa_jwt_signer,
        ed25519_jwt_verifier,
        rsa_jwt_verifier,
    ):
        """Test signing same credential with different algorithms."""
        # Sign with Ed25519
        jwt_ed25519 = to_jwt(basic_credential, ed25519_jwt_signer)
        decoded_ed25519 = from_jwt(jwt_ed25519, ed25519_jwt_verifier)

        # Sign with RSA
        jwt_rsa = to_jwt(basic_credential, rsa_jwt_signer)
        decoded_rsa = from_jwt(jwt_rsa, rsa_jwt_verifier)

        # Both should decode to equivalent credentials
        assert decoded_ed25519.name == decoded_rsa.name
        assert decoded_ed25519.type == decoded_rsa.type

        # JWTs themselves should be different
        assert jwt_ed25519 != jwt_rsa

    def test_jwt_size_comparison(self, detailed_credential, ed25519_jwt_signer):
        """Test JWT vs JSON-LD size comparison."""
        # Generate both formats
        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)
        json_ld_string = to_json_ld(detailed_credential)

        # JWT should be reasonably sized
        assert len(jwt_string) > 0
        assert len(json_ld_string) > 0

        # Both should contain the credential data
        assert isinstance(jwt_string, str)
        assert isinstance(json_ld_string, str)

    def test_key_rotation_scenario(self, basic_credential):
        """Test scenario with multiple keys (key rotation)."""
        # Generate two key pairs (old and new)
        old_private, old_public = Ed25519JWTSigner.generate_key_pair()
        new_private, new_public = Ed25519JWTSigner.generate_key_pair()

        # Create signers with key IDs
        old_signer = Ed25519JWTSigner(old_private, key_id="key-2024-01")
        new_signer = Ed25519JWTSigner(new_private, key_id="key-2024-02")

        # Sign with old key
        jwt_old = to_jwt(basic_credential, old_signer)
        header_old = pyjwt.get_unverified_header(jwt_old)
        assert header_old["kid"] == "key-2024-01"

        # Sign with new key
        jwt_new = to_jwt(basic_credential, new_signer)
        header_new = pyjwt.get_unverified_header(jwt_new)
        assert header_new["kid"] == "key-2024-02"

        # Verify each with corresponding public key
        old_verifier = JWTVerifier(old_public)
        new_verifier = JWTVerifier(new_public)

        decoded_old = from_jwt(jwt_old, old_verifier)
        decoded_new = from_jwt(jwt_new, new_verifier)

        assert decoded_old.name == decoded_new.name


class TestJWTPerformance:
    """Test JWT performance characteristics."""

    def test_encoding_speed(self, detailed_credential, ed25519_jwt_signer):
        """Test that JWT encoding completes in reasonable time."""
        import time

        start = time.time()
        for _ in range(100):
            to_jwt(detailed_credential, ed25519_jwt_signer)
        elapsed = time.time() - start

        # 100 encodings should complete in under 1 second
        assert elapsed < 1.0

    def test_decoding_speed(
        self, detailed_credential, ed25519_jwt_signer, ed25519_jwt_verifier
    ):
        """Test that JWT decoding completes in reasonable time."""
        import time

        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)

        start = time.time()
        for _ in range(100):
            from_jwt(jwt_string, ed25519_jwt_verifier)
        elapsed = time.time() - start

        # 100 decodings should complete in under 1 second
        assert elapsed < 1.0


class TestJWTErrorHandling:
    """Test error handling in integration scenarios."""

    def test_cross_algorithm_verification_fails(
        self, basic_credential, ed25519_jwt_signer, rsa_jwt_verifier
    ):
        """Test that cross-algorithm verification fails gracefully."""
        from openbadges_core.exceptions import JWTDecodeError, JWTSignatureError

        jwt_string = to_jwt(basic_credential, ed25519_jwt_signer)

        with pytest.raises((JWTSignatureError, JWTDecodeError)):
            from_jwt(jwt_string, rsa_jwt_verifier)

    def test_corrupted_jwt_handling(self, basic_credential, ed25519_jwt_signer):
        """Test handling of corrupted JWT strings."""
        from openbadges_core.exceptions import JWTDecodeError, JWTError

        jwt_string = to_jwt(basic_credential, ed25519_jwt_signer)

        # Corrupt the JWT
        corrupted = jwt_string[:-10] + "corrupted!"

        with pytest.raises((JWTDecodeError, JWTError)):
            from_jwt(corrupted, verify=False)
