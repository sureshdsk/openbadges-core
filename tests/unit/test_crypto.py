"""Unit tests for cryptographic signing and verification."""

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from openbadges_core.crypto import (
    CredentialVerifier,
    Ed25519Signer,
    RSASigner,
    verify_credential,
)
from openbadges_core.exceptions import SigningError, VerificationError
from openbadges_core.models.base import ProofPurpose


class TestEd25519Signer:
    """Tests for Ed25519 signature algorithm."""

    def test_generate_keypair(self):
        """Test Ed25519 key pair generation."""
        private_key, public_key = Ed25519Signer.generate_key_pair()

        assert isinstance(private_key, ed25519.Ed25519PrivateKey)
        assert isinstance(public_key, ed25519.Ed25519PublicKey)

    def test_signer_initialization_with_key(self, ed25519_keypair):
        """Test initializing signer with key object."""
        private_key, _ = ed25519_keypair

        signer = Ed25519Signer(
            private_key=private_key,
            verification_method="https://example.edu/keys/1",
        )

        assert signer.private_key == private_key
        assert signer.verification_method == "https://example.edu/keys/1"
        assert signer.proof_purpose == ProofPurpose.assertionMethod

    def test_signer_initialization_with_bytes(self):
        """Test initializing signer with 32-byte seed."""
        seed = b"a" * 32  # 32-byte seed
        signer = Ed25519Signer(
            private_key=seed, verification_method="https://example.edu/keys/1"
        )

        assert isinstance(signer.private_key, ed25519.Ed25519PrivateKey)

    def test_sign_credential(self, ed25519_signer, basic_credential):
        """Test signing a credential with Ed25519."""
        signed = ed25519_signer.sign(basic_credential)

        assert signed.proof is not None
        assert signed.proof.type == "Ed25519Signature2020"
        assert signed.proof.proof_value is not None
        assert signed.proof.verification_method == "https://example.edu/issuers/1#key-ed25519-1"
        assert signed.proof.proof_purpose == ProofPurpose.assertionMethod
        assert signed.proof.created is not None

    def test_proof_value_is_base64(self, ed25519_signer, basic_credential):
        """Test that proof value is valid base64."""
        signed = ed25519_signer.sign(basic_credential)
        proof_value = signed.proof.proof_value

        # Should be valid base64
        try:
            decoded = base64.b64decode(proof_value)
            assert len(decoded) > 0
        except Exception as e:
            pytest.fail(f"Proof value is not valid base64: {e}")

    def test_custom_proof_purpose(self, ed25519_keypair, basic_credential):
        """Test signer with custom proof purpose."""
        private_key, _ = ed25519_keypair
        signer = Ed25519Signer(
            private_key=private_key,
            verification_method="https://example.edu/keys/1",
            proof_purpose=ProofPurpose.authentication,
        )

        signed = signer.sign(basic_credential)
        assert signed.proof.proof_purpose == ProofPurpose.authentication


class TestRSASigner:
    """Tests for RSA signature algorithm."""

    def test_generate_keypair(self):
        """Test RSA key pair generation."""
        private_key, public_key = RSASigner.generate_key_pair(key_size=2048)

        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert isinstance(public_key, rsa.RSAPublicKey)

    def test_signer_initialization(self, rsa_keypair):
        """Test initializing RSA signer."""
        private_key, _ = rsa_keypair

        signer = RSASigner(
            private_key=private_key,
            verification_method="https://example.edu/keys/1",
        )

        assert signer.private_key == private_key

    def test_sign_credential(self, rsa_signer, basic_credential):
        """Test signing a credential with RSA."""
        signed = rsa_signer.sign(basic_credential)

        assert signed.proof is not None
        assert signed.proof.type == "RsaSignature2018"
        assert signed.proof.proof_value is not None
        assert signed.proof.created is not None

    def test_rsa_signature_length(self, rsa_signer, basic_credential):
        """Test that RSA signature has expected length."""
        signed = rsa_signer.sign(basic_credential)
        proof_value = signed.proof.proof_value

        # Decode base64
        decoded = base64.b64decode(proof_value)

        # RSA-2048 signature should be 256 bytes
        assert len(decoded) == 256


class TestCredentialVerifier:
    """Tests for credential verification."""

    def test_verify_ed25519_signed_credential(self, ed25519_signer, ed25519_keypair, basic_credential):
        """Test verifying Ed25519 signed credential."""
        _, public_key = ed25519_keypair

        # Sign
        signed = ed25519_signer.sign(basic_credential)

        # Verify
        is_valid = verify_credential(signed, public_key)
        assert is_valid is True

    def test_verify_rsa_signed_credential(self, rsa_signer, rsa_keypair, basic_credential):
        """Test verifying RSA signed credential."""
        _, public_key = rsa_keypair

        # Sign
        signed = rsa_signer.sign(basic_credential)

        # Verify
        is_valid = verify_credential(signed, public_key)
        assert is_valid is True

    def test_verification_fails_with_wrong_key(self, ed25519_signer, basic_credential):
        """Test that verification fails with wrong public key."""
        # Sign with one key
        signed = ed25519_signer.sign(basic_credential)

        # Generate different key pair
        _, wrong_public_key = Ed25519Signer.generate_key_pair()

        # Verification should fail
        with pytest.raises(VerificationError, match="Invalid signature"):
            verify_credential(signed, wrong_public_key)

    def test_verification_fails_for_modified_credential(
        self, ed25519_signer, ed25519_keypair, basic_credential
    ):
        """Test that verification fails if credential is modified."""
        _, public_key = ed25519_keypair

        # Sign
        signed = ed25519_signer.sign(basic_credential)

        # Modify the credential
        signed.name = "MODIFIED NAME"

        # Verification should fail
        with pytest.raises(VerificationError):
            verify_credential(signed, public_key)

    def test_verify_credential_without_proof(self, basic_credential, ed25519_keypair):
        """Test that verification fails for credential without proof."""
        _, public_key = ed25519_keypair

        with pytest.raises(VerificationError, match="no proof"):
            verify_credential(basic_credential, public_key)

    def test_verify_wrong_key_type_for_proof(self, ed25519_signer, rsa_keypair, basic_credential):
        """Test verification fails when using wrong key type."""
        # Sign with Ed25519
        signed = ed25519_signer.sign(basic_credential)

        # Try to verify with RSA key
        _, rsa_public_key = rsa_keypair

        with pytest.raises(VerificationError, match="not Ed25519"):
            verify_credential(signed, rsa_public_key)


class TestSignatureRoundTrip:
    """Integration-like tests for sign-verify round trips."""

    def test_ed25519_round_trip(self, ed25519_signer, ed25519_keypair, basic_credential):
        """Test complete Ed25519 sign and verify cycle."""
        _, public_key = ed25519_keypair

        # Sign
        signed = ed25519_signer.sign(basic_credential)

        # Verify
        assert verify_credential(signed, public_key) is True

    def test_rsa_round_trip(self, rsa_signer, rsa_keypair, basic_credential):
        """Test complete RSA sign and verify cycle."""
        _, public_key = rsa_keypair

        # Sign
        signed = rsa_signer.sign(basic_credential)

        # Verify
        assert verify_credential(signed, public_key) is True

    def test_multiple_sign_verify_cycles(self, ed25519_signer, ed25519_keypair, basic_credential):
        """Test signing and verifying multiple times produces consistent results."""
        import time
        _, public_key = ed25519_keypair

        # Sign first time
        signed1 = ed25519_signer.sign(basic_credential)

        # Small delay to ensure different timestamp
        time.sleep(0.001)

        # Sign second time
        signed2 = ed25519_signer.sign(basic_credential)

        # Both should verify
        assert verify_credential(signed1, public_key) is True
        assert verify_credential(signed2, public_key) is True

        # Note: Signatures may be different if timestamps differ
        # (test ensures both verify correctly)


class TestSignerEdgeCases:
    """Test edge cases and error conditions."""

    def test_sign_already_signed_credential(self, ed25519_signer, basic_credential):
        """Test signing a credential that already has a proof."""
        # Sign once
        signed = ed25519_signer.sign(basic_credential)
        first_proof = signed.proof

        # Sign again (should replace proof)
        signed_again = ed25519_signer.sign(signed)

        assert signed_again.proof is not None
        # Proof should be different (different timestamp)
        assert signed_again.proof.created != first_proof.created
