"""Credential verification utilities."""

import base64
import json
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.exceptions import InvalidSignature

from openbadges_core.exceptions import VerificationError
from openbadges_core.models.credential import OpenBadgeCredential


class CredentialVerifier:
    """Verifier for signed credentials."""

    def __init__(self, public_key: ed25519.Ed25519PublicKey | rsa.RSAPublicKey):
        """
        Initialize verifier with a public key.

        Args:
            public_key: The public key for verification
        """
        self.public_key = public_key

    def verify(self, credential: OpenBadgeCredential) -> bool:
        """
        Verify the signature on a credential.

        Args:
            credential: The credential to verify

        Returns:
            True if signature is valid

        Raises:
            VerificationError: If verification fails or signature is invalid
        """
        if not credential.proof:
            raise VerificationError("Credential has no proof to verify")

        # Handle multiple proofs - verify the first one for now
        proof = credential.proof if not isinstance(credential.proof, list) else credential.proof[0]

        if not proof.proof_value:
            raise VerificationError("Proof has no proofValue")

        try:
            # Prepare document without proof
            doc = credential.model_dump(mode="json", by_alias=True, exclude_none=True)
            doc.pop("proof", None)

            # Canonicalize
            canonical = self._canonicalize(doc)

            # Decode signature
            signature = base64.b64decode(proof.proof_value)

            # Verify based on proof type
            if proof.type == "Ed25519Signature2020":
                self._verify_ed25519(canonical, signature)
            elif proof.type == "RsaSignature2018":
                self._verify_rsa(canonical, signature)
            else:
                raise VerificationError(f"Unsupported proof type: {proof.type}")

            return True

        except InvalidSignature:
            raise VerificationError("Invalid signature")
        except Exception as e:
            raise VerificationError(f"Verification failed: {e}") from e

    def _canonicalize(self, data: dict[str, Any]) -> bytes:
        """
        Canonicalize data for verification.

        Args:
            data: The data to canonicalize

        Returns:
            Canonicalized bytes
        """
        # Simple JSON serialization - should match signer's canonicalization
        json_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return json_str.encode("utf-8")

    def _verify_ed25519(self, data: bytes, signature: bytes) -> None:
        """
        Verify Ed25519 signature.

        Args:
            data: The signed data
            signature: The signature to verify

        Raises:
            InvalidSignature: If signature is invalid
            VerificationError: If wrong key type
        """
        if not isinstance(self.public_key, ed25519.Ed25519PublicKey):
            raise VerificationError("Public key is not Ed25519")

        self.public_key.verify(signature, data)

    def _verify_rsa(self, data: bytes, signature: bytes) -> None:
        """
        Verify RSA signature.

        Args:
            data: The signed data
            signature: The signature to verify

        Raises:
            InvalidSignature: If signature is invalid
            VerificationError: If wrong key type
        """
        if not isinstance(self.public_key, rsa.RSAPublicKey):
            raise VerificationError("Public key is not RSA")

        self.public_key.verify(signature, data, PKCS1v15(), hashes.SHA256())


def verify_credential(
    credential: OpenBadgeCredential,
    public_key: ed25519.Ed25519PublicKey | rsa.RSAPublicKey,
) -> bool:
    """
    Verify a signed credential.

    Args:
        credential: The credential to verify
        public_key: The public key for verification

    Returns:
        True if signature is valid

    Raises:
        VerificationError: If verification fails
    """
    verifier = CredentialVerifier(public_key)
    return verifier.verify(credential)
