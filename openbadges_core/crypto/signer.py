"""Credential signing utilities."""

import base64
import hashlib
import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from openbadges_core.exceptions import SigningError
from openbadges_core.models.base import ProofPurpose
from openbadges_core.models.credential import OpenBadgeCredential
from openbadges_core.models.proof import Proof


class CredentialSigner(ABC):
    """Abstract base class for credential signers."""

    def __init__(
        self,
        private_key: Any,
        verification_method: str,
        proof_purpose: ProofPurpose = ProofPurpose.assertionMethod,
    ):
        """
        Initialize signer.

        Args:
            private_key: The private key for signing
            verification_method: URI of the public key for verification
            proof_purpose: Purpose of the proof
        """
        self.private_key = private_key
        self.verification_method = verification_method
        self.proof_purpose = proof_purpose

    @abstractmethod
    def sign(self, credential: OpenBadgeCredential) -> OpenBadgeCredential:
        """
        Sign a credential and add the proof.

        Args:
            credential: The credential to sign

        Returns:
            The credential with proof added

        Raises:
            SigningError: If signing fails
        """
        pass

    @abstractmethod
    def _create_signature(self, data: bytes) -> bytes:
        """Create a signature for the given data."""
        pass

    def _prepare_document(self, credential: OpenBadgeCredential) -> dict[str, Any]:
        """
        Prepare credential document for signing.

        Args:
            credential: The credential to prepare

        Returns:
            Dictionary representation without proof
        """
        # Get credential as dict, excluding proof
        doc = credential.model_dump(mode="json", by_alias=True, exclude_none=True)
        doc.pop("proof", None)
        return doc

    def _canonicalize(self, data: dict[str, Any]) -> bytes:
        """
        Canonicalize data for signing.

        This is a simplified canonicalization. For production use with JSON-LD,
        consider using URDNA2015 canonicalization algorithm.

        Args:
            data: The data to canonicalize

        Returns:
            Canonicalized bytes
        """
        # Simple JSON serialization for now
        # Production should use RDF Dataset Canonicalization
        json_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return json_str.encode("utf-8")


class Ed25519Signer(CredentialSigner):
    """Signer using Ed25519 signature algorithm."""

    def __init__(
        self,
        private_key: ed25519.Ed25519PrivateKey | bytes,
        verification_method: str,
        proof_purpose: ProofPurpose = ProofPurpose.assertionMethod,
    ):
        """
        Initialize Ed25519 signer.

        Args:
            private_key: Ed25519 private key or 32-byte seed
            verification_method: URI of the public key
            proof_purpose: Purpose of the proof
        """
        if isinstance(private_key, bytes):
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)

        super().__init__(private_key, verification_method, proof_purpose)

    def sign(self, credential: OpenBadgeCredential) -> OpenBadgeCredential:
        """Sign credential with Ed25519."""
        try:
            # Prepare document
            doc = self._prepare_document(credential)

            # Canonicalize
            canonical = self._canonicalize(doc)

            # Create signature
            signature = self._create_signature(canonical)

            # Encode signature
            signature_b64 = base64.b64encode(signature).decode("ascii")

            # Create proof
            proof = Proof(
                type="Ed25519Signature2020",
                created=datetime.now(timezone.utc),
                verification_method=self.verification_method,
                proof_purpose=self.proof_purpose,
                proof_value=signature_b64,
            )

            # Add proof to credential
            credential.proof = proof

            return credential

        except Exception as e:
            raise SigningError(f"Failed to sign credential: {e}") from e

    def _create_signature(self, data: bytes) -> bytes:
        """Create Ed25519 signature."""
        return self.private_key.sign(data)

    @staticmethod
    def generate_key_pair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """
        Generate a new Ed25519 key pair.

        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key


class RSASigner(CredentialSigner):
    """Signer using RSA signature algorithm."""

    def __init__(
        self,
        private_key: rsa.RSAPrivateKey | bytes,
        verification_method: str,
        proof_purpose: ProofPurpose = ProofPurpose.assertionMethod,
    ):
        """
        Initialize RSA signer.

        Args:
            private_key: RSA private key
            verification_method: URI of the public key
            proof_purpose: Purpose of the proof
        """
        if isinstance(private_key, bytes):
            private_key = serialization.load_pem_private_key(private_key, password=None)

        super().__init__(private_key, verification_method, proof_purpose)

    def sign(self, credential: OpenBadgeCredential) -> OpenBadgeCredential:
        """Sign credential with RSA."""
        try:
            # Prepare document
            doc = self._prepare_document(credential)

            # Canonicalize
            canonical = self._canonicalize(doc)

            # Create signature
            signature = self._create_signature(canonical)

            # Encode signature
            signature_b64 = base64.b64encode(signature).decode("ascii")

            # Create proof
            proof = Proof(
                type="RsaSignature2018",
                created=datetime.now(timezone.utc),
                verification_method=self.verification_method,
                proof_purpose=self.proof_purpose,
                proof_value=signature_b64,
            )

            # Add proof to credential
            credential.proof = proof

            return credential

        except Exception as e:
            raise SigningError(f"Failed to sign credential: {e}") from e

    def _create_signature(self, data: bytes) -> bytes:
        """Create RSA signature."""
        return self.private_key.sign(data, PKCS1v15(), hashes.SHA256())

    @staticmethod
    def generate_key_pair(
        key_size: int = 2048,
    ) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate a new RSA key pair.

        Args:
            key_size: Size of the key in bits (default 2048)

        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()
        return private_key, public_key
