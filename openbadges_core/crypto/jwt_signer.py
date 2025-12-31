"""JWT signing and verification for credentials."""

import jwt as pyjwt
from abc import ABC, abstractmethod
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from openbadges_core.exceptions import JWTDecodeError, JWTExpiredError, JWTSignatureError


class JWTSigner(ABC):
    """Abstract base class for JWT signers."""

    def __init__(self, private_key: Any, key_id: str | None = None):
        """
        Initialize JWT signer.

        Args:
            private_key: Private key for signing
            key_id: Optional key ID for JWT header (kid)
        """
        self.private_key = private_key
        self.key_id = key_id

    @abstractmethod
    def get_algorithm(self) -> str:
        """Get JWT algorithm name (e.g., 'EdDSA', 'RS256')."""
        pass

    def _get_signing_key(self) -> bytes:
        """
        Get key in format PyJWT expects.

        Returns:
            PEM-encoded private key bytes
        """
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def sign(self, payload: dict[str, Any], headers: dict[str, Any] | None = None) -> str:
        """
        Sign payload and return compact JWT.

        Args:
            payload: JWT payload claims
            headers: Optional additional headers

        Returns:
            Compact JWT string (header.payload.signature)

        Raises:
            JWTDecodeError: If signing fails
        """
        try:
            key = self._get_signing_key()
            jwt_headers = {}

            if self.key_id:
                jwt_headers["kid"] = self.key_id

            if headers:
                jwt_headers.update(headers)

            return pyjwt.encode(
                payload, key, algorithm=self.get_algorithm(), headers=jwt_headers or None
            )
        except Exception as e:
            raise JWTDecodeError(f"Failed to sign JWT: {e}") from e


class Ed25519JWTSigner(JWTSigner):
    """JWT signer using Ed25519 (EdDSA algorithm)."""

    def __init__(
        self, private_key: ed25519.Ed25519PrivateKey | bytes, key_id: str | None = None
    ):
        """
        Initialize Ed25519 JWT signer.

        Args:
            private_key: Ed25519 private key or 32-byte seed
            key_id: Optional key ID for JWT header (kid)
        """
        if isinstance(private_key, bytes):
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)

        super().__init__(private_key, key_id)

    def get_algorithm(self) -> str:
        """Return EdDSA algorithm identifier."""
        return "EdDSA"

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


class RSAJWTSigner(JWTSigner):
    """JWT signer using RSA (RS256 algorithm)."""

    def __init__(
        self, private_key: rsa.RSAPrivateKey | bytes, key_id: str | None = None
    ):
        """
        Initialize RSA JWT signer.

        Args:
            private_key: RSA private key or PEM-encoded bytes
            key_id: Optional key ID for JWT header (kid)
        """
        if isinstance(private_key, bytes):
            private_key = serialization.load_pem_private_key(private_key, password=None)

        super().__init__(private_key, key_id)

    def get_algorithm(self) -> str:
        """Return RS256 algorithm identifier."""
        return "RS256"

    @staticmethod
    def generate_key_pair(key_size: int = 2048) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
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


class JWTVerifier:
    """JWT signature verifier."""

    def __init__(
        self,
        public_key: ed25519.Ed25519PublicKey | rsa.RSAPublicKey,
        algorithms: list[str] | None = None,
    ):
        """
        Initialize JWT verifier.

        Args:
            public_key: Public key for verification
            algorithms: List of allowed algorithms (default: ["EdDSA", "RS256"])
        """
        self.public_key = public_key
        self.algorithms = algorithms or ["EdDSA", "RS256"]

    def _get_verification_key(self) -> bytes:
        """
        Get public key in PyJWT format.

        Returns:
            PEM-encoded public key bytes
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def verify(self, jwt_string: str, verify_exp: bool = True) -> dict[str, Any]:
        """
        Verify JWT signature and return payload.

        Args:
            jwt_string: Compact JWT string to verify
            verify_exp: Whether to verify expiration time (default True)

        Returns:
            Decoded JWT payload as dictionary

        Raises:
            JWTExpiredError: If JWT has expired
            JWTSignatureError: If signature verification fails
            JWTDecodeError: If JWT decoding fails
        """
        try:
            key = self._get_verification_key()
            options = {"verify_exp": verify_exp}

            return pyjwt.decode(jwt_string, key, algorithms=self.algorithms, options=options)
        except pyjwt.ExpiredSignatureError as e:
            raise JWTExpiredError("JWT has expired") from e
        except pyjwt.InvalidSignatureError as e:
            raise JWTSignatureError("Invalid JWT signature") from e
        except pyjwt.DecodeError as e:
            raise JWTDecodeError(f"JWT decode failed: {e}") from e
        except Exception as e:
            raise JWTDecodeError(f"JWT verification failed: {e}") from e
