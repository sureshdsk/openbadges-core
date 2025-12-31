"""Unit tests for JWT serialization and signing."""

import jwt as pyjwt
from datetime import datetime, timedelta, timezone

import pytest

from openbadges_core.crypto import Ed25519JWTSigner, JWTVerifier, RSAJWTSigner
from openbadges_core.exceptions import JWTDecodeError, JWTError, JWTExpiredError, JWTSignatureError
from openbadges_core.serialization import from_jwt, to_jwt


class TestJWTEncoding:
    """Test JWT encoding functionality."""

    def test_encode_basic_credential_ed25519(self, basic_credential, ed25519_jwt_signer):
        """Test encoding a basic credential as JWT with Ed25519."""
        jwt_string = to_jwt(basic_credential, ed25519_jwt_signer)

        assert isinstance(jwt_string, str)
        assert jwt_string.count(".") == 2  # JWT has 3 parts separated by dots

        # Decode without verification to inspect structure
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})
        assert "vc" in payload
        assert payload["vc"]["type"] == ["VerifiableCredential", "OpenBadgeCredential"]

    def test_encode_basic_credential_rsa(self, basic_credential, rsa_jwt_signer):
        """Test encoding a basic credential as JWT with RSA."""
        jwt_string = to_jwt(basic_credential, rsa_jwt_signer)

        assert isinstance(jwt_string, str)
        assert jwt_string.count(".") == 2

        # Verify it's a valid JWT
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})
        assert "vc" in payload

    def test_encode_includes_required_claims(self, detailed_credential, ed25519_jwt_signer):
        """Test that encoding includes all required JWT claims."""
        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})

        # Check vc claim
        assert "vc" in payload
        assert isinstance(payload["vc"], dict)

        # Check standard JWT claims
        assert "iss" in payload  # issuer
        assert "sub" in payload  # subject
        assert "jti" in payload  # JWT ID
        assert "iat" in payload  # issued at
        assert "exp" in payload  # expiration

    def test_encode_maps_issuer_correctly(self, detailed_credential, ed25519_jwt_signer):
        """Test that issuer is correctly mapped to iss claim."""
        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})

        assert payload["iss"] == "https://example.edu/issuers/dept-cs"

    def test_encode_maps_subject_correctly(self, detailed_credential, ed25519_jwt_signer):
        """Test that credential subject is correctly mapped to sub claim."""
        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})

        assert payload["sub"] == "mailto:learner@example.com"

    def test_encode_maps_timestamps(self, detailed_credential, ed25519_jwt_signer):
        """Test that timestamps are correctly mapped to JWT numeric dates."""
        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})

        # Check that timestamps are integers (Unix timestamps)
        assert isinstance(payload["iat"], int)
        assert isinstance(payload["exp"], int)
        assert isinstance(payload["nbf"], int)

        # Verify timestamps are reasonable (within expected range)
        now = datetime.now(timezone.utc).timestamp()
        assert abs(payload["iat"] - now) < 10  # Within 10 seconds
        assert payload["exp"] > payload["iat"]  # Expiration is in future

    def test_encode_with_key_id(self, basic_credential, ed25519_jwt_keypair):
        """Test encoding with key ID in header."""
        private_key, _ = ed25519_jwt_keypair
        signer = Ed25519JWTSigner(private_key, key_id="test-key-123")

        jwt_string = to_jwt(basic_credential, signer)

        # Decode header
        header = pyjwt.get_unverified_header(jwt_string)
        assert header["kid"] == "test-key-123"
        assert header["alg"] == "EdDSA"

    def test_encode_without_expiration(self, basic_credential, ed25519_jwt_signer):
        """Test encoding credential without expiration date."""
        # basic_credential doesn't have expiration_date set
        jwt_string = to_jwt(basic_credential, ed25519_jwt_signer)
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})

        # Should not have exp claim if credential has no expiration
        assert "exp" not in payload

    def test_encode_vc_claim_excludes_proof(
        self, basic_credential, ed25519_signer, ed25519_jwt_signer
    ):
        """Test that vc claim excludes proof field."""
        # Sign credential with linked data proof first
        signed_credential = ed25519_signer.sign(basic_credential)
        assert signed_credential.proof is not None

        # Encode as JWT
        jwt_string = to_jwt(signed_credential, ed25519_jwt_signer)
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})

        # vc claim should not include proof
        assert "proof" not in payload["vc"]


class TestJWTDecoding:
    """Test JWT decoding functionality."""

    def test_decode_valid_jwt(
        self, basic_credential, ed25519_jwt_signer, ed25519_jwt_verifier
    ):
        """Test decoding a valid JWT back to credential."""
        jwt_string = to_jwt(basic_credential, ed25519_jwt_signer)
        decoded_credential = from_jwt(jwt_string, ed25519_jwt_verifier)

        assert isinstance(decoded_credential, type(basic_credential))
        assert decoded_credential.name == basic_credential.name
        assert decoded_credential.type == basic_credential.type

    def test_decode_without_verification(self, basic_credential, ed25519_jwt_signer):
        """Test decoding JWT without signature verification."""
        jwt_string = to_jwt(basic_credential, ed25519_jwt_signer)
        decoded_credential = from_jwt(jwt_string, verify=False)

        assert isinstance(decoded_credential, type(basic_credential))
        assert decoded_credential.name == basic_credential.name

    def test_decode_with_verification_rsa(
        self, detailed_credential, rsa_jwt_signer, rsa_jwt_verifier
    ):
        """Test decoding and verifying JWT with RSA."""
        jwt_string = to_jwt(detailed_credential, rsa_jwt_signer)
        decoded_credential = from_jwt(jwt_string, rsa_jwt_verifier)

        assert decoded_credential.id == detailed_credential.id
        assert decoded_credential.name == detailed_credential.name

    def test_decode_missing_vc_claim_fails(self, ed25519_jwt_signer, ed25519_jwt_verifier):
        """Test that decoding fails if JWT is missing vc claim."""
        # Create a JWT without vc claim
        payload = {"iss": "https://example.edu", "sub": "did:example:123"}
        jwt_string = ed25519_jwt_signer.sign(payload)

        with pytest.raises(JWTDecodeError, match="missing required 'vc' claim"):
            from_jwt(jwt_string, ed25519_jwt_verifier)

    def test_decode_malformed_jwt_fails(self, ed25519_jwt_verifier):
        """Test that decoding malformed JWT fails."""
        malformed_jwt = "not.a.valid.jwt"

        with pytest.raises(JWTDecodeError):
            from_jwt(malformed_jwt, ed25519_jwt_verifier)

    def test_decode_requires_verifier_when_verify_true(self, basic_credential, ed25519_jwt_signer):
        """Test that verifier is required when verify=True."""
        jwt_string = to_jwt(basic_credential, ed25519_jwt_signer)

        with pytest.raises(Exception, match="Verifier required"):
            from_jwt(jwt_string, verifier=None, verify=True)


class TestJWTVerification:
    """Test JWT signature verification."""

    def test_verify_valid_signature_ed25519(
        self, basic_credential, ed25519_jwt_signer, ed25519_jwt_verifier
    ):
        """Test verifying valid Ed25519 signature."""
        jwt_string = to_jwt(basic_credential, ed25519_jwt_signer)
        decoded = from_jwt(jwt_string, ed25519_jwt_verifier)

        assert decoded is not None
        assert decoded.name == basic_credential.name

    def test_verify_valid_signature_rsa(
        self, basic_credential, rsa_jwt_signer, rsa_jwt_verifier
    ):
        """Test verifying valid RSA signature."""
        jwt_string = to_jwt(basic_credential, rsa_jwt_signer)
        decoded = from_jwt(jwt_string, rsa_jwt_verifier)

        assert decoded is not None

    def test_verify_fails_wrong_key(
        self, basic_credential, ed25519_jwt_signer, rsa_jwt_verifier
    ):
        """Test that verification fails with wrong public key."""
        # Sign with Ed25519
        jwt_string = to_jwt(basic_credential, ed25519_jwt_signer)

        # Try to verify with RSA key
        with pytest.raises((JWTSignatureError, JWTDecodeError)):
            from_jwt(jwt_string, rsa_jwt_verifier)

    def test_verify_fails_tampered_payload(
        self, basic_credential, ed25519_jwt_signer, ed25519_jwt_verifier
    ):
        """Test that verification fails if payload is tampered."""
        jwt_string = to_jwt(basic_credential, ed25519_jwt_signer)

        # Tamper with the JWT (change middle part)
        parts = jwt_string.split(".")
        # Decode, modify, re-encode the payload
        import base64

        payload = base64.urlsafe_b64decode(parts[1] + "==")
        tampered_payload = payload.replace(b"Test Badge", b"Hacked Badge")
        parts[1] = base64.urlsafe_b64encode(tampered_payload).decode().rstrip("=")
        tampered_jwt = ".".join(parts)

        with pytest.raises((JWTSignatureError, JWTDecodeError, JWTError)):
            from_jwt(tampered_jwt, ed25519_jwt_verifier)

    def test_verify_expired_jwt_fails(self, basic_issuer, basic_subject, ed25519_jwt_signer, ed25519_jwt_verifier):
        """Test that verification fails for expired JWT."""
        from openbadges_core import OpenBadgeCredential

        # Create credential that expired 1 day ago
        past = datetime.now(timezone.utc) - timedelta(days=2)
        expired = past + timedelta(days=1)  # Expired 1 day ago

        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2", "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=basic_issuer,
            credential_subject=basic_subject,
            issuance_date=past,
            expiration_date=expired,
        )

        jwt_string = to_jwt(credential, ed25519_jwt_signer)

        with pytest.raises(JWTExpiredError, match="expired"):
            from_jwt(jwt_string, ed25519_jwt_verifier)

    def test_verify_not_yet_valid_fails(
        self, basic_issuer, basic_subject, ed25519_jwt_signer, ed25519_jwt_verifier
    ):
        """Test that verification fails for JWT not yet valid (nbf)."""
        from openbadges_core import OpenBadgeCredential

        # Create credential valid starting tomorrow
        future = datetime.now(timezone.utc) + timedelta(days=1)

        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2", "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=basic_issuer,
            credential_subject=basic_subject,
            issuance_date=datetime.now(timezone.utc),
            valid_from=future,
        )

        jwt_string = to_jwt(credential, ed25519_jwt_signer)

        with pytest.raises(JWTDecodeError):
            from_jwt(jwt_string, ed25519_jwt_verifier)


class TestJWTRoundTrip:
    """Test round-trip encoding and decoding."""

    def test_roundtrip_ed25519(
        self, detailed_credential, ed25519_jwt_signer, ed25519_jwt_verifier
    ):
        """Test round-trip with Ed25519 preserves credential data."""
        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)
        decoded = from_jwt(jwt_string, ed25519_jwt_verifier)

        assert decoded.id == detailed_credential.id
        assert decoded.name == detailed_credential.name
        assert decoded.description == detailed_credential.description
        assert decoded.type == detailed_credential.type

    def test_roundtrip_rsa(self, detailed_credential, rsa_jwt_signer, rsa_jwt_verifier):
        """Test round-trip with RSA preserves credential data."""
        jwt_string = to_jwt(detailed_credential, rsa_jwt_signer)
        decoded = from_jwt(jwt_string, rsa_jwt_verifier)

        assert decoded.id == detailed_credential.id
        assert decoded.name == detailed_credential.name

    def test_roundtrip_preserves_all_fields(
        self, detailed_credential, ed25519_jwt_signer, ed25519_jwt_verifier
    ):
        """Test that round-trip preserves all credential fields."""
        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)
        decoded = from_jwt(jwt_string, ed25519_jwt_verifier)

        # Check issuer (may be dict or Profile object)
        issuer = decoded.issuer
        issuer_id = issuer["id"] if isinstance(issuer, dict) else issuer.id
        issuer_name = issuer["name"] if isinstance(issuer, dict) else issuer.name
        assert issuer_id == detailed_credential.issuer.id
        assert issuer_name == detailed_credential.issuer.name

        # Check subject
        subject = decoded.credential_subject
        subject_id = subject["id"] if isinstance(subject, dict) else subject.id
        assert subject_id == detailed_credential.credential_subject.id

        # Check evidence
        assert decoded.evidence is not None
        assert len(decoded.evidence) == len(detailed_credential.evidence)

    def test_roundtrip_with_complex_credential(
        self, detailed_credential, ed25519_jwt_signer, ed25519_jwt_verifier
    ):
        """Test round-trip with credential containing all features."""
        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)
        decoded = from_jwt(jwt_string, ed25519_jwt_verifier)

        # Verify achievement details (may be dict or Achievement object)
        subject = decoded.credential_subject
        achievement = subject["achievement"] if isinstance(subject, dict) else subject.achievement
        achievement_name = achievement["name"] if isinstance(achievement, dict) else achievement.name
        achievement_tags = achievement["tags"] if isinstance(achievement, dict) else achievement.tags

        assert achievement_name == "Advanced Python Certificate"
        assert achievement_tags == ["python", "programming", "advanced"]


class TestJWTClaimsMapping:
    """Test JWT claims mapping."""

    def test_iss_from_issuer_profile(self, detailed_credential, ed25519_jwt_signer):
        """Test iss claim extracted from issuer Profile."""
        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})

        assert payload["iss"] == "https://example.edu/issuers/dept-cs"

    def test_sub_from_subject_id(self, detailed_credential, ed25519_jwt_signer):
        """Test sub claim extracted from credential subject."""
        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})

        assert payload["sub"] == "mailto:learner@example.com"

    def test_exp_from_expiration_date(self, detailed_credential, ed25519_jwt_signer):
        """Test exp claim from expiration_date field."""
        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})

        # Should have exp claim
        assert "exp" in payload
        assert isinstance(payload["exp"], int)

    def test_iat_from_issuance_date(self, basic_credential, ed25519_jwt_signer):
        """Test iat claim from issuance_date."""
        jwt_string = to_jwt(basic_credential, ed25519_jwt_signer)
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})

        assert "iat" in payload
        assert isinstance(payload["iat"], int)

    def test_jti_from_credential_id(self, detailed_credential, ed25519_jwt_signer):
        """Test jti claim from credential id."""
        jwt_string = to_jwt(detailed_credential, ed25519_jwt_signer)
        payload = pyjwt.decode(jwt_string, options={"verify_signature": False})

        assert payload["jti"] == "https://example.edu/credentials/12345"


class TestJWTEdgeCases:
    """Test edge cases in JWT encoding/decoding."""

    def test_credential_without_optional_claims(
        self, basic_issuer, basic_subject, ed25519_jwt_signer, ed25519_jwt_verifier
    ):
        """Test encoding credential with minimal fields."""
        from openbadges_core import OpenBadgeCredential

        minimal = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2", "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=basic_issuer,
            credential_subject=basic_subject
        )

        jwt_string = to_jwt(minimal, ed25519_jwt_signer)
        decoded = from_jwt(jwt_string, ed25519_jwt_verifier, verify=False)

        # Issuer may be dict or Profile object
        issuer = decoded.issuer
        issuer_id = issuer["id"] if isinstance(issuer, dict) else issuer.id
        assert issuer_id == basic_issuer.id

    def test_additional_headers(self, basic_credential, ed25519_jwt_signer):
        """Test adding custom headers to JWT."""
        custom_headers = {"custom": "value", "version": "1.0"}

        jwt_string = to_jwt(basic_credential, ed25519_jwt_signer, custom_headers)
        header = pyjwt.get_unverified_header(jwt_string)

        assert header["custom"] == "value"
        assert header["version"] == "1.0"
