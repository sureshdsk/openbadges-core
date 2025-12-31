"""JWT (JSON Web Token) serialization for OpenBadges credentials."""

import jwt as pyjwt
from typing import Any

from openbadges_core.crypto.jwt_signer import JWTSigner, JWTVerifier
from openbadges_core.exceptions import JWTDecodeError, JWTError, JWTExpiredError, JWTSignatureError
from openbadges_core.models.credential import OpenBadgeCredential


def _credential_to_jwt_payload(credential: OpenBadgeCredential) -> dict[str, Any]:
    """
    Convert credential to JWT payload with proper claims mapping.

    Args:
        credential: The OpenBadgeCredential to convert

    Returns:
        JWT payload dictionary with vc claim and standard JWT claims

    Note:
        Follows W3C VC Data Model 2.0 JWT encoding specification.
    """
    # Extract vc claim (credential without proof)
    vc_data = credential.model_dump(mode="json", by_alias=True, exclude_none=True)
    vc_data.pop("proof", None)

    # Remove JWT-specific fields from vc claim (they go in top-level claims)
    for jwt_field in ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]:
        vc_data.pop(jwt_field, None)

    # Build JWT claims with vc claim
    payload: dict[str, Any] = {"vc": vc_data}

    # Map issuer to iss claim
    if isinstance(credential.issuer, str):
        payload["iss"] = credential.issuer
    elif hasattr(credential.issuer, "id") and credential.issuer.id:
        payload["iss"] = credential.issuer.id
    elif hasattr(credential.issuer, "model_dump"):
        # If issuer is a Profile object, try to get id from the dict
        issuer_dict = credential.issuer.model_dump(mode="json", exclude_none=True)
        if "id" in issuer_dict:
            payload["iss"] = issuer_dict["id"]

    # Map subject to sub claim
    if isinstance(credential.credential_subject, dict):
        if "id" in credential.credential_subject:
            payload["sub"] = credential.credential_subject["id"]
    elif isinstance(credential.credential_subject, list):
        # If multiple subjects, use first one's ID
        if len(credential.credential_subject) > 0:
            first_subject = credential.credential_subject[0]
            if isinstance(first_subject, dict) and "id" in first_subject:
                payload["sub"] = first_subject["id"]
            elif hasattr(first_subject, "id") and first_subject.id:
                payload["sub"] = first_subject.id
    elif hasattr(credential.credential_subject, "id") and credential.credential_subject.id:
        payload["sub"] = credential.credential_subject.id

    # Map timestamps to JWT numeric date values (Unix timestamps)
    if credential.issuance_date:
        payload["iat"] = int(credential.issuance_date.timestamp())

    # Prefer expiration_date, fall back to valid_until
    if credential.expiration_date:
        payload["exp"] = int(credential.expiration_date.timestamp())
    elif credential.valid_until:
        payload["exp"] = int(credential.valid_until.timestamp())

    if credential.valid_from:
        payload["nbf"] = int(credential.valid_from.timestamp())

    # Map credential ID to jti (JWT ID)
    if credential.id:
        payload["jti"] = credential.id

    # Optional audience
    if credential.aud:
        payload["aud"] = credential.aud

    return payload


def to_jwt(
    credential: OpenBadgeCredential,
    signer: JWTSigner,
    additional_headers: dict[str, Any] | None = None,
) -> str:
    """
    Encode an OpenBadgeCredential as a JWT (VC-JWT format).

    Args:
        credential: The credential to encode
        signer: JWTSigner instance with private key and algorithm
        additional_headers: Optional additional JWT headers

    Returns:
        Compact JWT string (header.payload.signature)

    Raises:
        JWTError: If encoding fails

    Example:
        >>> from openbadges_core.crypto import Ed25519JWTSigner
        >>> private_key, public_key = Ed25519JWTSigner.generate_key_pair()
        >>> signer = Ed25519JWTSigner(private_key, key_id="key-1")
        >>> jwt_string = to_jwt(credential, signer)
    """
    try:
        payload = _credential_to_jwt_payload(credential)
        return signer.sign(payload, additional_headers)
    except Exception as e:
        raise JWTError(f"Failed to encode credential as JWT: {e}") from e


def from_jwt(
    jwt_string: str, verifier: JWTVerifier | None = None, verify: bool = True
) -> OpenBadgeCredential:
    """
    Decode a JWT to an OpenBadgeCredential.

    Args:
        jwt_string: Compact JWT string to decode
        verifier: JWTVerifier instance with public key (required if verify=True)
        verify: Whether to verify signature (default True)

    Returns:
        OpenBadgeCredential instance

    Raises:
        JWTError: If JWT is invalid or missing vc claim
        JWTSignatureError: If signature verification fails
        JWTExpiredError: If credential is expired

    Example:
        >>> from openbadges_core.crypto import JWTVerifier
        >>> verifier = JWTVerifier(public_key)
        >>> credential = from_jwt(jwt_string, verifier)
    """
    if verify and not verifier:
        raise JWTError("Verifier required for signature verification")

    try:
        # Decode JWT
        if verifier:
            payload = verifier.verify(jwt_string)
        else:
            # Decode without verification
            payload = pyjwt.decode(jwt_string, options={"verify_signature": False})

        # Extract vc claim
        vc_data = payload.get("vc")
        if not vc_data:
            raise JWTDecodeError("JWT missing required 'vc' claim")

        # Reconstruct credential from vc claim
        return OpenBadgeCredential.model_validate(vc_data)

    except (JWTDecodeError, JWTExpiredError, JWTSignatureError):
        # Re-raise JWT-specific exceptions without wrapping
        raise
    except Exception as e:
        raise JWTError(f"Failed to decode JWT to credential: {e}") from e
