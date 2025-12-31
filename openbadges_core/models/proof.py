"""Proof models for cryptographic verification in OpenBadges 3.0."""

from datetime import datetime
from typing import Any

from pydantic import Field

from openbadges_core.models.base import URI, BaseModel, ProofPurpose


class Proof(BaseModel):
    """
    A cryptographic proof for verifying the integrity and authenticity of a credential.

    This implements the W3C Verifiable Credentials Data Model proof mechanism.
    Supports both Linked Data Proofs and embedded proof formats.
    """

    type: str = Field(
        ..., description="Type of proof (e.g., 'Ed25519Signature2020', 'RsaSignature2018')"
    )

    # Proof metadata
    created: datetime | None = Field(
        None, description="When the proof was created (ISO 8601)"
    )
    proof_purpose: ProofPurpose = Field(
        ...,
        alias="proofPurpose",
        description="Purpose of the proof (typically 'assertionMethod')",
    )
    verification_method: URI = Field(
        ...,
        alias="verificationMethod",
        description="URI of the verification method (public key)",
    )

    # Cryptographic values
    proof_value: str | None = Field(
        None,
        alias="proofValue",
        description="The proof value (signature) encoded as base64",
    )
    jws: str | None = Field(
        None, description="JSON Web Signature for the proof"
    )

    # Challenge and domain for security
    challenge: str | None = Field(
        None, description="Random challenge to prevent replay attacks"
    )
    domain: str | None = Field(
        None, description="Domain for which the proof is valid"
    )

    # Nonce for uniqueness
    nonce: str | None = Field(
        None, description="Nonce for proof uniqueness"
    )


class CredentialStatus(BaseModel):
    """
    Status information for a credential (for revocation checking).
    """

    id: URI = Field(..., description="URI of the credential status")
    type: str = Field(..., description="Type of status mechanism")


class CredentialSchema(BaseModel):
    """
    A schema for validating the structure of a credential.
    """

    id: URI = Field(..., description="URI of the schema")
    type: str = Field(..., description="Type of schema (e.g., 'JsonSchema')")


class RefreshService(BaseModel):
    """
    Service for refreshing a credential.
    """

    id: URI = Field(..., description="URI of the refresh service")
    type: str = Field(..., description="Type of refresh service")


class TermsOfUse(BaseModel):
    """
    Terms of use for a credential.
    """

    type: str = Field(..., description="Type of terms")
    id: URI | None = Field(None, description="URI of the terms document")


class Evidence(BaseModel):
    """
    Evidence supporting the achievement of a credential.
    """

    id: URI | None = Field(None, description="URI of the evidence")
    type: list[str] | str = Field(default="Evidence", description="Must include 'Evidence'")
    name: str | None = Field(None, description="Name of the evidence")
    description: str | None = Field(None, description="Description of the evidence")
    genre: str | None = Field(None, description="Genre or type of evidence")
    audience: str | None = Field(None, description="Intended audience")
    narrative: str | None = Field(None, description="Narrative description of the evidence")
