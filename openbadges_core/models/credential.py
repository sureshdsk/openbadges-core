"""OpenBadgeCredential model - the main verifiable credential for OpenBadges 3.0."""

from datetime import datetime
from typing import Any

from pydantic import Field, HttpUrl

from openbadges_core.models.base import URI, BaseModel
from openbadges_core.models.proof import (
    CredentialSchema,
    CredentialStatus,
    Evidence,
    Proof,
    RefreshService,
    TermsOfUse,
)
from openbadges_core.models.subject import AchievementSubject


class OpenBadgeCredential(BaseModel):
    """
    An OpenBadgeCredential (also known as AchievementCredential).

    This is the main verifiable credential that asserts a learner has achieved
    specific criteria. It combines the W3C Verifiable Credentials Data Model
    with OpenBadges-specific extensions.

    This credential can be cryptographically verified and is portable across
    systems that support OpenBadges 3.0.
    """

    # JSON-LD context
    context: list[URI | dict[str, Any]] | URI | dict[str, Any] = Field(
        ...,
        alias="@context",
        description="JSON-LD context (must include VC and OB contexts)",
    )

    # Core VC properties
    id: URI | None = Field(
        None, description="Unique URI identifier for this credential"
    )
    type: list[str] | str = Field(
        ...,
        description="Must include 'VerifiableCredential' and 'OpenBadgeCredential'",
    )

    # Issuer
    issuer: Any = Field(
        ...,
        description="Issuer of the credential (Profile or URI)",
    )

    # Issuance date (required by VC spec)
    issuance_date: datetime | None = Field(
        None,
        alias="issuanceDate",
        description="When the credential was issued (ISO 8601)",
    )

    # Valid from/until (OB 3.0 uses these instead of issuanceDate for some cases)
    valid_from: datetime | None = Field(
        None,
        alias="validFrom",
        description="When the credential becomes valid (ISO 8601)",
    )
    valid_until: datetime | None = Field(
        None,
        alias="validUntil",
        description="When the credential expires (ISO 8601)",
    )

    # Expiration date (VC spec)
    expiration_date: datetime | None = Field(
        None,
        alias="expirationDate",
        description="When the credential expires (ISO 8601)",
    )

    # Subject - who earned the achievement
    credential_subject: AchievementSubject | list[AchievementSubject] = Field(
        ...,
        alias="credentialSubject",
        description="The subject(s) of the credential who earned the achievement",
    )

    # Name and description
    name: str | None = Field(
        None, description="Name of the credential"
    )
    description: str | None = Field(
        None, description="Description of the credential"
    )

    # Image (for display)
    image: Any | None = Field(
        None, description="Image representing this credential"
    )

    # Proof (cryptographic signature)
    proof: Proof | list[Proof] | None = Field(
        None, description="Cryptographic proof(s) of authenticity"
    )

    # Evidence supporting the achievement
    evidence: list[Evidence] | Evidence | None = Field(
        None, description="Evidence supporting the achievement claim"
    )

    # Status (for revocation)
    credential_status: CredentialStatus | None = Field(
        None,
        alias="credentialStatus",
        description="Status information for revocation checking",
    )

    # Schema for validation
    credential_schema: CredentialSchema | list[CredentialSchema] | None = Field(
        None,
        alias="credentialSchema",
        description="Schema(s) for validating this credential",
    )

    # Refresh service
    refresh_service: RefreshService | list[RefreshService] | None = Field(
        None,
        alias="refreshService",
        description="Service(s) for refreshing this credential",
    )

    # Terms of use
    terms_of_use: TermsOfUse | list[TermsOfUse] | None = Field(
        None,
        alias="termsOfUse",
        description="Terms of use for this credential",
    )

    # Related resources
    related: list[Any] | None = Field(
        None, description="Related resources"
    )

    # Version
    version: str | None = Field(
        None, description="Version of this credential"
    )

    # Endorsements
    endorsement: list["EndorsementCredential"] | None = Field(
        None, description="Endorsements of this credential"
    )

    # Additional JWT claims (when credential is in JWT format)
    iss: str | None = Field(None, description="JWT issuer claim")
    sub: str | None = Field(None, description="JWT subject claim")
    aud: str | None = Field(None, description="JWT audience claim")
    exp: int | None = Field(None, description="JWT expiration time claim")
    nbf: int | None = Field(None, description="JWT not before time claim")
    iat: int | None = Field(None, description="JWT issued at time claim")
    jti: str | None = Field(None, description="JWT ID claim")

    def model_post_init(self, __context: Any) -> None:
        """Ensure required contexts are present."""
        # Normalize context to list
        if not isinstance(self.context, list):
            self.context = [self.context]

        # Ensure required contexts
        required_contexts = [
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        ]

        for req_ctx in required_contexts:
            if req_ctx not in self.context:
                self.context.insert(0, req_ctx)

        # Normalize type to list
        if not isinstance(self.type, list):
            self.type = [self.type]

        # Ensure required types
        required_types = ["VerifiableCredential", "OpenBadgeCredential"]
        for req_type in required_types:
            if req_type not in self.type:
                self.type.append(req_type)


# Alias for clarity
AchievementCredential = OpenBadgeCredential


class EndorsementCredential(BaseModel):
    """
    An endorsement credential that provides third-party validation.

    Endorsements can be made about Achievements, Profiles, or other credentials.
    """

    context: list[URI | dict[str, Any]] | URI | dict[str, Any] = Field(
        ...,
        alias="@context",
        description="JSON-LD context",
    )

    id: URI | None = Field(None, description="Unique URI identifier")
    type: list[str] | str = Field(
        ...,
        description="Must include 'VerifiableCredential' and 'EndorsementCredential'",
    )

    issuer: Any = Field(..., description="Issuer of the endorsement")

    issuance_date: datetime | None = Field(
        None, alias="issuanceDate", description="When issued"
    )

    valid_from: datetime | None = Field(
        None, alias="validFrom", description="Valid from date"
    )

    valid_until: datetime | None = Field(
        None, alias="validUntil", description="Valid until date"
    )

    credential_subject: Any = Field(
        ...,
        alias="credentialSubject",
        description="What is being endorsed (Achievement, Profile, or Credential)",
    )

    proof: Proof | list[Proof] | None = Field(
        None, description="Cryptographic proof"
    )

    credential_status: CredentialStatus | None = Field(
        None, alias="credentialStatus", description="Status for revocation"
    )


# Update forward refs
OpenBadgeCredential.model_rebuild()
