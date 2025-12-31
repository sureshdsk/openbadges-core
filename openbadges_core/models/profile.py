"""Profile model for OpenBadges 3.0 issuers and holders."""

from typing import Any

from pydantic import Field, HttpUrl

from openbadges_core.models.base import URI, BaseModel


class Image(BaseModel):
    """An image representing an achievement, profile, or result."""

    id: URI = Field(..., description="The URI of the image")
    type: str = Field(default="Image", description="The type must be 'Image'")
    caption: str | None = Field(None, description="Caption for the image")


class IdentityObject(BaseModel):
    """An identifier for a person or organization."""

    type: str = Field(..., description="Type of identifier (e.g., 'email', 'url', 'telephone')")
    hashed: bool = Field(
        default=False, description="Whether the identifier value is hashed"
    )
    identity_hash: str | None = Field(
        None, alias="identityHash", description="Hash of the identity if hashed is true"
    )
    identity_type: str = Field(
        ..., alias="identityType", description="Type of identity (email, url, telephone, etc.)"
    )
    salt: str | None = Field(
        None, description="Salt value used for hashing if hashed is true"
    )


class Address(BaseModel):
    """A physical address."""

    type: list[str] | str = Field(default="Address", description="Must include 'Address'")
    address_country: str | None = Field(
        None, alias="addressCountry", description="Country code"
    )
    address_country_code: str | None = Field(
        None, alias="addressCountryCode", description="ISO 3166-1 alpha-2 country code"
    )
    address_locality: str | None = Field(
        None, alias="addressLocality", description="City or locality"
    )
    address_region: str | None = Field(
        None, alias="addressRegion", description="State, province, or region"
    )
    postal_code: str | None = Field(None, alias="postalCode", description="Postal code")
    post_office_box_number: str | None = Field(
        None, alias="postOfficeBoxNumber", description="Post office box number"
    )
    street_address: str | None = Field(
        None, alias="streetAddress", description="Street address"
    )


class Profile(BaseModel):
    """
    Profile representing an organization or person (issuer, endorser, or learner).

    A Profile is used to describe the issuer of credentials, endorsers,
    or the learner who is the subject of the credential.
    """

    id: URI = Field(..., description="Unique URI identifier for this profile")
    type: list[str] | str = Field(
        default="Profile", description="Must include 'Profile'"
    )

    # Core identification
    name: str | None = Field(None, description="Name of the entity")
    url: HttpUrl | None = Field(None, description="Homepage or primary URL")
    phone: str | None = Field(None, description="Phone number")
    description: str | None = Field(None, description="Description of the entity")

    # Email can be string or IdentityObject
    email: str | IdentityObject | None = Field(
        None, description="Email address or email identity object"
    )

    # Visual identity
    image: Image | URI | None = Field(
        None, description="Image representing this entity"
    )

    # Address information
    address: Address | None = Field(None, description="Physical address")

    # Additional identifiers
    official_name: str | None = Field(
        None, alias="officialName", description="Official legal name if different from name"
    )
    parent_org: "Profile | URI | None" = Field(
        None, alias="parentOrg", description="Parent organization if this is a department/division"
    )
    family_name: str | None = Field(
        None, alias="familyName", description="Family name (for person profiles)"
    )
    given_name: str | None = Field(
        None, alias="givenName", description="Given name (for person profiles)"
    )
    additional_name: str | None = Field(
        None, alias="additionalName", description="Additional name (for person profiles)"
    )
    patronymic_name: str | None = Field(
        None, alias="patronymicName", description="Patronymic name"
    )
    honorific_prefix: str | None = Field(
        None, alias="honorificPrefix", description="Honorific prefix (Dr., Mr., etc.)"
    )
    honorific_suffix: str | None = Field(
        None, alias="honorificSuffix", description="Honorific suffix (PhD, Esq., etc.)"
    )

    # Dates
    date_of_birth: str | None = Field(
        None, alias="dateOfBirth", description="Date of birth (ISO 8601)"
    )

    # Additional properties
    other_identifier: list[IdentityObject] | None = Field(
        None, alias="otherIdentifier", description="Additional identifiers"
    )


# Update forward refs for recursive model
Profile.model_rebuild()
