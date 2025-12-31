"""Achievement model for OpenBadges 3.0."""

from datetime import datetime
from typing import Any

from pydantic import Field, HttpUrl

from openbadges_core.models.base import (
    URI,
    AchievementType,
    AlignmentTargetType,
    BaseModel,
    LanguageString,
    ResultType,
)
from openbadges_core.models.profile import Image, Profile


class Criteria(BaseModel):
    """Criteria for earning an achievement."""

    id: URI | None = Field(None, description="URI of the criteria")
    narrative: str | LanguageString | None = Field(
        None, description="Narrative description of criteria"
    )


class Alignment(BaseModel):
    """Alignment to an external framework or competency."""

    type: list[str] | str = Field(default="Alignment", description="Must include 'Alignment'")
    target_name: str = Field(
        ..., alias="targetName", description="Name of the alignment target"
    )
    target_url: HttpUrl = Field(
        ..., alias="targetUrl", description="URL of the alignment target"
    )
    target_description: str | None = Field(
        None, alias="targetDescription", description="Description of the alignment target"
    )
    target_framework: str | None = Field(
        None, alias="targetFramework", description="Name of the framework"
    )
    target_code: str | None = Field(
        None, alias="targetCode", description="Code for the target within the framework"
    )
    target_type: AlignmentTargetType | None = Field(
        None, alias="targetType", description="Type of the alignment target"
    )


class ResultDescription(BaseModel):
    """Description of a possible result."""

    id: URI = Field(..., description="Unique URI for this result description")
    type: list[str] | str = Field(
        default="ResultDescription", description="Must include 'ResultDescription'"
    )
    name: str = Field(..., description="Name of the result")
    result_type: ResultType = Field(
        ..., alias="resultType", description="Type of result"
    )

    # Value constraints
    allowed_value: list[str] | None = Field(
        None, alias="allowedValue", description="List of allowed values"
    )
    required_level: HttpUrl | None = Field(
        None, alias="requiredLevel", description="URI of required rubric criterion level"
    )
    required_value: str | None = Field(
        None, alias="requiredValue", description="Value required to pass"
    )
    value_max: str | None = Field(
        None, alias="valueMax", description="Maximum possible value"
    )
    value_min: str | None = Field(
        None, alias="valueMin", description="Minimum possible value"
    )

    # Alignment
    alignment: list[Alignment] | None = Field(
        None, description="Alignment to external frameworks"
    )

    # Rubric information
    rubric_criterion_level: list["RubricCriterionLevel"] | None = Field(
        None, alias="rubricCriterionLevel", description="Ordered list of rubric criterion levels"
    )


class RubricCriterionLevel(BaseModel):
    """A rubric criterion level."""

    id: URI = Field(..., description="Unique URI for this level")
    type: list[str] | str = Field(
        default="RubricCriterionLevel", description="Must include 'RubricCriterionLevel'"
    )
    name: str = Field(..., description="Name of the level")
    description: str | None = Field(None, description="Description of the level")
    level: str | None = Field(None, description="Level identifier")
    points: str | None = Field(None, description="Points associated with this level")
    alignment: list[Alignment] | None = Field(
        None, description="Alignment to external frameworks"
    )


class Achievement(BaseModel):
    """
    An achievement that can be earned.

    Defines the criteria, metadata, and alignment for a recognized accomplishment.
    This is what is referenced by an OpenBadgeCredential.
    """

    id: URI = Field(..., description="Unique URI for this achievement")
    type: list[str] | str = Field(
        default="Achievement", description="Must include 'Achievement'"
    )

    # Core properties
    name: str = Field(..., description="Name of the achievement")
    description: str = Field(..., description="Description of the achievement")

    # Criteria
    criteria: Criteria = Field(..., description="Criteria for earning this achievement")

    # Type classification
    achievement_type: AchievementType | str | None = Field(
        None, alias="achievementType", description="Type of achievement"
    )

    # Issuer information
    creator: Profile | URI | None = Field(
        None, description="Entity that created this achievement definition"
    )

    # Visual representation
    image: Image | URI | None = Field(None, description="Image representing the achievement")

    # Alignment to standards/frameworks
    alignment: list[Alignment] | None = Field(
        None, description="List of alignments to external frameworks"
    )

    # Tags and categorization
    tags: list[str] | None = Field(None, description="Tags for categorization")
    field_of_study: str | None = Field(
        None, alias="fieldOfStudy", description="Field of study"
    )
    human_code: str | None = Field(
        None, alias="humanCode", description="Human-readable code for the achievement"
    )
    specialty: str | None = Field(None, description="Specialty or focus area")

    # Version and temporal information
    version: str | None = Field(None, description="Version of this achievement")
    related: list["Related"] | None = Field(
        None, description="Related achievements"
    )

    # Assessment and results
    result_description: list[ResultDescription] | None = Field(
        None,
        alias="resultDescription",
        description="Descriptions of possible results when earning this achievement",
    )

    # Additional metadata
    credits_available: float | None = Field(
        None, alias="creditsAvailable", description="Credits available for this achievement"
    )
    other_identifier: list[Any] | None = Field(
        None, alias="otherIdentifier", description="Other identifiers for this achievement"
    )


class Related(BaseModel):
    """A related achievement."""

    id: URI = Field(..., description="URI of the related achievement")
    type: list[str] | str = Field(default="Related", description="Must include 'Related'")
    version: str | None = Field(None, description="Version of the related achievement")
    in_language: str | None = Field(
        None, alias="inLanguage", description="Language code (e.g., 'en-US')"
    )


# Update forward refs for recursive models
ResultDescription.model_rebuild()
Achievement.model_rebuild()
