"""AchievementSubject model for OpenBadges 3.0."""

from datetime import datetime
from typing import Any

from pydantic import Field, HttpUrl

from openbadges_core.models.base import URI, BaseModel, ResultType
from openbadges_core.models.profile import IdentityObject, Image


class Result(BaseModel):
    """A result achieved by the subject."""

    type: list[str] | str = Field(default="Result", description="Must include 'Result'")
    result_description: URI | None = Field(
        None,
        alias="resultDescription",
        description="URI of the ResultDescription this result is based on",
    )
    result_type: ResultType | None = Field(
        None, alias="resultType", description="Type of result"
    )
    value: str | None = Field(None, description="Value of the result")
    achieved_level: HttpUrl | None = Field(
        None, alias="achievedLevel", description="URI of the rubric criterion level achieved"
    )
    alignment: list[Any] | None = Field(
        None, description="Alignment objects for this result"
    )


class AchievementSubject(BaseModel):
    """
    The subject (learner/recipient) of an achievement credential.

    Represents the person or entity who earned the achievement,
    along with their results and verification identifiers.
    """

    # Identity - can be URI or more complex identifier
    id: URI | None = Field(
        None, description="URI identifier for the subject (may be hashed for privacy)"
    )
    type: list[str] | str = Field(
        default="AchievementSubject", description="Must include 'AchievementSubject'"
    )

    # Achievement reference
    achievement: Any = Field(
        ...,
        description="The Achievement earned (can be embedded Achievement or URI reference)",
    )

    # Subject identification
    identifier: list[IdentityObject] | None = Field(
        None, description="Additional identifiers for the subject"
    )

    # Results
    result: list[Result] | None = Field(
        None, description="Results achieved by the subject"
    )

    # Source/license info
    source: Any | None = Field(
        None, description="Source of the achievement (Profile or URI)"
    )
    license_number: str | None = Field(
        None, alias="licenseNumber", description="License number if applicable"
    )

    # Term information
    term: str | None = Field(
        None, description="Term or semester when achievement was earned"
    )

    # Visual representation
    image: Image | URI | None = Field(
        None, description="Image of the subject (badge baked image, portrait, etc.)"
    )

    # Narrative
    narrative: str | None = Field(
        None, description="Narrative describing the subject's achievement"
    )

    # Activity/evidence related
    activity_end_date: datetime | None = Field(
        None, alias="activityEndDate", description="When the activity ended"
    )
    activity_start_date: datetime | None = Field(
        None, alias="activityStartDate", description="When the activity started"
    )

    # Credit information
    credits_earned: float | None = Field(
        None, alias="creditsEarned", description="Number of credits earned"
    )

    # Role information
    role: str | None = Field(
        None, description="Role of the subject in earning the achievement"
    )
