"""Base models and types for OpenBadges 3.0."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict, Field, HttpUrl


class BaseModel(PydanticBaseModel):
    """Base model with common configuration for all OpenBadges models."""

    model_config = ConfigDict(
        extra="allow",  # Allow additional properties per JSON-LD spec
        populate_by_name=True,
        use_enum_values=False,
        validate_assignment=True,
    )


class CredentialStatus(str, Enum):
    """Status of a verifiable credential."""

    ACTIVE = "Active"
    REVOKED = "Revoked"
    SUSPENDED = "Suspended"


class AlignmentTargetType(str, Enum):
    """Type of alignment target."""

    CFItem = "CFItem"  # CASE Framework Item
    CFRubric = "CFRubric"
    CFRubricCriterion = "CFRubricCriterion"
    CFRubricCriterionLevel = "CFRubricCriterionLevel"
    CTDL = "CTDL"  # Credential Transparency Description Language
    Competency = "Competency"


class AchievementType(str, Enum):
    """Type of achievement."""

    Achievement = "Achievement"
    ApprenticeshipCertificate = "ApprenticeshipCertificate"
    Assessment = "Assessment"
    Assignment = "Assignment"
    AssociateDegree = "AssociateDegree"
    Award = "Award"
    Badge = "Badge"
    BachelorDegree = "BachelorDegree"
    Certificate = "Certificate"
    CertificateOfCompletion = "CertificateOfCompletion"
    Certification = "Certification"
    CommunityService = "CommunityService"
    Competency = "Competency"
    Course = "Course"
    CoCurricular = "CoCurricular"
    Degree = "Degree"
    Diploma = "Diploma"
    DoctoralDegree = "DoctoralDegree"
    Fieldwork = "Fieldwork"
    GeneralEducationDevelopment = "GeneralEducationDevelopment"
    JourneymanCertificate = "JourneymanCertificate"
    LearningProgram = "LearningProgram"
    License = "License"
    Membership = "Membership"
    MasterCertificate = "MasterCertificate"
    MasterDegree = "MasterDegree"
    MicroCredential = "MicroCredential"
    ProfessionalDoctorate = "ProfessionalDoctorate"
    QualityAssuranceCredential = "QualityAssuranceCredential"
    ResearchDoctorate = "ResearchDoctorate"


class ResultType(str, Enum):
    """Type of result."""

    GradePointAverage = "GradePointAverage"
    LetterGrade = "LetterGrade"
    Percent = "Percent"
    PerformanceLevel = "PerformanceLevel"
    PredictedScore = "PredictedScore"
    RawScore = "RawScore"
    Result = "Result"
    RubricCriterion = "RubricCriterion"
    RubricCriterionLevel = "RubricCriterionLevel"
    RubricScore = "RubricScore"
    ScaledScore = "ScaledScore"
    Status = "Status"


class IdentifierType(str, Enum):
    """Type of identifier."""

    name = "name"
    sourcedId = "sourcedId"
    systemId = "systemId"
    productId = "productId"
    userName = "userName"
    accountId = "accountId"
    emailAddress = "emailAddress"
    nationalIdentityNumber = "nationalIdentityNumber"
    isbn = "isbn"
    issn = "issn"
    lisSourcedId = "lisSourcedId"
    oneRosterSourcedId = "oneRosterSourcedId"
    sisSourcedId = "sisSourcedId"
    ltiContextId = "ltiContextId"
    ltiDeploymentId = "ltiDeploymentId"
    ltiToolId = "ltiToolId"
    ltiPlatformId = "ltiPlatformId"
    ltiUserId = "ltiUserId"
    identifier = "identifier"


class ProofPurpose(str, Enum):
    """Purpose of a cryptographic proof."""

    assertionMethod = "assertionMethod"
    authentication = "authentication"
    capabilityInvocation = "capabilityInvocation"
    capabilityDelegation = "capabilityDelegation"
    keyAgreement = "keyAgreement"


# Type aliases for common patterns
URI = str
DateTime = datetime
LanguageString = dict[str, str]  # Language map (e.g., {"en": "English", "es": "Español"})
