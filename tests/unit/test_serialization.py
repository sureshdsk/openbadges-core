"""Unit tests for JSON-LD serialization and deserialization."""

import json

import pytest

from openbadges_core.exceptions import SerializationError
from openbadges_core.models.credential import OpenBadgeCredential
from openbadges_core.serialization import from_json_ld, to_dict, to_json_ld


class TestJSONLDSerialization:
    """Tests for serializing models to JSON-LD."""

    def test_to_json_ld_basic_credential(self, basic_credential):
        """Test serializing basic credential to JSON-LD string."""
        json_ld = to_json_ld(basic_credential)

        assert isinstance(json_ld, str)
        assert len(json_ld) > 0

        # Should be valid JSON
        data = json.loads(json_ld)
        assert isinstance(data, dict)

    def test_json_ld_contains_context(self, basic_credential):
        """Test that serialized JSON-LD contains @context."""
        json_ld = to_json_ld(basic_credential)
        data = json.loads(json_ld)

        assert "@context" in data
        assert isinstance(data["@context"], list)

    def test_json_ld_contains_type(self, basic_credential):
        """Test that serialized JSON-LD contains type."""
        json_ld = to_json_ld(basic_credential)
        data = json.loads(json_ld)

        assert "type" in data
        assert "VerifiableCredential" in data["type"]
        assert "OpenBadgeCredential" in data["type"]

    def test_json_ld_uses_aliases(self, basic_credential):
        """Test that JSON-LD uses camelCase aliases."""
        json_ld = to_json_ld(basic_credential)
        data = json.loads(json_ld)

        # Should use camelCase (aliases)
        assert "credentialSubject" in data
        assert "issuanceDate" in data

        # Should NOT use snake_case
        assert "credential_subject" not in data
        assert "issuance_date" not in data

    def test_json_ld_excludes_none_values(self):
        """Test that None values are excluded from JSON-LD."""
        from openbadges_core import Achievement, AchievementSubject, Profile
        from openbadges_core.models.achievement import Criteria
        from datetime import datetime, timezone

        issuer = Profile(id="https://example.edu/1", name="Test")
        achievement = Achievement(
            id="https://example.edu/a1",
            name="Test",
            description="Test",
            criteria=Criteria(narrative="Test"),
            tags=None,  # Explicitly None
        )
        subject = AchievementSubject(id="did:test", achievement=achievement)

        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2"],
            type="OpenBadgeCredential",
            issuer=issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=subject,
            description=None,  # Explicitly None
        )

        json_ld = to_json_ld(credential)
        data = json.loads(json_ld)

        # None values should be excluded
        assert "description" not in data

    def test_to_json_ld_with_compact_output(self, basic_credential):
        """Test compact JSON-LD output (no indentation)."""
        json_ld = to_json_ld(basic_credential, indent=None)

        # Should not contain newlines (compact)
        assert "\n" not in json_ld

    def test_to_json_ld_with_pretty_print(self, basic_credential):
        """Test pretty-printed JSON-LD output."""
        json_ld = to_json_ld(basic_credential, indent=2)

        # Should contain newlines (pretty)
        assert "\n" in json_ld

    def test_serialize_detailed_credential(self, detailed_credential):
        """Test serializing credential with all features."""
        json_ld = to_json_ld(detailed_credential)
        data = json.loads(json_ld)

        # Check complex nested structures
        assert "credentialSubject" in data
        subject = data["credentialSubject"]
        assert "achievement" in subject
        assert "result" in subject
        assert len(subject["result"]) == 2

        # Check evidence
        assert "evidence" in data
        assert len(data["evidence"]) == 1

    def test_serialize_signed_credential(self, ed25519_signer, basic_credential):
        """Test serializing signed credential with proof."""
        signed = ed25519_signer.sign(basic_credential)
        json_ld = to_json_ld(signed)
        data = json.loads(json_ld)

        # Should contain proof
        assert "proof" in data
        assert data["proof"]["type"] == "Ed25519Signature2020"
        assert "proofValue" in data["proof"]
        assert "verificationMethod" in data["proof"]


class TestJSONLDDeserialization:
    """Tests for deserializing JSON-LD to models."""

    def test_from_json_ld_string(self, basic_credential):
        """Test deserializing from JSON-LD string."""
        # Serialize
        json_ld = to_json_ld(basic_credential)

        # Deserialize
        restored = from_json_ld(json_ld, OpenBadgeCredential)

        assert isinstance(restored, OpenBadgeCredential)
        assert restored.type == basic_credential.type

    def test_from_json_ld_dict(self, basic_credential):
        """Test deserializing from dictionary."""
        # Get as dict
        data = json.loads(to_json_ld(basic_credential))

        # Deserialize
        restored = from_json_ld(data, OpenBadgeCredential)

        assert isinstance(restored, OpenBadgeCredential)

    def test_round_trip_basic_credential(self, basic_credential):
        """Test serialize-deserialize round trip."""
        # Serialize
        json_ld = to_json_ld(basic_credential)

        # Deserialize
        restored = from_json_ld(json_ld, OpenBadgeCredential)

        # Compare key fields
        assert restored.type == basic_credential.type
        assert "VerifiableCredential" in restored.type
        assert "OpenBadgeCredential" in restored.type

    def test_round_trip_detailed_credential(self, detailed_credential):
        """Test round trip with complex credential."""
        json_ld = to_json_ld(detailed_credential)
        restored = from_json_ld(json_ld, OpenBadgeCredential)

        # Check nested structures preserved
        assert restored.id == detailed_credential.id
        assert len(restored.evidence) == len(detailed_credential.evidence)

        # Check subject results
        subject = restored.credential_subject
        assert len(subject.result) == 2

    def test_round_trip_signed_credential(self, ed25519_signer, basic_credential):
        """Test round trip with signed credential."""
        signed = ed25519_signer.sign(basic_credential)
        json_ld = to_json_ld(signed)
        restored = from_json_ld(json_ld, OpenBadgeCredential)

        # Proof should be preserved
        assert restored.proof is not None
        assert restored.proof.type == "Ed25519Signature2020"
        assert restored.proof.proof_value == signed.proof.proof_value

    def test_deserialize_invalid_json(self):
        """Test that invalid JSON raises error."""
        invalid_json = "{invalid json}"

        with pytest.raises(SerializationError):
            from_json_ld(invalid_json, OpenBadgeCredential)

    def test_deserialize_missing_required_field(self):
        """Test deserialization fails with missing required fields."""
        incomplete_data = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": "OpenBadgeCredential",
            # Missing issuer, credential_subject
        }

        with pytest.raises(SerializationError):
            from_json_ld(incomplete_data, OpenBadgeCredential)


class TestToDictHelper:
    """Tests for to_dict helper function."""

    def test_to_dict_basic(self, basic_credential):
        """Test converting model to dictionary."""
        result = to_dict(basic_credential)

        assert isinstance(result, dict)
        assert "@context" in result
        assert "type" in result

    def test_to_dict_uses_aliases(self, basic_credential):
        """Test that to_dict uses field aliases."""
        result = to_dict(basic_credential)

        assert "credentialSubject" in result
        assert "issuanceDate" in result

    def test_to_dict_excludes_none(self):
        """Test that to_dict excludes None values by default."""
        from openbadges_core import Achievement, AchievementSubject, Profile
        from openbadges_core.models.achievement import Criteria
        from datetime import datetime, timezone

        issuer = Profile(id="https://example.edu/1", name="Test")
        achievement = Achievement(
            id="https://example.edu/a1",
            name="Test",
            description="Test",
            criteria=Criteria(narrative="Test"),
        )
        subject = AchievementSubject(id="did:test", achievement=achievement)

        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2"],
            type="OpenBadgeCredential",
            issuer=issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=subject,
            description=None,
        )

        result = to_dict(credential)
        assert "description" not in result

    def test_to_dict_include_none(self):
        """Test that to_dict can include None values."""
        from openbadges_core import Achievement, AchievementSubject, Profile
        from openbadges_core.models.achievement import Criteria
        from datetime import datetime, timezone

        issuer = Profile(id="https://example.edu/1", name="Test")
        achievement = Achievement(
            id="https://example.edu/a1",
            name="Test",
            description="Test",
            criteria=Criteria(narrative="Test"),
        )
        subject = AchievementSubject(id="did:test", achievement=achievement)

        credential = OpenBadgeCredential(
            context=["https://www.w3.org/ns/credentials/v2"],
            type="OpenBadgeCredential",
            issuer=issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=subject,
            description=None,
        )

        result = to_dict(credential, exclude_none=False)
        assert "description" in result
