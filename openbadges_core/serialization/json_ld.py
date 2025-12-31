"""JSON-LD serialization and processing utilities."""

import json
from typing import Any, TypeVar

from pydantic import BaseModel

from openbadges_core.exceptions import SerializationError

T = TypeVar("T", bound=BaseModel)


def to_json_ld(model: BaseModel, indent: int | None = 2) -> str:
    """
    Serialize a Pydantic model to JSON-LD string.

    Args:
        model: The Pydantic model instance to serialize
        indent: Indentation level for pretty printing (None for compact)

    Returns:
        JSON-LD string representation

    Raises:
        SerializationError: If serialization fails
    """
    try:
        # Use by_alias=True to ensure @context is serialized correctly
        data = model.model_dump(mode="json", by_alias=True, exclude_none=True)
        return json.dumps(data, indent=indent, ensure_ascii=False)
    except Exception as e:
        raise SerializationError(f"Failed to serialize to JSON-LD: {e}") from e


def from_json_ld(data: str | dict[str, Any], model_class: type[T]) -> T:
    """
    Deserialize JSON-LD string or dict to a Pydantic model.

    Args:
        data: JSON-LD string or dictionary
        model_class: The Pydantic model class to deserialize into

    Returns:
        Instance of the model class

    Raises:
        SerializationError: If deserialization fails
    """
    try:
        if isinstance(data, str):
            json_data = json.loads(data)
        else:
            json_data = data

        return model_class.model_validate(json_data)
    except Exception as e:
        raise SerializationError(f"Failed to deserialize from JSON-LD: {e}") from e


def compact(data: dict[str, Any], context: dict[str, Any] | str) -> dict[str, Any]:
    """
    Compact JSON-LD data using the provided context.

    Args:
        data: The JSON-LD data to compact
        context: The JSON-LD context to use for compaction

    Returns:
        Compacted JSON-LD data

    Raises:
        SerializationError: If compaction fails

    Note:
        This is a basic implementation. For full JSON-LD processing,
        consider using the pyld library directly.
    """
    try:
        # For now, this is a pass-through
        # Full implementation would use pyld.jsonld.compact()
        import pyld.jsonld as jsonld

        return jsonld.compact(data, context)
    except ImportError:
        # Fallback if pyld not available
        result = data.copy()
        result["@context"] = context
        return result
    except Exception as e:
        raise SerializationError(f"Failed to compact JSON-LD: {e}") from e


def expand(data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Expand JSON-LD data to remove context and use full URIs.

    Args:
        data: The JSON-LD data to expand

    Returns:
        Expanded JSON-LD data (always a list per JSON-LD spec)

    Raises:
        SerializationError: If expansion fails

    Note:
        This is a basic implementation. For full JSON-LD processing,
        consider using the pyld library directly.
    """
    try:
        import pyld.jsonld as jsonld

        return jsonld.expand(data)
    except ImportError:
        # Fallback if pyld not available
        return [data]
    except Exception as e:
        raise SerializationError(f"Failed to expand JSON-LD: {e}") from e


def to_dict(model: BaseModel, exclude_none: bool = True) -> dict[str, Any]:
    """
    Convert a Pydantic model to a dictionary suitable for JSON-LD.

    Args:
        model: The Pydantic model instance
        exclude_none: Whether to exclude None values

    Returns:
        Dictionary representation
    """
    return model.model_dump(mode="json", by_alias=True, exclude_none=exclude_none)
