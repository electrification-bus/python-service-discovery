"""Access to the bundled v1 record JSON Schema and optional validation."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

SCHEMA_RESOURCE = "record.schema.json"


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    """Return the bundled draft 2020-12 record schema as a dict."""
    text = resources.files(__package__).joinpath(SCHEMA_RESOURCE).read_text("utf-8")
    return json.loads(text)


def validate_record(record: dict[str, Any]) -> None:
    """Validate a record dict against the v1 schema; raise on invalid.

    Requires the optional ``validation`` extra (``jsonschema``). Kept optional
    so a constrained build can ship the model without a validator.
    """
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "record validation requires the 'validation' extra (jsonschema)"
        ) from exc

    Draft202012Validator(load_schema()).validate(record)
