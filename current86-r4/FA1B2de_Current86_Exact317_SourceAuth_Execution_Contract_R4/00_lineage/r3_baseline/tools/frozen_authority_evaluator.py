from __future__ import annotations

import json
from typing import Any

from .canonical import canonical_json_bytes, sha256_hex


def evaluate_authority_bytes(raw: bytes) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:
        parsed = []
    if not isinstance(parsed, list):
        return []
    tuples = [item for item in parsed if isinstance(item, dict)]
    return sorted(tuples, key=lambda item: sha256_hex(canonical_json_bytes(item)).encode("utf-8"))
