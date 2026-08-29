#!/usr/bin/env python3
"""Synthetic verifier probe: demonstrates primary roots are absent."""
import hashlib
import json
import sys
from pathlib import Path

common, private, commitment, forbidden_private, forbidden_commitment = map(Path, sys.argv[1:6])
sentinel = (common / "synthetic-common.txt").read_bytes()

def observable(path):
    try:
        path.read_bytes()
        return True
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return path.exists()

record = {
    "mode": "SYNTHETIC_NON_SEMANTIC_ONLY",
    "role": "VERIFIER",
    "common_sha256": hashlib.sha256(sentinel).hexdigest(),
    "observed_primary_private": observable(forbidden_private / "primary-private.txt"),
    "observed_primary_commitment": observable(forbidden_commitment / "commitment.json"),
}
(private / "verifier-private.json").write_text(
    json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
)
(commitment / "commitment.json").write_text(
    json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
)
