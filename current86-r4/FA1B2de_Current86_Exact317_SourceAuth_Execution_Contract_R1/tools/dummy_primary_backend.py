#!/usr/bin/env python3
"""Synthetic primary probe: no source-auth semantics and no production inputs."""
import hashlib
import json
import sys
from pathlib import Path

common, private, commitment = map(Path, sys.argv[1:4])
sentinel = (common / "synthetic-common.txt").read_bytes()
private_payload = b"SYNTHETIC_PRIMARY_PRIVATE_OUTPUT_ONLY\n"
(private / "primary-private.txt").write_bytes(private_payload)
record = {
    "mode": "SYNTHETIC_NON_SEMANTIC_ONLY",
    "role": "PRIMARY",
    "common_sha256": hashlib.sha256(sentinel).hexdigest(),
    "private_sha256": hashlib.sha256(private_payload).hexdigest(),
}
(commitment / "commitment.json").write_text(
    json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
)
