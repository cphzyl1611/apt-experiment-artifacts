#!/usr/bin/env python3
import hashlib
import json
import sys
from pathlib import Path


def ident(obj):
    return hashlib.sha256(json.dumps({k: v for k, v in obj.items() if k != "commitment_id"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


role, common, private, commitment, forbidden_private, forbidden_commitment = sys.argv[1:]
common = Path(common)
private = Path(private)
commitment = Path(commitment)
forbidden_private = Path(forbidden_private)
forbidden_commitment = Path(forbidden_commitment)
def seen(path):
    try:
        path.read_bytes()
        return True
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return path.exists()

observed_private = seen(forbidden_private / "secret.txt") if role == "VERIFIER" else False
observed_commitment = seen(forbidden_commitment / "commitment.json") if role == "VERIFIER" else False
row = {
    "schema": "FA1B2DE_CURRENT86_SOURCE_AUTH_PRIMARY_COMMITMENT_R2" if role == "PRIMARY" else "FA1B2DE_CURRENT86_SOURCE_AUTH_VERIFIER_COMMITMENT_R2",
    "role": role,
    "common_input_set_id": "synthetic-common-input-r2",
    "implementation_id": "synthetic-impl-" + role.lower(),
    "context_id": "synthetic-context-" + role.lower(),
    "run_id": "synthetic-run-" + role.lower(),
    "isolation_audit_id": "synthetic-isolation-audit-r2",
    "ordered_result_vector_sha256": "1" * 64,
    "terminal_state_count_map": {"BLOCKED_FIELD_PIN": 1},
    "exact_target_id_set_sha256": "2" * 64,
    "private_output_manifest_sha256": "3" * 64,
}
if role == "VERIFIER":
    row["verifier_observed_primary_private"] = observed_private
    row["verifier_observed_primary_commitment"] = observed_commitment
    # The extra observability fields are intentionally private and are not part of the commitment schema.
    audit = {"observed_primary_private": observed_private, "observed_primary_commitment": observed_commitment}
    (private / "verifier-audit.json").write_text(json.dumps(audit, sort_keys=True), encoding="utf-8")
    row.pop("verifier_observed_primary_private", None)
    row.pop("verifier_observed_primary_commitment", None)
row["commitment_id"] = ident(row)
(private / "secret.txt").write_text("synthetic-private\n", encoding="utf-8")
(commitment / "commitment.json").write_text(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
