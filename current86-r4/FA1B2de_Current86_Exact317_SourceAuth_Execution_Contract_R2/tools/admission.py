from __future__ import annotations

from typing import Any, Mapping

from .canonical import ContractError
from .records import validate_record


def validate_field_pin_zero_proof_freshness(proof: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
    validate_record("no_machine_field_pin_authority_proof_v2", proof)
    fields = (
        "machine_field_pin_authority_input_set_id",
        "field_pin_authority_evaluation_contract_id",
        "machine_authority_evaluation_evidence_id",
        "admission_record_id",
        "admission_tuple_id",
        "admitted_exact_RFC6901_pointer_utf8_sha256",
    )
    if any(proof.get(field) != context.get(field) for field in fields):
        raise ContractError("STALE_FIELD_PIN_ZERO_PROOF")
    return True


def validate_source_admission_zero_proof_freshness(proof: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
    validate_record("source_admission_machine_zero_proof", proof)
    fields = (
        "machine_authority_input_set_id",
        "source_admission_evaluation_contract_id",
        "machine_authority_evaluation_evidence_id",
    )
    if any(proof.get(field) != context.get(field) for field in fields):
        raise ContractError("STALE_SOURCE_ADMISSION_ZERO_PROOF")
    if proof["machine_valid_admission_tuple_count"] != 0 or proof["machine_conflict_count"] != 0:
        raise ContractError("SOURCE_ADMISSION_ZERO_PROOF_NONZERO")
    return True


def validate_human_admission_eligibility(proof: Mapping[str, Any], context: Mapping[str, Any], machine_conflict_count: int) -> bool:
    if machine_conflict_count != 0:
        raise ContractError("HUMAN_ADMISSION_FORBIDDEN_ON_MACHINE_CONFLICT")
    validate_source_admission_zero_proof_freshness(proof, context)
    return True
