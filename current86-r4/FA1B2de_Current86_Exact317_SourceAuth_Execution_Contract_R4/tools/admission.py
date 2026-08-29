from __future__ import annotations

from typing import Any, Mapping

from .canonical import ContractError
from .records import validate_record
from .authority import MachineAuthorityContext, derive_machine_authority_context


def _current_derivation(context: Mapping[str, Any]) -> Mapping[str, Any]:
    """Re-run the exact authenticated EC-B2 graph carried by the context."""
    try:
        graph = MachineAuthorityContext.extract_graph_inputs(context)
        current = derive_machine_authority_context(
            graph["manifest"],
            graph["authority_records"],
            graph["expansion_records"],
            graph["required_roles"],
            graph["evaluation_contract_id"],
            graph["evaluation_evidence"],
            graph.get("admission_record"),
        )
    except (AttributeError, ContractError, KeyError, TypeError) as exc:
        raise ContractError("CURRENT_DERIVATION_REQUIRED") from exc
    return current


def validate_field_pin_zero_proof_freshness(proof: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
    validate_record("no_machine_field_pin_authority_proof_v2", proof)
    context = _current_derivation(context)
    fields = (
        "machine_field_pin_authority_input_set_id",
        "field_pin_authority_evaluation_contract_id",
        "machine_authority_evaluation_evidence_id",
        "admission_record_id",
        "admission_tuple_id",
        "admitted_exact_RFC6901_pointer_utf8_sha256",
    )
    evidence = context["machine_authority_evaluation_evidence"]
    expected = {
        "machine_field_pin_authority_input_set_id": context["machine_authority_input_set_id"],
        "field_pin_authority_evaluation_contract_id": context["evaluation_contract_id"],
        "machine_authority_evaluation_evidence_id": evidence["machine_authority_evaluation_evidence_id"],
        "admission_record_id": context.get("admission_record_id"),
        "admission_tuple_id": context.get("admission_tuple_id"),
        "admitted_exact_RFC6901_pointer_utf8_sha256": context.get("admitted_exact_RFC6901_pointer_utf8_sha256"),
    }
    if any(expected[field] is None for field in fields[3:]):
        raise ContractError("CURRENT_ADMISSION_DERIVATION_REQUIRED")
    if any(proof.get(field) != expected[field] for field in fields):
        raise ContractError("STALE_FIELD_PIN_ZERO_PROOF")
    return True


def validate_source_admission_zero_proof_freshness(proof: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
    validate_record("source_admission_machine_zero_proof", proof)
    context = _current_derivation(context)
    evidence = context["machine_authority_evaluation_evidence"]
    expected = {
        "machine_authority_input_set_id": context["machine_authority_input_set_id"],
        "source_admission_evaluation_contract_id": context["evaluation_contract_id"],
        "machine_authority_evaluation_evidence_id": evidence["machine_authority_evaluation_evidence_id"],
    }
    if any(proof.get(field) != expected[field] for field in expected):
        raise ContractError("STALE_SOURCE_ADMISSION_ZERO_PROOF")
    if proof["machine_valid_admission_tuple_count"] != 0 or proof["machine_conflict_count"] != 0:
        raise ContractError("SOURCE_ADMISSION_ZERO_PROOF_NONZERO")
    return True


def validate_human_admission_eligibility(proof: Mapping[str, Any], context: Mapping[str, Any], machine_conflict_count: int) -> bool:
    if machine_conflict_count != 0:
        raise ContractError("HUMAN_ADMISSION_FORBIDDEN_ON_MACHINE_CONFLICT")
    validate_source_admission_zero_proof_freshness(proof, context)
    return True
