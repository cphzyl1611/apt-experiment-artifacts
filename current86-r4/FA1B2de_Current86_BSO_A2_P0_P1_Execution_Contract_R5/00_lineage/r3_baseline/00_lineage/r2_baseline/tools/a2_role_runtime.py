#!/usr/bin/env python3
"""Shared non-semantic A2 role runtime boundary.

The runtime accepts only a frozen proposal-input bundle and emits a validated,
structured commitment envelope. It never persists private chain-of-thought,
freezes an owner, or publishes a binding.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


FROZEN_PROMPT_TEMPLATE_VERSION = "A2_HUMAN_LIGHT_PROPOSER_VERIFIER_PROMPT_TEMPLATE_V1"
FROZEN_NORMATIVE_INSTRUCTIONS = [
    "machine output is NON_AUTHORITATIVE_MACHINE_PROPOSAL",
    "consider complete candidate universe without hidden pruning or top-k truncation",
    "evidence must be a subset of admissible normative source facts",
    "do not use historical comparative relation outputs as normative evidence",
    "do not record private chain-of-thought",
]


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def role_prompt_template(role: str) -> dict[str, object]:
    prompt = {
        "template_version": FROZEN_PROMPT_TEMPLATE_VERSION,
        "role": role,
        "normative_instructions": FROZEN_NORMATIVE_INSTRUCTIONS,
        "dynamic_runtime_data_excluded": ["raw_key", "source_facts", "candidate_universe"],
    }
    prompt["template_canonical_id"] = _hash(prompt)
    return prompt


def _validate_commitment(commitment: dict[str, object], bundle: dict[str, object], role: str) -> None:
    required = {"schema", "role", "raw_key", "proposal_input_bundle_id", "execution_manifest_id", "computational_contract_id", "complete_candidate_universe_hash", "complete_relation_set_hash", "result_status", "selected_candidate_scoring_id", "selected_relation_identity", "evidence_fact_ids", "evidence_set_hash", "hard_gate_results", "context_identity", "run_identity", "runtime_binding", "prompt_template_identity", "private_chain_of_thought_persisted", "owner_freeze_performed", "binding_publication_performed", "commitment_id"}
    if set(commitment) != required:
        raise ValueError("commitment output is not the exact structured schema")
    if commitment["role"] != role or commitment["raw_key"] != bundle["raw_key"] or commitment["proposal_input_bundle_id"] != bundle["proposal_input_bundle_id"]:
        raise ValueError("commitment does not bind the frozen role input")
    if commitment["private_chain_of_thought_persisted"] is not False or commitment["owner_freeze_performed"] is not False or commitment["binding_publication_performed"] is not False:
        raise ValueError("role runtime crossed a prohibited persistence/authority boundary")
    if commitment["commitment_id"] != _hash({key: value for key, value in commitment.items() if key != "commitment_id"}):
        raise ValueError("commitment identity mismatch")


def execute_role(role: str, proposal_input_path: Path, structured_commitment_path: Path, output_path: Path, *, expected_execution_manifest_id: str, computational_contract_id: str, provider: str, model_id: str, context_identity: str, run_identity: str) -> dict[str, object]:
    if role not in {"PRIMARY", "VERIFIER"}:
        raise ValueError("role must be PRIMARY or VERIFIER")
    bundle = json.loads(proposal_input_path.read_text(encoding="utf-8"))
    required = {"proposal_input_bundle_id", "raw_key", "execution_manifest_id", "complete_candidate_universe_hash", "complete_candidate_relation_set_hash", "input_status"}
    if not required <= bundle.keys() or bundle["input_status"] != "FROZEN_PREPARATION_ONLY":
        raise ValueError("proposal input bundle is not frozen and complete")
    if bundle["proposal_input_bundle_id"] != _hash({k: v for k, v in bundle.items() if k != "proposal_input_bundle_id"}):
        raise ValueError("proposal input bundle identity mismatch")
    if bundle["execution_manifest_id"] != expected_execution_manifest_id:
        raise ValueError("proposal input execution manifest identity mismatch")
    if len(computational_contract_id) != 64:
        raise ValueError("computational contract identity is required")
    if not context_identity or not run_identity:
        raise ValueError("context and run identities are required")
    if not provider or not model_id:
        raise ValueError("provider and model_id are required at invocation")
    candidate = json.loads(structured_commitment_path.read_text(encoding="utf-8"))
    allowed_candidate_fields = {"result_status", "selected_candidate_scoring_id", "selected_relation_identity", "evidence_fact_ids", "evidence_set_hash", "hard_gate_results"}
    if set(candidate) != allowed_candidate_fields:
        raise ValueError("model output must contain only structured commitment fields")
    runtime_binding = {
        "provider": provider,
        "model_id": model_id,
        "model_variant_or_snapshot": None,
        "agent_or_cli_version": None,
        "tool_mode": f"A2_{role}_ROLE_RUNTIME",
        "decoding_or_runtime_configuration": None,
        "context_identity": context_identity,
        "run_identity": run_identity,
    }
    runtime_binding["runtime_binding_id"] = _hash(runtime_binding)
    commitment = {
        "schema": "A2_STRUCTURED_COMMITMENT_V2",
        "role": role,
        "raw_key": bundle["raw_key"],
        "proposal_input_bundle_id": bundle["proposal_input_bundle_id"],
        "execution_manifest_id": expected_execution_manifest_id,
        "computational_contract_id": computational_contract_id,
        "complete_candidate_universe_hash": bundle["complete_candidate_universe_hash"],
        "complete_relation_set_hash": bundle["complete_candidate_relation_set_hash"],
        **candidate,
        "context_identity": context_identity,
        "run_identity": run_identity,
        "runtime_binding": runtime_binding,
        "prompt_template_identity": role_prompt_template(role),
        "private_chain_of_thought_persisted": False,
        "owner_freeze_performed": False,
        "binding_publication_performed": False,
    }
    commitment["commitment_id"] = _hash(commitment)
    _validate_commitment(commitment, bundle, role)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(commitment, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return commitment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=["PRIMARY", "VERIFIER"], required=True)
    parser.add_argument("--proposal-input", type=Path, required=True)
    parser.add_argument("--structured-commitment", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-execution-manifest-id", required=True)
    parser.add_argument("--computational-contract-id", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--context-identity", required=True)
    parser.add_argument("--run-identity", required=True)
    args = parser.parse_args(argv)
    try:
        execute_role(args.role, args.proposal_input, args.structured_commitment, args.output, expected_execution_manifest_id=args.expected_execution_manifest_id, computational_contract_id=args.computational_contract_id, provider=args.provider, model_id=args.model_id, context_identity=args.context_identity, run_identity=args.run_identity)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL_CLOSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
