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
import os
from pathlib import Path
import subprocess
import sys
import tempfile


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


def _field(value: object, *, required: bool = True) -> dict[str, object]:
    if value is None:
        if required:
            raise ValueError("required runtime identity was not exposed")
        return {"field_status": "UNAVAILABLE_BY_RUNTIME", "value": None}
    if not isinstance(value, str) or not value:
        raise ValueError("runtime identity fields must be non-empty strings")
    return {"field_status": "OBSERVED", "value": value}


def _load_backend_config(path: Path, role: str) -> dict[str, object]:
    config = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or config.get("role") != role:
        raise ValueError("backend configuration role mismatch")
    config_id = config.get("backend_configuration_id")
    if not isinstance(config_id, str) or config_id != _hash({k: v for k, v in config.items() if k != "backend_configuration_id"}):
        raise ValueError("backend configuration identity mismatch")
    command = config.get("command")
    if not isinstance(command, list) or not command or any(not isinstance(item, str) or not item for item in command):
        raise ValueError("backend command is not frozen and complete")
    for key in ("provider", "model_id", "context_identity", "run_identity", "tool_mode", "capture_method"):
        if not isinstance(config.get(key), str) or not config[key]:
            raise ValueError(f"backend configuration missing {key}")
    if config["tool_mode"] != f"A2_{role}_ROLE_RUNTIME":
        raise ValueError("backend tool mode is not role-bound")
    return config


def execute_role_with_backend(
    role: str,
    proposal_input_path: Path,
    backend_config_path: Path,
    output_path: Path,
    *,
    expected_execution_manifest_id: str,
    computational_contract_id: str,
    backend_configuration_id: str | None = None,
    expected_context_identity: str | None = None,
    expected_run_identity: str | None = None,
) -> dict[str, object]:
    """Execute a frozen local backend and bind identity from that invocation.

    The caller supplies only a backend configuration ID (inside the frozen file); no
    commitment or provider/model fields are accepted on this production path.
    """
    if role not in {"PRIMARY", "VERIFIER"}:
        raise ValueError("role must be PRIMARY or VERIFIER")
    bundle = json.loads(Path(proposal_input_path).read_text(encoding="utf-8"))
    required = {"proposal_input_bundle_id", "raw_key", "execution_manifest_id", "complete_candidate_universe_hash", "complete_candidate_relation_set_hash", "input_status"}
    if not required <= bundle.keys() or bundle["input_status"] != "FROZEN_PREPARATION_ONLY":
        raise ValueError("proposal input bundle is not frozen and complete")
    if bundle["proposal_input_bundle_id"] != _hash({k: v for k, v in bundle.items() if k != "proposal_input_bundle_id"}):
        raise ValueError("proposal input bundle identity mismatch")
    if bundle["execution_manifest_id"] != expected_execution_manifest_id:
        raise ValueError("proposal input execution manifest identity mismatch")
    if not isinstance(computational_contract_id, str) or len(computational_contract_id) != 64:
        raise ValueError("computational contract identity is required")
    config = _load_backend_config(Path(backend_config_path), role)
    if backend_configuration_id is not None and backend_configuration_id != config["backend_configuration_id"]:
        raise ValueError("caller-selected backend configuration ID does not match frozen configuration")
    command = list(config["command"])
    executable = Path(command[0])
    if not executable.is_absolute():
        executable = (Path(backend_config_path).parent / executable).resolve()
        command[0] = str(executable)
    if not executable.is_file():
        raise ValueError("configured backend executable is unavailable")
    implementation_path = executable
    for argument in command[1:]:
        candidate = Path(argument)
        if candidate.is_file():
            implementation_path = candidate
            break
    implementation_hash = hashlib.sha256(implementation_path.read_bytes()).hexdigest()
    configured_impl = config.get("backend_implementation_hash")
    if not isinstance(configured_impl, str) or configured_impl != implementation_hash:
        raise ValueError("configured backend implementation hash mismatch")
    if config.get("frozen_configuration") is not True:
        raise ValueError("backend configuration is not marked frozen")
    invocation_identity = _hash({"command": config["command"], "backend_configuration_id": config["backend_configuration_id"]})
    env = os.environ.copy()
    env["A2_BACKEND_CONFIG"] = json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    completed = subprocess.run(command, input=json.dumps(bundle, ensure_ascii=False), text=True, capture_output=True, check=False, env=env)
    if completed.returncode != 0:
        raise ValueError("configured execution backend failed")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("backend did not return structured JSON") from exc
    if not isinstance(result, dict):
        raise ValueError("backend result must be an object")
    runtime = result.pop("runtime_identity", None)
    if not isinstance(runtime, dict):
        raise ValueError("backend did not expose execution-time runtime identity")
    for name in ("provider", "model_id", "context_identity", "run_identity"):
        if runtime.get(name) != config.get(name):
            raise ValueError(f"execution-bound {name} does not match frozen backend")
    if expected_context_identity is not None and expected_context_identity != runtime.get("context_identity"):
        raise ValueError("context identity assertion does not match execution-bound runtime")
    if expected_run_identity is not None and expected_run_identity != runtime.get("run_identity"):
        raise ValueError("run identity assertion does not match execution-bound runtime")
    allowed_candidate_fields = {"result_status", "selected_candidate_scoring_id", "selected_relation_identity", "evidence_fact_ids", "evidence_set_hash", "hard_gate_results"}
    if set(result) != allowed_candidate_fields:
        raise ValueError("backend output must contain only structured commitment fields")
    binding = {
        "backend_implementation_hash": _field(implementation_hash),
        "backend_configuration_id": _field(config["backend_configuration_id"]),
        "provider": _field(runtime.get("provider")),
        "model_id": _field(runtime.get("model_id")),
        "provider_source": _field(config.get("provider_source", config.get("provider"))),
        "model_source": _field(config.get("model_source", config.get("model_id"))),
        "agent_or_cli_version_source": _field(config.get("agent_or_cli_version_source"), required=False),
        "invocation_command_config_identity": _field(invocation_identity),
        "tool_mode": _field(config["tool_mode"]),
        "context_identity": _field(runtime.get("context_identity")),
        "run_identity": _field(runtime.get("run_identity")),
        "capture_method": _field(config["capture_method"]),
    }
    binding["runtime_binding_id"] = _hash(binding)
    commitment = {
        "schema": "A2_STRUCTURED_COMMITMENT_V2",
        "role": role,
        "raw_key": bundle["raw_key"],
        "proposal_input_bundle_id": bundle["proposal_input_bundle_id"],
        "execution_manifest_id": expected_execution_manifest_id,
        "computational_contract_id": computational_contract_id,
        "complete_candidate_universe_hash": bundle["complete_candidate_universe_hash"],
        "complete_relation_set_hash": bundle["complete_candidate_relation_set_hash"],
        **result,
        "context_identity": runtime["context_identity"],
        "run_identity": runtime["run_identity"],
        "runtime_binding": binding,
        "prompt_template_identity": role_prompt_template(role),
        "private_chain_of_thought_persisted": False,
        "owner_freeze_performed": False,
        "binding_publication_performed": False,
    }
    commitment["commitment_id"] = _hash(commitment)
    _validate_commitment(commitment, bundle, role)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output_path.parent, delete=False) as handle:
        json.dump(commitment, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(output_path)
    return commitment


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=["PRIMARY", "VERIFIER"], required=True)
    parser.add_argument("--proposal-input", type=Path, required=True)
    parser.add_argument("--backend-config", type=Path, required=True)
    parser.add_argument("--backend-configuration-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-execution-manifest-id", required=True)
    parser.add_argument("--computational-contract-id", required=True)
    parser.add_argument("--context-identity")
    parser.add_argument("--run-identity")
    args = parser.parse_args(argv)
    try:
        execute_role_with_backend(args.role, args.proposal_input, args.backend_config, args.output, expected_execution_manifest_id=args.expected_execution_manifest_id, computational_contract_id=args.computational_contract_id, backend_configuration_id=args.backend_configuration_id, expected_context_identity=args.context_identity, expected_run_identity=args.run_identity)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL_CLOSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
