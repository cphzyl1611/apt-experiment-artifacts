from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from tests.fixtures import (
    authority_evidence,
    authority_expansion,
    common_entry,
    common_manifest,
    commitment,
    digest,
    frozen_authority,
    source_admission_zero_proof,
    with_id,
)

from tools.authority import MachineAuthorityContext, derive_machine_authority_context
from tools.canonical import ContractError
from tools.frozen_authority_evaluator import R4_EVALUATOR_CONFIGURATION_ID, evaluate_authority_bytes
from tools.transaction import compare_commitments


ROOT = Path(__file__).resolve().parents[1]
ROLES = (
    "EXACT_TARGET_POINTER_AUTHORITY",
    "FIELD_PIN_REGISTRY",
    "DETERMINISTIC_CORPUS_SCHEMA_FIELD_PIN_RULE",
)
SCHEMA = "synthetic-schema-r2"
CONTRACT_ID = "synthetic-evaluation-contract-r2"


def evaluate(raw: bytes, role: str, schema: str):
    """Keep the R3 API gap as a normal RED assertion rather than a test error."""
    try:
        return evaluate_authority_bytes(raw, role, schema, R4_EVALUATOR_CONFIGURATION_ID)
    except TypeError:
        return object()


def exact_target_ids() -> list[str]:
    manifest = json.loads((ROOT / "00_lineage/EXACT317_TARGET_MANIFEST.json").read_text(encoding="utf-8"))
    return [row["source_binding_target_id"] for row in manifest["targets"]]


def authority_graph():
    entries = [common_entry(f"synthetic-r4-root-{index}", role, b"[]") for index, role in enumerate(ROLES)]
    manifest = common_manifest(entries)
    authorities = [frozen_authority(entry) for entry in entries]
    expansions = [authority_expansion(record, evaluation_contract_id=CONTRACT_ID) for record in authorities]
    return manifest, authorities, expansions, authority_evidence(authorities, expansions, evaluation_contract_id=CONTRACT_ID)


def exact_commitment(kind: str, targets: list[str], result: str, context: str, run: str) -> dict[str, object]:
    row = commitment(kind, context=context, run=run)
    vector = [{"target_id": target, "result_commitment": result} for target in targets]
    row["ordered_target_result_vector"] = vector
    row["ordered_result_vector_sha256"] = digest(vector)
    row["terminal_state_count_map"] = {"BLOCKED_FIELD_PIN": len(targets)}
    row["exact_target_id_set_sha256"] = digest(targets)
    return with_id(row, "commitment_id")


class EC_B2FailClosedRedTests(unittest.TestCase):
    def test_invalid_utf8_is_not_a_zero_tuple_expansion(self):
        with self.assertRaises(ContractError):
            value = evaluate(b"\xff", "FIELD_PIN_REGISTRY", SCHEMA)
            if value is not None:
                raise AssertionError("R3 evaluator returned without failing")

    def test_invalid_json_is_not_a_zero_tuple_expansion(self):
        with self.assertRaises(ContractError):
            value = evaluate(b"{", "FIELD_PIN_REGISTRY", SCHEMA)
            if value is not None:
                raise AssertionError("R3 evaluator returned without failing")

    def test_non_list_top_level_is_not_a_zero_tuple_expansion(self):
        with self.assertRaises(ContractError):
            value = evaluate(b"{}", "FIELD_PIN_REGISTRY", SCHEMA)
            if value is not None:
                raise AssertionError("R3 evaluator returned without failing")

    def test_unsupported_role_or_schema_is_not_a_zero_tuple_expansion(self):
        with self.assertRaises(ContractError):
            value = evaluate(b"[]", "UNSUPPORTED_ROLE", SCHEMA)
            if value is not None:
                raise AssertionError("R3 evaluator returned without failing")
        with self.assertRaises(ContractError):
            value = evaluate(b"[]", "FIELD_PIN_REGISTRY", "unsupported-schema")
            if value is not None:
                raise AssertionError("R3 evaluator returned without failing")

    def test_schema_invalid_tuple_is_rejected(self):
        with self.assertRaises(ContractError):
            value = evaluate(b'[{"unexpected":true}]', "FIELD_PIN_REGISTRY", SCHEMA)
            if value is not None:
                raise AssertionError("R3 evaluator returned without failing")

    def test_supported_empty_authority_is_the_only_valid_zero_tuple_expansion(self):
        self.assertEqual(evaluate(b"[]", "FIELD_PIN_REGISTRY", SCHEMA), [])


class EC_B3RevalidationRedTests(unittest.TestCase):
    def test_direct_private_context_fabrication_is_rejected(self):
        evidence = with_id(
            {
                "schema": "FA1B2DE_CURRENT86_MACHINE_AUTHORITY_EVALUATION_EVIDENCE_R3",
                "audit_scope_id": "34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306",
                "machine_authority_input_set_id": "fabricated-input",
                "evaluation_contract_id": "fabricated-contract",
                "evaluator_implementation_id": "FA1B2DE_FROZEN_MACHINE_AUTHORITY_EVALUATOR_R3",
                "evaluator_implementation_sha256": "0" * 64,
                "evaluator_configuration_id": "FA1B2DE_MACHINE_AUTHORITY_EVALUATOR_CONFIG_R3",
                "evaluation_run_input_identity": "fabricated-run",
                "evaluation_evidence_id": "fabricated-evidence",
                "authority_record_ids": [],
                "ordered_expansion_record_ids": [],
                "complete_input_open_audit": [],
                "authority_authentication_results": [],
                "deterministic_expansion_outputs": [],
                "rejected_record_reason_codes": [],
                "ordered_set_commitments": [],
                "machine_authority_evaluation_evidence_id": None,
            },
            "machine_authority_evaluation_evidence_id",
        )
        proof = source_admission_zero_proof(input_set_id="fabricated-input", contract_id="fabricated-contract")
        proof["machine_authority_evaluation_evidence_id"] = evidence["machine_authority_evaluation_evidence_id"]
        proof["source_admission_machine_zero_proof_id"] = with_id(proof, "source_admission_machine_zero_proof_id")["source_admission_machine_zero_proof_id"]
        with self.assertRaises(ContractError):
            MachineAuthorityContext._from_derived(
                {
                    "derivation_graph_valid": True,
                    "machine_authority_input_set_id": "fabricated-input",
                    "evaluation_contract_id": "fabricated-contract",
                    "machine_authority_evaluation_evidence": evidence,
                }
            )

    def test_valid_current_graph_is_revalidated_and_evidence_replacement_fails(self):
        manifest, authorities, expansions, evidence = authority_graph()
        context = derive_machine_authority_context(manifest, authorities, expansions, ROLES, CONTRACT_ID, evidence)
        proof = source_admission_zero_proof(
            input_set_id=context["machine_authority_input_set_id"],
            contract_id=CONTRACT_ID,
            evidence_id="unused",
        )
        proof["machine_authority_evaluation_evidence_id"] = context["machine_authority_evaluation_evidence"]["machine_authority_evaluation_evidence_id"]
        proof["source_admission_machine_zero_proof_id"] = with_id(proof, "source_admission_machine_zero_proof_id")["source_admission_machine_zero_proof_id"]
        from tools.admission import validate_source_admission_zero_proof_freshness

        self.assertTrue(validate_source_admission_zero_proof_freshness(proof, context))
        replacement = copy.deepcopy(context.graph_inputs()["evaluation_evidence"])
        replacement["evaluation_run_input_identity"] = "replacement-run"
        replacement["machine_authority_evaluation_evidence_id"] = with_id(replacement, "machine_authority_evaluation_evidence_id")["machine_authority_evaluation_evidence_id"]
        tampered_proof = copy.deepcopy(proof)
        tampered_proof["machine_authority_evaluation_evidence_id"] = replacement["machine_authority_evaluation_evidence_id"]
        tampered_proof["source_admission_machine_zero_proof_id"] = with_id(tampered_proof, "source_admission_machine_zero_proof_id")["source_admission_machine_zero_proof_id"]
        with self.assertRaises((TypeError, ContractError)):
            context["machine_authority_evaluation_evidence"] = replacement
        with self.assertRaises(ContractError):
            validate_source_admission_zero_proof_freshness(tampered_proof, context)

    def test_post_derivation_context_mutation_is_rejected(self):
        manifest, authorities, expansions, evidence = authority_graph()
        context = derive_machine_authority_context(manifest, authorities, expansions, ROLES, CONTRACT_ID, evidence)
        with self.assertRaises((TypeError, ContractError)):
            context["machine_authority_input_set_id"] = "forged"

    def test_caller_created_subclass_or_mapping_is_not_current_derivation(self):
        manifest, authorities, expansions, evidence = authority_graph()
        genuine = derive_machine_authority_context(manifest, authorities, expansions, ROLES, CONTRACT_ID, evidence)

        class CallerSubclass(dict):
            pass

        forged = CallerSubclass(genuine)
        proof = source_admission_zero_proof(
            input_set_id=genuine["machine_authority_input_set_id"],
            contract_id=CONTRACT_ID,
            evidence_id=genuine["machine_authority_evaluation_evidence"]["machine_authority_evaluation_evidence_id"],
        )
        from tools.admission import validate_source_admission_zero_proof_freshness

        with self.assertRaises(ContractError):
            validate_source_admission_zero_proof_freshness(proof, forged)


class EC_B4Exact317UniverseRedTests(unittest.TestCase):
    def test_exact317_universe_positive_case(self):
        targets = exact_target_ids()
        primary = exact_commitment("primary_commitment", targets, "a" * 64, "primary-context", "primary-run")
        verifier = exact_commitment("verifier_commitment", targets, "a" * 64, "verifier-context", "verifier-run")
        self.assertTrue(compare_commitments(primary, verifier, both_frozen=True)["comparison_equal"])

    def test_truncated_substituted_extra_duplicate_and_reordered_universes_fail(self):
        targets = exact_target_ids()
        mutations = [
            targets[:-1],
            ["0" * 64, *targets[1:]],
            [*targets, "1" * 64],
            [targets[0], targets[0], *targets[2:]],
            [targets[1], targets[0], *targets[2:]],
        ]
        for mutated in mutations:
            with self.subTest(length=len(mutated), first=mutated[0]):
                primary = exact_commitment("primary_commitment", mutated, "a" * 64, "primary-context", "primary-run")
                verifier = exact_commitment("verifier_commitment", mutated, "a" * 64, "verifier-context", "verifier-run")
                with self.assertRaises(ContractError):
                    compare_commitments(primary, verifier, both_frozen=True)

    def test_primary_and_verifier_agreeing_on_same_wrong_universe_fails(self):
        targets = exact_target_ids()[:-1]
        primary = exact_commitment("primary_commitment", targets, "a" * 64, "primary-context", "primary-run")
        verifier = exact_commitment("verifier_commitment", targets, "a" * 64, "verifier-context", "verifier-run")
        with self.assertRaises(ContractError):
            compare_commitments(primary, verifier, both_frozen=True)


if __name__ == "__main__":
    unittest.main()
