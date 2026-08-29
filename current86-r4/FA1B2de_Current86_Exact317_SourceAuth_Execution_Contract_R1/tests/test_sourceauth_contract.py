import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.sourceauth_contract import (
    AUDIT_SCOPE_ID,
    ContractError,
    admission_context,
    canonical_json_bytes,
    canonical_scalar_bytes,
    evaluate_field_pin_authority,
    machine_authority_input_set_id,
    parse_json_strict,
    resolve_rfc6901,
    self_excluding_id,
    validate_conservation,
    validate_human_field_pin_record_v2,
    validate_isolation_contract,
    validate_no_machine_field_pin_proof_v2,
    validate_record,
    validate_synthetic_fixture_manifest,
)


SYNTHETIC_TARGET = "synthetic-non-production-target-0001"
SYNTHETIC_CANDIDATE = "synthetic-non-production-candidate-0001"
SEMANTICS = "synthetic-canonical-intrinsic-semantics-v1"
P1 = "/intrinsic/name"
P2 = "/intrinsic/title"


def admission(pointer=P1):
    row = {
        "schema": "FA1B2DE_CURRENT86_SOURCE_ADMISSION_RECORD_V1",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "source_binding_target_id": SYNTHETIC_TARGET,
        "candidate_object_id": SYNTHETIC_CANDIDATE,
        "canonical_intrinsic_field_semantics_id": SEMANTICS,
        "exact_RFC6901_pointer_utf8_sha256": __import__("hashlib").sha256(pointer.encode()).hexdigest(),
        "exact_RFC6901_pointer": pointer,
        "admission_authority_type": "SYNTHETIC_NON_AUTHORITATIVE_FIXTURE",
        "admission_authority_artifact_id": "synthetic-admission-authority",
        "admission_authority_sha256_or_pinned_identity": "0" * 64,
        "admission_authority_provenance_id": "synthetic-provenance",
    }
    row["admission_record_id"] = self_excluding_id(row, "admission_record_id")
    return row


def field_tuple(pointer=P1):
    return {
        "source_binding_target_id": SYNTHETIC_TARGET,
        "candidate_object_id": SYNTHETIC_CANDIDATE,
        "canonical_intrinsic_field_semantics_id": SEMANTICS,
        "exact_RFC6901_pointer": pointer,
    }


def authority_roots(*tuples):
    rows = []
    roles = (
        "EXACT_TARGET_POINTER_AUTHORITY",
        "FIELD_PIN_REGISTRY",
        "DETERMINISTIC_CORPUS_SCHEMA_FIELD_PIN_RULE",
    )
    for index, role in enumerate(roles):
        rows.append({
            "authority_role": role,
            "authority_set_id": f"synthetic-set-{index}",
            "available": True,
            "authenticated": True,
            "provenance_valid": True,
            "evaluation_complete": True,
            "tuples": list(tuples) if index == 0 else [],
        })
    return rows


def zero_proof(adm):
    ctx = admission_context(adm)
    proof = {
        "schema": "FA1B2DE_CURRENT86_NO_MACHINE_FIELD_PIN_AUTHORITY_PROOF_V2",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "exact_target_manifest_sha256": "d8d55d369fe433bf7b93a3c332b8ac9a517a9146b28fa223370ff3ec946955ac",
        "source_binding_target_id": SYNTHETIC_TARGET,
        "candidate_object_id": SYNTHETIC_CANDIDATE,
        "canonical_intrinsic_field_semantics_id": SEMANTICS,
        "admission_record_id": ctx["admission_record_id"],
        "admission_tuple_id": ctx["admission_tuple_id"],
        "admitted_exact_RFC6901_pointer_utf8_sha256": ctx["admitted_exact_RFC6901_pointer_utf8_sha256"],
        "machine_field_pin_authority_input_set_id": machine_authority_input_set_id(authority_roots()),
        "exact_target_pointer_authority_set_id": "synthetic-set-0",
        "field_pin_registry_authority_set_id": "synthetic-set-1",
        "deterministic_corpus_schema_rule_authority_set_id": "synthetic-set-2",
        "field_pin_authority_evaluation_contract_id": "synthetic-evaluation-contract",
        "exact_target_valid_tuple_ids": [],
        "field_pin_registry_valid_tuple_ids": [],
        "deterministic_corpus_schema_rule_valid_tuple_ids": [],
        "machine_valid_field_pin_tuple_ids": [],
        "valid_exact_target_pointer_authority_count": 0,
        "valid_field_pin_registry_tuple_count": 0,
        "valid_deterministic_corpus_schema_rule_tuple_count": 0,
        "machine_valid_field_pin_tuple_count": 0,
        "machine_conflict_count": 0,
        "machine_admission_tuple_mismatch_count": 0,
        "machine_authority_evaluation_evidence_id": "synthetic-evaluation-evidence",
    }
    proof["no_machine_field_pin_authority_proof_id"] = self_excluding_id(
        proof, "no_machine_field_pin_authority_proof_id"
    )
    return proof


def human_record(adm, proof, pointer=P1):
    ctx = admission_context(adm)
    row = {
        "schema": "FA1B2DE_CURRENT86_HUMAN_FIELD_PIN_GOVERNANCE_RECORD_V2",
        "audit_scope_id": AUDIT_SCOPE_ID,
        "source_binding_target_id": SYNTHETIC_TARGET,
        "candidate_object_id": SYNTHETIC_CANDIDATE,
        "canonical_intrinsic_field_semantics_id": SEMANTICS,
        "admission_record_id": ctx["admission_record_id"],
        "admission_tuple_id": ctx["admission_tuple_id"],
        "admitted_exact_RFC6901_pointer_utf8_sha256": ctx["admitted_exact_RFC6901_pointer_utf8_sha256"],
        "exact_RFC6901_pointer": pointer,
        "exact_RFC6901_pointer_utf8_sha256": __import__("hashlib").sha256(pointer.encode()).hexdigest(),
        "no_machine_field_pin_authority_proof_id": proof["no_machine_field_pin_authority_proof_id"],
        "human_native_decision_bytes_sha256": "1" * 64,
        "human_origin_provenance_mode": "SYNTHETIC_TEST_EVENT_ONLY",
        "governance_event_id": "synthetic-governance-event",
        "independent_capture_verification_id": "synthetic-capture-verification",
    }
    row["human_field_pin_governance_record_id"] = self_excluding_id(
        row, "human_field_pin_governance_record_id"
    )
    return row


class CanonicalizationTests(unittest.TestCase):
    def test_canonical_json_utf8_byte_order_and_duplicate_rejection(self):
        self.assertEqual(canonical_json_bytes({"z": 1, "a": True}), b'{"a":true,"z":1}')
        with self.assertRaisesRegex(ContractError, "DUPLICATE_JSON_KEY"):
            parse_json_strict(b'{"a":1,"a":2}')
        with self.assertRaisesRegex(ContractError, "FLOAT_FORBIDDEN"):
            parse_json_strict(b'{"a":1.0}')

    def test_rfc6901_and_scalar_rules(self):
        doc = {"a/b": {"~key": [None, "e\u0301"]}}
        self.assertEqual(resolve_rfc6901(doc, "/a~1b/~0key/1"), "e\u0301")
        self.assertNotEqual(canonical_scalar_bytes("e\u0301"), canonical_scalar_bytes("é"))
        with self.assertRaisesRegex(ContractError, "INVALID_POINTER_ESCAPE"):
            resolve_rfc6901(doc, "/a~2b")
        with self.assertRaisesRegex(ContractError, "INVALID_ARRAY_INDEX"):
            resolve_rfc6901([1], "/00")
        with self.assertRaisesRegex(ContractError, "COMPOSITE_TERMINAL_FORBIDDEN"):
            canonical_scalar_bytes({"x": 1})


class CrossBindingTests(unittest.TestCase):
    def assert_block(self, result, reason="ADMISSION_FIELD_PIN_TUPLE_MISMATCH"):
        self.assertEqual(result["state"], "BLOCKED_FIELD_PIN")
        self.assertEqual(result["reason"], reason)
        self.assertFalse(result["human_fallback_allowed"])
        self.assertFalse(result["alternate_pointer_allowed"])

    def test_admission_p1_machine_p2_fails_closed(self):
        self.assert_block(evaluate_field_pin_authority(admission(), authority_roots(field_tuple(P2))))

    def test_admission_p1_human_p2_fails_closed(self):
        adm = admission()
        proof = zero_proof(adm)
        result = evaluate_field_pin_authority(adm, authority_roots(), proof, [human_record(adm, proof, P2)])
        self.assert_block(result)

    def test_wrong_admission_record_id_fails_closed(self):
        adm = admission()
        proof = zero_proof(adm)
        human = human_record(adm, proof)
        human["admission_record_id"] = "f" * 64
        human["human_field_pin_governance_record_id"] = self_excluding_id(human, "human_field_pin_governance_record_id")
        self.assert_block(evaluate_field_pin_authority(adm, authority_roots(), proof, [human]))

    def test_wrong_admission_tuple_id_fails_closed(self):
        adm = admission()
        proof = zero_proof(adm)
        human = human_record(adm, proof)
        human["admission_tuple_id"] = "e" * 64
        human["human_field_pin_governance_record_id"] = self_excluding_id(human, "human_field_pin_governance_record_id")
        self.assert_block(evaluate_field_pin_authority(adm, authority_roots(), proof, [human]))

    def test_stale_zero_proof_after_admission_change(self):
        old = admission(P1)
        proof = zero_proof(old)
        new = admission(P2)
        with self.assertRaisesRegex(ContractError, "STALE_NO_MACHINE_PROOF"):
            validate_no_machine_field_pin_proof_v2(proof, admission_context(new), authority_roots())

    def test_missing_root_is_not_zero(self):
        roots = authority_roots()[:-1]
        result = evaluate_field_pin_authority(admission(), roots)
        self.assert_block(result, "MISSING_AUTHORITY_ROOT_NOT_ZERO")

    def test_machine_conflict_forbids_human(self):
        adm = admission()
        proof = zero_proof(adm)
        result = evaluate_field_pin_authority(
            adm, authority_roots(field_tuple(P1), field_tuple(P1)), proof, [human_record(adm, proof)]
        )
        self.assert_block(result, "DUPLICATE_OR_CONFLICTING_MACHINE_AUTHORITY")

    def test_identical_machine_confirmation_is_valid_synthetic_path(self):
        result = evaluate_field_pin_authority(admission(), authority_roots(field_tuple(P1)))
        self.assertEqual(result["state"], "FIELD_PIN_AUTHORITY_ELIGIBLE_SYNTHETIC")
        self.assertEqual(result["authority_path"], "MACHINE_CONFIRMATION")

    def test_zero_plus_exact_human_ratification_is_valid_synthetic_path(self):
        adm = admission()
        proof = zero_proof(adm)
        result = evaluate_field_pin_authority(adm, authority_roots(), proof, [human_record(adm, proof)])
        self.assertEqual(result["state"], "FIELD_PIN_AUTHORITY_ELIGIBLE_SYNTHETIC")
        self.assertEqual(result["authority_path"], "HUMAN_RATIFICATION")


class SchemaIsolationConservationTests(unittest.TestCase):
    def test_schema_unknown_field_and_identity_rejected(self):
        adm = admission()
        validate_record("admission_record", adm)
        bad = copy.deepcopy(adm)
        bad["owner"] = "forbidden"
        with self.assertRaisesRegex(ContractError, "UNKNOWN_FIELDS"):
            validate_record("admission_record", bad)

    def test_schema_rejects_wrong_plain_string_type(self):
        bad = admission()
        bad["candidate_object_id"] = 7
        bad["admission_record_id"] = self_excluding_id(bad, "admission_record_id")
        with self.assertRaisesRegex(ContractError, "WRONG_TYPE"):
            validate_record("admission_record", bad)

    def test_verifier_primary_roots_must_be_disjoint(self):
        contract = {
            "COMMON_INPUT_SET": ["common-a"],
            "PRIMARY_PRIVATE_OUTPUT_SET": ["primary-secret", "primary-commitment"],
            "VERIFIER_READABLE_SET": ["common-a", "primary-commitment"],
            "PRIMARY_IMPLEMENTATION_ID": "p-impl",
            "VERIFIER_IMPLEMENTATION_ID": "v-impl",
            "PRIMARY_CONTEXT_ID": "p-context",
            "VERIFIER_CONTEXT_ID": "v-context",
            "PRIMARY_RUN_ID": "p-run",
            "VERIFIER_RUN_ID": "v-run",
        }
        with self.assertRaisesRegex(ContractError, "VERIFIER_PRIMARY_SET_INTERSECTION"):
            validate_isolation_contract(contract)

    def test_equal_role_identities_fail_closed(self):
        base = {
            "COMMON_INPUT_SET": ["common-a"],
            "PRIMARY_PRIVATE_OUTPUT_SET": ["primary-secret"],
            "VERIFIER_READABLE_SET": ["common-a"],
            "PRIMARY_IMPLEMENTATION_ID": "same",
            "VERIFIER_IMPLEMENTATION_ID": "same",
            "PRIMARY_CONTEXT_ID": "same-context",
            "VERIFIER_CONTEXT_ID": "same-context",
            "PRIMARY_RUN_ID": "same-run",
            "VERIFIER_RUN_ID": "same-run",
        }
        with self.assertRaisesRegex(ContractError, "ROLE_IDENTITY_NOT_DISTINCT"):
            validate_isolation_contract(base)

    def test_terminal_conservation_rejects_duplicate_and_missing(self):
        targets = ["t1", "t2"]
        duplicate = [
            {"source_binding_target_id": "t1", "terminal_state": "BLOCKED_FIELD_PIN"},
            {"source_binding_target_id": "t1", "terminal_state": "BLOCKED_SOURCE_OBJECT"},
        ]
        with self.assertRaisesRegex(ContractError, "TARGET_STATE_NOT_EXACTLY_ONCE"):
            validate_conservation(targets, duplicate)

    def test_synthetic_fixture_ids_are_outside_production(self):
        manifest = {
            "fixture_authority": "NON_AUTHORITATIVE_SYNTHETIC_ONLY",
            "synthetic_target_ids": [SYNTHETIC_TARGET],
            "production_target_ids": ["a" * 64, "b" * 64],
            "real_source_auth_targets_executed": 0,
        }
        self.assertTrue(validate_synthetic_fixture_manifest(manifest))
        manifest["synthetic_target_ids"] = ["a" * 64]
        with self.assertRaisesRegex(ContractError, "SYNTHETIC_PRODUCTION_ID_INTERSECTION"):
            validate_synthetic_fixture_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
