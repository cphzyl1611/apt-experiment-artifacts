import copy
import unittest

from tests.fixtures import (
    authority_expansion,
    authority_evidence,
    commitment,
    common_entry,
    common_manifest,
    digest,
    digest,
    frozen_authority,
    source_admission_zero_proof,
)

try:
    from tools.authority import derive_machine_authority_context
    from tools.admission import validate_source_admission_zero_proof_freshness
    from tools.transaction import compare_commitments
    from tools.canonical import ContractError
except ImportError as import_error:
    _IMPORT_ERROR = import_error
    ContractError = ValueError
else:
    _IMPORT_ERROR = None


ROLES = (
    "EXACT_TARGET_POINTER_AUTHORITY",
    "FIELD_PIN_REGISTRY",
    "DETERMINISTIC_CORPUS_SCHEMA_FIELD_PIN_RULE",
)
CONTRACT_ID = "synthetic-evaluation-contract-r2"


def authority_graph():
    entries = [common_entry(f"synthetic-r3-root-{index}", role, b"[]") for index, role in enumerate(ROLES)]
    manifest = common_manifest(entries)
    authorities = [frozen_authority(entry) for entry in entries]
    expansions = [authority_expansion(record, evaluation_contract_id=CONTRACT_ID) for record in authorities]
    return manifest, authorities, expansions, authority_evidence(authorities, expansions)


class R3DefectRegressionTests(unittest.TestCase):
    def setUp(self):
        if _IMPORT_ERROR is not None:
            self.fail(f"R3_IMPORT_FAILED: {_IMPORT_ERROR}")

    def test_b2_injected_tuple_is_rejected(self):
        manifest, authorities, expansions, evidence = authority_graph()
        injected = copy.deepcopy(expansions[0])
        injected["tuples"] = [{"unexpected": "caller-injected"}]
        injected["ordered_tuple_ids"] = [digest(injected["tuples"][0])]
        injected["ordered_set_commitment_id"] = digest(injected["ordered_tuple_ids"])
        injected["expansion_record_id"] = __import__("tests.fixtures", fromlist=["with_id"]).with_id(injected, "expansion_record_id")["expansion_record_id"]
        expansions[0] = injected
        with self.assertRaisesRegex(ContractError, "EXPANSION_NOT_DERIVED_FROM_AUTHENTICATED_ARTIFACT"):
            derive_machine_authority_context(manifest, authorities, expansions, ROLES, CONTRACT_ID, evidence)

    def test_b2_omitted_and_extra_tuples_are_rejected(self):
        real = {
            "source_binding_target_id": "a" * 64,
            "candidate_object_id": "b" * 64,
            "canonical_intrinsic_field_semantics_id": "c" * 64,
            "exact_RFC6901_pointer": "/intrinsic/name",
        }
        entry = common_entry("synthetic-r3-populated", ROLES[0], __import__("json").dumps([real], separators=(",", ":")).encode())
        manifest = common_manifest([entry])
        authority = frozen_authority(entry)
        expansion = authority_expansion(authority, [real], CONTRACT_ID)
        evidence = authority_evidence([authority], [expansion])
        omitted = authority_expansion(authority, [], CONTRACT_ID)
        omitted["evaluation_evidence_id"] = expansion["evaluation_evidence_id"]
        omitted["expansion_record_id"] = __import__("tests.fixtures", fromlist=["with_id"]).with_id(omitted, "expansion_record_id")["expansion_record_id"]
        with self.assertRaisesRegex(ContractError, "EXPANSION_NOT_DERIVED_FROM_AUTHENTICATED_ARTIFACT"):
            derive_machine_authority_context(manifest, [authority], [omitted], ROLES[:1], CONTRACT_ID, evidence)
        extra = authority_expansion(authority, [real, {"authorized": "extra"}], CONTRACT_ID)
        extra["evaluation_evidence_id"] = expansion["evaluation_evidence_id"]
        extra["expansion_record_id"] = __import__("tests.fixtures", fromlist=["with_id"]).with_id(extra, "expansion_record_id")["expansion_record_id"]
        with self.assertRaisesRegex(ContractError, "EXPANSION_NOT_DERIVED_FROM_AUTHENTICATED_ARTIFACT"):
            derive_machine_authority_context(manifest, [authority], [extra], ROLES[:1], CONTRACT_ID, evidence)

    def test_b2_wrong_evaluator_artifact_and_stale_expansion_are_rejected(self):
        manifest, authorities, expansions, evidence = authority_graph()
        for field, value, reason in (
            ("evaluator_implementation_id", "wrong-evaluator", "EVALUATOR_IDENTITY_MISMATCH"),
            ("artifact_content_identity", "f" * 64, "EVALUATOR_IDENTITY_MISMATCH"),
            ("evaluation_run_input_identity", "stale-run", "EVALUATOR_IDENTITY_MISMATCH"),
        ):
            candidate = copy.deepcopy(expansions[0])
            candidate[field] = value
            candidate["expansion_record_id"] = __import__("tests.fixtures", fromlist=["with_id"]).with_id(candidate, "expansion_record_id")["expansion_record_id"]
            altered = list(expansions)
            altered[0] = candidate
            with self.assertRaisesRegex(ContractError, reason):
                derive_machine_authority_context(manifest, authorities, altered, ROLES, CONTRACT_ID, evidence)

    def test_b2_caller_only_expansion_without_authenticated_evidence_is_rejected(self):
        manifest, authorities, expansions, _ = authority_graph()
        with self.assertRaisesRegex(ContractError, "AUTHENTICATED_EVALUATION_EVIDENCE_REQUIRED"):
            derive_machine_authority_context(manifest, authorities, expansions, ROLES, CONTRACT_ID)

    def test_b3_free_form_context_is_rejected(self):
        proof = source_admission_zero_proof()
        context = {
            "machine_authority_input_set_id": proof["machine_authority_input_set_id"],
            "source_admission_evaluation_contract_id": proof["source_admission_evaluation_contract_id"],
            "machine_authority_evaluation_evidence_id": proof["machine_authority_evaluation_evidence_id"],
        }
        with self.assertRaisesRegex(ContractError, "CURRENT_DERIVATION_REQUIRED"):
            validate_source_admission_zero_proof_freshness(proof, context)

    def test_b3_current_derivation_binds_proof_and_rejects_stale_or_wrong_graph(self):
        current = __import__("tests.test_ec_b3_zero_proof", fromlist=["derivation"]).derivation("current-contract")
        proof = source_admission_zero_proof(input_set_id=current["machine_authority_input_set_id"], contract_id="current-contract")
        proof["machine_authority_evaluation_evidence_id"] = current["machine_authority_evaluation_evidence"]["machine_authority_evaluation_evidence_id"]
        proof["source_admission_machine_zero_proof_id"] = __import__("tests.fixtures", fromlist=["with_id"]).with_id(proof, "source_admission_machine_zero_proof_id")["source_admission_machine_zero_proof_id"]
        self.assertTrue(validate_source_admission_zero_proof_freshness(proof, current))
        stale_context = __import__("tests.test_ec_b3_zero_proof", fromlist=["derivation"]).derivation("old-contract")
        with self.assertRaisesRegex(ContractError, "STALE_SOURCE_ADMISSION_ZERO_PROOF"):
            validate_source_admission_zero_proof_freshness(proof, stale_context)
        wrong_contract = __import__("tests.test_ec_b3_zero_proof", fromlist=["derivation"]).derivation("wrong-contract")
        with self.assertRaisesRegex(ContractError, "STALE_SOURCE_ADMISSION_ZERO_PROOF"):
            validate_source_admission_zero_proof_freshness(proof, wrong_contract)
        with self.assertRaises((TypeError, ContractError)):
            current["machine_authority_evaluation_evidence"] = {"replacement": True}

    def test_b4_wrong_singleton_is_rejected(self):
        primary = commitment()
        verifier = commitment("verifier_commitment", result_hash="9" * 64, context="context-v", run="run-v")
        with self.assertRaisesRegex(ContractError, "AFFECTED_TARGET_LIST_INCONSISTENT"):
            compare_commitments(primary, verifier, both_frozen=True, affected_target_ids=["wrong-target"])

    def test_b4_exact_set_is_derived_and_subsets_supersets_duplicates_rejected(self):
        def make(kind, values, context):
            row = commitment(kind, context=context, run=context)
            target_ids = [item["target_id"] for item in row["ordered_target_result_vector"]]
            value_by_target = dict(values)
            vector = [{"target_id": target, "result_commitment": value_by_target.get(target, "b" * 64)} for target in target_ids]
            row["ordered_target_result_vector"] = vector
            row["ordered_result_vector_sha256"] = digest(vector)
            row["exact_target_id_set_sha256"] = digest([item["target_id"] for item in vector])
            return __import__("tests.fixtures", fromlist=["with_id"]).with_id(row, "commitment_id")

        target_ids = [item["target_id"] for item in commitment()["ordered_target_result_vector"]]
        primary = make("primary_commitment", [(target_ids[0], "a" * 64)], "primary-context")
        verifier = make("verifier_commitment", [(target_ids[0], "x" * 64)], "verifier-context")
        self.assertEqual(compare_commitments(primary, verifier, True, affected_target_ids=[target_ids[0]])["affected_target_ids"], [target_ids[0]])
        for asserted in ([target_ids[1]], [], [target_ids[0], target_ids[1]], ["unrelated"], [target_ids[0], target_ids[0]]):
            with self.assertRaisesRegex(ContractError, "AFFECTED_TARGET_LIST_INCONSISTENT"):
                compare_commitments(primary, verifier, True, affected_target_ids=asserted)
        equal = make("verifier_commitment", [(target_ids[0], "a" * 64)], "equal-verifier")
        with self.assertRaisesRegex(ContractError, "AFFECTED_TARGET_LIST_INCONSISTENT"):
            compare_commitments(primary, equal, True, affected_target_ids=[target_ids[0]])
        with self.assertRaisesRegex(ContractError, "AFFECTED_TARGET_LIST_INCONSISTENT"):
            compare_commitments(primary, verifier, True, affected_target_ids=[])


if __name__ == "__main__":
    unittest.main()
