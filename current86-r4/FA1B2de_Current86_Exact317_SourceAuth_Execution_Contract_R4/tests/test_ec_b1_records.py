import copy
import unittest

from tests.fixtures import (
    admission_record,
    candidate_commitment,
    common_entry,
    common_manifest,
    conservation_record,
    field_pin_record,
    frozen_authority,
    readiness_record,
    target_for_candidate,
    with_id,
)


try:
    from tools.records import (
        ContractError,
        EXACT_SCHEMA_NAME,
        validate_candidate_source_object_commitment,
        validate_common_input_manifest,
        validate_field_pin_record,
        validate_frozen_authority_record,
        validate_per_target_readiness_record,
        validate_record,
        validate_terminal_conservation_record,
    )
except ImportError as import_error:
    ContractError = ValueError
    EXACT_SCHEMA_NAME = {}
    _IMPORT_ERROR = import_error
else:
    _IMPORT_ERROR = None


class ExactSchemaAndCrossObjectTests(unittest.TestCase):
    def setUp(self):
        if _IMPORT_ERROR is not None:
            self.fail(f"R2_RECORDS_NOT_IMPLEMENTED: {_IMPORT_ERROR}")

    def test_exact_schema_registry_covers_every_required_kind(self):
        expected = {
            "common_input_entry", "common_input_manifest", "authenticated_frozen_authority_record",
            "candidate_source_object_commitment", "admission_record",
            "source_admission_machine_zero_proof", "human_normative_admission_record",
            "no_machine_field_pin_authority_proof_v2", "human_field_pin_governance_record_v2",
            "field_pin_record", "primary_commitment", "verifier_commitment",
            "comparison_record", "per_target_readiness_record", "terminal_conservation_record",
            "machine_authority_expansion_record", "machine_authority_evaluation_evidence"
        }
        self.assertEqual(set(EXACT_SCHEMA_NAME), expected)

    def test_wrong_schema_with_recomputed_self_id_is_rejected(self):
        manifest = common_manifest()
        manifest["schema"] = "ARBITRARY_BUT_STRING_SCHEMA"
        manifest = with_id(manifest, "common_input_set_id")
        with self.assertRaisesRegex(ContractError, "WRONG_SCHEMA_DISCRIMINATOR"):
            validate_record("common_input_manifest", manifest)

    def test_common_input_requires_exact_order_unique_ids_and_opened_content(self):
        first = common_entry("synthetic-b", "FIELD_PIN_REGISTRY")
        second = common_entry("synthetic-a", "EXACT_TARGET_POINTER_AUTHORITY")
        valid = common_manifest([first, second])
        self.assertTrue(validate_common_input_manifest(valid))
        wrong_order = copy.deepcopy(valid)
        wrong_order["entries"] = list(reversed(wrong_order["entries"]))
        wrong_order = with_id(wrong_order, "common_input_set_id")
        with self.assertRaisesRegex(ContractError, "COMMON_INPUT_ORDER_INVALID"):
            validate_common_input_manifest(wrong_order)
        unreadable = copy.deepcopy(valid)
        unreadable["entries"][0]["content_opened"] = False
        unreadable["entries"][0] = with_id(unreadable["entries"][0], "common_input_entry_id")
        unreadable = with_id(unreadable, "common_input_set_id")
        with self.assertRaisesRegex(ContractError, "COMMON_INPUT_UNAVAILABLE_OR_UNREADABLE"):
            validate_common_input_manifest(unreadable)

    def test_frozen_authority_must_match_exact_common_input_entry(self):
        entry = common_entry()
        manifest = common_manifest([entry])
        record = frozen_authority(entry)
        self.assertTrue(validate_frozen_authority_record(record, manifest))
        wrong = copy.deepcopy(record)
        wrong["provenance_id"] = "wrong-provenance"
        wrong = with_id(wrong, "authority_record_id")
        with self.assertRaisesRegex(ContractError, "AUTHORITY_COMMON_INPUT_MISMATCH"):
            validate_frozen_authority_record(wrong, manifest)

    def test_candidate_object_validator_binds_artifact_target_locator_rule_and_provenance(self):
        corpus = common_entry("synthetic-corpus", "CANDIDATE_CORPUS", b"synthetic-corpus\n")
        extraction_entry = common_entry("synthetic-extraction", "CANDIDATE_OBJECT_EXTRACTION_RULE", b"synthetic-rule\n")
        manifest = common_manifest([corpus, extraction_entry])
        extraction = frozen_authority(extraction_entry)
        candidate = candidate_commitment(corpus, extraction)
        self.assertTrue(validate_candidate_source_object_commitment(candidate, target_for_candidate(candidate), manifest, extraction))
        wrong = copy.deepcopy(candidate)
        wrong["object_locator_canonical_sha256"] = "f" * 64
        wrong = with_id(wrong, "candidate_object_id")
        with self.assertRaisesRegex(ContractError, "CANDIDATE_OBJECT_BINDING_MISMATCH"):
            validate_candidate_source_object_commitment(wrong, target_for_candidate(wrong), manifest, extraction)

    def test_field_pin_validator_recomputes_admission_tuple_pointer_and_scalar(self):
        corpus = common_entry("synthetic-corpus", "CANDIDATE_CORPUS")
        extraction_entry = common_entry("synthetic-extraction", "CANDIDATE_OBJECT_EXTRACTION_RULE")
        extraction = frozen_authority(extraction_entry)
        candidate = candidate_commitment(corpus, extraction)
        admission = admission_record(candidate)
        pin = field_pin_record(admission)
        self.assertTrue(validate_field_pin_record(pin, admission, "synthetic-value"))
        wrong = copy.deepcopy(pin)
        wrong["authenticated_value_sha256"] = "e" * 64
        wrong = with_id(wrong, "field_pin_id")
        with self.assertRaisesRegex(ContractError, "FIELD_PIN_VALUE_HASH_MISMATCH"):
            validate_field_pin_record(wrong, admission, "synthetic-value")

    def test_readiness_and_conservation_are_substantive(self):
        record = readiness_record()
        self.assertTrue(validate_per_target_readiness_record(record, {record["source_binding_target_id"]}))
        conservation = conservation_record([record["source_binding_target_id"]], [record])
        self.assertTrue(validate_terminal_conservation_record(conservation, [record["source_binding_target_id"]], [record], expected_side_counts=(1, 0)))
        duplicate = [record, copy.deepcopy(record)]
        bad = conservation_record([record["source_binding_target_id"]], duplicate)
        with self.assertRaisesRegex(ContractError, "TARGET_STATE_NOT_EXACTLY_ONCE"):
            validate_terminal_conservation_record(bad, [record["source_binding_target_id"]], duplicate, expected_side_counts=(1, 0))


if __name__ == "__main__":
    unittest.main()
