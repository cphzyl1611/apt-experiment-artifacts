import copy
import unittest

from tests.fixtures import admission_record, candidate_commitment, common_entry, frozen_authority, field_pin_zero_proof, source_admission_zero_proof

try:
    from tools.admission import validate_field_pin_zero_proof_freshness, validate_source_admission_zero_proof_freshness, validate_human_admission_eligibility
    from tools.records import ContractError
except ImportError as import_error:
    _IMPORT_ERROR = import_error
    ContractError = ValueError
else:
    _IMPORT_ERROR = None


def admission_fixture():
    corpus = common_entry("synthetic-corpus-b3", "CANDIDATE_CORPUS")
    extraction = frozen_authority(common_entry("synthetic-extraction-b3", "CANDIDATE_OBJECT_EXTRACTION_RULE"))
    candidate = candidate_commitment(corpus, extraction)
    return admission_record(candidate)


class ZeroProofFreshnessTests(unittest.TestCase):
    def setUp(self):
        if _IMPORT_ERROR is not None:
            self.fail(f"R2_ADMISSION_NOT_IMPLEMENTED: {_IMPORT_ERROR}")

    def test_field_pin_zero_proof_requires_current_contract_and_evidence(self):
        admission = admission_fixture()
        proof = field_pin_zero_proof(admission)
        context = {
            "machine_field_pin_authority_input_set_id": "synthetic-field-pin-input-set-r2",
            "field_pin_authority_evaluation_contract_id": "synthetic-field-pin-evaluation-contract-r2",
            "machine_authority_evaluation_evidence_id": "synthetic-field-pin-evidence-r2",
            "admission_record_id": admission["admission_record_id"],
            "admission_tuple_id": proof["admission_tuple_id"],
            "admitted_exact_RFC6901_pointer_utf8_sha256": admission["exact_RFC6901_pointer_utf8_sha256"],
        }
        self.assertTrue(validate_field_pin_zero_proof_freshness(proof, context))
        for field in ("field_pin_authority_evaluation_contract_id", "machine_authority_evaluation_evidence_id", "machine_field_pin_authority_input_set_id"):
            stale = copy.deepcopy(proof)
            stale[field] = "stale-" + field
            stale["no_machine_field_pin_authority_proof_id"] = __import__("tests.fixtures", fromlist=["with_id"]).with_id(stale, "no_machine_field_pin_authority_proof_id")["no_machine_field_pin_authority_proof_id"]
            with self.assertRaisesRegex(ContractError, "STALE_FIELD_PIN_ZERO_PROOF"):
                validate_field_pin_zero_proof_freshness(stale, context)

    def test_source_admission_zero_proof_requires_current_contract_and_evidence(self):
        proof = source_admission_zero_proof()
        context = {
            "machine_authority_input_set_id": "synthetic-authority-input-set-r2",
            "source_admission_evaluation_contract_id": "synthetic-admission-evaluation-contract-r2",
            "machine_authority_evaluation_evidence_id": "synthetic-admission-evidence-r2",
        }
        self.assertTrue(validate_source_admission_zero_proof_freshness(proof, context))
        stale = copy.deepcopy(proof)
        stale["machine_authority_evaluation_evidence_id"] = "wrong-evidence"
        stale["source_admission_machine_zero_proof_id"] = __import__("tests.fixtures", fromlist=["with_id"]).with_id(stale, "source_admission_machine_zero_proof_id")["source_admission_machine_zero_proof_id"]
        with self.assertRaisesRegex(ContractError, "STALE_SOURCE_ADMISSION_ZERO_PROOF"):
            validate_source_admission_zero_proof_freshness(stale, context)

    def test_human_admission_requires_exact_zero_proof_and_cannot_override_conflict(self):
        proof = source_admission_zero_proof()
        context = {
            "machine_authority_input_set_id": "synthetic-authority-input-set-r2",
            "source_admission_evaluation_contract_id": "synthetic-admission-evaluation-contract-r2",
            "machine_authority_evaluation_evidence_id": "synthetic-admission-evidence-r2",
        }
        self.assertTrue(validate_human_admission_eligibility(proof, context, machine_conflict_count=0))
        with self.assertRaisesRegex(ContractError, "HUMAN_ADMISSION_FORBIDDEN_ON_MACHINE_CONFLICT"):
            validate_human_admission_eligibility(proof, context, machine_conflict_count=1)


if __name__ == "__main__":
    unittest.main()
