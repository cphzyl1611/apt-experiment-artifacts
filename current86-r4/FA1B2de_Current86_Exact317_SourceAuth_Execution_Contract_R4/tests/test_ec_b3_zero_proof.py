import copy
import unittest

from tests.fixtures import (
    admission_record,
    authority_evidence,
    authority_expansion,
    candidate_commitment,
    common_entry,
    common_manifest,
    field_pin_zero_proof,
    frozen_authority,
    source_admission_zero_proof,
    with_id,
)

from tools.admission import (
    validate_field_pin_zero_proof_freshness,
    validate_human_admission_eligibility,
    validate_source_admission_zero_proof_freshness,
)
from tools.authority import derive_machine_authority_context
from tools.canonical import ContractError


ROLES = (
    "EXACT_TARGET_POINTER_AUTHORITY",
    "FIELD_PIN_REGISTRY",
    "DETERMINISTIC_CORPUS_SCHEMA_FIELD_PIN_RULE",
)
CONTRACT_ID = "synthetic-admission-evaluation-contract-r2"


def admission_fixture():
    corpus = common_entry("synthetic-corpus-b3", "CANDIDATE_CORPUS")
    extraction = frozen_authority(common_entry("synthetic-extraction-b3", "CANDIDATE_OBJECT_EXTRACTION_RULE"))
    candidate = candidate_commitment(corpus, extraction)
    return admission_record(candidate)


def derivation(contract_id=CONTRACT_ID, admission=None):
    entries = [common_entry(f"synthetic-b3-root-{index}", role, b"[]") for index, role in enumerate(ROLES)]
    manifest = common_manifest(entries)
    authorities = [frozen_authority(entry) for entry in entries]
    expansions = [authority_expansion(record, evaluation_contract_id=contract_id) for record in authorities]
    evidence = authority_evidence(authorities, expansions, evaluation_contract_id=contract_id)
    return derive_machine_authority_context(manifest, authorities, expansions, ROLES, contract_id, evidence, admission)


class ZeroProofFreshnessTests(unittest.TestCase):
    def test_field_pin_zero_proof_requires_current_contract_and_evidence(self):
        admission = admission_fixture()
        context = derivation(admission=admission)
        proof = field_pin_zero_proof(
            admission,
            input_set_id=context["machine_authority_input_set_id"],
            contract_id=context["evaluation_contract_id"],
            evidence_id=context["machine_authority_evaluation_evidence"]["machine_authority_evaluation_evidence_id"],
        )
        self.assertTrue(validate_field_pin_zero_proof_freshness(proof, context))
        for field in ("field_pin_authority_evaluation_contract_id", "machine_authority_evaluation_evidence_id", "machine_field_pin_authority_input_set_id"):
            stale = copy.deepcopy(proof)
            stale[field] = "stale-" + field
            stale["no_machine_field_pin_authority_proof_id"] = with_id(stale, "no_machine_field_pin_authority_proof_id")["no_machine_field_pin_authority_proof_id"]
            with self.assertRaisesRegex(ContractError, "STALE_FIELD_PIN_ZERO_PROOF"):
                validate_field_pin_zero_proof_freshness(stale, context)

    def test_source_admission_zero_proof_requires_current_contract_and_evidence(self):
        context = derivation()
        proof = source_admission_zero_proof(
            input_set_id=context["machine_authority_input_set_id"],
            contract_id=context["evaluation_contract_id"],
            evidence_id=context["machine_authority_evaluation_evidence"]["machine_authority_evaluation_evidence_id"],
        )
        self.assertTrue(validate_source_admission_zero_proof_freshness(proof, context))
        stale = copy.deepcopy(proof)
        stale["machine_authority_evaluation_evidence_id"] = "wrong-evidence"
        stale["source_admission_machine_zero_proof_id"] = with_id(stale, "source_admission_machine_zero_proof_id")["source_admission_machine_zero_proof_id"]
        with self.assertRaisesRegex(ContractError, "STALE_SOURCE_ADMISSION_ZERO_PROOF"):
            validate_source_admission_zero_proof_freshness(stale, context)

    def test_human_admission_requires_exact_zero_proof_and_cannot_override_conflict(self):
        context = derivation()
        proof = source_admission_zero_proof(
            input_set_id=context["machine_authority_input_set_id"],
            contract_id=context["evaluation_contract_id"],
            evidence_id=context["machine_authority_evaluation_evidence"]["machine_authority_evaluation_evidence_id"],
        )
        self.assertTrue(validate_human_admission_eligibility(proof, context, machine_conflict_count=0))
        with self.assertRaisesRegex(ContractError, "HUMAN_ADMISSION_FORBIDDEN_ON_MACHINE_CONFLICT"):
            validate_human_admission_eligibility(proof, context, machine_conflict_count=1)


if __name__ == "__main__":
    unittest.main()
