import copy
import unittest

from tests.fixtures import authority_evidence, authority_expansion, common_entry, common_manifest, frozen_authority, with_id

try:
    from tools.authority import derive_machine_authority_context
    from tools.records import ContractError
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


def graph():
    entries = [common_entry(f"synthetic-root-{index}", role, f"root-{index}\n".encode()) for index, role in enumerate(ROLES)]
    manifest = common_manifest(entries)
    authorities = [frozen_authority(entry) for entry in entries]
    expansions = [authority_expansion(record, evaluation_contract_id=CONTRACT_ID) for record in authorities]
    return manifest, authorities, expansions, authority_evidence(authorities, expansions)


class AuthenticatedAuthorityGraphTests(unittest.TestCase):
    def setUp(self):
        if _IMPORT_ERROR is not None:
            self.fail(f"R2_AUTHORITY_GRAPH_NOT_IMPLEMENTED: {_IMPORT_ERROR}")

    def test_valid_synthetic_graph_derives_status_and_ordered_input_set(self):
        manifest, authorities, expansions, evidence = graph()
        context = derive_machine_authority_context(manifest, authorities, expansions, ROLES, CONTRACT_ID, evidence)
        self.assertEqual(context["valid_tuple_count"], 0)
        self.assertEqual(context["evaluation_contract_id"], CONTRACT_ID)
        self.assertEqual([row["authority_role"] for row in context["ordered_artifact_records"]], sorted(ROLES, key=lambda value: value.encode("utf-8")))
        self.assertTrue(context["derived_available"])
        self.assertTrue(context["derived_authenticated"])
        self.assertTrue(context["derived_provenance_valid"])
        self.assertTrue(context["derived_evaluation_complete"])

    def test_caller_authenticated_boolean_without_frozen_record_is_rejected(self):
        manifest, _, expansions, evidence = graph()
        caller_summary = [{"authenticated": True, "available": True, "provenance_valid": True, "evaluation_complete": True}]
        with self.assertRaisesRegex(ContractError, "CALLER_TRUSTED_STATUS_REJECTED"):
            derive_machine_authority_context(manifest, caller_summary, expansions, ROLES, CONTRACT_ID, evidence)

    def test_wrong_artifact_hash_fails(self):
        manifest, authorities, expansions, evidence = graph()
        manifest["entries"][0]["content_sha256_observed"] = "f" * 64
        manifest["entries"][0] = with_id(manifest["entries"][0], "common_input_entry_id")
        manifest = with_id(manifest, "common_input_set_id")
        with self.assertRaisesRegex(ContractError, "COMMON_INPUT_CONTENT_IDENTITY_MISMATCH"):
            derive_machine_authority_context(manifest, authorities, expansions, ROLES, CONTRACT_ID, evidence)

    def test_wrong_authority_role_fails(self):
        manifest, authorities, expansions, evidence = graph()
        authorities[0]["authority_role"] = "WRONG_ROLE"
        authorities[0] = with_id(authorities[0], "authority_record_id")
        with self.assertRaisesRegex(ContractError, "AUTHORITY_COMMON_INPUT_MISMATCH"):
            derive_machine_authority_context(manifest, authorities, expansions, ROLES, CONTRACT_ID, evidence)

    def test_wrong_provenance_fails(self):
        manifest, authorities, expansions, evidence = graph()
        authorities[0]["provenance_id"] = "wrong-provenance"
        authorities[0] = with_id(authorities[0], "authority_record_id")
        with self.assertRaisesRegex(ContractError, "AUTHORITY_COMMON_INPUT_MISMATCH"):
            derive_machine_authority_context(manifest, authorities, expansions, ROLES, CONTRACT_ID, evidence)

    def test_root_not_in_common_input_fails(self):
        manifest, authorities, expansions, evidence = graph()
        outside_entry = common_entry("outside-root", ROLES[0], b"outside\n")
        authorities[0] = frozen_authority(outside_entry)
        expansions[0] = authority_expansion(authorities[0], evaluation_contract_id=CONTRACT_ID)
        with self.assertRaisesRegex(ContractError, "AUTHORITY_NOT_IN_COMMON_INPUT"):
            derive_machine_authority_context(manifest, authorities, expansions, ROLES, CONTRACT_ID, evidence)

    def test_incomplete_expansion_fails(self):
        manifest, authorities, expansions, evidence = graph()
        expansions[0] = authority_expansion(authorities[0], evaluation_contract_id=CONTRACT_ID, complete=False)
        with self.assertRaisesRegex(ContractError, "INCOMPLETE_AUTHORITY_ENUMERATION"):
            derive_machine_authority_context(manifest, authorities, expansions, ROLES, CONTRACT_ID, evidence)

    def test_missing_root_is_not_zero(self):
        manifest, authorities, expansions, evidence = graph()
        with self.assertRaisesRegex(ContractError, "MISSING_AUTHORITY_ROOT_NOT_ZERO"):
            derive_machine_authority_context(manifest, authorities[:-1], expansions[:-1], ROLES, CONTRACT_ID, evidence)


if __name__ == "__main__":
    unittest.main()
