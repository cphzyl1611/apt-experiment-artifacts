from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path
import tempfile
import unittest

from tools import materialize_p0_p1_contract as contract


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DESIGN_SHA256 = "5465c2047604b616c4966678b5fb1e823020be8011e655fb5582c556c04a837f"
EXPECTED_CANDIDATE_ID = "36831020b75a201420bd5cfce97a54ada12d44246f56a7812455bc21b99f9477"
EXPECTED_H2_ID = "939cc0c72e77bc437f0ab436cdf61c276d0ba1959273bbe0f46344e77ddff99e"
EXPECTED_ACTIVATION_ID = "bf4569d2116ac16a994feda733468faf2eeac92cc1f6eda46a77eac7312b718f"


class CanonicalizationTests(unittest.TestCase):
    def test_rfc8785_project_canonicalization_is_ordered_and_nfc_checked(self):
        self.assertEqual(
            contract.project_canonical_json({"b": 2, "a": 1}),
            b'{"a":1,"b":2}',
        )
        # RFC 8785 orders object names by UTF-16 code units, not locale/code-point collation.
        self.assertEqual(
            contract.project_canonical_json({"\ue000": 1, "\U00010000": 2}),
            '{"\U00010000":2,"\ue000":1}'.encode("utf-8"),
        )
        with self.assertRaises(ValueError):
            contract.strict_json_loads('{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            contract.project_canonical_json({"n": 1.5})
        with self.assertRaises(ValueError):
            contract.project_canonical_json({"n": "e\u0301"})


class AuthenticationTests(unittest.TestCase):
    def test_authenticates_exact_design_authority_and_scope_sets(self):
        auth = contract.authenticate_inputs(ROOT)
        self.assertEqual(auth.design_sha256, EXPECTED_DESIGN_SHA256)
        self.assertEqual(auth.candidate_id, EXPECTED_CANDIDATE_ID)
        self.assertEqual(auth.h2_evidence_id, EXPECTED_H2_ID)
        self.assertEqual(auth.activation_transaction_id, EXPECTED_ACTIVATION_ID)
        self.assertEqual(len(auth.raw_keys), 86)
        self.assertEqual(len(auth.relations), 4219)
        self.assertEqual(len(auth.hard_negative_relation_ids), 58)
        self.assertEqual(len(auth.human_review_relation_ids), 4161)
        self.assertEqual(auth.scope_object, auth.v4_scope_object)


class OrderingAndIsolationTests(unittest.TestCase):
    def test_ordering_registry_freezes_all_required_set_orderings(self):
        auth = contract.authenticate_inputs(ROOT)
        registry = contract.build_set_ordering_registry(auth)
        self.assertEqual(registry["canonicalization_contract"], "PROJECT_CANONICAL_JSON_V1")
        names = {entry["schema_field_path"] for entry in registry["entries"]}
        self.assertTrue({
            "exact_current86_raw_set",
            "relation_set",
            "per_raw_complete_candidate_universe_entries",
            "normative_evidence_fact_set",
            "owner_terminal_raw_set",
            "escalation_terminal_raw_set",
            "p3_current_state_partition_sets",
        } <= names)
        self.assertEqual(
            registry["set_ordering_registry_id"],
            contract.canonical_object_id(registry, "set_ordering_registry_id"),
        )

    def test_ordering_registry_and_candidate_universes_are_repeatable_and_complete(self):
        auth = contract.authenticate_inputs(ROOT)
        first = contract.build_set_ordering_registry(auth)
        second = contract.build_set_ordering_registry(auth)
        self.assertEqual(first, second)
        for raw_entry in auth.candidate_registry["raw_candidate_sets"]:
            relations = raw_entry["candidate_relations"]
            self.assertEqual(
                relations,
                sorted(relations, key=lambda item: (
                    item["candidate_scoring_id"].encode("utf-8"),
                    item["relation_identity"].encode("utf-8"),
                )),
            )
            self.assertEqual(raw_entry["candidate_relation_count"], len(relations))

    def test_m2_isolation_requires_set_disjointness_and_common_input_equality(self):
        auth = contract.authenticate_inputs(ROOT)
        ordering = contract.build_set_ordering_registry(auth)
        isolation = contract.build_isolation_enforcement_contract(auth, ordering)
        self.assertEqual(isolation["verifier_precommit_readable_input_set"]
                         .__class__, list)
        self.assertTrue(contract.validate_isolation_contract(isolation))
        self.assertTrue(set(isolation["verifier_precommit_readable_input_set"]) .isdisjoint(
            set(isolation["primary_private_or_commitment_output_set"])
        ))
        forged = json.loads(json.dumps(isolation))
        forged["verifier_precommit_readable_input_set"].append(
            forged["primary_private_or_commitment_output_set"][0]
        )
        with self.assertRaises(ValueError):
            contract.validate_isolation_contract(forged)


class DispositionTests(unittest.TestCase):
    def _record(self, raw: str, seq: int, typ: str, prior: str | None,
                prior_state: str | None, next_state: str, **refs):
        def exact_id(value):
            if value is None:
                return None
            if isinstance(value, str) and len(value) == 64:
                return value
            return hashlib.sha256(str(value).encode("utf-8")).hexdigest()
        value = {
            "schema": "A2_AUTHORITATIVE_DISPOSITION_RECORD_V1",
            "raw_key": raw,
            "disposition_type": typ,
            "prior_state": prior_state,
            "next_state": next_state,
            "disposition_sequence": seq,
            "prior_disposition_id": prior,
            "referenced_attempt_id": exact_id(refs.get("attempt")),
            "referenced_pending_terminal_id": exact_id(refs.get("pending")),
            "referenced_review_id": exact_id(refs.get("review")),
            "referenced_accepted_terminal_id": exact_id(refs.get("accepted")),
            "remediation_reference": exact_id(refs.get("remediation") or ("remediation" if typ == "REMEDIATION_RESTARTED" else None)),
            "reason_class": refs.get("reason"),
        }
        value["disposition_id"] = contract.canonical_object_id(value, "disposition_id")
        return value

    def test_valid_chain_and_stale_pending_exclusion(self):
        raw = "6000002::S02::A001"
        r0 = self._record(raw, 0, "INITIAL_STATE", None, None, "NOT_STARTED_FOR_ADJUDICATION")
        r1 = self._record(raw, 1, "EXECUTION_STARTED", r0["disposition_id"],
                          "NOT_STARTED_FOR_ADJUDICATION", "IN_PROGRESS_OR_INCOMPLETE")
        r2 = self._record(raw, 2, "PENDING_TERMINAL_CREATED", r1["disposition_id"],
                          "IN_PROGRESS_OR_INCOMPLETE", "PENDING_REVIEW", pending="p-old")
        r3 = self._record(raw, 3, "PENDING_TERMINAL_INVALIDATED", r2["disposition_id"],
                          "PENDING_REVIEW", "BLOCKED_ATTEMPT", pending="p-old", review="review-1",
                          reason="SUBSTANTIVE_TERMINAL_REJECTION")
        result = contract.validate_disposition_chain([r0, r1, r2, r3])
        self.assertEqual(result["current_state"], "BLOCKED_ATTEMPT")
        self.assertEqual(result["current_pending_terminal_id"], None)

    def test_accepted_terminal_supersedes_historical_blocked_state(self):
        raw = "6000002::S02::A001"
        r0 = self._record(raw, 0, "INITIAL_STATE", None, None, "NOT_STARTED_FOR_ADJUDICATION")
        r1 = self._record(raw, 1, "EXECUTION_STARTED", r0["disposition_id"],
                          "NOT_STARTED_FOR_ADJUDICATION", "IN_PROGRESS_OR_INCOMPLETE")
        r2 = self._record(raw, 2, "ATTEMPT_BLOCKED", r1["disposition_id"],
                          "IN_PROGRESS_OR_INCOMPLETE", "BLOCKED_ATTEMPT", reason="TECHNICAL_FAILURE")
        r3 = self._record(raw, 3, "REMEDIATION_RESTARTED", r2["disposition_id"],
                          "BLOCKED_ATTEMPT", "IN_PROGRESS_OR_INCOMPLETE")
        r4 = self._record(raw, 4, "PENDING_TERMINAL_CREATED", r3["disposition_id"],
                          "IN_PROGRESS_OR_INCOMPLETE", "PENDING_REVIEW", pending="p-new")
        r5 = self._record(raw, 5, "TERMINAL_ACCEPTED", r4["disposition_id"],
                          "PENDING_REVIEW", "ACCEPTED_TERMINAL", pending="p-new", review="review-2",
                          accepted="accepted-1")
        result = contract.validate_disposition_chain([r0, r1, r2, r3, r4, r5])
        self.assertEqual(result["current_state"], "ACCEPTED_TERMINAL")
        self.assertIsNone(result["current_pending_terminal_id"])

    def test_fork_duplicate_sequence_and_missing_parent_fail_closed(self):
        raw = "6000002::S02::A001"
        r0 = self._record(raw, 0, "INITIAL_STATE", None, None, "NOT_STARTED_FOR_ADJUDICATION")
        r1 = self._record(raw, 1, "EXECUTION_STARTED", r0["disposition_id"],
                          "NOT_STARTED_FOR_ADJUDICATION", "IN_PROGRESS_OR_INCOMPLETE")
        fork = self._record(raw, 1, "ATTEMPT_BLOCKED", r0["disposition_id"],
                            "NOT_STARTED_FOR_ADJUDICATION", "BLOCKED_ATTEMPT")
        with self.assertRaises(ValueError):
            contract.validate_disposition_chain([r0, r1, fork])
        missing = self._record(raw, 2, "PENDING_TERMINAL_CREATED", "not-a-parent",
                               "IN_PROGRESS_OR_INCOMPLETE", "PENDING_REVIEW", pending="p")
        with self.assertRaises(ValueError):
            contract.validate_disposition_chain([r0, r1, missing])

    def test_reviewer_infrastructure_failure_keeps_pending_and_pauses(self):
        outcome = contract.reviewer_infrastructure_failure("PENDING_REVIEW")
        self.assertEqual(outcome, {"current_state": "PENDING_REVIEW", "global_pause": True,
                                   "append_disposition": False})


class MaterializationTests(unittest.TestCase):
    def test_materializes_contract_only_package_and_deterministic_pilot(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "package"
            summary = contract.materialize(ROOT, out)
            self.assertEqual(summary["PILOT_RAW_KEY"], "6000002::S02::A001")
            self.assertEqual(summary["P0_EXECUTED"], "NO")
            self.assertEqual(summary["P1_EXECUTED"], "NO")
            self.assertEqual(summary["RAW_LEVEL_HUMAN_DECISIONS"], 0)
            self.assertEqual(summary["BINDING_PUBLICATION"], "NO")
            self.assertTrue((out / "00_lineage").is_dir())
            self.assertTrue((out / "02_set_ordering/SET_ORDERING_REGISTRY.json").is_file())
            self.assertTrue((out / "03_isolation/A2_VERIFIER_ISOLATION_ENFORCEMENT_CONTRACT.json").is_file())
            self.assertTrue((out / "a2_pilot_selection.json").is_file())
            forbidden = {"execution_attempt_ledger.jsonl", "pending_terminal_ledger.jsonl",
                         "accepted_terminal_ledger.jsonl", "human_decision_record.jsonl"}
            self.assertFalse(forbidden & {p.name for p in out.rglob("*") if p.is_file()})
            contract.verify_package(out)

    def test_owner_and_escalation_schema_nullability_is_explicit(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "package"
            contract.materialize(ROOT, out)
            schemas = json.loads((out / "05_schemas/schema_registry.json").read_text())
            owner = schemas["schemas"]["owner_terminal"]
            escalation = schemas["schemas"]["escalation_terminal"]
            self.assertEqual(owner["properties"]["escalation_class"], {"const": None})
            self.assertEqual(escalation["properties"]["selected_owner_candidate_scoring_id"], {"const": None})
            self.assertEqual(len(owner["oneOf"]), 2)
            self.assertEqual(len(escalation["oneOf"]), 3)
            self.assertTrue(owner["x-cross-field-constraints"])
            self.assertTrue(escalation["x-cross-field-constraints"])

    def test_workload_only_mutation_changes_package_not_normative_identity(self):
        normative = {"scope": "scope-id", "accepted": ["raw"]}
        package_a = {"normative": normative, "workload_summary": {"ms": 1}}
        package_b = {"normative": normative, "workload_summary": {"ms": 2}}
        self.assertEqual(contract.normative_freeze_id(package_a["normative"]),
                         contract.normative_freeze_id(package_b["normative"]))
        self.assertNotEqual(contract.package_manifest_id(package_a), contract.package_manifest_id(package_b))

    def test_p4_files_are_schemas_only_without_freeze_ids(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "package"
            contract.materialize(ROOT, out)
            normative = json.loads((out / "08_p4_identity_separation_contract/FINAL_FREEZE_NORMATIVE_MANIFEST.schema.json").read_text())
            package = json.loads((out / "08_p4_identity_separation_contract/FINAL_FREEZE_PACKAGE_MANIFEST.schema.json").read_text())
            self.assertEqual(normative["materialization_status"], "SCHEMA_ONLY_NO_P4_FREEZE")
            self.assertNotIn("CURRENT86_A2_FINAL_FREEZE_ID", normative)
            self.assertEqual(package["materialization_status"], "SCHEMA_ONLY_NO_P4_FREEZE")
            self.assertNotIn("FINAL_FREEZE_PACKAGE_MANIFEST_ID", package)


if __name__ == "__main__":
    unittest.main()
