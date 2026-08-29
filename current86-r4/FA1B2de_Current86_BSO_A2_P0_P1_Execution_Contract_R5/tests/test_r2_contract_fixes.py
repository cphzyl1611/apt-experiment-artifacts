from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools import materialize_p0_p1_contract as contract


ROOT = Path(__file__).resolve().parents[1]


class B1OrderingRegressionTests(unittest.TestCase):
    def setUp(self):
        self.auth = contract.authenticate_inputs(ROOT)
        self.registry = contract.build_set_ordering_registry(self.auth)

    def test_relation_ordering_is_identity_only_and_manifest_recomputes_from_registry(self):
        relation_entry = next(e for e in self.registry["entries"] if e["schema_field_path"] == "relation_set")
        self.assertEqual(relation_entry["element_identity_field_or_tuple"], "relation_identity")
        self.assertEqual(relation_entry["comparison_rule"], "BYTEWISE_ASCENDING_UTF8")
        manifest = contract.build_execution_manifest(
            self.auth,
            self.registry,
            (isolation := contract.build_isolation_enforcement_contract(self.auth, self.registry)),
            {"computational_contract_id": "0" * 64},
            {"computational_contract_id": "1" * 64},
            contract.build_schema_registry(self.auth, self.registry, isolation),
        )
        expected = contract.hash_declared_set("relation_set", list(self.auth.relations), self.registry)
        self.assertEqual(manifest["exact_current86_relation_set_hash"], expected)

    def test_tuple_ordering_is_rejected_and_unregistered_sets_fail_closed(self):
        tuple_hash = contract.sha256_bytes(contract.project_canonical_json(sorted(
            self.auth.relations,
            key=lambda x: (x["raw_key"].encode("utf-8"), x["candidate_scoring_id"].encode("utf-8"), x["relation_identity"].encode("utf-8")),
        )))
        identity_hash = contract.hash_declared_set("relation_set", list(self.auth.relations), self.registry)
        self.assertNotEqual(tuple_hash, identity_hash)
        with self.assertRaises(ValueError):
            contract.validate_declared_set_hash("relation_set", tuple_hash, list(self.auth.relations), self.registry)
        with self.assertRaises(ValueError):
            contract.hash_declared_set("unregistered_normative_set", [], self.registry)

    def test_evidence_uses_one_identity_field_and_rejects_duplicates(self):
        entry = next(e for e in self.registry["entries"] if e["schema_field_path"] == "normative_evidence_fact_set")
        self.assertEqual(entry["element_identity_field_or_tuple"], "source_fact_id")
        facts = [{"source_fact_id": "b" * 64}, {"source_fact_id": "a" * 64}]
        self.assertEqual(
            contract.order_declared_set("normative_evidence_fact_set", facts, self.registry),
            [facts[1], facts[0]],
        )
        with self.assertRaises(ValueError):
            contract.order_declared_set(
                "normative_evidence_fact_set",
                [facts[0], dict(facts[0])],
                self.registry,
            )


class B2RuntimeIsolationRegressionTests(unittest.TestCase):
    def test_role_contracts_bind_actual_runtime_and_role_tool_mode(self):
        auth = contract.authenticate_inputs(ROOT)
        ordering = contract.build_set_ordering_registry(auth)
        isolation = contract.build_isolation_enforcement_contract(auth, ordering)
        schemas = contract.build_schema_registry(auth, ordering, isolation)
        primary = contract.build_computational_contract("PRIMARY", auth, ordering, isolation, schemas)
        verifier = contract.build_computational_contract("VERIFIER", auth, ordering, isolation, schemas)
        for role_contract, role, entrypoint in (
            (primary, "PRIMARY", "tools/run_a2_primary.py"),
            (verifier, "VERIFIER", "tools/run_a2_verifier.py"),
        ):
            self.assertEqual(role_contract["static_execution_implementation_identity"]["entrypoint"], entrypoint)
            self.assertNotEqual(entrypoint, "tools/materialize_p0_p1_contract.py")
            self.assertEqual(role_contract["model_runtime_identity"]["tool_mode"], f"A2_{role}_ROLE_RUNTIME")
            self.assertIn("execution_time_runtime_binding", role_contract)
            self.assertIn("context_identity", role_contract["execution_time_runtime_binding"])
            self.assertIn("run_identity", role_contract["execution_time_runtime_binding"])

    def test_execution_time_binding_fails_closed_for_missing_stable_fields(self):
        binding = contract.capture_execution_time_runtime_binding(
            {"provider": "p", "model_id": "m", "tool_mode": "A2_PRIMARY_ROLE_RUNTIME", "context_identity": "c", "run_identity": "r"}
        )
        self.assertEqual(binding["provider"]["value"], "p")
        self.assertEqual(binding["model_id"]["value"], "m")
        self.assertEqual(binding["context_identity"]["value"], "c")
        self.assertEqual(binding["run_identity"]["value"], "r")
        with self.assertRaises(ValueError):
            contract.capture_execution_time_runtime_binding({"tool_mode": "A2_PRIMARY_ROLE_RUNTIME"})

    def test_os_isolation_probe_reads_common_and_denies_private_and_commitment(self):
        with tempfile.TemporaryDirectory() as td:
            result = contract.run_isolation_probe(Path(td))
        self.assertTrue(result["common_frozen_sentinel_readable"])
        self.assertFalse(result["primary_private_sentinel_readable"])
        self.assertFalse(result["primary_commitment_sentinel_readable"])
        self.assertTrue(result["prohibited_read_failed_at_boundary"])


class B3HumanTerminalRegressionTests(unittest.TestCase):
    def _registry(self):
        auth = contract.authenticate_inputs(ROOT)
        ordering = contract.build_set_ordering_registry(auth)
        isolation = contract.build_isolation_enforcement_contract(auth, ordering)
        return contract.build_schema_registry(auth, ordering, isolation)

    def _base(self):
        h = "a" * 64
        return {
            "schema": "A2_OWNER_OR_ESCALATION_TERMINAL_V2",
            "raw_key": "6000002::S02::A001",
            "proposed_candidate_scoring_id": "b" * 64,
            "proposed_relation_identity": "c" * 64,
            "complete_candidate_universe_hash": "d" * 64,
            "complete_candidate_count": 2,
            "primary_commitment_id": h,
            "verifier_commitment_id": "e" * 64,
            "comparison_id": "f" * 64,
            "raw_side_evidence_fact_ids": ["1" * 64],
            "candidate_side_evidence_fact_ids": ["2" * 64],
            "concise_source_grounded_basis": "basis",
            "full_candidate_option_mapping": [
                {"packet_local_human_option_id": "option-1", "candidate_scoring_id": "b" * 64, "relation_identity": "c" * 64, "candidate_label_or_reference": "candidate one"},
                {"packet_local_human_option_id": "option-2", "candidate_scoring_id": "0" * 64, "relation_identity": "1" * 64, "candidate_label_or_reference": "candidate two"},
            ],
            "human_packet_id": h,
            "human_packet_hash": h,
        }

    def test_three_human_actions_and_owner_terminal_paths_are_mechanical(self):
        packet = self._base()
        packet.update({
            "candidate_count": 2,
            "authenticated_raw_action_reference": "raw-action-ref",
            "raw_side_evidence_source_references": [{"source_fact_id": "1" * 64}],
            "candidate_side_evidence_source_references": [{"source_fact_id": "2" * 64}],
            "complete_universe_expansion_audit": {"option_mapping_hash": contract.sha256_bytes(contract.project_canonical_json(packet["full_candidate_option_mapping"])), "expanded_option_count": 2, "complete_candidate_count_exact_match": True},
            "human_input_mode": "PACKET_LOCAL_OPTION_ONLY_NO_MANUAL_ID_OR_HASH_ENTRY",
        })
        with self.assertRaises(ValueError):
            contract.validate_human_packet(packet)
        for action in ("CONFIRM_PROPOSED_OWNER", "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE", "NOT_SURE_ESCALATE"):
            decision = {"schema": "A2_HUMAN_DECISION_RECORD_V2", "human_action": action, "human_provenance": {"event_id": "1" * 64}}
            if action == "CONFIRM_PROPOSED_OWNER":
                decision.update({"human_selected_candidate_scoring_id": "b" * 64, "human_selected_relation_identity": "c" * 64})
            elif action == "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE":
                decision.update({"selected_packet_option_id": "option-2", "human_selected_candidate_scoring_id": "0" * 64, "human_selected_relation_identity": "1" * 64, "fresh_alternative_verification": "PASS"})
            else:
                decision.update({"human_selected_candidate_scoring_id": None, "human_selected_relation_identity": None})
            with self.assertRaises(ValueError):
                contract.validate_human_decision(packet, decision)
        owner = {"terminal_record_class": "A2_OWNER_ADJUDICATION_FROZEN", "human_action": "NOT_SURE_ESCALATE", "unresolved_state": False, "selected_owner_candidate_scoring_id": "b" * 64}
        with self.assertRaises(ValueError):
            contract.validate_owner_terminal(owner)

    def test_alternative_mismatch_and_failed_alternative_are_escalations(self):
        packet = self._base()
        bad = {"schema": "A2_HUMAN_DECISION_RECORD_V2", "human_action": "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE", "human_provenance": {"event_id": "1" * 64}, "selected_packet_option_id": "option-2", "human_selected_candidate_scoring_id": "b" * 64, "human_selected_relation_identity": "1" * 64, "fresh_alternative_verification": "PASS"}
        with self.assertRaises(ValueError):
            contract.validate_human_decision(packet, bad)
        escalation = contract.build_escalation_terminal("PRE_HUMAN_PROPOSER_VERIFIER_DISAGREEMENT")
        self.assertIsNone(escalation["human_action"])
        self.assertTrue(escalation["unresolved_state"])
        self.assertTrue(contract.validate_escalation_terminal(escalation))
        human_escalation = contract.build_escalation_terminal("HUMAN_NOT_SURE", human_provenance={"event_id": "1" * 64})
        self.assertTrue(contract.validate_escalation_terminal(human_escalation))
        failed_alternative = contract.build_escalation_terminal("HUMAN_SELECTED_ALTERNATIVE_VERIFICATION_FAILED", human_provenance={"event_id": "1" * 64})
        failed_alternative["human_action"] = "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE"
        self.assertTrue(contract.validate_escalation_terminal(failed_alternative))
        with self.assertRaises(ValueError):
            contract.build_escalation_terminal("TECHNICAL_EXECUTION_DEFECT")

    def test_json_schemas_enforce_owner_and_escalation_branches(self):
        registry = self._registry()
        h = lambda c: c * 64
        base = {"schema": "A2_TERMINAL_V2", "authority_version_id": h("a"), "authority_scope_id": h("b"), "raw_key": "6000002::S02::A001", "complete_candidate_universe_hash": h("c"), "complete_candidate_relation_set_hash": h("d"), "input_bundle_hash": h("e"), "proposal_hash": h("f"), "proposal_evidence_set_hash": h("0"), "primary_derivation_commitment_hash": h("1"), "primary_run_identity": "primary-run", "verifier_derivation_commitment_hash": h("2"), "verifier_run_identity": "verifier-run", "hard_gate_results": {}, "terminal_record_hash": h("3")}
        human = {"human_origin_provenance_evidence_id": h("4"), "human_origin_provenance_verification": "PASS", "human_decision_record_id": h("5"), "human_provenance": {"event_id": h("6")}}
        owner = {**base, **human, "terminal_record_class": "A2_OWNER_ADJUDICATION_FROZEN", "independent_commitment_comparison": "PASS", "all_hard_gates": "PASS", "human_action": "CONFIRM_PROPOSED_OWNER", "selected_owner_candidate_scoring_id": h("7"), "selected_relation_identity": h("8"), "unresolved_state": False, "escalation_class": None, "selected_packet_option_id": None, "fresh_alternative_verification": None, "fresh_alternative_verification_id": None}
        self.assertTrue(contract.validate_schema_instance("owner_terminal", owner, registry))
        bad_owner = dict(owner, human_action="NOT_SURE_ESCALATE")
        with self.assertRaises(ValueError):
            contract.validate_schema_instance("owner_terminal", bad_owner, registry)
        alternative_owner = dict(owner, human_action="REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE", selected_packet_option_id="option-2", fresh_alternative_verification="PASS", fresh_alternative_verification_id=h("9"))
        self.assertTrue(contract.validate_schema_instance("owner_terminal", alternative_owner, registry))
        missing_option = dict(alternative_owner, selected_packet_option_id=None)
        with self.assertRaises(ValueError):
            contract.validate_schema_instance("owner_terminal", missing_option, registry)
        pre_human = {**base, "terminal_record_class": "A2_ESCALATION_FROZEN", "independent_commitment_comparison": "FAIL_CLOSED", "all_hard_gates": "INDETERMINATE", "human_action": None, "human_origin_provenance_evidence_id": None, "human_origin_provenance_verification": None, "human_decision_record_id": None, "human_provenance": None, "selected_owner_candidate_scoring_id": None, "selected_relation_identity": None, "unresolved_state": True, "escalation_class": "PRE_HUMAN_PROPOSER_VERIFIER_DISAGREEMENT", "selected_packet_option_id": None, "human_selected_alternative_candidate_scoring_id": None, "human_selected_alternative_relation_identity": None, "fresh_alternative_verification": None, "fresh_alternative_verification_id": None}
        self.assertTrue(contract.validate_schema_instance("escalation_terminal", pre_human, registry))
        not_sure = dict(pre_human, **human, independent_commitment_comparison="PASS", all_hard_gates="PASS", human_action="NOT_SURE_ESCALATE", escalation_class="HUMAN_NOT_SURE")
        self.assertTrue(contract.validate_schema_instance("escalation_terminal", not_sure, registry))
        technical = dict(pre_human, escalation_class="TECHNICAL_EXECUTION_DEFECT")
        with self.assertRaises(ValueError):
            contract.validate_schema_instance("escalation_terminal", technical, registry)


class B4SchemaDispositionRegressionTests(unittest.TestCase):
    def test_source_fact_schema_is_self_contained_and_validates_non_empty_facts(self):
        auth = contract.authenticate_inputs(ROOT)
        ordering = contract.build_set_ordering_registry(auth)
        isolation = contract.build_isolation_enforcement_contract(auth, ordering)
        registry = contract.build_schema_registry(auth, ordering, isolation)
        fact = {
            "schema": "A2_ADMISSIBLE_SOURCE_FACT_V2", "source_fact_id": "a" * 64, "source_artifact_identity": "artifact", "source_artifact_sha256_or_pinned_identity": "pin", "source_provenance_identity": "b" * 64, "source_fact_type": "PINNED_RAW_SOURCE_FIELD", "source_side": "RAW", "raw_key": "6000002::S02::A001", "candidate_scoring_id": None, "exact_field_path_or_claim_id": "x", "authenticated_value_canonical_json": {"v": 1}, "authenticated_value_sha256": "c" * 64, "admissible_source_fact_id": "d" * 64,
        }
        bundle = {"schema": "A2_SOURCE_FACT_BUNDLE_V2", "raw_key": "6000002::S02::A001", "facts": [fact], "source_registry_id": "e" * 64, "normative_source_profile_hash": "f" * 64, "source_bundle_status": "RUNTIME_EXTRACTED", "authenticated_source_references": [], "source_bundle_hash": "0" * 64}
        self.assertTrue(contract.validate_schema_instance("source_fact_bundle", bundle, registry))
        bad = json.loads(json.dumps(bundle)); bad["facts"][0]["source_fact_id"] = "bad"
        with self.assertRaises(ValueError):
            contract.validate_schema_instance("source_fact_bundle", bad, registry)
        candidate_fact = dict(fact, source_fact_id="1" * 64, source_fact_type="PINNED_SCORING_ROW_FIELD", source_side="CANDIDATE", raw_key=None, candidate_scoring_id="2" * 64, source_provenance_identity="3" * 64, authenticated_value_sha256="4" * 64, admissible_source_fact_id="5" * 64)
        candidate_bundle = dict(bundle, raw_key="6000002::S02::A001", facts=[candidate_fact], source_bundle_status="RUNTIME_EXTRACTED")
        self.assertTrue(contract.validate_schema_instance("source_fact_bundle", candidate_bundle, registry))

    def test_disposition_lineage_required_fields_and_remediation_reference(self):
        record = {"schema": "A2_AUTHORITATIVE_DISPOSITION_RECORD_V2", "raw_key": "6000002::S02::A001", "disposition_type": "PENDING_TERMINAL_INVALIDATED", "prior_state": "PENDING_REVIEW", "next_state": "BLOCKED_ATTEMPT", "disposition_sequence": 1, "prior_disposition_id": "a" * 64, "referenced_pending_terminal_id": "b" * 64, "referenced_review_id": "c" * 64, "reason_class": "SUBSTANTIVE_TERMINAL_REJECTION", "referenced_attempt_id": None, "referenced_accepted_terminal_id": None, "disposition_id": None}
        record["disposition_id"] = contract.canonical_object_id(record, "disposition_id")
        with self.assertRaises(ValueError):
            contract.validate_disposition_record(record)
        for field in ("referenced_pending_terminal_id", "referenced_review_id", "reason_class"):
            bad = dict(record); bad[field] = None
            with self.assertRaises(ValueError):
                contract.validate_disposition_record(bad)
        remediation = dict(record, disposition_type="REMEDIATION_RESTARTED", prior_state="BLOCKED_ATTEMPT", next_state="IN_PROGRESS_OR_INCOMPLETE", remediation_reference=None)
        remediation["disposition_id"] = contract.canonical_object_id(remediation, "disposition_id")
        with self.assertRaises(ValueError):
            contract.validate_disposition_record(remediation)

    def test_terminal_acceptance_requires_all_three_exact_lineage_ids(self):
        record = {"schema": "A2_AUTHORITATIVE_DISPOSITION_RECORD_V2", "raw_key": "6000002::S02::A001", "disposition_type": "TERMINAL_ACCEPTED", "prior_state": "PENDING_REVIEW", "next_state": "ACCEPTED_TERMINAL", "disposition_sequence": 2, "prior_disposition_id": "a" * 64, "referenced_pending_terminal_id": "b" * 64, "referenced_review_id": "c" * 64, "referenced_accepted_terminal_id": "d" * 64, "referenced_attempt_id": None, "remediation_reference": None, "reason_class": None, "disposition_id": None}
        record["disposition_id"] = contract.canonical_object_id(record, "disposition_id")
        with self.assertRaises(ValueError):
            contract.validate_disposition_record(record)
        for field in ("referenced_pending_terminal_id", "referenced_review_id", "referenced_accepted_terminal_id"):
            bad = dict(record); bad[field] = None
            with self.assertRaises(ValueError):
                contract.validate_disposition_record(bad)

    def test_owner_confirm_and_reject_paths_require_human_provenance_and_pass(self):
        base = {"terminal_record_class": "A2_OWNER_ADJUDICATION_FROZEN", "unresolved_state": False, "selected_owner_candidate_scoring_id": "a" * 64, "selected_relation_identity": "b" * 64, "human_decision_record_id": "c" * 64, "human_provenance": {"event_id": "d" * 64}, "escalation_class": None}
        with self.assertRaises(ValueError):
            contract.validate_owner_terminal(dict(base, human_action="CONFIRM_PROPOSED_OWNER", fresh_alternative_verification=None))
        with self.assertRaises(ValueError):
            contract.validate_owner_terminal(dict(base, human_action="REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE", fresh_alternative_verification={"status": "PASS"}))

    def test_stale_pending_is_excluded_after_accepted_head(self):
        raw = "6000002::S02::A001"
        def make(seq, typ, prior_state, next_state, prior, **values):
            row = {"schema": "A2_AUTHORITATIVE_DISPOSITION_RECORD_V2", "raw_key": raw, "disposition_type": typ, "prior_state": prior_state, "next_state": next_state, "disposition_sequence": seq, "prior_disposition_id": prior, "referenced_attempt_id": None, "referenced_pending_terminal_id": values.get("pending"), "referenced_review_id": values.get("review"), "referenced_accepted_terminal_id": values.get("accepted"), "remediation_reference": values.get("remediation"), "reason_class": values.get("reason"), "disposition_id": None}
            row["disposition_id"] = contract.canonical_object_id(row, "disposition_id")
            return row
        r0 = make(0, "INITIAL_STATE", None, "NOT_STARTED_FOR_ADJUDICATION", None)
        r1 = make(1, "EXECUTION_STARTED", "NOT_STARTED_FOR_ADJUDICATION", "IN_PROGRESS_OR_INCOMPLETE", r0["disposition_id"])
        r2 = make(2, "PENDING_TERMINAL_CREATED", "IN_PROGRESS_OR_INCOMPLETE", "PENDING_REVIEW", r1["disposition_id"], pending="e" * 64)
        r3 = make(3, "TERMINAL_ACCEPTED", "PENDING_REVIEW", "ACCEPTED_TERMINAL", r2["disposition_id"], pending="e" * 64, review="f" * 64, accepted="0" * 64)
        pending = {"id": "e" * 64, "raw_key": raw}
        review = {"id": "f" * 64, "raw_key": raw, "status": "PASS", "referenced_pending_terminal_id": "e" * 64, "approved_terminal_id": "0" * 64}
        accepted = {"id": "0" * 64, "raw_key": raw, "referenced_pending_terminal_id": "e" * 64, "referenced_review_id": "f" * 64}
        graph = {"by_raw": {raw: {
            "pending_terminals": {pending["id"]: pending},
            "independent_reviews": {review["id"]: review},
            "accepted_terminals": {accepted["id"]: accepted},
        }}}
        result = contract.validate_disposition_chain([r0, r1, r2, r3], graph)
        self.assertEqual(result["current_state"], "ACCEPTED_TERMINAL")
        self.assertIsNone(result["current_pending_terminal_id"])


class R2LineagePackageRegressionTests(unittest.TestCase):
    def test_r2_package_contains_runtime_tests_patch_lineage_and_r2_archive(self):
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td)
            out = parent / "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R2"
            contract.materialize(ROOT, out)
            self.assertTrue((parent / "fa1b2de-current86-bso-a2-p0-p1-execution-contract-r2-review-input.tar.gz").is_file())
            for relative in (
                "tools/a2_role_runtime.py",
                "tools/a2_bwrap_isolation.py",
                "tools/run_a2_primary.py",
                "tools/run_a2_verifier.py",
                "09_tests/test_r2_contract_fixes.py",
                "00_lineage/FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R1_to_R2_Patch_Summary.json",
                "00_lineage/R1_TO_R2_DEFECT_REPRODUCTION_AND_TDD_LOG.json",
            ):
                self.assertTrue((out / relative).is_file(), relative)


if __name__ == "__main__":
    unittest.main()
