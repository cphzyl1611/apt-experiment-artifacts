from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from tools import materialize_p0_p1_contract as contract


class B2ExecutionBoundRuntimeR3Tests(unittest.TestCase):
    def _bundle(self, root: Path) -> Path:
        bundle = {
            "proposal_input_bundle_id": "",
            "raw_key": "6000002::S02::A001",
            "execution_manifest_id": "m" * 64,
            "complete_candidate_universe_hash": "u" * 64,
            "complete_candidate_relation_set_hash": "r" * 64,
            "input_status": "FROZEN_PREPARATION_ONLY",
        }
        bundle["proposal_input_bundle_id"] = contract.canonical_object_id(bundle, "proposal_input_bundle_id")
        path = root / "bundle.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        return path

    def _backend(self, root: Path, provider="bound-provider", model="bound-model") -> Path:
        script = root / "dummy_backend.py"
        script.write_text(
            "import json,sys\n"
            "cfg=json.loads(__import__('os').environ['A2_BACKEND_CONFIG'])\n"
            "print(json.dumps({'result_status':'PASS','selected_candidate_scoring_id':None,'selected_relation_identity':None,'evidence_fact_ids':[],'evidence_set_hash':None,'hard_gate_results':{},'runtime_identity':{'provider':cfg['provider'],'model_id':cfg['model_id'],'context_identity':cfg['context_identity'],'run_identity':cfg['run_identity']}}))\n",
            encoding="utf-8",
        )
        cfg = {
            "role": "PRIMARY",
            "frozen_configuration": True,
            "provider": provider,
            "model_id": model,
            "context_identity": "ctx-bound",
            "run_identity": "run-bound",
            "tool_mode": "A2_PRIMARY_ROLE_RUNTIME",
            "agent_or_cli_version_source": "dummy-backend/1",
            "command": ["/usr/bin/python3", str(script)],
            "capture_method": "SUBPROCESS_STDOUT_RUNTIME_IDENTITY_V1",
        }
        cfg["backend_implementation_hash"] = __import__("hashlib").sha256(script.read_bytes()).hexdigest()
        cfg["backend_configuration_id"] = contract.canonical_object_id(cfg, "backend_configuration_id")
        path = root / "backend.json"
        path.write_text(json.dumps(cfg), encoding="utf-8")
        return path

    def test_caller_cannot_override_provider_or_model_and_commitment_path_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bundle = self._bundle(root)
            backend = self._backend(root)
            output = root / "out.json"
            result = contract.execute_role_with_backend(
                "PRIMARY", bundle, backend, output,
                expected_execution_manifest_id="m" * 64,
                computational_contract_id="c" * 64,
            )
            self.assertEqual(result["runtime_binding"]["provider"]["value"], "bound-provider")
            self.assertEqual(result["runtime_binding"]["model_id"]["value"], "bound-model")
            with self.assertRaises(TypeError):
                contract.execute_role_with_backend(
                    "PRIMARY", bundle, backend, output,
                    expected_execution_manifest_id="m" * 64,
                    computational_contract_id="c" * 64,
                    provider="spoofed", model_id="spoofed",
                )

    def test_mismatched_backend_configuration_id_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bundle = self._bundle(root)
            backend = self._backend(root)
            cfg = json.loads(backend.read_text())
            cfg["backend_configuration_id"] = "0" * 64
            backend.write_text(json.dumps(cfg))
            with self.assertRaises(ValueError):
                contract.execute_role_with_backend("PRIMARY", bundle, backend, root / "out.json", expected_execution_manifest_id="m" * 64, computational_contract_id="c" * 64)

    def test_backend_spoofed_runtime_identity_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bundle = self._bundle(root)
            backend = self._backend(root)
            script = root / "dummy_backend.py"
            script.write_text("import json; print(json.dumps({'result_status':'PASS','selected_candidate_scoring_id':None,'selected_relation_identity':None,'evidence_fact_ids':[],'evidence_set_hash':None,'hard_gate_results':{},'runtime_identity':{'provider':'spoof','model_id':'spoof','context_identity':'ctx-bound','run_identity':'run-bound'}}))", encoding="utf-8")
            cfg = json.loads(backend.read_text())
            cfg["command"] = ["/usr/bin/python3", str(script)]
            cfg["backend_configuration_id"] = contract.canonical_object_id({k: v for k, v in cfg.items() if k != "backend_configuration_id"}, "backend_configuration_id")
            backend.write_text(json.dumps(cfg))
            with self.assertRaises(ValueError):
                contract.execute_role_with_backend("PRIMARY", bundle, backend, root / "out.json", expected_execution_manifest_id="m" * 64, computational_contract_id="c" * 64)


class B3CrossObjectR3Tests(unittest.TestCase):
    def setUp(self):
        self.proposal = {"candidate_scoring_id": "b" * 64, "relation_identity": "c" * 64}
        self.universe = {"candidate_relations": [self.proposal, {"candidate_scoring_id": "0" * 64, "relation_identity": "1" * 64}]}
        self.comparison = {"status": "AGREEMENT", "selected_candidate_scoring_id": "b" * 64, "selected_relation_identity": "c" * 64}

    def _packet(self):
        mapping = [
            {"packet_local_human_option_id": "option-1", **self.proposal},
            {"packet_local_human_option_id": "option-2", "candidate_scoring_id": "0" * 64, "relation_identity": "1" * 64},
        ]
        return {
            "proposed_candidate_scoring_id": "b" * 64,
            "proposed_relation_identity": "c" * 64,
            "complete_candidate_count": 2,
            "candidate_count": 2,
            "full_candidate_option_mapping": mapping,
            "raw_side_evidence_fact_ids": ["1" * 64], "raw_side_evidence_source_references": [{"source_fact_id": "1" * 64}],
            "candidate_side_evidence_fact_ids": ["2" * 64], "candidate_side_evidence_source_references": [{"source_fact_id": "2" * 64}],
            "complete_universe_expansion_audit": {"expanded_option_count": 2, "complete_candidate_count_exact_match": True, "option_mapping_hash": contract.sha256_bytes(contract.project_canonical_json(mapping))},
            "human_input_mode": "PACKET_LOCAL_OPTION_ONLY_NO_MANUAL_ID_OR_HASH_ENTRY",
        }

    def test_truncated_mapping_is_rejected_against_authenticated_universe(self):
        packet = self._packet()
        packet["full_candidate_option_mapping"] = packet["full_candidate_option_mapping"][:1]
        with self.assertRaises(ValueError):
            contract.validate_human_packet(packet, self.universe, self.comparison)

    def test_reject_select_original_proposal_is_rejected(self):
        packet = self._packet()
        decision = {"human_action": "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE", "selected_packet_option_id": "option-1", "human_selected_candidate_scoring_id": "b" * 64, "human_selected_relation_identity": "c" * 64, "fresh_alternative_verification": "PASS", "human_provenance": {"event_id": "e" * 64}}
        with self.assertRaises(ValueError):
            contract.validate_human_decision(packet, decision, self.comparison)

    def test_owner_unrelated_candidate_is_rejected(self):
        packet = self._packet()
        decision = {"human_action": "CONFIRM_PROPOSED_OWNER", "human_selected_candidate_scoring_id": "b" * 64, "human_selected_relation_identity": "c" * 64, "human_provenance": {"event_id": "e" * 64}}
        owner = {"terminal_record_class": "A2_OWNER_ADJUDICATION_FROZEN", "human_action": "CONFIRM_PROPOSED_OWNER", "unresolved_state": False, "selected_owner_candidate_scoring_id": "9" * 64, "selected_relation_identity": "8" * 64, "human_decision_record_id": "d" * 64, "human_provenance": {"event_id": "e" * 64}}
        with self.assertRaises(ValueError):
            contract.validate_owner_terminal(owner, decision, packet, self.comparison, self.universe)


class B4DispositionLineageR3Tests(unittest.TestCase):
    def test_random_and_cross_raw_references_fail_closed(self):
        record = {"schema": "A2_AUTHORITATIVE_DISPOSITION_RECORD_V2", "raw_key": "6000002::S02::A001", "disposition_type": "PENDING_TERMINAL_INVALIDATED", "prior_state": "PENDING_REVIEW", "next_state": "BLOCKED_ATTEMPT", "disposition_sequence": 1, "prior_disposition_id": "a" * 64, "referenced_pending_terminal_id": "b" * 64, "referenced_review_id": "c" * 64, "reason_class": "SUBSTANTIVE_TERMINAL_REJECTION", "referenced_attempt_id": None, "referenced_accepted_terminal_id": None, "remediation_reference": None, "disposition_id": None}
        record["disposition_id"] = contract.canonical_object_id(record, "disposition_id")
        refs = {"current_pending_terminal": {"id": "x" * 64, "raw_key": record["raw_key"]}, "reviews": {"c" * 64: {"id": "c" * 64, "raw_key": record["raw_key"], "status": "BLOCKING"}}, "pending_terminals": {"b" * 64: {"id": "b" * 64, "raw_key": "other::S01::A001"}}}
        with self.assertRaises(ValueError):
            contract.validate_disposition_record(record, refs)

    def test_wrong_review_and_random_remediation_references_fail_closed(self):
        record = {"schema": "A2_AUTHORITATIVE_DISPOSITION_RECORD_V2", "raw_key": "6000002::S02::A001", "disposition_type": "PENDING_TERMINAL_INVALIDATED", "prior_state": "PENDING_REVIEW", "next_state": "BLOCKED_ATTEMPT", "disposition_sequence": 1, "prior_disposition_id": "a" * 64, "referenced_pending_terminal_id": "b" * 64, "referenced_review_id": "c" * 64, "reason_class": "SUBSTANTIVE_TERMINAL_REJECTION", "referenced_attempt_id": None, "referenced_accepted_terminal_id": None, "remediation_reference": None, "disposition_id": None}
        record["disposition_id"] = contract.canonical_object_id(record, "disposition_id")
        refs = {"current_pending_terminal": {"id": "b" * 64, "raw_key": record["raw_key"]}, "pending_terminals": {"b" * 64: {"id": "b" * 64, "raw_key": record["raw_key"]}}, "reviews": {"c" * 64: {"id": "c" * 64, "raw_key": record["raw_key"], "status": "NON_BLOCKING"}}}
        with self.assertRaises(ValueError):
            contract.validate_disposition_record(record, refs)
        remediation = dict(record, disposition_type="REMEDIATION_RESTARTED", prior_state="BLOCKED_ATTEMPT", next_state="IN_PROGRESS_OR_INCOMPLETE", referenced_pending_terminal_id=None, referenced_review_id=None, remediation_reference="f" * 64)
        remediation["disposition_id"] = contract.canonical_object_id(remediation, "disposition_id")
        with self.assertRaises(ValueError):
            contract.validate_disposition_record(remediation, {"remediations": {}, "preceding_blocked_attempt": {"id": "e" * 64, "raw_key": record["raw_key"]}})

    def test_wrong_accepted_terminal_reference_fails_closed(self):
        record = {"schema": "A2_AUTHORITATIVE_DISPOSITION_RECORD_V2", "raw_key": "6000002::S02::A001", "disposition_type": "TERMINAL_ACCEPTED", "prior_state": "PENDING_REVIEW", "next_state": "ACCEPTED_TERMINAL", "disposition_sequence": 2, "prior_disposition_id": "a" * 64, "referenced_pending_terminal_id": "b" * 64, "referenced_review_id": "c" * 64, "referenced_accepted_terminal_id": "d" * 64, "reason_class": None, "referenced_attempt_id": None, "remediation_reference": None, "disposition_id": None}
        record["disposition_id"] = contract.canonical_object_id(record, "disposition_id")
        refs = {
            "current_pending_terminal": {"id": "b" * 64, "raw_key": record["raw_key"]},
            "pending_terminals": {"b" * 64: {"id": "b" * 64, "raw_key": record["raw_key"]}},
            "reviews": {"c" * 64: {"id": "c" * 64, "raw_key": record["raw_key"], "status": "PASS", "approved_terminal_id": "e" * 64}},
            "accepted_terminals": {"d" * 64: {"id": "d" * 64, "raw_key": record["raw_key"]}},
        }
        with self.assertRaises(ValueError):
            contract.validate_disposition_record(record, refs)
