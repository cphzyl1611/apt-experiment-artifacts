from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tools import materialize_p0_p1_contract as contract
from tests.test_r5_contract_fixes import B3References


ROOT = Path(__file__).resolve().parents[1]
RAW = "6000002::S02::A001"


def object_hash(value: dict[str, object]) -> str:
    return contract.sha256_bytes(contract.project_canonical_json(value))


def add_id(value: dict[str, object], field: str) -> dict[str, object]:
    value[field] = contract.canonical_object_id(value, field)
    return value


class B2VerifierProductionE2ER4Tests(unittest.TestCase):
    def test_valid_frozen_verifier_configuration_e2e(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            common = root / "common"
            runtime = root / "runtime"
            output = root / "output"
            common.mkdir()
            runtime.mkdir()
            output.mkdir()
            output.chmod(0o777)

            bundle = {
                "proposal_input_bundle_id": "",
                "raw_key": RAW,
                "execution_manifest_id": "a" * 64,
                "complete_candidate_universe_hash": "b" * 64,
                "complete_candidate_relation_set_hash": "3d5c5c4e7f07130d85a55f39c450080c1c2fbc4d91fcf62721db86b2e10b8192",
                "input_status": "FROZEN_PREPARATION_ONLY",
            }
            bundle["proposal_input_bundle_id"] = contract.canonical_object_id(bundle, "proposal_input_bundle_id")
            (common / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")

            backend = common / "dummy_backend.py"
            backend.write_text(
                "import json,os\n"
                "cfg=json.loads(os.environ['A2_BACKEND_CONFIG'])\n"
                "open('/role-output/backend_marker.json','w').write(json.dumps({'backend':'NON_SEMANTIC_DUMMY','invoked':True}))\n"
                "print(json.dumps({'result_status':'ESCALATE_STRUCTURE','selected_candidate_scoring_id':None,'selected_relation_identity':None,'evidence_fact_ids':[],'evidence_set_hash':None,'hard_gate_results':{'dummy_backend_marker':'PASS'},'runtime_identity':{'provider':cfg['provider'],'model_id':cfg['model_id'],'context_identity':cfg['context_identity'],'run_identity':cfg['run_identity']}}))\n",
                encoding="utf-8",
            )
            config = {
                "role": "VERIFIER",
                "frozen_configuration": True,
                "provider": "non-semantic-dummy-provider",
                "model_id": "non-semantic-dummy-model",
                "context_identity": "execution-bound-verifier-context",
                "run_identity": "execution-bound-verifier-run",
                "tool_mode": "A2_VERIFIER_ROLE_RUNTIME",
                "agent_or_cli_version_source": "dummy-backend/1",
                "command": ["/usr/bin/python3", "/frozen-input/dummy_backend.py"],
                "capture_method": "SUBPROCESS_STDOUT_RUNTIME_IDENTITY_V1",
                "backend_implementation_hash": hashlib.sha256(backend.read_bytes()).hexdigest(),
            }
            config["backend_configuration_id"] = contract.canonical_object_id(config, "backend_configuration_id")
            (common / "backend.json").write_text(json.dumps(config), encoding="utf-8")
            shutil.copyfile(ROOT / "tools/a2_role_runtime.py", runtime / "a2_role_runtime.py")

            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/run_a2_verifier.py"),
                    "--common-dir", str(common),
                    "--runtime-dir", str(runtime),
                    "--output-dir", str(output),
                    "--proposal-input-relative", "bundle.json",
                    "--backend-config-relative", "backend.json",
                    "--backend-configuration-id", config["backend_configuration_id"],
                    "--expected-execution-manifest-id", "a" * 64,
                    "--computational-contract-id", "c" * 64,
                    "--context-identity", config["context_identity"],
                    "--run-identity", config["run_identity"],
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            marker = json.loads((output / "backend_marker.json").read_text(encoding="utf-8"))
            commitment = json.loads((output / "verifier_commitment.json").read_text(encoding="utf-8"))
            self.assertEqual(marker, {"backend": "NON_SEMANTIC_DUMMY", "invoked": True})
            self.assertEqual(commitment["hard_gate_results"]["dummy_backend_marker"], "PASS")
            self.assertEqual(commitment["runtime_binding"]["context_identity"]["value"], config["context_identity"])
            self.assertEqual(commitment["runtime_binding"]["run_identity"]["value"], config["run_identity"])
            self.assertEqual(commitment["commitment_id"], contract.canonical_object_id(commitment, "commitment_id"))


class AuthenticatedHumanReferences:
    def __init__(self) -> None:
        self.raw_evidence = {"source_fact_id": "1" * 64, "raw_key": RAW, "source_side": "RAW"}
        self.candidate_evidence = {"source_fact_id": "2" * 64, "raw_key": RAW, "source_side": "CANDIDATE"}
        self.universe = {
            "raw_key": RAW,
            "candidate_relations": [
                {"candidate_scoring_id": "b" * 64, "relation_identity": "c" * 64},
                {"candidate_scoring_id": "0" * 64, "relation_identity": "1" * 64},
            ],
        }
        self.proposal = add_id({
            "raw_key": RAW,
            "selected_candidate_scoring_id": "b" * 64,
            "selected_relation_identity": "c" * 64,
            "evidence_fact_ids": ["1" * 64, "2" * 64],
            "proposal_id": None,
        }, "proposal_id")
        self.primary = add_id({
            "role": "PRIMARY",
            "raw_key": RAW,
            "selected_candidate_scoring_id": "b" * 64,
            "selected_relation_identity": "c" * 64,
            "evidence_fact_ids": ["1" * 64, "2" * 64],
            "commitment_id": None,
        }, "commitment_id")
        self.verifier = add_id({
            "role": "VERIFIER",
            "raw_key": RAW,
            "selected_candidate_scoring_id": "b" * 64,
            "selected_relation_identity": "c" * 64,
            "evidence_fact_ids": ["1" * 64, "2" * 64],
            "commitment_id": None,
        }, "commitment_id")
        self.comparison = add_id({
            "raw_key": RAW,
            "primary_commitment_id": self.primary["commitment_id"],
            "verifier_commitment_id": self.verifier["commitment_id"],
            "selected_candidate_scoring_id": "b" * 64,
            "selected_relation_identity": "c" * 64,
            "independent_commitment_comparison": "PASS",
            "comparison_id": None,
        }, "comparison_id")
        mapping = [
            {"packet_local_human_option_id": "option-1", "candidate_scoring_id": "b" * 64, "relation_identity": "c" * 64},
            {"packet_local_human_option_id": "option-2", "candidate_scoring_id": "0" * 64, "relation_identity": "1" * 64},
        ]
        self.packet = {
            "raw_key": RAW,
            "proposed_candidate_scoring_id": "b" * 64,
            "proposed_relation_identity": "c" * 64,
            "proposal_hash": object_hash(self.proposal),
            "primary_commitment_id": self.primary["commitment_id"],
            "primary_commitment_hash": object_hash(self.primary),
            "verifier_commitment_id": self.verifier["commitment_id"],
            "verifier_commitment_hash": object_hash(self.verifier),
            "comparison_id": self.comparison["comparison_id"],
            "comparison_hash": object_hash(self.comparison),
            "verifier_comparison_hash": object_hash(self.comparison),
            "complete_candidate_universe_hash": object_hash(self.universe),
            "complete_candidate_count": 2,
            "candidate_count": 2,
            "full_candidate_option_mapping": mapping,
            "raw_side_evidence_fact_ids": ["1" * 64],
            "raw_side_evidence_source_references": [dict(self.raw_evidence)],
            "candidate_side_evidence_fact_ids": ["2" * 64],
            "candidate_side_evidence_source_references": [dict(self.candidate_evidence)],
            "complete_universe_expansion_audit": {
                "expanded_option_count": 2,
                "complete_candidate_count_exact_match": True,
                "option_mapping_hash": contract.sha256_bytes(contract.project_canonical_json(mapping)),
            },
            "human_input_mode": "PACKET_LOCAL_OPTION_ONLY_NO_MANUAL_ID_OR_HASH_ENTRY",
            "human_packet_id": None,
        }
        self.packet["human_packet_id"] = contract.canonical_object_id(self.packet, "human_packet_id")
        self.decision = add_id({
            "raw_key": RAW,
            "human_packet_id": self.packet["human_packet_id"],
            "human_packet_hash": object_hash(self.packet),
            "human_action": "CONFIRM_PROPOSED_OWNER",
            "human_selected_candidate_scoring_id": "b" * 64,
            "human_selected_relation_identity": "c" * 64,
            "selected_packet_option_id": None,
            "fresh_alternative_verification": None,
            "fresh_alternative_verification_id": None,
            "human_provenance": {"event_id": "e" * 64},
            "human_decision_record_id": None,
        }, "human_decision_record_id")

    def packet_refs(self) -> dict[str, object]:
        return {
            "frozen_candidate_universe": self.universe,
            "proposal": self.proposal,
            "primary_commitment": self.primary,
            "verifier_commitment": self.verifier,
            "comparison": self.comparison,
            "authenticated_evidence_references": [self.raw_evidence, self.candidate_evidence],
        }

    def decision_refs(self) -> dict[str, object]:
        return {"human_packet": self.packet, **self.packet_refs()}

    def owner_refs(self) -> dict[str, object]:
        return {"human_decision": self.decision, **self.decision_refs()}


class B3MandatoryAuthenticatedCrossObjectR4Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = B3References()

    def test_human_packet_without_authenticated_referenced_objects_fails(self):
        with self.assertRaises(ValueError):
            contract.validate_human_packet(self.fx.packet)

    def test_human_decision_without_complete_authenticated_references_fails(self):
        with self.assertRaises(ValueError):
            contract.validate_human_decision(self.fx.packet, self.fx.decision)

    def test_owner_terminal_without_authenticated_references_fails(self):
        owner = self._owner()
        with self.assertRaises(ValueError):
            contract.validate_owner_terminal(owner)

    def test_plausible_random_owner_pair_with_omitted_refs_fails(self):
        owner = self._owner()
        owner["selected_owner_candidate_scoring_id"] = "9" * 64
        owner["selected_relation_identity"] = "8" * 64
        with self.assertRaises(ValueError):
            contract.validate_owner_terminal(owner)

    def test_complete_authenticated_reference_graph_passes(self):
        self.assertTrue(contract.validate_human_packet(self.fx.packet, **self.fx.packet_refs()))
        self.assertTrue(contract.validate_human_decision(self.fx.packet, self.fx.decision, **self.fx.decision_refs()))
        self.assertTrue(contract.validate_owner_terminal(self._owner(), **self.fx.owner_refs()))

    def test_truncated_extra_duplicate_and_candidate_relation_mappings_fail(self):
        mutations = []
        truncated = json.loads(json.dumps(self.fx.packet))
        truncated["full_candidate_option_mapping"] = truncated["full_candidate_option_mapping"][:1]
        truncated["candidate_count"] = truncated["complete_candidate_count"] = 1
        truncated["complete_universe_expansion_audit"]["expanded_option_count"] = 1
        truncated["complete_universe_expansion_audit"]["option_mapping_hash"] = contract.sha256_bytes(contract.project_canonical_json(truncated["full_candidate_option_mapping"]))
        mutations.append(truncated)
        extra = json.loads(json.dumps(self.fx.packet))
        extra["full_candidate_option_mapping"].append({"packet_local_human_option_id": "option-3", "candidate_scoring_id": "3" * 64, "relation_identity": "4" * 64})
        extra["candidate_count"] = extra["complete_candidate_count"] = 3
        extra["complete_universe_expansion_audit"]["expanded_option_count"] = 3
        extra["complete_universe_expansion_audit"]["option_mapping_hash"] = contract.sha256_bytes(contract.project_canonical_json(extra["full_candidate_option_mapping"]))
        mutations.append(extra)
        duplicate = json.loads(json.dumps(self.fx.packet))
        duplicate["full_candidate_option_mapping"][1]["packet_local_human_option_id"] = "option-1"
        duplicate["complete_universe_expansion_audit"]["option_mapping_hash"] = contract.sha256_bytes(contract.project_canonical_json(duplicate["full_candidate_option_mapping"]))
        mutations.append(duplicate)
        mismatch = json.loads(json.dumps(self.fx.packet))
        mismatch["full_candidate_option_mapping"][1]["relation_identity"] = "4" * 64
        mismatch["complete_universe_expansion_audit"]["option_mapping_hash"] = contract.sha256_bytes(contract.project_canonical_json(mismatch["full_candidate_option_mapping"]))
        mutations.append(mismatch)
        for packet in mutations:
            with self.subTest(packet=packet["full_candidate_option_mapping"]), self.assertRaises(ValueError):
                contract.validate_human_packet(packet, **self.fx.packet_refs())

    def test_reject_select_original_proposal_and_owner_mismatch_fail(self):
        decision = dict(self.fx.decision)
        decision.update({
            "human_action": "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE",
            "selected_packet_option_id": "option-1",
            "fresh_alternative_verification": "PASS",
            "fresh_alternative_verification_id": "f" * 64,
        })
        decision["human_decision_record_id"] = contract.canonical_object_id(decision, "human_decision_record_id")
        with self.assertRaises(ValueError):
            contract.validate_human_decision(self.fx.packet, decision, **self.fx.decision_refs())
        owner = self._owner()
        owner["selected_owner_candidate_scoring_id"] = "0" * 64
        owner["selected_relation_identity"] = "1" * 64
        with self.assertRaises(ValueError):
            contract.validate_owner_terminal(owner, **self.fx.owner_refs())

    def test_alternative_verification_must_be_exact_pass_for_selected_pair(self):
        decision = dict(self.fx.decision)
        decision.update({
            "human_action": "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE",
            "selected_packet_option_id": "option-2",
            "human_selected_candidate_scoring_id": "0" * 64,
            "human_selected_relation_identity": "1" * 64,
            "fresh_alternative_verification": "PASS",
        })
        alternative = add_id({
            "raw_key": RAW,
            "candidate_scoring_id": "0" * 64,
            "relation_identity": "1" * 64,
            "status": "PASS",
            "alternative_verification_id": None,
        }, "alternative_verification_id")
        decision["fresh_alternative_verification_id"] = alternative["alternative_verification_id"]
        decision["human_decision_record_id"] = contract.canonical_object_id(decision, "human_decision_record_id")
        owner = self._owner(decision)
        owner.update({
            "human_action": decision["human_action"],
            "selected_owner_candidate_scoring_id": "0" * 64,
            "selected_relation_identity": "1" * 64,
            "fresh_alternative_verification": "PASS",
            "fresh_alternative_verification_id": alternative["alternative_verification_id"],
        })
        refs = self.fx.owner_refs()
        refs["human_decision"] = decision
        refs["alternative_verification"] = alternative
        self.assertTrue(contract.validate_owner_terminal(owner, **refs))
        wrong = dict(alternative, candidate_scoring_id="b" * 64)
        with self.assertRaises(ValueError):
            contract.validate_owner_terminal(owner, **{**refs, "alternative_verification": wrong})

    def _owner(self, decision: dict[str, object] | None = None) -> dict[str, object]:
        decision = decision or self.fx.decision
        return {
            "terminal_record_class": "A2_OWNER_ADJUDICATION_FROZEN",
            "raw_key": RAW,
            "human_action": decision["human_action"],
            "unresolved_state": False,
            "selected_owner_candidate_scoring_id": decision["human_selected_candidate_scoring_id"],
            "selected_relation_identity": decision["human_selected_relation_identity"],
            "human_decision_record_id": decision["human_decision_record_id"],
            "human_packet_id": self.fx.packet["human_packet_id"],
            "human_provenance": decision["human_provenance"],
            "fresh_alternative_verification": decision.get("fresh_alternative_verification"),
            "fresh_alternative_verification_id": decision.get("fresh_alternative_verification_id"),
        }


class DispositionReferences:
    def __init__(self) -> None:
        self.pending = {"id": "b" * 64, "raw_key": RAW}
        self.prior_pending = add_id({
            "schema": "A2_AUTHORITATIVE_DISPOSITION_RECORD_V2",
            "raw_key": RAW,
            "disposition_type": "PENDING_TERMINAL_CREATED",
            "prior_state": "IN_PROGRESS_OR_INCOMPLETE",
            "next_state": "PENDING_REVIEW",
            "disposition_sequence": 1,
            "prior_disposition_id": "a" * 64,
            "referenced_attempt_id": "9" * 64,
            "referenced_pending_terminal_id": self.pending["id"],
            "referenced_review_id": None,
            "referenced_accepted_terminal_id": None,
            "remediation_reference": None,
            "reason_class": None,
            "disposition_id": None,
        }, "disposition_id")
        self.blocking_review = {
            "id": "c" * 64,
            "raw_key": RAW,
            "status": "BLOCKING",
            "referenced_pending_terminal_id": self.pending["id"],
        }
        self.invalidated = self._record(
            "PENDING_TERMINAL_INVALIDATED", "PENDING_REVIEW", "BLOCKED_ATTEMPT",
            self.prior_pending["disposition_id"], pending=self.pending["id"], review=self.blocking_review["id"],
            reason="SUBSTANTIVE_TERMINAL_REJECTION",
        )
        self.accepted_terminal = {
            "id": "d" * 64,
            "raw_key": RAW,
            "referenced_pending_terminal_id": self.pending["id"],
            "referenced_review_id": "e" * 64,
        }
        self.passing_review = {
            "id": "e" * 64,
            "raw_key": RAW,
            "status": "PASS",
            "referenced_pending_terminal_id": self.pending["id"],
            "approved_terminal_id": self.accepted_terminal["id"],
        }
        self.accepted = self._record(
            "TERMINAL_ACCEPTED", "PENDING_REVIEW", "ACCEPTED_TERMINAL",
            self.prior_pending["disposition_id"], pending=self.pending["id"], review=self.passing_review["id"],
            accepted=self.accepted_terminal["id"],
        )
        self.attempt = {"id": "6" * 64, "raw_key": RAW, "state": "BLOCKED_ATTEMPT", "disposition_id": self.invalidated["disposition_id"]}
        self.blocked_head = dict(self.invalidated, referenced_attempt_id=self.attempt["id"])
        self.blocked_head["disposition_id"] = contract.canonical_object_id(self.blocked_head, "disposition_id")
        self.attempt["disposition_id"] = self.blocked_head["disposition_id"]
        self.remediation = {
            "id": "f" * 64,
            "raw_key": RAW,
            "authorizes_restart_of": self.blocked_head["disposition_id"],
            "authorizes_restart_of_attempt_id": self.attempt["id"],
        }
        self.restarted = self._record(
            "REMEDIATION_RESTARTED", "BLOCKED_ATTEMPT", "IN_PROGRESS_OR_INCOMPLETE",
            self.blocked_head["disposition_id"], attempt=self.attempt["id"], remediation=self.remediation["id"],
        )
        self.restarted["disposition_sequence"] = self.blocked_head["disposition_sequence"] + 1
        self.restarted["disposition_id"] = contract.canonical_object_id(self.restarted, "disposition_id")

    def _record(self, typ: str, prior: str, next_state: str, prior_id: str, *, attempt=None, pending=None, review=None, accepted=None, remediation=None, reason=None) -> dict[str, object]:
        return add_id({
            "schema": "A2_AUTHORITATIVE_DISPOSITION_RECORD_V2",
            "raw_key": RAW,
            "disposition_type": typ,
            "prior_state": prior,
            "next_state": next_state,
            "disposition_sequence": 2,
            "prior_disposition_id": prior_id,
            "referenced_attempt_id": attempt,
            "referenced_pending_terminal_id": pending,
            "referenced_review_id": review,
            "referenced_accepted_terminal_id": accepted,
            "remediation_reference": remediation,
            "reason_class": reason,
            "disposition_id": None,
        }, "disposition_id")


class B4MandatoryExactDispositionLineageR4Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = DispositionReferences()

    def test_all_references_omitted_fail_for_each_exact_lineage_transition(self):
        for record in (self.fx.invalidated, self.fx.accepted, self.fx.restarted):
            with self.subTest(record=record["disposition_type"]), self.assertRaises(ValueError):
                contract.validate_disposition_record(record)

    def test_valid_complete_reference_graphs_pass(self):
        self.assertTrue(contract.validate_disposition_record(self.fx.invalidated, {
            "current_pending_terminal": self.fx.pending,
            "blocking_review": self.fx.blocking_review,
            "current_prior_disposition": self.fx.prior_pending,
        }))
        self.assertTrue(contract.validate_disposition_record(self.fx.accepted, {
            "current_pending_terminal": self.fx.pending,
            "passing_independent_review": self.fx.passing_review,
            "accepted_terminal": self.fx.accepted_terminal,
            "current_prior_disposition": self.fx.prior_pending,
        }))
        self.assertTrue(contract.validate_disposition_record(self.fx.restarted, {
            "current_prior_disposition": self.fx.blocked_head,
            "preceding_blocked_attempt": self.fx.attempt,
            "remediation_record": self.fx.remediation,
        }))

    def test_wrong_same_raw_review_and_pass_review_on_wrong_pending_fail(self):
        wrong_review = dict(self.fx.blocking_review, id="7" * 64)
        with self.assertRaises(ValueError):
            contract.validate_disposition_record(self.fx.invalidated, {
                "current_pending_terminal": self.fx.pending,
                "blocking_review": wrong_review,
                "current_prior_disposition": self.fx.prior_pending,
            })
        wrong_pending_review = dict(self.fx.passing_review, referenced_pending_terminal_id="8" * 64)
        with self.assertRaises(ValueError):
            contract.validate_disposition_record(self.fx.accepted, {
                "current_pending_terminal": self.fx.pending,
                "passing_independent_review": wrong_pending_review,
                "accepted_terminal": self.fx.accepted_terminal,
                "current_prior_disposition": self.fx.prior_pending,
            })

    def test_cross_raw_and_wrong_state_preceding_objects_fail(self):
        cross_raw = dict(self.fx.blocked_head, raw_key="6000003::S03::A003")
        with self.assertRaises(ValueError):
            contract.validate_disposition_record(self.fx.restarted, {
                "current_prior_disposition": cross_raw,
                "preceding_blocked_attempt": self.fx.attempt,
                "remediation_record": self.fx.remediation,
            })
        wrong_state = dict(self.fx.blocked_head, next_state="PENDING_REVIEW")
        with self.assertRaises(ValueError):
            contract.validate_disposition_record(self.fx.restarted, {
                "current_prior_disposition": wrong_state,
                "preceding_blocked_attempt": self.fx.attempt,
                "remediation_record": self.fx.remediation,
            })

    def test_random_64_hex_remediation_reference_fails(self):
        record = dict(self.fx.restarted, remediation_reference="5" * 64)
        record["disposition_id"] = contract.canonical_object_id(record, "disposition_id")
        with self.assertRaises(ValueError):
            contract.validate_disposition_record(record, {
                "current_prior_disposition": self.fx.blocked_head,
                "preceding_blocked_attempt": self.fx.attempt,
                "remediation_record": self.fx.remediation,
            })


class R4MaterializationTests(unittest.TestCase):
    def test_materializes_r4_with_byte_preserved_r3_and_required_handoff_files(self):
        from tools import materialize_r4_contract as r4

        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / r4.R4_DIR_NAME
            result = r4.materialize(ROOT, output)
            self.assertEqual(result["P0_P1_EXECUTION_CONTRACT_R4_PATCH_STATUS"], "COMPLETE_CONTRACT_ONLY")
            self.assertTrue(output.is_dir())
            self.assertTrue((output.parent / r4.R4_HANDOFF_NAME).is_file())
            for relative in (
                "R3_TO_R4_DEFECT_REPRODUCTION_AND_TDD_LOG.json",
                "R3_TO_R4_PATCH_SUMMARY.json",
                "00_lineage/r3_baseline/CONTRACT_MANIFEST.json",
                "00_lineage/r3_baseline/SHA256SUMS.txt",
                "tools/a2_role_runtime.py",
                "tools/run_a2_verifier.py",
                "tools/materialize_r4_contract.py",
                "09_tests/test_r4_contract_fixes.py",
            ):
                self.assertTrue((output / relative).is_file(), relative)
            manifest = json.loads((output / "CONTRACT_MANIFEST.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["r3_handoff_sha256"], r4.R3_HANDOFF_SHA256)
            self.assertEqual(manifest["b1_m1_non_regression"], "PASS")
            self.assertEqual(manifest["b2_verifier_production_e2e"], "CLOSED")
            self.assertEqual(manifest["b3_mandatory_authenticated_cross_object_validation"], "CLOSED")
            self.assertEqual(manifest["b4_mandatory_exact_disposition_lineage"], "CLOSED")
            self.assertEqual(manifest["p0_executed"], "NO")
            self.assertEqual(manifest["p1_executed"], "NO")
            self.assertEqual(manifest["primary_proposer_executed"], "NO")
            self.assertEqual(manifest["independent_verifier_semantic_execution"], "NO")
            self.assertEqual(manifest["raw_level_human_decisions"], 0)
            self.assertEqual(manifest["binding_publication"], "NO")
            self.assertEqual(manifest["next_action"], "FRESH_TARGETED_INDEPENDENT_REVIEW_OF_R4_B2_B3_B4_ONLY")
            r4.verify_package(output)
            self.assertEqual(
                r4.sha256_tree(output / "00_lineage/r3_baseline"),
                r4.sha256_tree(ROOT / r4.R3_DIR_NAME),
            )
            self.assertEqual(
                r4.sha256_file(ROOT / r4.R3_HANDOFF_NAME),
                "59d4215d5c150ca6814963f361188c620ff0cf8b22f49af4c3868556431da0f7",
            )


if __name__ == "__main__":
    unittest.main()
