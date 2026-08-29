from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools import materialize_p0_p1_contract as contract


ROOT = Path(__file__).resolve().parents[1]
R4_PACKAGE = ROOT / "FA1B2de_Current86_BSO_A2_P0_P1_Execution_Contract_R4"
if not R4_PACKAGE.is_dir():
    R4_PACKAGE = ROOT / "00_lineage/r4_baseline"
RAW = "6000002::S02::A001"


def add_id(value: dict[str, object], field: str) -> dict[str, object]:
    value[field] = contract.canonical_object_id(value, field)
    return value


def object_hash(value: dict[str, object]) -> str:
    return contract.sha256_bytes(contract.project_canonical_json(value))


class B3References:
    def __init__(self) -> None:
        self.relation_set_hash = "3" * 64
        self.rows = [
            {
                "candidate_scoring_id": "b" * 64,
                "relation_identity": "c" * 64,
            },
            {
                "candidate_scoring_id": "0" * 64,
                "relation_identity": "1" * 64,
            },
        ]
        self.universe_hash = contract.canonical_object_id(
            {
                "raw_key": RAW,
                "candidate_relations": self.rows,
                "complete_candidate_relation_set_hash": self.relation_set_hash,
            },
            "complete_candidate_universe_hash",
        )
        self.universe = add_id(
            {
                "schema": "COMPLETE_CANDIDATE_UNIVERSE_CONTRACT_V1",
                "raw_key": RAW,
                "candidate_relations": copy.deepcopy(self.rows),
                "candidate_relation_count": len(self.rows),
                "complete_candidate_relation_set_hash": self.relation_set_hash,
                "complete_candidate_universe_hash": self.universe_hash,
                "complete_candidate_universe_preserved": True,
                "hidden_pruning": "PROHIBITED",
                "top_k_candidate_truncation": "PROHIBITED",
                "materialization_status": "PREPARED_NOT_ADJUDICATED",
                "complete_candidate_universe_id": None,
            },
            "complete_candidate_universe_id",
        )
        self.bundle = add_id(
            {
                "schema": "PROPOSAL_INPUT_BUNDLE_CONTRACT_V1",
                "authority_scope_id": "2" * 64,
                "raw_key": RAW,
                "active_authority_id": "4" * 64,
                "execution_manifest_id": "5" * 64,
                "raw_identity_hash": "6" * 64,
                "raw_source_bundle_hash": "7" * 64,
                "complete_candidate_universe_hash": self.universe_hash,
                "complete_candidate_relation_set_hash": self.relation_set_hash,
                "candidate_source_bundle_hashes": ["8" * 64, "9" * 64],
                "admissible_source_fact_set_hash": "a" * 64,
                "proposal_evidence_profile_hash": "d" * 64,
                "source_class_fact_type_registry_id": "e" * 64,
                "historical_output_denylist_hash": "f" * 64,
                "input_status": "FROZEN_PREPARATION_ONLY",
                "proposal_input_bundle_id": None,
            },
            "proposal_input_bundle_id",
        )
        self.raw_evidence = {
            "source_fact_id": "1" * 64,
            "raw_key": RAW,
            "source_side": "RAW",
        }
        self.candidate_evidence = {
            "source_fact_id": "2" * 64,
            "raw_key": RAW,
            "source_side": "CANDIDATE",
        }
        self.proposal = add_id(
            {
                "raw_key": RAW,
                "selected_candidate_scoring_id": "b" * 64,
                "selected_relation_identity": "c" * 64,
                "evidence_fact_ids": ["1" * 64, "2" * 64],
                "proposal_id": None,
            },
            "proposal_id",
        )
        self.primary = self._commitment("PRIMARY", "primary-context", "primary-run")
        self.verifier = self._commitment("VERIFIER", "verifier-context", "verifier-run")
        self.comparison = self._comparison()
        mapping = [
            {
                "packet_local_human_option_id": "option-1",
                "candidate_scoring_id": "b" * 64,
                "relation_identity": "c" * 64,
                "candidate_label_or_reference": "candidate-b",
            },
            {
                "packet_local_human_option_id": "option-2",
                "candidate_scoring_id": "0" * 64,
                "relation_identity": "1" * 64,
                "candidate_label_or_reference": "candidate-0",
            },
        ]
        self.packet = {
            "schema": "A2_HUMAN_PACKET_R2",
            "raw_key": RAW,
            "raw_action": "test action",
            "authenticated_raw_action_reference": "frozen test action",
            "machine_proposal_label": "NON_AUTHORITATIVE_MACHINE_PROPOSAL",
            "proposed_candidate_scoring_id": "b" * 64,
            "proposed_relation_identity": "c" * 64,
            "raw_side_evidence_fact_ids": ["1" * 64],
            "raw_side_evidence_source_references": [copy.deepcopy(self.raw_evidence)],
            "candidate_side_evidence_fact_ids": ["2" * 64],
            "candidate_side_evidence_source_references": [copy.deepcopy(self.candidate_evidence)],
            "concise_source_grounded_basis": "test-only authenticated basis",
            "complete_candidate_universe_hash": self.universe_hash,
            "complete_candidate_count": 2,
            "candidate_count": 2,
            "full_candidate_option_mapping": mapping,
            "complete_universe_expansion_audit": {
                "expanded_option_count": 2,
                "complete_candidate_count_exact_match": True,
                "option_mapping_hash": contract.sha256_bytes(
                    contract.project_canonical_json(mapping)
                ),
            },
            "human_input_mode": "PACKET_LOCAL_OPTION_ONLY_NO_MANUAL_ID_OR_HASH_ENTRY",
            "complete_candidate_universe_disclosed": True,
            "hidden_pruning": "NO",
            "top_k_truncation": "NO",
            "normative_actions": [
                "CONFIRM_PROPOSED_OWNER",
                "REJECT_PROPOSAL_AND_SELECT_OTHER_EXISTING_CANDIDATE",
                "NOT_SURE_ESCALATE",
            ],
            "proposal_hash": object_hash(self.proposal),
            "human_packet_id": None,
        }
        self.refresh_bindings()
        self.decision = add_id(
            {
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
            },
            "human_decision_record_id",
        )

    def _commitment(self, role: str, context: str, run: str) -> dict[str, object]:
        return add_id(
            {
                "schema": f"A2_{role}_COMMITMENT_V1",
                "role": role,
                "raw_key": RAW,
                "proposal_input_bundle_id": self.bundle["proposal_input_bundle_id"],
                "execution_manifest_id": self.bundle["execution_manifest_id"],
                "computational_contract_id": ("a" if role == "PRIMARY" else "b") * 64,
                "complete_candidate_universe_hash": self.universe_hash,
                "complete_relation_set_hash": self.relation_set_hash,
                "result_status": "UNIQUE_EXISTING_OWNER_PROPOSAL",
                "selected_candidate_scoring_id": "b" * 64,
                "selected_relation_identity": "c" * 64,
                "evidence_fact_ids": ["1" * 64, "2" * 64],
                "evidence_set_hash": "4" * 64,
                "hard_gate_results": {"all_hard_gates": "PASS"},
                "context_identity": context,
                "run_identity": run,
                "runtime_binding": {"runtime_binding_id": "5" * 64},
                "prompt_template_identity": {"prompt_template_id": "6" * 64},
                "private_chain_of_thought_persisted": False,
                "owner_freeze_performed": False,
                "binding_publication_performed": False,
                "commitment_id": None,
            },
            "commitment_id",
        )

    def _comparison(self) -> dict[str, object]:
        return add_id(
            {
                "schema": "A2_PROPOSER_VERIFIER_COMPARISON_V1",
                "raw_key": RAW,
                "primary_commitment_id": self.primary["commitment_id"],
                "verifier_commitment_id": self.verifier["commitment_id"],
                "same_input_bundle": True,
                "same_candidate_universe": True,
                "context_identities_distinct": True,
                "run_identities_distinct": True,
                "independent_commitment_comparison": "PASS",
                "comparison_id": None,
            },
            "comparison_id",
        )

    def refresh_bindings(self) -> None:
        self.primary["commitment_id"] = contract.canonical_object_id(
            self.primary, "commitment_id"
        )
        self.verifier["commitment_id"] = contract.canonical_object_id(
            self.verifier, "commitment_id"
        )
        self.comparison["primary_commitment_id"] = self.primary["commitment_id"]
        self.comparison["verifier_commitment_id"] = self.verifier["commitment_id"]
        self.comparison["comparison_id"] = contract.canonical_object_id(
            self.comparison, "comparison_id"
        )
        self.packet["primary_commitment_id"] = self.primary["commitment_id"]
        self.packet["primary_commitment_hash"] = object_hash(self.primary)
        self.packet["verifier_commitment_id"] = self.verifier["commitment_id"]
        self.packet["verifier_commitment_hash"] = object_hash(self.verifier)
        self.packet["comparison_id"] = self.comparison["comparison_id"]
        self.packet["comparison_hash"] = object_hash(self.comparison)
        self.packet["verifier_comparison_hash"] = object_hash(self.comparison)
        self.packet["human_packet_id"] = contract.canonical_object_id(
            self.packet, "human_packet_id"
        )

    def references(self) -> dict[str, object]:
        return {
            "frozen_candidate_universe": self.universe,
            "authenticated_proposal_input_bundle": self.bundle,
            "proposal": self.proposal,
            "primary_commitment": self.primary,
            "verifier_commitment": self.verifier,
            "comparison": self.comparison,
            "authenticated_evidence_references": [
                self.raw_evidence,
                self.candidate_evidence,
            ],
        }

    def packet_refs(self) -> dict[str, object]:
        return self.references()

    def decision_refs(self) -> dict[str, object]:
        return {"human_packet": self.packet, **self.references()}

    def owner_refs(self) -> dict[str, object]:
        return {"human_decision": self.decision, **self.decision_refs()}


class B3MandatoryCrossObjectR5Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = B3References()

    def validate(self) -> bool:
        return contract.validate_human_packet(self.fx.packet, **self.fx.references())

    def test_schema_valid_complete_authenticated_graph_passes(self):
        self.assertTrue(self.validate())

    def test_different_proposal_input_bundle_ids_fail_closed(self):
        self.fx.verifier["proposal_input_bundle_id"] = "0" * 64
        self.fx.refresh_bindings()
        with self.assertRaises(ValueError):
            self.validate()

    def test_different_semantic_candidate_universe_hashes_fail_closed(self):
        self.fx.verifier["complete_candidate_universe_hash"] = "0" * 64
        self.fx.refresh_bindings()
        with self.assertRaises(ValueError):
            self.validate()

    def test_different_relation_set_hashes_fail_closed(self):
        self.fx.verifier["complete_relation_set_hash"] = "0" * 64
        self.fx.refresh_bindings()
        with self.assertRaises(ValueError):
            self.validate()

    def test_packet_semantic_universe_hash_mismatch_fails_closed(self):
        self.fx.packet["complete_candidate_universe_hash"] = "0" * 64
        self.fx.packet["human_packet_id"] = contract.canonical_object_id(
            self.fx.packet, "human_packet_id"
        )
        with self.assertRaises(ValueError):
            self.validate()

    def test_missing_or_false_comparison_assertions_fail_closed(self):
        fields = (
            "same_input_bundle",
            "same_candidate_universe",
            "context_identities_distinct",
            "run_identities_distinct",
        )
        for field in fields:
            for mode in ("missing", "false"):
                with self.subTest(field=field, mode=mode):
                    fx = B3References()
                    if mode == "missing":
                        del fx.comparison[field]
                    else:
                        fx.comparison[field] = False
                    fx.refresh_bindings()
                    with self.assertRaises(ValueError):
                        contract.validate_human_packet(fx.packet, **fx.references())

    def test_equal_context_identities_fail_closed(self):
        self.fx.verifier["context_identity"] = self.fx.primary["context_identity"]
        self.fx.refresh_bindings()
        with self.assertRaises(ValueError):
            self.validate()

    def test_equal_run_identities_fail_closed(self):
        self.fx.verifier["run_identity"] = self.fx.primary["run_identity"]
        self.fx.refresh_bindings()
        with self.assertRaises(ValueError):
            self.validate()

    def test_schema_invalid_commitment_or_comparison_cannot_be_positive_proof(self):
        mutations = []
        missing_commitment_field = B3References()
        del missing_commitment_field.primary["runtime_binding"]
        missing_commitment_field.refresh_bindings()
        mutations.append(missing_commitment_field)
        extra_comparison_field = B3References()
        extra_comparison_field.comparison["selected_candidate_scoring_id"] = "b" * 64
        extra_comparison_field.refresh_bindings()
        mutations.append(extra_comparison_field)
        for fx in mutations:
            with self.subTest(comparison=fx.comparison), self.assertRaises(ValueError):
                contract.validate_human_packet(fx.packet, **fx.references())


class B4References:
    def __init__(self) -> None:
        self.pending = {"id": "b" * 64, "raw_key": RAW}
        self.blocking_review = {
            "id": "c" * 64,
            "raw_key": RAW,
            "status": "BLOCKING",
            "referenced_pending_terminal_id": self.pending["id"],
        }
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
        self.attempt = {
            "id": "6" * 64,
            "raw_key": RAW,
            "state": "BLOCKED_ATTEMPT",
            "disposition_id": None,
        }
        self.remediation = {
            "id": "f" * 64,
            "raw_key": RAW,
            "authorizes_restart_of": None,
            "authorizes_restart_of_attempt_id": self.attempt["id"],
        }

    def graph(self) -> dict[str, object]:
        return {
            "by_raw": {
                RAW: {
                    "pending_terminals": {self.pending["id"]: self.pending},
                    "independent_reviews": {
                        self.blocking_review["id"]: self.blocking_review,
                        self.passing_review["id"]: self.passing_review,
                    },
                    "accepted_terminals": {
                        self.accepted_terminal["id"]: self.accepted_terminal
                    },
                    "blocked_attempts": {self.attempt["id"]: self.attempt},
                    "remediation_records": {
                        self.remediation["id"]: self.remediation
                    },
                }
            }
        }

    def invalidated_chain(self) -> list[dict[str, object]]:
        r0, r1 = self._started_chain()
        r2 = self._record(
            2,
            "PENDING_TERMINAL_CREATED",
            r1["disposition_id"],
            "IN_PROGRESS_OR_INCOMPLETE",
            "PENDING_REVIEW",
            pending=self.pending["id"],
        )
        r3 = self._record(
            3,
            "PENDING_TERMINAL_INVALIDATED",
            r2["disposition_id"],
            "PENDING_REVIEW",
            "BLOCKED_ATTEMPT",
            pending=self.pending["id"],
            review=self.blocking_review["id"],
            reason="SUBSTANTIVE_TERMINAL_REJECTION",
        )
        return [r0, r1, r2, r3]

    def accepted_chain(self) -> list[dict[str, object]]:
        r0, r1 = self._started_chain()
        r2 = self._record(
            2,
            "PENDING_TERMINAL_CREATED",
            r1["disposition_id"],
            "IN_PROGRESS_OR_INCOMPLETE",
            "PENDING_REVIEW",
            pending=self.pending["id"],
        )
        r3 = self._record(
            3,
            "TERMINAL_ACCEPTED",
            r2["disposition_id"],
            "PENDING_REVIEW",
            "ACCEPTED_TERMINAL",
            pending=self.pending["id"],
            review=self.passing_review["id"],
            accepted=self.accepted_terminal["id"],
        )
        return [r0, r1, r2, r3]

    def restarted_chain(self) -> list[dict[str, object]]:
        r0, r1 = self._started_chain()
        r2 = self._record(
            2,
            "ATTEMPT_BLOCKED",
            r1["disposition_id"],
            "IN_PROGRESS_OR_INCOMPLETE",
            "BLOCKED_ATTEMPT",
            attempt=self.attempt["id"],
            reason="TECHNICAL_FAILURE",
        )
        self.attempt["disposition_id"] = r2["disposition_id"]
        self.remediation["authorizes_restart_of"] = r2["disposition_id"]
        r3 = self._record(
            3,
            "REMEDIATION_RESTARTED",
            r2["disposition_id"],
            "BLOCKED_ATTEMPT",
            "IN_PROGRESS_OR_INCOMPLETE",
            attempt=self.attempt["id"],
            remediation=self.remediation["id"],
        )
        return [r0, r1, r2, r3]

    def _started_chain(self) -> tuple[dict[str, object], dict[str, object]]:
        r0 = self._record(
            0, "INITIAL_STATE", None, None, "NOT_STARTED_FOR_ADJUDICATION"
        )
        r1 = self._record(
            1,
            "EXECUTION_STARTED",
            r0["disposition_id"],
            "NOT_STARTED_FOR_ADJUDICATION",
            "IN_PROGRESS_OR_INCOMPLETE",
        )
        return r0, r1

    @staticmethod
    def _record(
        sequence: int,
        typ: str,
        prior_id: str | None,
        prior_state: str | None,
        next_state: str,
        *,
        attempt: str | None = None,
        pending: str | None = None,
        review: str | None = None,
        accepted: str | None = None,
        remediation: str | None = None,
        reason: str | None = None,
    ) -> dict[str, object]:
        return add_id(
            {
                "schema": "A2_AUTHORITATIVE_DISPOSITION_RECORD_V2",
                "raw_key": RAW,
                "disposition_type": typ,
                "prior_state": prior_state,
                "next_state": next_state,
                "disposition_sequence": sequence,
                "prior_disposition_id": prior_id,
                "referenced_attempt_id": attempt,
                "referenced_pending_terminal_id": pending,
                "referenced_review_id": review,
                "referenced_accepted_terminal_id": accepted,
                "remediation_reference": remediation,
                "reason_class": reason,
                "disposition_id": None,
            },
            "disposition_id",
        )


class B4DispositionReferenceGraphR5Tests(unittest.TestCase):
    def test_valid_exact_lineage_chains_resolve_from_one_authenticated_graph(self):
        cases = (
            ("PENDING_TERMINAL_INVALIDATED", "BLOCKED_ATTEMPT"),
            ("TERMINAL_ACCEPTED", "ACCEPTED_TERMINAL"),
            ("REMEDIATION_RESTARTED", "IN_PROGRESS_OR_INCOMPLETE"),
        )
        for transition, state in cases:
            with self.subTest(transition=transition):
                fx = B4References()
                chain = {
                    "PENDING_TERMINAL_INVALIDATED": fx.invalidated_chain,
                    "TERMINAL_ACCEPTED": fx.accepted_chain,
                    "REMEDIATION_RESTARTED": fx.restarted_chain,
                }[transition]()
                result = contract.validate_disposition_chain(chain, fx.graph())
                self.assertEqual(result["current_state"], state)

    def test_partition_reconstruction_requires_and_uses_same_graph(self):
        cases = (
            ("invalidated_chain", "S_BLOCKED_ATTEMPT"),
            ("accepted_chain", "S_ACCEPTED_TERMINAL"),
            ("restarted_chain", "S_IN_PROGRESS_OR_INCOMPLETE"),
        )
        for factory_name, expected_partition in cases:
            with self.subTest(factory=factory_name):
                fx = B4References()
                chain = getattr(fx, factory_name)()
                partitions = contract.reconstruct_partitions(
                    [RAW], {RAW: chain}, fx.graph()
                )
                self.assertEqual(partitions[expected_partition], [RAW])
                self.assertEqual(
                    sum(RAW in values for values in partitions.values()), 1
                )

    def test_missing_exact_reference_fails_closed_for_each_transition(self):
        cases = (
            ("invalidated_chain", "independent_reviews", "c" * 64),
            ("accepted_chain", "accepted_terminals", "d" * 64),
            ("restarted_chain", "remediation_records", "f" * 64),
        )
        for factory_name, collection, identifier in cases:
            with self.subTest(factory=factory_name):
                fx = B4References()
                chain = getattr(fx, factory_name)()
                graph = fx.graph()
                del graph["by_raw"][RAW][collection][identifier]
                with self.assertRaises(ValueError):
                    contract.validate_disposition_chain(chain, graph)
                with self.assertRaises(ValueError):
                    contract.reconstruct_partitions([RAW], {RAW: chain}, graph)

    def test_wrong_exact_reference_fails_closed_for_each_transition(self):
        cases = (
            ("invalidated_chain", "independent_reviews", "c" * 64, "status", "PASS"),
            ("accepted_chain", "accepted_terminals", "d" * 64, "referenced_review_id", "0" * 64),
            ("restarted_chain", "blocked_attempts", "6" * 64, "state", "PENDING_REVIEW"),
            ("restarted_chain", "remediation_records", "f" * 64, "authorizes_restart_of", "0" * 64),
        )
        for factory_name, collection, identifier, field, wrong in cases:
            with self.subTest(factory=factory_name, collection=collection):
                fx = B4References()
                chain = getattr(fx, factory_name)()
                graph = fx.graph()
                graph["by_raw"][RAW][collection][identifier][field] = wrong
                with self.assertRaises(ValueError):
                    contract.validate_disposition_chain(chain, graph)

    def test_fork_duplicate_gap_and_multiple_heads_fail_closed(self):
        fx = B4References()
        chain = fx.invalidated_chain()
        duplicate_head = copy.deepcopy(chain[-1])
        duplicate_head["disposition_id"] = "0" * 64
        with self.assertRaises(ValueError):
            contract.validate_disposition_chain(chain + [duplicate_head], fx.graph())
        gap = copy.deepcopy(chain)
        gap[-1]["disposition_sequence"] = 4
        gap[-1]["disposition_id"] = contract.canonical_object_id(
            gap[-1], "disposition_id"
        )
        with self.assertRaises(ValueError):
            contract.validate_disposition_chain(gap, fx.graph())
        missing_parent = copy.deepcopy(chain)
        missing_parent[-1]["prior_disposition_id"] = "0" * 64
        missing_parent[-1]["disposition_id"] = contract.canonical_object_id(
            missing_parent[-1], "disposition_id"
        )
        with self.assertRaises(ValueError):
            contract.validate_disposition_chain(missing_parent, fx.graph())


class FrozenSchemaFixtureTests(unittest.TestCase):
    def test_positive_b3_fixture_is_valid_against_shipped_r4_schemas(self):
        try:
            import jsonschema
        except ImportError as exc:
            self.fail(f"jsonschema is required: {exc}")
        fx = B3References()
        cases = (
            ("complete_candidate_universe", fx.universe),
            ("proposal_input_bundle", fx.bundle),
            ("primary_commitment", fx.primary),
            ("verifier_commitment", fx.verifier),
            ("proposer_verifier_comparison", fx.comparison),
        )
        for name, instance in cases:
            with self.subTest(schema=name):
                schema = json.loads(
                    (R4_PACKAGE / "05_schemas" / f"{name}.schema.json").read_text(
                        encoding="utf-8"
                    )
                )
                jsonschema.Draft202012Validator(schema).validate(instance)


class R5MaterializationTests(unittest.TestCase):
    def test_materializes_r5_with_authenticated_byte_preserved_r4_lineage(self):
        from tools import materialize_r5_contract as r5

        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / r5.R5_DIR_NAME
            result = r5.materialize(ROOT, output)
            self.assertEqual(
                result["P0_P1_EXECUTION_CONTRACT_R5_PATCH_STATUS"],
                "COMPLETE_CONTRACT_ONLY",
            )
            self.assertEqual(result["B2_VERIFIER_PRODUCTION_E2E"], "PRESERVED")
            self.assertEqual(
                result["B3_MANDATORY_AUTHENTICATED_CROSS_OBJECT_VALIDATION"],
                "CLOSED_CANDIDATE",
            )
            self.assertEqual(
                result["B4_MANDATORY_EXACT_DISPOSITION_LINEAGE"],
                "CLOSED_CANDIDATE",
            )
            self.assertEqual(result["P0_EXECUTED"], "NO")
            self.assertEqual(result["P1_EXECUTED"], "NO")
            self.assertEqual(result["RAW_LEVEL_HUMAN_DECISIONS"], 0)
            self.assertEqual(result["BSO_V_EXECUTED"], "NO")
            self.assertEqual(result["BSO_P_EXECUTED"], "NO")
            self.assertEqual(result["BINDING_PUBLICATION"], "NO")
            self.assertEqual(
                result["NEXT_ACTION"],
                "FRESH_TARGETED_INDEPENDENT_REVIEW_OF_R5_B3_B4_ONLY",
            )
            self.assertTrue((output.parent / r5.R5_HANDOFF_NAME).is_file())
            for relative in (
                "R4_TO_R5_DEFECT_REPRODUCTION_AND_TDD_LOG.json",
                "R4_TO_R5_PATCH_SUMMARY.json",
                "CONTRACT_MANIFEST.json",
                "FILE_LIST.txt",
                "SHA256SUMS.txt",
                "00_lineage/r4_baseline/CONTRACT_MANIFEST.json",
                "00_lineage/r4_review_input/fa1b2de-current86-bso-a2-p0-p1-execution-contract-r4-review-input.tar.gz",
                "09_tests/test_r5_contract_fixes.py",
                "09_tests/PACKAGED_TEST_EXECUTION.json",
                "run_packaged_tests.py",
                "tools/materialize_r5_contract.py",
            ):
                self.assertTrue((output / relative).is_file(), relative)
            self.assertEqual(
                r5.sha256_tree(output / "00_lineage/r4_baseline"),
                r5.sha256_tree(ROOT / r5.R4_DIR_NAME),
            )
            r5.verify_package(output)

    def test_review_handoff_is_path_independent_and_deterministic(self):
        from tools import materialize_r5_contract as r5

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            left_parent = root / "left"
            right_parent = root / "right"
            left_parent.mkdir()
            right_parent.mkdir()
            left = left_parent / r5.R5_DIR_NAME
            right = right_parent / r5.R5_DIR_NAME
            r5.materialize(ROOT, left)
            r5.materialize(ROOT, right)
            left_archive = (left.parent / r5.R5_HANDOFF_NAME).read_bytes()
            right_archive = (right.parent / r5.R5_HANDOFF_NAME).read_bytes()
            self.assertEqual(left_archive, right_archive)
            self.assertEqual(left_archive[3], 0)


if __name__ == "__main__":
    unittest.main()
