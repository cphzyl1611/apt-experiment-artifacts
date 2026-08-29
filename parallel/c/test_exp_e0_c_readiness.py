from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from build_exp_e0_c_readiness import (
    audit_raw_authority,
    build_readiness_rows,
    observability_summary,
)


CORPUS = Path("/home/cph/experiment/APT数据集/playbooks")
REGISTRY = Path(
    "/home/cph/experiment-worktrees/full-action-protocol-binding/"
    "data/full_action/raw_action_registry.jsonl"
)


class RawAuthorityAuditTests(unittest.TestCase):
    def test_known_corpus_and_registry_conserve_all_1796_raw_actions(self):
        audit = audit_raw_authority(CORPUS, REGISTRY)

        self.assertTrue(audit["passed"], audit["failure_reasons"])
        self.assertEqual(audit["source_playbook_count"], 53)
        self.assertEqual(audit["source_stage_count"], 434)
        self.assertEqual(audit["source_derived_raw_count"], 1796)
        self.assertEqual(audit["registry_row_count"], 1796)
        self.assertEqual(audit["source_derived_unique_raw_keys"], 1796)
        self.assertEqual(audit["registry_unique_raw_keys"], 1796)
        self.assertEqual(audit["missing_in_registry"], [])
        self.assertEqual(audit["extra_in_registry"], [])
        self.assertEqual(audit["raw_key_mismatch_count"], 0)
        self.assertEqual(audit["source_file_sha_mismatch_count"], 0)
        self.assertEqual(audit["source_locator_mismatch_count"], 0)
        self.assertEqual(
            audit["historical_manifest_recomputed_sha256"],
            "d52db285fc38deb0430ee32fad24b37e54e2f2b95f6f0ac35b96a42754725efa",
        )

    def test_readiness_rows_remain_unexecuted_and_conservative(self):
        audit = audit_raw_authority(CORPUS, REGISTRY)
        rows = build_readiness_rows(audit["source_rows"])

        self.assertEqual(len(rows), 1796)
        self.assertEqual(len({row["raw_key"] for row in rows}), 1796)
        self.assertTrue(all(row["raw_authority_status"] == "AUTHENTICATED" for row in rows))
        self.assertTrue(all(row["candidate_fidelity"] == "NOT_YET_EXECUTABLE" for row in rows))
        self.assertTrue(all(row["formal_execution_authorized"] is False for row in rows))
        self.assertTrue(
            all(row["attack_action_success"] == "UNEXECUTED_NOT_OBSERVED" for row in rows)
        )
        self.assertTrue(
            all(row["provx_expected_entity_types"] == ["UNKNOWN"] for row in rows)
        )

    def test_observability_summary_covers_each_playbook_and_stage(self):
        audit = audit_raw_authority(CORPUS, REGISTRY)
        summary = observability_summary(build_readiness_rows(audit["source_rows"]))

        self.assertEqual(len(summary["by_playbook"]), 53)
        self.assertEqual(sum(summary["by_playbook"].values()), 1796)
        self.assertEqual(len(summary["by_stage"]), 434)
        self.assertEqual(sum(summary["by_stage"].values()), 1796)

    def test_blocked_authority_terminal_preserves_boundary_statuses(self):
        script = Path(__file__).with_name("build_exp_e0_c_readiness.py")
        with TemporaryDirectory() as directory:
            corpus = Path(directory) / "playbooks"
            corpus.mkdir()
            (corpus / "malformed.json").write_text("{}", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--playbooks-root",
                    str(corpus),
                    "--registry",
                    str(REGISTRY),
                    "--output-dir",
                    directory,
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("EXP_E0_C_RAW_AUTHORITY = BLOCKED", result.stdout)
        self.assertIn("EXP_E0_C_CONSERVATION = BLOCKED", result.stdout)
        self.assertIn("FORMAL_EXPERIMENT_EXECUTED = NO", result.stdout)
        self.assertIn("BINDING_AUTHORITY_MUTATION = NO", result.stdout)
        self.assertIn("SCORING_AUTHORITY_MUTATION = NO", result.stdout)
        self.assertIn("DENOMINATOR_CHANGE = NO", result.stdout)
        self.assertIn("NEXT_ACTION = FIX_EXACT_RAW_AUTHORITY_DEFECT", result.stdout)
        self.assertIn("STOP = true", result.stdout)

    def test_source_stage_census_includes_empty_action_lists(self):
        with TemporaryDirectory() as directory:
            corpus = Path(directory) / "playbooks"
            corpus.mkdir()
            (corpus / "P1.json").write_text(
                '{"vid":"P1","pipeline":[{"actions":[]},{"actions":['
                '{"name":"action","desc":"","action_type":"host_cli","os":"linux"}]}]}',
                encoding="utf-8",
            )
            audit = audit_raw_authority(corpus, REGISTRY)

        self.assertEqual(audit["source_stage_count"], 2)
        self.assertEqual(audit["source_derived_raw_count"], 1)


if __name__ == "__main__":
    unittest.main()
