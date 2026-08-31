import hashlib
import json
import sys
from pathlib import Path

import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from r5_wrapper import (
    WrapperError,
    authenticate_human_approval,
    extract_c0,
    extract_raw,
    extract_scoring,
    validate_exact317_conservation,
)


ROOT = Path(__file__).resolve().parents[2]
R4 = ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Prospective_Canonical_Wrapper_Governance_R4"
TARGET_MANIFEST = ROOT / "FA1B2de_Current86_Exact317_SourceAuth_Execution_Contract_R4/00_lineage/EXACT317_TARGET_MANIFEST.json"
RAW_REGISTRY = Path("/home/cph/experiment-artifacts/fa1b2de-bso-r-20260825T100958Z/inputs/project_snapshots/raw_action_registry.jsonl")
PLAYBOOK_ROOT = Path("/home/cph/experiment")
C0_SOURCE = Path("/home/cph/experiment-artifacts/tier-de1c0-handoff-20260823-083725/tier_de1c0_typed_operation_semantics.jsonl")
SCORING_SOURCE = Path("/home/cph/experiment-artifacts/fa1b2de-bso-r-20260825T100958Z/inputs/c2/c2_scoring_snapshot_post_c1.jsonl")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def targets():
    return read_json(TARGET_MANIFEST)["targets"]


def route_targets(rule_id):
    commitments = read_json(R4 / "PROSPECTIVE_TARGET_EXPANSION_COMMITMENTS.json")
    ids = next(r["target_ids"] for r in commitments["routes"] if r["rule_id"] == rule_id)
    by_id = {t["source_binding_target_id"]: t for t in targets()}
    return [by_id[i] for i in ids]


class R5MaterializationTests(unittest.TestCase):
  def test_human_approval_authenticates_all_three_exact_r4_rules(self):
    rules = read_json(R4 / "PROSPECTIVE_EXTRACTION_AUTHORITY_RULES.json")
    frozen_hash = hashlib.sha256((R4 / "SHA256SUMS.txt").read_bytes()).hexdigest()
    approval = {
        "HUMAN_ORIGIN": "USER_EXPLICIT_APPROVAL",
        "decisions": {
            "R4_WRAPPER_RAW_LEGACY_26": "APPROVE_EXACT_CANONICAL_WRAPPER_RULE",
            "R4_WRAPPER_C0_60": "APPROVE_EXACT_CANONICAL_WRAPPER_RULE",
            "R4_WRAPPER_SCORING_231": "APPROVE_EXACT_CANONICAL_WRAPPER_RULE",
        },
    }
    result = authenticate_human_approval(approval, rules, frozen_hash)
    self.assertIs(result["authenticated"], True)
    self.assertEqual(result["human_origin"], "USER_EXPLICIT_APPROVAL")
    self.assertEqual(result["approved_rule_ids"], sorted(approval["decisions"]))
    self.assertEqual(result["frozen_r4_sha256sums_sha256"], frozen_hash)


  def test_human_approval_rejects_missing_or_extra_rule(self):
    rules = read_json(R4 / "PROSPECTIVE_EXTRACTION_AUTHORITY_RULES.json")
    frozen_hash = hashlib.sha256((R4 / "SHA256SUMS.txt").read_bytes()).hexdigest()
    approval = {
        "HUMAN_ORIGIN": "USER_EXPLICIT_APPROVAL",
        "decisions": {"R4_WRAPPER_RAW_LEGACY_26": "APPROVE_EXACT_CANONICAL_WRAPPER_RULE"},
    }
    with self.assertRaises(WrapperError):
        authenticate_human_approval(approval, rules, frozen_hash)


  def test_raw_positional_extractor_is_exact_one_for_26_targets(self):
    rows = read_jsonl(RAW_REGISTRY)
    records = extract_raw(route_targets("R4_WRAPPER_RAW_LEGACY_26"), rows, PLAYBOOK_ROOT)
    self.assertEqual(len(records), 26)
    self.assertEqual({r["target_index"] for r in records}, {t["target_index"] for t in route_targets("R4_WRAPPER_RAW_LEGACY_26")})
    self.assertTrue(all(r["authority_status"] == "CANDIDATE_WRAPPER_OBJECTS_ONLY" for r in records))
    self.assertTrue(all(r["historical_producer_identity_recovered"] is False for r in records))
    self.assertTrue(all(r["source_locator"].startswith("$.pipeline[") for r in records))


  def test_c0_exact_row_extractor_is_exact_one_for_60_targets(self):
    records = extract_c0(
        route_targets("R4_WRAPPER_C0_60"),
        C0_SOURCE,
        expected_source_sha256="0036c42fb02026182274a7ac2a33b103b03b1e527856eb33b5ad650ceddd5c32",
    )
    self.assertEqual(len(records), 60)
    self.assertEqual(len({r["target_index"] for r in records}), 60)
    self.assertTrue(all(r["authority_status"] == "CANDIDATE_WRAPPER_OBJECTS_ONLY" for r in records))
    self.assertTrue(all(r["historical_source_identity_preserved"] is True for r in records))


  def test_scoring_exact_id_extractor_is_exact_one_for_231_targets(self):
    records = extract_scoring(
        route_targets("R4_WRAPPER_SCORING_231"),
        SCORING_SOURCE,
        expected_source_sha256="748a3808290f9e78f71c18d4553c77ae208517fd31d163fc2b3008cfcb57f1bb",
    )
    self.assertEqual(len(records), 231)
    self.assertEqual(len({r["target_index"] for r in records}), 231)
    self.assertTrue(all(r["authority_status"] == "CANDIDATE_WRAPPER_OBJECTS_ONLY" for r in records))
    self.assertTrue(all(r["scoring_authority_mutated"] is False for r in records))
    target_100 = next(record for record in records if record["target_index"] == 100)
    self.assertEqual(target_100["jsonl_line"], 48)
    self.assertEqual(target_100["row_bytes_sha256"], "32dfc70eaf48e9a00d795641f8e3f121ff9b7d8516df75ed3d0140fe14bf1ba7")


  def test_extractors_fail_closed_on_zero_multiple_and_cross_route_substitution(self):
    import tempfile
    with tempfile.TemporaryDirectory() as td:
      tmp_path = Path(td)
      target = {"target_index": 1, "source_binding_target_id": "t1", "bound_raw_key": "p::S01::A001", "source_side": "RAW"}
      registry = [{"raw_action_key": "p::S01::A001", "playbook_id": "p", "stage_identifier": "S01", "stage_index": 1, "action_index": 1, "source_file": "p.json", "source_file_sha256": "x"}]
      (tmp_path / "p.json").write_text('{"pipeline":[{"actions":[{}]}]}', encoding="utf-8")
      with self.assertRaises(WrapperError):
          extract_raw([target], registry, tmp_path)
      with self.assertRaises(WrapperError):
          extract_c0([target], tmp_path / "empty.jsonl", expected_source_sha256=hashlib.sha256(b"").hexdigest())
      with self.assertRaises(WrapperError):
          extract_scoring([target], tmp_path / "empty.jsonl", expected_source_sha256=hashlib.sha256(b"").hexdigest())


  def test_exact317_union_conservation_and_zero_duplicates(self):
    ts = targets()
    raw = extract_raw(route_targets("R4_WRAPPER_RAW_LEGACY_26"), read_jsonl(RAW_REGISTRY), PLAYBOOK_ROOT)
    c0 = extract_c0(route_targets("R4_WRAPPER_C0_60"), C0_SOURCE, "0036c42fb02026182274a7ac2a33b103b03b1e527856eb33b5ad650ceddd5c32")
    scoring = extract_scoring(route_targets("R4_WRAPPER_SCORING_231"), SCORING_SOURCE, "748a3808290f9e78f71c18d4553c77ae208517fd31d163fc2b3008cfcb57f1bb")
    summary = validate_exact317_conservation(ts, {"R4_WRAPPER_RAW_LEGACY_26": raw, "R4_WRAPPER_C0_60": c0, "R4_WRAPPER_SCORING_231": scoring})
    self.assertEqual(summary, {
        "targets_total": 317,
        "raw": 86,
        "candidate": 231,
        "duplicates": 0,
        "cross_route_substitution": 0,
        "union": "Exact317",
        "exact": True,
    })

  def test_non_active_admission_candidate_references_all_wrapper_objects(self):
    dry_run = [
        json.loads(line)
        for line in (R4.parent / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R5_Wrapper_Materialization/05_dry_run/EXACT317_CANDIDATE_WRAPPER_OBJECTS_ONLY.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    root = json.loads((R4.parent / "FA1B2de_Current86_Exact317_SourceAuth_Binding_R5_Wrapper_Materialization/06_non_active_candidates/SOURCE_ADMISSION_REGISTRY_ROOT_CANDIDATE.json").read_text(encoding="utf-8"))
    self.assertEqual(len({r["candidate_object_id"] for r in dry_run}), 317)
    self.assertEqual(set(root["candidate_object_ids"]), {r["candidate_object_id"] for r in dry_run})
    self.assertEqual(root["field_pin_authority_status"], "BLOCKED_NOT_CREATED")


if __name__ == "__main__":
    unittest.main()
