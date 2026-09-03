import importlib.util
import json
from copy import deepcopy
from pathlib import Path
import unittest


PACKAGE = Path(__file__).resolve().parents[1]
RECORD = PACKAGE.parent / "FA1B2de_Current86_FirstTranche24_G1G2_Decision_Preparation_V2" / "FIRST_TRANCHE24_GOVERNANCE_DECISION_RECORD_V2.json"


def load_module():
    path = PACKAGE / "tools" / "independent_recompute.py"
    spec = importlib.util.spec_from_file_location("independent_recompute", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class IndependentRecomputationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_module()
        cls.record = json.loads(RECORD.read_text(encoding="utf-8"))

    def test_independent_recomputation_matches_declared_values(self):
        result = self.tool.recompute(self.record)
        self.assertEqual(result["decision_record_id"], self.record["decision_identity"]["decision_record_id"])
        self.assertEqual(result["transaction_hash"], self.record["decision_identity"]["decision_transaction_hash"])
        self.assertEqual(result["basis_sha256"], self.tool.EXPECTED_BASIS_DIGEST)

    def test_metadata_is_excluded(self):
        candidate = deepcopy(self.record)
        candidate["decision_timestamp_metadata"]["decided_at_utc"] = "2099-12-31T23:59:59Z"
        candidate["reviewer_metadata"] = {"random": "value"}
        self.assertEqual(self.tool.recompute(candidate), self.tool.recompute(self.record))

    def test_duplicate_json_keys_fail_closed(self):
        with self.assertRaises(self.tool.IndependentIdentityError):
            self.tool.load_json(str(PACKAGE / "fixtures" / "duplicate_keys.json"))


if __name__ == "__main__":
    unittest.main()
