import importlib.util
import json
from copy import deepcopy
from pathlib import Path
import unittest


PACKAGE = Path(__file__).resolve().parents[1]
RECORD = PACKAGE / "fixtures" / "valid_record.json"


def load_module():
    path = PACKAGE / "tools" / "independent_recompute.py"
    spec = importlib.util.spec_from_file_location("independent_recompute_fail_closed", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FailClosedRecomputationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_module()
        cls.record = json.loads(RECORD.read_text(encoding="utf-8"))

    def load_fixture(self, name):
        return json.loads((PACKAGE / "fixtures" / "negative" / name).read_text(encoding="utf-8"))

    def test_authorized_valid_record_remains_accepted(self):
        result = self.tool.recompute(self.record)
        self.assertEqual(result["decision_record_id"], self.record["decision_identity"]["decision_record_id"])
        self.assertEqual(result["transaction_hash"], self.record["decision_identity"]["decision_transaction_hash"])

    def test_rejects_unauthorized_top_level_field(self):
        candidate = self.load_fixture("unauthorized_top_level_field.json")
        with self.assertRaisesRegex(self.tool.IndependentIdentityError, "unauthorized top-level field"):
            self.tool.recompute(candidate)

    def test_rejects_unauthorized_nested_identity_field(self):
        candidate = self.load_fixture("unauthorized_nested_identity_field.json")
        with self.assertRaisesRegex(self.tool.IndependentIdentityError, "unauthorized or missing identity field"):
            self.tool.recompute(candidate)

    def test_accepts_exact_identity_procedure_value(self):
        self.assertEqual(self.tool.recompute(self.record)["basis_sha256"], self.tool.EXPECTED_BASIS_DIGEST)

    def test_rejects_missing_identity_procedure_value(self):
        candidate = self.load_fixture("identity_procedure_missing.json")
        with self.assertRaisesRegex(self.tool.IndependentIdentityError, "missing required identity procedure"):
            self.tool.recompute(candidate)

    def test_rejects_mismatched_identity_procedure_value(self):
        candidate = self.load_fixture("identity_procedure_mismatch.json")
        with self.assertRaisesRegex(self.tool.IndependentIdentityError, "identity procedure mismatch"):
            self.tool.recompute(candidate)


if __name__ == "__main__":
    unittest.main()
