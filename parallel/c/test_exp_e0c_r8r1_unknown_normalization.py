import json
import unittest

from build_exp_e0c_r8_structured_human_review_support import (
    UNKNOWN,
    _is_unknown,
    _json_value,
)


class E0CR8R1UnknownNormalizationTests(unittest.TestCase):
    def test_all_unknown_collection_collapses_to_scalar_unknown(self):
        self.assertEqual(_json_value(["UNKNOWN"]), UNKNOWN)
        self.assertEqual(_json_value([UNKNOWN]), UNKNOWN)
        self.assertEqual(_json_value(("UNKNOWN",)), UNKNOWN)

    def test_empty_collection_is_unknown(self):
        self.assertEqual(_json_value([]), UNKNOWN)
        self.assertEqual(_json_value({}), UNKNOWN)
        self.assertTrue(_is_unknown(_json_value([])))

    def test_mixed_collection_preserves_known_value_and_counts_unknown_evidence(self):
        canonical = _json_value(["UNKNOWN", "HTTP"])
        self.assertEqual(json.loads(canonical), ["HTTP", "UNKNOWN"])
        self.assertTrue(_is_unknown(canonical))


if __name__ == "__main__":
    unittest.main()
