"""Tests for the standalone PROVX-R7 fresh independent review."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from PROVX_R7_FRESH_INDEPENDENT_REVIEW import run_review


EVIDENCE = Path("/home/cph/experiment-parallel/e0-a/e1c-r5-run-20260831T111849Z")
REPO = Path("/home/cph/fa1b2de-review-artifacts")


class FreshIndependentReviewTests(unittest.TestCase):
    def test_review_reaches_partial_terminal_and_recomputes_claimed_counts(self):
        with tempfile.TemporaryDirectory() as temp:
            result = run_review(EVIDENCE, REPO, Path(temp))
        self.assertEqual(result["PROVX_R7_FRESH_INDEPENDENT_REVIEW"], "PASS_PARTIAL_WAITING_FOR_E1C_R6_FILE_RW")
        self.assertEqual(result["CONSUMED_NORMALIZED_RECORDS"], 28)
        self.assertEqual(result["QUARANTINED_NORMALIZED_RECORDS"], 6)
        self.assertEqual(result["NODE_COUNT"], 10)
        self.assertEqual(result["EDGE_COUNT"], 22)

    def test_review_recomputes_claimed_hashes_and_contract_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            result = run_review(EVIDENCE, REPO, Path(temp))
        self.assertEqual(result["GRAPH_SHA256"], "b24b424d0e530a9d03c2bf01ed6a193447e3fa75b9725b978d7c27a0998b9acd")
        self.assertEqual(result["TENSOR_X_SHA256"], "605d1e2133589f9ae68d104ac62c2092d1d7238becf2a4cd99f9e7d34b9b621d")
        self.assertEqual(result["EDGE_INDEX_SHA256"], "f29e051b027b7fd5eb20b995cf82f5906b2eaceda75dd12c76ebae24c0dabd21")
        self.assertEqual(result["FILE_READ_OR_WRITE_PRESENT"], "NO")
        self.assertEqual(result["STAGE_A_FULL_COLLECTOR_ADAPTER_PASS"], "NO")
        self.assertEqual(result["NEXT_ACTION"], "WAIT_FOR_MININET_E1C_R6_RUNTIME_EVIDENCE")

    def test_review_records_zero_file_rw_and_full_regeneration_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            result = run_review(EVIDENCE, REPO, Path(temp))
        self.assertEqual(result["FILE_READ_OR_WRITE_SOURCE_COUNT"], 0)
        self.assertEqual(result["SYNTHESIZED_FILE_READ_OR_WRITE_EDGE_COUNT"], 0)
        self.assertTrue(result["REVERSED_INPUT_HASHES"]["tensor_x_identical"])
        self.assertTrue(result["REVERSED_INPUT_HASHES"]["edge_index_identical"])
        self.assertTrue(result["EDGE_SOURCE_HASH_EVIDENCE"])


if __name__ == "__main__":
    unittest.main()
