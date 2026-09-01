"""Regression tests for the R7 R5 development-fixture adapter."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from PROVX_R7_NORMALIZED_TO_GRAPH_ADAPTER import (
    NORMALIZED_NAME,
    RAW_NAME,
    R5_RUN_ID,
    authenticate_r5_evidence,
    build_graph,
    encode_graph,
    load_jsonl,
    write_r7_outputs,
)


EVIDENCE = Path("/home/cph/experiment-parallel/e0-a/e1c-r5-run-20260831T111849Z")


class R7GraphAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.auth = authenticate_r5_evidence(EVIDENCE)
        cls.rows = [row for row in cls.auth["_normalized"] if row["raw_serial"] in set(cls.auth["_consumed_serials"])]

    def test_recomputes_all_links_and_retains_historical_discrepancy(self):
        self.assertEqual(self.auth["independent_recomputation"]["consumed_records"], 28)
        self.assertEqual(self.auth["independent_recomputation"]["serial_links"], "28/28")
        self.assertEqual(self.auth["independent_recomputation"]["raw_event_sha256_matches_raw_sha256"], "28/28")
        self.assertFalse(self.auth["historical_normalized_raw_links_valid"])
        self.assertTrue(self.auth["historical_discrepancy_recorded"])

    def test_unjoined_records_are_quarantined_and_no_read_write_is_synthesized(self):
        graph = build_graph(self.rows, self.auth["_joins"], run_id=R5_RUN_ID)
        self.assertEqual(graph.manifest["quarantined_event_count"], 6)
        self.assertFalse(any(row["event_type"] == "write" for row in graph.encoder_records))
        self.assertFalse(any(row["raw_serial"] in {697, 698, 699, 700, 701, 703} for row in graph.edge_map))

    def test_reversible_graph_and_frozen_tensor_contract(self):
        graph = build_graph(self.rows, self.auth["_joins"], run_id=R5_RUN_ID)
        encoded, tensor = encode_graph(graph)
        self.assertEqual(encoded.x.dtype, np.float32)
        self.assertEqual(encoded.x.shape[1], 32)
        self.assertEqual(encoded.edge_index.dtype, np.int64)
        self.assertEqual(encoded.edge_index.shape[0], 2)
        self.assertTrue(np.isfinite(encoded.x).all())
        self.assertEqual(set(graph.reversibility["graph_node_id_to_evidence"]), {r["graph_node_id"] for r in graph.node_map})
        self.assertFalse(tensor["checkpoint_loaded"])

    def test_reversed_input_is_byte_for_byte_deterministic(self):
        first = build_graph(self.rows, self.auth["_joins"], run_id=R5_RUN_ID)
        second = build_graph(list(reversed(self.rows)), self.auth["_joins"], run_id=R5_RUN_ID)
        self.assertEqual(first.manifest["graph_sha256"], second.manifest["graph_sha256"])
        encoded_a, _ = encode_graph(first)
        encoded_b, _ = encode_graph(second)
        np.testing.assert_array_equal(encoded_a.x, encoded_b.x)
        np.testing.assert_array_equal(encoded_a.edge_index, encoded_b.edge_index)

    def test_writer_emits_all_r7_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            result = write_r7_outputs(EVIDENCE, temp)
            for name in (
                "PROVX_R7_R5_EVIDENCE_AUTHENTICATION.json",
                "PROVX_R7_NORMALIZED_GRAPH_INPUT_SCHEMA.json",
                "PROVX_R7_R5_PARTIAL_GRAPH_MANIFEST.json",
                "PROVX_R7_R5_GRAPH_RAW_REVERSIBILITY.json",
                "PROVX_R7_R5_32D_TENSOR_MANIFEST.json",
                "PROVX_R7_DETERMINISTIC_REGENERATION_VERIFICATION.json",
                "PROVX_R7_E1C_R6_REVALIDATION_CONTRACT.json",
                "PROVX_R7_STAGE_A_PARTIAL_ADAPTER_REPORT.md",
            ):
                self.assertTrue((Path(temp) / name).exists(), name)
            self.assertEqual(result["deterministic"]["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
