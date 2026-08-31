"""TDD tests for the frozen PROVX adapted live encoder."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import numpy as np

from PROVX_R4_ENCODER_IMPLEMENTATION import EncodingError, encode_records


ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "PROVX_R4_GOLDEN_FIXTURES.jsonl"


def load_fixture() -> list[dict]:
    return [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line.strip()]


class EncoderTests(unittest.TestCase):
  def test_encoder_returns_frozen_32d_float_and_int_tensors(self):
    encoded = encode_records(load_fixture(), run_id="fixture-run", graph_id="golden")
    self.assertEqual(encoded.x.dtype, np.float32)
    self.assertEqual(encoded.x.shape, (len(encoded.node_map), 32))
    self.assertEqual(encoded.edge_index.dtype, np.int64)
    self.assertEqual(encoded.edge_index.shape[0], 2)
    self.assertEqual(encoded.edge_index.shape[1], len(encoded.edge_map))
    self.assertTrue(np.isfinite(encoded.x).all())


  def test_encoder_covers_all_entity_and_event_classes(self):
    encoded = encode_records(load_fixture(), run_id="fixture-run", graph_id="golden")
    names = {row["entity_type"] for row in encoded.node_map}
    self.assertTrue({"process", "file", "socket", "other"}.issubset(names))
    self.assertTrue(all(encoded.x[:, i].max() > 0 for i in range(4)))
    # The six declared classes plus unknown-event routing must be represented.
    event_columns = list(range(19, 27))
    self.assertTrue(all(encoded.x[:, i].max() > 0 for i in event_columns))


  def test_unknown_and_missing_fields_are_explicitly_encoded(self):
    encoded = encode_records(load_fixture(), run_id="fixture-run", graph_id="golden")
    other_rows = [i for i, row in enumerate(encoded.node_map) if row["entity_type"] == "other"]
    self.assertTrue(other_rows)
    self.assertTrue(np.all(encoded.x[other_rows, 3] == 1.0))
    self.assertTrue(np.all(encoded.x[other_rows, 4] == 1.0))
    socket_missing = next(i for i, row in enumerate(encoded.node_map) if row["entity_type"] == "socket" and row["canonical_entity_id"].endswith("s-2"))
    self.assertEqual(encoded.x[socket_missing, 13], 0.0)
    self.assertEqual(encoded.x[socket_missing, 14], 0.0)
    self.assertEqual(encoded.x[socket_missing, 15], 0.0)
    self.assertEqual(encoded.x[socket_missing, 16], 0.0)


  def test_nonfinite_input_is_rejected(self):
    records = load_fixture()
    records[0]["timestamp_ms"] = float("nan")
    with self.assertRaisesRegex(EncodingError, "finite"):
        encode_records(records, run_id="fixture-run", graph_id="invalid")


  def test_duplicate_coalescing_self_loop_and_raw_key_reversibility(self):
    encoded = encode_records(load_fixture(), run_id="fixture-run", graph_id="golden")
    duplicate_groups = encoded.normalization_map["duplicate_columns_coalesced"]
    self.assertTrue(duplicate_groups)
    self.assertTrue(any(len(group["source_record_refs"]) == 2 for group in duplicate_groups))
    self.assertTrue(encoded.normalization_map["self_loop_columns"])
    all_refs = {ref for edge in encoded.edge_map for ref in edge["source_record_refs"]}
    self.assertTrue(all(ref in all_refs for ref in {row["id"] for row in load_fixture()}))


  def test_ordering_and_repeat_generation_are_stable(self):
    records = load_fixture()
    first = encode_records(records, run_id="fixture-run", graph_id="golden")
    second = encode_records(list(reversed(records)), run_id="fixture-run", graph_id="golden")
    np.testing.assert_array_equal(first.x, second.x)
    np.testing.assert_array_equal(first.edge_index, second.edge_index)
    self.assertEqual(first.node_map, second.node_map)
    self.assertEqual(first.edge_map, second.edge_map)
    self.assertEqual(first.normalization_map, second.normalization_map)
    self.assertEqual(first.run_manifest, second.run_manifest)


  def test_run_id_changes_raw_keys_but_preserves_feature_content(self):
    records = load_fixture()
    first = encode_records(records, run_id="fixture-run-a", graph_id="golden")
    second = encode_records(records, run_id="fixture-run-b", graph_id="golden")
    np.testing.assert_array_equal(first.x, second.x)
    self.assertNotEqual([row["raw_key"] for row in first.edge_map], [row["raw_key"] for row in second.edge_map])


if __name__ == "__main__":
    unittest.main()
