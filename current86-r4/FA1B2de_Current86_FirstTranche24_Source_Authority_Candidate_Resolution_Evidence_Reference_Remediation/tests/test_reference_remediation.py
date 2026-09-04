#!/usr/bin/env python3
"""Tests for the single-reference candidate-resolution remediation."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("verify_remediation", PACKAGE / "tools/verify_remediation.py")
assert spec is not None and spec.loader is not None
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class ReferenceRemediationTests(unittest.TestCase):
    def test_corrected_reference_closes_without_semantic_drift(self) -> None:
        result = verifier.main()
        self.assertEqual(result["RESOLVED_EVIDENCE_AUTHENTICATION"], "PASS")
        self.assertEqual(result["RESOLVED_EVIDENCE_SEMANTIC_SUPPORT"], "PASS")
        self.assertEqual(result["CANDIDATE_SEMANTIC_DRIFT"], 0)
        self.assertEqual(result["STALE_BAD_REFERENCE_COUNT"], 0)

    def test_operational_boundary_remains_zero(self) -> None:
        result = verifier.main()
        for key in (
            "SOURCE_AUTHORITY_ID_DERIVED",
            "SOURCE_AUTHORITY_ACTIVATED",
            "SOURCE_ACQUISITION",
            "SOURCE_AUTH_EXECUTED",
            "P0_EXECUTED",
            "P1_EXECUTED",
            "FORMAL_1796_EXPERIMENT_EXECUTED",
        ):
            self.assertEqual(result[key], "NO")
        for key in ("STAGE_A_ADMISSIONS", "STAGE_B_EXPOSURES", "FIELD_PINS", "OPERATIVE_RECORDS"):
            self.assertEqual(result[key], 0)


if __name__ == "__main__":
    unittest.main()
