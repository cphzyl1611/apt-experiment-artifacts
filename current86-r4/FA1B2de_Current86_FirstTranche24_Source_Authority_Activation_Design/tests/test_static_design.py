#!/usr/bin/env python3
"""Static tests for the design package; no external or operational calls."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = PACKAGE / "tools" / "validate_design.py"
spec = importlib.util.spec_from_file_location("validate_design", VALIDATOR_PATH)
assert spec is not None and spec.loader is not None
validate_design = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate_design)


class StaticDesignTests(unittest.TestCase):
    def test_package_passes_fail_closed_validator(self) -> None:
        result = validate_design.validate_package()
        self.assertEqual(result["schema_meta_validation"], "PASS")
        self.assertEqual(result["valid_synthetic_fixture"], "PASS")
        self.assertEqual(result["negative_fixtures_rejected"], 10)
        self.assertEqual(result["governance_decision_binding"], "PASS")
        self.assertEqual(result["first_tranche24_scope_exactness"], "PASS")
        self.assertEqual(result["static_validator_fail_closed"], "PASS")

    def test_validator_is_read_only_and_non_operational(self) -> None:
        source = VALIDATOR_PATH.read_text(encoding="utf-8")
        for forbidden in ("subprocess", "socket", "requests", "urllib", "activate_authority", "acquire_source"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
