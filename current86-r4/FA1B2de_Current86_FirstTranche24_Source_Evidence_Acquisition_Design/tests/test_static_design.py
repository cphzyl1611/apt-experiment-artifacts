#!/usr/bin/env python3
"""Static tests for the source-evidence acquisition design package."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = PACKAGE / "tools" / "validate_design.py"


class StaticDesignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not VALIDATOR_PATH.exists():
            raise AssertionError("static validator has not been created")
        spec = importlib.util.spec_from_file_location("validate_design", VALIDATOR_PATH)
        if spec is None or spec.loader is None:
            raise AssertionError("could not load static validator")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.validator = module

    def test_design_package_passes_fail_closed_validator(self) -> None:
        result = self.validator.validate_package()
        self.assertEqual(result["schema_meta_validation"], "PASS")
        self.assertEqual(result["static_validator"], "PASS")
        self.assertEqual(result["governance_decision_binding"], "PASS")
        self.assertEqual(result["first_tranche24_scope_exactness"], "PASS")
        self.assertEqual(result["negative_fixtures_rejected"], 19)
        self.assertEqual(result["zero_operational_effect"], "PASS")

    def test_validator_is_local_and_non_operational(self) -> None:
        source = VALIDATOR_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "subprocess",
            "socket",
            "requests",
            "urllib",
            "httpx",
            "activate_authority",
            "acquire_source",
            "SOURCE_AUTHORITY_ID",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
