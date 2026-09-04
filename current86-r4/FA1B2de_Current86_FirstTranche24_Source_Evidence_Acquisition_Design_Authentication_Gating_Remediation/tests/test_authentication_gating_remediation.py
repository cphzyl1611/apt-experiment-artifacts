#!/usr/bin/env python3
"""Regression tests for the envelope authentication-gating remediation."""

from __future__ import annotations

import json
import importlib.util
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


PACKAGE = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PACKAGE / "ACQUIRED_EVIDENCE_ENVELOPE_SCHEMA.json"
COUNTEREXAMPLE_PATH = PACKAGE / "BLOCKER_COUNTEREXAMPLE.json"
VALIDATOR_PATH = PACKAGE / "tools" / "validate_remediation.py"


class AuthenticationGatingSchemaTests(unittest.TestCase):
    def test_pass_with_null_execution_reference_is_rejected(self) -> None:
        """A PASS status without execution evidence must never be eligible."""
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        counterexample = json.loads(COUNTEREXAMPLE_PATH.read_text(encoding="utf-8"))

        errors = list(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
                counterexample
            )
        )

        self.assertGreater(len(errors), 0)

    def test_remediation_validator_accepts_only_gated_synthetic_fixtures(self) -> None:
        """The full local suite must retain legacy rejections and admit P1/P2 only."""
        spec = importlib.util.spec_from_file_location("validate_remediation", VALIDATOR_PATH)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        result = module.validate_package()

        self.assertEqual(result["draft_2020_12_meta_validation"], "PASS")
        self.assertEqual(result["static_validator"], "PASS")
        self.assertEqual(result["authentication_gating_invariant"], "PASS")
        self.assertEqual(result["negative_fixtures"], "24/24 REJECTED")
        self.assertEqual(result["positive_fixtures"], "2/2 ACCEPTED")
        self.assertEqual(result["semantic_non_regression"]["acquisition_design_semantic_drift"], 0)
        self.assertEqual(result["zero_operational_effect"]["zero_operational_effect"], "PASS")


if __name__ == "__main__":
    unittest.main()
