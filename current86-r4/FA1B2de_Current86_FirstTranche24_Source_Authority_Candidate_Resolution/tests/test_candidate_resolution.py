#!/usr/bin/env python3
"""Static fail-closed tests for FIRST_TRANCHE24 candidate resolution."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = PACKAGE / "tools" / "validate_candidate_resolution.py"
spec = importlib.util.spec_from_file_location("validate_candidate_resolution", VALIDATOR_PATH)
assert spec is not None and spec.loader is not None
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class CandidateResolutionTests(unittest.TestCase):
    def test_package_passes_static_validation(self) -> None:
        result = validator.validate_package()
        self.assertEqual(result["entry_binding_authentication"], "PASS")
        self.assertEqual(result["governance_binding"], "PASS")
        self.assertEqual(result["first_tranche24_scope_exactness"], "PASS")
        self.assertEqual(result["candidate_set_consistency"], "PASS")
        self.assertEqual(result["provenance_map_consistency"], "PASS")
        self.assertEqual(result["version_policy_compatibility"], "PASS_PENDING")
        self.assertEqual(result["negative_fixtures_rejected"], 10)
        self.assertEqual(result["zero_operational_effect"], "PASS")

    def test_validator_is_read_only_and_non_operational(self) -> None:
        source = VALIDATOR_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "subprocess",
            "socket",
            "requests",
            "urllib",
            "activate_authority",
            "acquire_source",
            "clone",
            "download",
            "urlopen",
        ):
            self.assertNotIn(forbidden, source)

    def test_required_negative_cases_are_present_and_rejected(self) -> None:
        result = validator.validate_package()
        self.assertEqual(result["negative_fixtures_rejected"], 10)
        self.assertEqual(
            result["negative_fixture_codes"],
            [
                "MULTIPLE_CANDIDATES_RESOLVED",
                "ZERO_RESOLVED_CANDIDATES",
                "WRONG_GOVERNANCE_DECISION_ID",
                "WRONG_GOVERNANCE_TRANSACTION_HASH",
                "SCOPE_WIDENING",
                "PROVENANCE_REFERENCE_MISMATCH",
                "VERSION_POLICY_INCOMPATIBILITY",
                "UNAUTHORIZED_FIELD",
                "MIXED_CANDIDATE_EVIDENCE",
                "FAKE_ACTIVATED_STATE",
            ],
        )


if __name__ == "__main__":
    unittest.main()
