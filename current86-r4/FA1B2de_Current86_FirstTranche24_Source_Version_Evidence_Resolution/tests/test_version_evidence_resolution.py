#!/usr/bin/env python3
"""Static tests for the bounded source-version evidence resolution package."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "tools" / "validate_version_evidence_resolution.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("version_evidence_validator", VALIDATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VersionEvidenceResolutionTests(unittest.TestCase):
    def test_valid_acquisition_pending_package_passes(self) -> None:
        validator = load_validator()
        result = validator.validate_package()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["version_evidence_resolution_state"], "VERSION_EVIDENCE_REQUIRES_SOURCE_ACQUISITION")
        self.assertEqual(result["version_evidence_inventory_consistency"], "PASS")
        self.assertEqual(result["negative_fixtures"], "12/12 REJECTED")
        self.assertEqual(result["zero_operational_effect"], "PASS")

    def test_each_required_negative_fixture_rejects_with_expected_code(self) -> None:
        validator = load_validator()
        index = json.loads((ROOT / "fixtures" / "NEGATIVE_FIXTURE_INDEX.json").read_text(encoding="utf-8"))
        required = {
            "ARTIFACT_IDENTITY_MISMATCH",
            "AMBIGUOUS_ARTIFACT_IDENTITY",
            "FLOATING_VERSION_REFERENCE",
            "UNSUPPORTED_IMMUTABLE_VERSION_FORM",
            "CONTENT_SHA_MISMATCH",
            "DIGEST_FROM_WRONG_ARTIFACT",
            "BROKEN_AUTHORITY_TO_ARTIFACT_LINEAGE",
            "MISSING_OWNER_ISSUER_AUTHORIZATION",
            "WRONG_GOVERNANCE_DECISION_BINDING",
            "SCOPE_WIDENING",
            "MIXED_ARTIFACT_VERSIONS",
            "UNAUTHORIZED_FIELD",
        }
        self.assertEqual({item["expected_rejection"] for item in index["fixtures"]}, required)
        results = validator.validate_negative_fixtures()
        self.assertEqual(len(results), 12)
        self.assertEqual({item["rejection"] for item in results}, required)

    def test_validator_has_no_operational_or_source_acquisition_capability(self) -> None:
        source = VALIDATOR_PATH.read_text(encoding="utf-8")
        forbidden_imports = (
            "import requests",
            "import socket",
            "import subprocess",
            "import urllib",
            "from requests",
            "from socket",
            "from subprocess",
            "from urllib",
        )
        self.assertTrue(all(token not in source for token in forbidden_imports))
        forbidden_calls = ("urlopen(", "Popen(", "run(", "check_call(", "check_output(")
        self.assertTrue(all(token not in source for token in forbidden_calls))

    def test_manifest_excludes_itself_and_covers_all_other_payload_files(self) -> None:
        manifest = json.loads((ROOT / "MATERIALIZATION_MANIFEST.json").read_text(encoding="utf-8"))
        self.assertEqual(set(manifest), {"version", "track", "task_id", "commit_message", "files"})
        self.assertEqual(manifest["version"], "1.0")
        self.assertEqual(manifest["track"], "binding")
        self.assertEqual(manifest["task_id"], "FIRST_TRANCHE24_SOURCE_VERSION_EVIDENCE_RESOLUTION")
        destinations = {entry["destination"] for entry in manifest["files"]}
        self.assertTrue(all(set(entry) == {"source", "destination", "sha256"} for entry in manifest["files"]))
        self.assertFalse(any(path.endswith("/MATERIALIZATION_MANIFEST.json") for path in destinations))

        payload = {
            path.relative_to(ROOT).as_posix()
            for path in ROOT.rglob("*")
            if path.is_file()
            and path.name != "MATERIALIZATION_MANIFEST.json"
            and "__pycache__" not in path.parts
        }
        manifested = {
            entry["destination"].split("FA1B2de_Current86_FirstTranche24_Source_Version_Evidence_Resolution/", 1)[1]
            for entry in manifest["files"]
        }
        self.assertEqual(manifested, payload)


if __name__ == "__main__":
    unittest.main()
