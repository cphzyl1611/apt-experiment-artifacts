"""Static tests for the R6R4 privileged-runtime smoke preparation package."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parent
REPOSITORY_ROOT = PACKAGE.parents[2]
sys.dont_write_bytecode = True


def load_validator(package: Path):
    module_path = package / "validate_runtime_smoke_preparation.py"
    spec = importlib.util.spec_from_file_location("runtime_smoke_preparation_validator", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RuntimeSmokePreparationTests(unittest.TestCase):
    def test_valid_package_materializes_only_after_static_validation(self):
        self.assertTrue((PACKAGE / "validate_runtime_smoke_preparation.py").is_file())
        with tempfile.TemporaryDirectory() as temp:
            candidate = Path(temp) / "package"
            shutil.copytree(PACKAGE, candidate, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            (candidate / "MATERIALIZATION_MANIFEST.json").unlink(missing_ok=True)

            result = load_validator(candidate).validate_package(
                candidate,
                materialize=True,
                repository_root=REPOSITORY_ROOT,
            )

            manifest_path = candidate / "MATERIALIZATION_MANIFEST.json"
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(manifest_path.is_file())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "PASS_STATIC_PREPARATION_ONLY")
            self.assertEqual(manifest["PRIVILEGED_RUNTIME_SMOKE_EXECUTED"], "NO")
            self.assertEqual(manifest["FILE_READ_OR_WRITE_RUNTIME_CLOSURE"], "NOT_PROVEN")

    def test_invalid_package_does_not_create_manifest(self):
        self.assertTrue((PACKAGE / "EXPECTED_RUNTIME_RECEIPT_SCHEMA.json").is_file())
        with tempfile.TemporaryDirectory() as temp:
            candidate = Path(temp) / "package"
            shutil.copytree(PACKAGE, candidate, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            (candidate / "MATERIALIZATION_MANIFEST.json").unlink(missing_ok=True)
            schema_path = candidate / "EXPECTED_RUNTIME_RECEIPT_SCHEMA.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["receipt"]["required_artifacts"].remove("pcap_hash_source")
            schema_path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")

            result = load_validator(candidate).validate_package(
                candidate,
                materialize=True,
                repository_root=REPOSITORY_ROOT,
            )

            self.assertEqual(result["status"], "BLOCKED")
            self.assertFalse((candidate / "MATERIALIZATION_MANIFEST.json").exists())
            self.assertIn("pcap_hash_source", " ".join(result["failures"]))

    def test_non_string_receipt_artifact_blocks_and_removes_stale_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            candidate = Path(temp) / "package"
            shutil.copytree(PACKAGE, candidate, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            (candidate / "MATERIALIZATION_MANIFEST.json").write_text("{}\n", encoding="utf-8")
            schema_path = candidate / "EXPECTED_RUNTIME_RECEIPT_SCHEMA.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["receipt"]["required_artifacts"][0] = {"invalid": "artifact"}
            schema_path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")

            result = load_validator(candidate).validate_package(
                candidate,
                materialize=True,
                repository_root=REPOSITORY_ROOT,
            )

            self.assertEqual(result["status"], "BLOCKED")
            self.assertFalse((candidate / "MATERIALIZATION_MANIFEST.json").exists())
            self.assertIn("required_artifacts", " ".join(result["failures"]))

    def test_receipt_schema_requires_file_rw_closure_fields(self):
        self.assertTrue((PACKAGE / "EXPECTED_RUNTIME_RECEIPT_SCHEMA.json").is_file())
        schema = json.loads((PACKAGE / "EXPECTED_RUNTIME_RECEIPT_SCHEMA.json").read_text(encoding="utf-8"))
        file_rw = schema["file_read_or_write"]

        self.assertEqual(file_rw["required_evidence_basis"], "AUDIT_FILESYSTEM_PERMISSION_FILTER")
        self.assertEqual(
            file_rw["required_same_serial_raw_record_types"],
            ["SYSCALL", "PATH"],
        )
        self.assertTrue(file_rw["require_authenticated_raw_bytes_and_sha256_link"])
        self.assertTrue(file_rw["require_pid_netns_logical_host_join"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
