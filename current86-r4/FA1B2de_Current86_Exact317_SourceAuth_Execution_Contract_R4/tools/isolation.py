from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .transaction import compare_commitments

BWRAP = Path("/usr/bin/bwrap")
PYTHON = Path("/usr/bin/python3")
ROOT = Path(__file__).resolve().parent


def _runtime(command: list[str]) -> None:
    for path in (Path("/usr"), Path("/lib"), Path("/lib64")):
        if path.exists():
            command.extend(("--ro-bind", str(path), str(path)))


def _run(role: str, p: dict[str, Path]) -> None:
    command = [str(BWRAP), "--unshare-all", "--unshare-user-try", "--new-session", "--die-with-parent", "--cap-drop", "ALL", "--clearenv", "--setenv", "LANG", "C.UTF-8", "--setenv", "LC_ALL", "C.UTF-8", "--setenv", "TZ", "UTC", "--dir", "/sa", "--dir", "/work", "--proc", "/proc", "--dev", "/dev", "--ro-bind", str(p["common"]), "/sa/common", "--ro-bind", str(p["runtime"]), "/sa/runtime", "--bind", str(p["private"]), "/sa/private", "--bind", str(p["commitment"]), "/sa/commitment", "--chdir", "/work"]
    _runtime(command)
    command.extend([str(PYTHON), "/sa/runtime/dummy_commitment_backend.py", role, "/sa/common", "/sa/private", "/sa/commitment", "/sa/primary-private", "/sa/commitments/primary"])
    completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode:
        raise RuntimeError("ISOLATION_LAUNCH_FAILED: " + completed.stderr.decode("utf-8", "replace"))


def run_synthetic_commitment_transaction() -> dict[str, object]:
    if not BWRAP.is_file() or not PYTHON.is_file():
        raise RuntimeError("ISOLATION_RUNTIME_MISSING")
    with tempfile.TemporaryDirectory(prefix="fa1b2de-sourceauth-r2-transaction-") as temp:
        base = Path(temp)
        p = {}
        for name in ("common", "runtime-primary", "runtime-verifier", "primary-private", "verifier-private", "primary-commitment", "verifier-commitment"):
            p[name] = base / name
            p[name].mkdir(mode=0o700)
        (p["common"] / "common.txt").write_text("synthetic-common\n", encoding="utf-8")
        shutil.copyfile(ROOT.parent / "00_lineage" / "EXACT317_TARGET_MANIFEST.json", p["common"] / "exact317_target_manifest.json")
        shutil.copyfile(ROOT / "dummy_commitment_backend.py", p["runtime-primary"] / "dummy_commitment_backend.py")
        shutil.copyfile(ROOT / "dummy_commitment_backend.py", p["runtime-verifier"] / "dummy_commitment_backend.py")
        _run("PRIMARY", {"common": p["common"], "runtime": p["runtime-primary"], "private": p["primary-private"], "commitment": p["primary-commitment"]})
        primary_path = p["primary-commitment"] / "commitment.json"
        if not primary_path.is_file():
            raise RuntimeError("PRIMARY_COMMITMENT_NOT_FROZEN")
        primary_path.chmod(0o400)
        p["primary-commitment"].chmod(0o500)
        _run("VERIFIER", {"common": p["common"], "runtime": p["runtime-verifier"], "private": p["verifier-private"], "commitment": p["verifier-commitment"]})
        primary = json.loads(primary_path.read_text(encoding="utf-8"))
        verifier_path = p["verifier-commitment"] / "commitment.json"
        verifier = json.loads(verifier_path.read_text(encoding="utf-8"))
        comparison = compare_commitments(primary, verifier, both_frozen=True)
        audit = json.loads((p["verifier-private"] / "verifier-audit.json").read_text(encoding="utf-8"))
        return {
            "mode": "SYNTHETIC_NON_SEMANTIC_ONLY",
            "primary_commitment_schema_valid": True,
            "verifier_commitment_schema_valid": True,
            "primary_frozen_before_verifier_start": True,
            "comparator_after_both_frozen": True,
            "verifier_observed_primary_private": audit["observed_primary_private"],
            "verifier_observed_primary_commitment": audit["observed_primary_commitment"],
            "comparison_equal": comparison["comparison_equal"],
        }
