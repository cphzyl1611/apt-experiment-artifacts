#!/usr/bin/env python3
"""Bubblewrap-backed synthetic SA-B3 isolation probe."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .sourceauth_contract import ContractError, canonical_json_bytes, sha256_hex, validate_isolation_contract

ROOT = Path(__file__).resolve().parent
BWRAP = Path("/usr/bin/bwrap")
PYTHON = Path("/usr/bin/python3")


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bind_system_runtime(command: list[str]) -> None:
    for path in (Path("/usr"), Path("/lib"), Path("/lib64")):
        if path.exists():
            command.extend(("--ro-bind", str(path), str(path)))


def _launch(role: str, common: Path, runtime: Path, private: Path, commitment: Path, work: Path) -> None:
    script_name = "dummy_primary_backend.py" if role == "PRIMARY" else "dummy_verifier_backend.py"
    command = [
        str(BWRAP),
        "--unshare-all",
        "--unshare-user-try",
        "--new-session",
        "--die-with-parent",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "LC_ALL",
        "C.UTF-8",
        "--setenv",
        "TZ",
        "UTC",
        "--setenv",
        "PATH",
        "/usr/bin",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--dir",
        "/sa",
        "--dir",
        "/work",
        "--ro-bind",
        str(common),
        "/sa/common",
        "--ro-bind",
        str(runtime),
        "/sa/runtime-" + role.lower(),
        "--bind",
        str(private),
        "/sa/" + role.lower() + "-private",
        "--bind",
        str(commitment),
        "/sa/commitments/" + role.lower(),
        "--bind",
        str(work),
        "/work/" + role.lower(),
        "--chdir",
        "/work/" + role.lower(),
    ]
    _bind_system_runtime(command)
    command.extend(
        [
            str(PYTHON),
            "/sa/runtime-" + role.lower() + "/" + script_name,
            "/sa/common",
            "/sa/" + role.lower() + "-private",
            "/sa/commitments/" + role.lower(),
        ]
    )
    if role == "VERIFIER":
        command.extend(("/sa/primary-private", "/sa/commitments/primary"))
    completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode != 0:
        raise ContractError(
            "ISOLATION_LAUNCH_FAILED: " + completed.stderr.decode("utf-8", "replace").strip()
        )


def run_synthetic_isolation_probe() -> dict[str, object]:
    """Run a temporary dummy derivation; never opens the exact-317 manifest or corpora."""
    if not BWRAP.is_file() or not PYTHON.is_file():
        raise ContractError("ISOLATION_RUNTIME_MISSING")
    with tempfile.TemporaryDirectory(prefix="fa1b2de-sourceauth-synthetic-isolation-") as temp:
        base = Path(temp)
        paths = {
            name: base / name
            for name in (
                "common",
                "runtime-primary",
                "runtime-verifier",
                "primary-private",
                "verifier-private",
                "primary-commitment",
                "verifier-commitment",
                "work-primary",
                "work-verifier",
            )
        }
        for path in paths.values():
            path.mkdir(mode=0o700)
        (paths["common"] / "synthetic-common.txt").write_bytes(b"SYNTHETIC_COMMON_INPUT_ONLY\n")
        shutil.copyfile(ROOT / "dummy_primary_backend.py", paths["runtime-primary"] / "dummy_primary_backend.py")
        shutil.copyfile(ROOT / "dummy_verifier_backend.py", paths["runtime-verifier"] / "dummy_verifier_backend.py")
        primary_impl = _file_sha(paths["runtime-primary"] / "dummy_primary_backend.py")
        verifier_impl = _file_sha(paths["runtime-verifier"] / "dummy_verifier_backend.py")
        common_id = _file_sha(paths["common"] / "synthetic-common.txt")
        primary_context = sha256_hex(canonical_json_bytes({"role": "PRIMARY", "readable": [common_id, primary_impl], "writable": ["primary-private", "primary-commitment"], "network": "DISABLED", "cwd": "/work/primary"}))
        verifier_context = sha256_hex(canonical_json_bytes({"role": "VERIFIER", "readable": [common_id, verifier_impl], "writable": ["verifier-private", "verifier-commitment"], "network": "DISABLED", "cwd": "/work/verifier"}))
        primary_run = sha256_hex(canonical_json_bytes({"role": "PRIMARY", "context": primary_context, "nonce": base.name + "-p"}))
        verifier_run = sha256_hex(canonical_json_bytes({"role": "VERIFIER", "context": verifier_context, "nonce": base.name + "-v"}))
        isolation_contract = {
            "COMMON_INPUT_SET": [common_id],
            "PRIMARY_PRIVATE_OUTPUT_SET": ["primary-private", "primary-commitment"],
            "VERIFIER_READABLE_SET": [common_id, verifier_impl],
            "PRIMARY_IMPLEMENTATION_ID": primary_impl,
            "VERIFIER_IMPLEMENTATION_ID": verifier_impl,
            "PRIMARY_CONTEXT_ID": primary_context,
            "VERIFIER_CONTEXT_ID": verifier_context,
            "PRIMARY_RUN_ID": primary_run,
            "VERIFIER_RUN_ID": verifier_run,
        }
        validate_isolation_contract(isolation_contract)
        old_umask = os.umask(0o077)
        try:
            _launch("PRIMARY", paths["common"], paths["runtime-primary"], paths["primary-private"], paths["primary-commitment"], paths["work-primary"])
            primary_commitment_path = paths["primary-commitment"] / "commitment.json"
            if not primary_commitment_path.is_file():
                raise ContractError("PRIMARY_COMMITMENT_NOT_FROZEN")
            primary_commitment_path.chmod(0o400)
            paths["primary-commitment"].chmod(0o500)
            _launch("VERIFIER", paths["common"], paths["runtime-verifier"], paths["verifier-private"], paths["verifier-commitment"], paths["work-verifier"])
        finally:
            os.umask(old_umask)
        verifier_record = json.loads((paths["verifier-commitment"] / "commitment.json").read_text(encoding="utf-8"))
        # Comparator begins only here, after both role processes exited and both files exist.
        both_frozen = primary_commitment_path.is_file() and (paths["verifier-commitment"] / "commitment.json").is_file()
        return {
            "probe_mode": "SYNTHETIC_NON_SEMANTIC_ONLY",
            "sandbox_runtime": str(BWRAP),
            "network_policy": "UNSHARE_ALL_NO_NETWORK",
            "environment_policy": "CLEAR_THEN_EXACT_ALLOWLIST",
            "primary_torn_down_before_verifier": True,
            "primary_commitment_frozen_before_verifier": True,
            "verifier_observed_primary_private": verifier_record["observed_primary_private"],
            "verifier_observed_primary_commitment": verifier_record["observed_primary_commitment"],
            "comparator_started_after_both_commitments_frozen": both_frozen,
            **{key: isolation_contract[key] for key in ("PRIMARY_IMPLEMENTATION_ID", "VERIFIER_IMPLEMENTATION_ID", "PRIMARY_CONTEXT_ID", "VERIFIER_CONTEXT_ID", "PRIMARY_RUN_ID", "VERIFIER_RUN_ID")},
        }
