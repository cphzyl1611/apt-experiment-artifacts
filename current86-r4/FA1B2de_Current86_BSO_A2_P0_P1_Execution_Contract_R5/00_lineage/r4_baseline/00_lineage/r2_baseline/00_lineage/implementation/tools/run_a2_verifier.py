#!/usr/bin/env python3
"""Mandatory isolated entrypoint for future A2 verifier execution."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

from a2_bwrap_isolation import build_command


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--common-dir", type=Path, required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--proposal-input-relative", type=Path, required=True)
    parser.add_argument("--structured-commitment-relative", type=Path, required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--expected-execution-manifest-id", required=True)
    parser.add_argument("--computational-contract-id", required=True)
    parser.add_argument("--context-identity", required=True)
    parser.add_argument("--run-identity", required=True)
    args = parser.parse_args(argv)
    for relative in (args.proposal_input_relative, args.structured_commitment_relative):
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit("FAIL_CLOSED: frozen input paths must be relative and confined")
    command = [
        "/usr/bin/python3", "/role-runtime/a2_role_runtime.py",
        "--role", "VERIFIER",
        "--proposal-input", f"/frozen-input/{args.proposal_input_relative.as_posix()}",
        "--structured-commitment", f"/frozen-input/{args.structured_commitment_relative.as_posix()}",
        "--output", "/role-output/verifier_commitment.json",
        "--provider", args.provider, "--model-id", args.model_id,
        "--expected-execution-manifest-id", args.expected_execution_manifest_id,
        "--computational-contract-id", args.computational_contract_id,
        "--context-identity", args.context_identity, "--run-identity", args.run_identity,
    ]
    return subprocess.run(build_command(args.common_dir, args.runtime_dir, args.output_dir, command), check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
