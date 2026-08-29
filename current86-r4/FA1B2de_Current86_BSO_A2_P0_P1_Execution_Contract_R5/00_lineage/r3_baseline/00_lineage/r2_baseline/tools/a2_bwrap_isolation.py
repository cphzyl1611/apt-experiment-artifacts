#!/usr/bin/env python3
"""Run an A2 role inside a read-capability bubblewrap boundary."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


def build_command(common_dir: Path, runtime_dir: Path, output_dir: Path, command: list[str]) -> list[str]:
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise RuntimeError("bubblewrap is unavailable")
    if not command:
        raise ValueError("role command is required")
    args = [
        bwrap,
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--unshare-user-try",
        "--uid", "65534",
        "--gid", "65534",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--ro-bind", str(common_dir.resolve()), "/frozen-input",
        "--ro-bind", str(runtime_dir.resolve()), "/role-runtime",
        "--bind", str(output_dir.resolve()), "/role-output",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--clearenv",
        "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
        "--",
    ]
    return args + command


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--common-dir", type=Path, required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        args.common_dir.resolve(strict=True)
        args.runtime_dir.resolve(strict=True)
        args.output_dir.resolve(strict=True)
        return subprocess.run(build_command(args.common_dir, args.runtime_dir, args.output_dir, command), check=False).returncode
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"FAIL_CLOSED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
