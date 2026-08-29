#!/usr/bin/env python3
"""Regenerate and verify this already-materialized contract-only package."""

from __future__ import annotations

import argparse
import json
import runpy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("regenerate", "verify"))
    args = parser.parse_args(argv)
    try:
        if args.command == "regenerate":
            runpy.run_path(str(ROOT / "tools/regenerate_metadata.py"), run_name="__main__")
        result = runpy.run_path(str(ROOT / "verify_package.py"), run_name="verify_package")
        result["main"]()
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"FAIL_CLOSED: {exc}")
        return 1
    if args.command == "regenerate":
        print(json.dumps({"deterministic_regeneration": "PASS", "package_verification": "PASS"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
