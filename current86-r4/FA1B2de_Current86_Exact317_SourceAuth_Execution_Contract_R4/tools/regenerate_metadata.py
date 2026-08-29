#!/usr/bin/env python3
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
paths = sorted(path.relative_to(ROOT).as_posix() for path in ROOT.rglob("*") if path.is_file() and "__pycache__" not in path.parts and path != ROOT / "SHA256SUMS.txt")
(ROOT / "FILE_LIST.txt").write_text("\n".join(sorted(paths + ["SHA256SUMS.txt"])) + "\n", encoding="utf-8")
lines = [f"{hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()}  ./{rel}" for rel in paths]
(ROOT / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
