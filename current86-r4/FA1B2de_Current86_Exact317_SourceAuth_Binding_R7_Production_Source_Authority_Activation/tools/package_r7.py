#!/usr/bin/env python3
"""Create the deterministic R7 file-list and checksum envelope."""

from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    files = sorted(
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.is_file()
        and path.name != "SHA256SUMS.txt"
        and "__pycache__" not in path.parts
    )
    (ROOT / "FILE_LIST.txt").write_text("\n".join(files) + "\n", encoding="utf-8")
    lines = []
    for relative in files:
        digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        lines.append(f"{digest}  ./{relative}")
    (ROOT / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"packaged {len(files)} files")


if __name__ == "__main__":
    main()
