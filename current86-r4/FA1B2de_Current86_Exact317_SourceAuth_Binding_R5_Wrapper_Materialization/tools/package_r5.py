#!/usr/bin/env python3
"""Create deterministic file inventory and SHA256 manifest for R5."""

from __future__ import annotations

import hashlib
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]
FILE_LIST = PACKAGE / "FILE_LIST.txt"
SHA256SUMS = PACKAGE / "SHA256SUMS.txt"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def paths() -> list[Path]:
    result = []
    for path in PACKAGE.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(PACKAGE)
        if "__pycache__" in relative.parts or path.suffix == ".pyc" or path.name == "SHA256SUMS.txt":
            continue
        result.append(relative)
    return sorted(result, key=lambda p: p.as_posix())


def main() -> int:
    listed = paths()
    FILE_LIST.write_text("\n".join(p.as_posix() for p in listed) + "\n", encoding="utf-8")
    listed = paths()
    SHA256SUMS.write_text(
        "\n".join(f"{digest(PACKAGE / p)}  ./{p.as_posix()}" for p in listed) + "\n", encoding="utf-8"
    )
    print(f"files={len(listed)} sha256sums={SHA256SUMS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
