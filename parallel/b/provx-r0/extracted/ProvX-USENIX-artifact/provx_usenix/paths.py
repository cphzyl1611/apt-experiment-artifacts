from pathlib import Path
from typing import Optional


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def original_project_root() -> Path:
    root = project_root()
    return root


def dataset_dir(dataset_name: str, original_root: Optional[Path] = None) -> Path:
    root = original_root or original_project_root()
    return root / "Datasets" / dataset_name


def cache_dir(original_root: Optional[Path] = None) -> Path:
    root = original_root or original_project_root()
    return root / "storage" / "cache"
