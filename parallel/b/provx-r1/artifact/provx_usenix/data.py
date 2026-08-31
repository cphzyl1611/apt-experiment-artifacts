from __future__ import annotations

from pathlib import Path
from typing import Any


def _torch():
    try:
        import torch
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "PyTorch is required to load ProvX graph data. Install the artifact "
            "environment before running this command."
        ) from exc
    return torch


def load_partition(dataset_dir: str | Path, partition: str):
    """Load a local PyTorch Geometric graph list such as test_100nodes.pt."""
    torch = _torch()
    path = Path(dataset_dir) / f"{partition}.pt"
    if not path.exists():
        raise FileNotFoundError(f"partition file not found: {path}")
    try:
        return torch.load(path, map_location="cpu", weights_only=False)
    except TypeError:
        return torch.load(path, map_location="cpu")


def graph_label(graph: Any) -> int:
    """Return graph label inferred from node-level _VULN labels."""
    if not hasattr(graph, "_VULN"):
        return 0
    vuln = graph._VULN
    if hasattr(vuln, "bool"):
        return int(vuln.bool().any().item())
    return int(any(bool(v) for v in vuln))


def sample_id(graph: Any, fallback: int) -> int:
    if hasattr(graph, "_SAMPLE"):
        sample = graph._SAMPLE
        if hasattr(sample, "max"):
            return int(sample.max().item())
    return fallback


def move_graph(graph: Any, device: str):
    if hasattr(graph, "to"):
        return graph.to(device)
    return graph


def graph_batch(graph: Any):
    torch = _torch()
    if hasattr(graph, "batch") and graph.batch is not None:
        return graph.batch
    return torch.zeros(graph.x.size(0), dtype=torch.long, device=graph.x.device)
