from __future__ import annotations

from pathlib import Path
from typing import Any

from .paths import cache_dir


def best_checkpoint_path(dataset_name: str, gnn_model: str, original_root: Path | None = None) -> Path:
    return cache_dir(original_root) / dataset_name / "saved_models" / gnn_model / "checkpoint-best-acc" / "model.bin"


def checkpoint_input_feature_dim(checkpoint_path: str | Path) -> int:
    try:
        import torch
    except ModuleNotFoundError as exc:
        raise RuntimeError("PyTorch is required to inspect detector checkpoints.") from exc

    path = Path(checkpoint_path)
    if not path.exists():
        raise FileNotFoundError(f"checkpoint not found: {path}")
    state = torch.load(path, map_location="cpu")
    weight = state.get("feature_transform.0.weight")
    if weight is None:
        raise KeyError(f"checkpoint does not contain feature_transform.0.weight: {path}")
    return int(weight.shape[1])


def checkpoint_detector_hparams(checkpoint_path: str | Path, gnn_model: str) -> dict:
    try:
        import torch
    except ModuleNotFoundError as exc:
        raise RuntimeError("PyTorch is required to inspect detector checkpoints.") from exc

    path = Path(checkpoint_path)
    if not path.exists():
        raise FileNotFoundError(f"checkpoint not found: {path}")
    state = torch.load(path, map_location="cpu")
    hparams = {
        "gnn_model": gnn_model,
        "gnn_feature_dim_size": int(state["feature_transform.2.bias"].shape[0]),
        "gnn_hidden_size": int(state["linear.0.bias"].shape[0]),
    }
    if gnn_model == "GAT" and "gnn_layers.0.att_src" in state:
        hparams["gat_heads"] = int(state["gnn_layers.0.att_src"].shape[1])
    return hparams


def load_checkpoint(model: Any, checkpoint_path: str | Path, device: str):
    try:
        import torch
    except ModuleNotFoundError as exc:
        raise RuntimeError("PyTorch is required to load detector checkpoints.") from exc

    path = Path(checkpoint_path)
    if not path.exists():
        raise FileNotFoundError(f"checkpoint not found: {path}")
    state = torch.load(path, map_location=device)
    model.load_state_dict(state)
    return model
