from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import torch


ARTIFACT_ROOT = Path(__file__).resolve().parents[1] / "provx-r1" / "artifact"
if str(ARTIFACT_ROOT) not in sys.path:
    sys.path.insert(0, str(ARTIFACT_ROOT))

from provx_usenix.checkpoints import (  # noqa: E402
    best_checkpoint_path,
    checkpoint_detector_hparams,
    checkpoint_input_feature_dim,
    load_checkpoint,
)
from provx_usenix.data import load_partition  # noqa: E402
from provx_usenix.detector import Detector, DetectorConfig  # noqa: E402
from provx_usenix.evaluation import mitigation_flip  # noqa: E402
from provx_usenix.provx import ProvXConfig, ProvXExplainer  # noqa: E402


def set_external_seed(seed: int) -> None:
    """Set all RNGs used by the wrapper and the artifact's Phase-II API."""
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed(seed)


def _load_context() -> tuple[list[Any], torch.nn.Module, Path]:
    data_dir = ARTIFACT_ROOT / "Datasets" / "Sample"
    graphs = load_partition(data_dir, "test_100nodes")
    checkpoint = best_checkpoint_path("Sample", "GCNConv", ARTIFACT_ROOT)
    input_feature_dim = int(graphs[0].x.size(1))
    checkpoint_dim = checkpoint_input_feature_dim(checkpoint)
    if input_feature_dim != checkpoint_dim:
        raise RuntimeError(f"feature dimension mismatch: data={input_feature_dim} checkpoint={checkpoint_dim}")
    model = Detector(DetectorConfig(**checkpoint_detector_hparams(checkpoint, "GCNConv")), input_feature_dim).to("cpu")
    load_checkpoint(model, checkpoint, "cpu")
    model.eval()
    return graphs, model, checkpoint


def _topk_records(explanation: Any, top_k: int) -> list[dict[str, Any]]:
    weights = explanation.edge_weight.detach().cpu()
    edges = explanation.edge_index.detach().cpu()
    count = min(top_k, int(weights.numel()))
    indices = torch.topk(weights, k=count).indices
    return [
        {
            "rank": rank,
            "edge_index": int(index),
            "src": int(edges[0, index].item()),
            "dst": int(edges[1, index].item()),
            "weight": float(weights[index].item()),
        }
        for rank, index in enumerate(indices.tolist(), start=1)
    ]


def run_phase2_once(seed: int | None, output_path: Path | None, top_k: int = 30, graph_index: int = 19) -> dict[str, Any]:
    """Invoke the artifact Phase-II API once and return a serializable audit row."""
    if seed is not None:
        set_external_seed(seed)
    graphs, model, checkpoint = _load_context()
    graph = graphs[graph_index]
    config = ProvXConfig()
    started = time.perf_counter()
    explanation = ProvXExplainer(model, config).explain(graph)
    mer_flip = int(mitigation_flip(model, graph, explanation, top_k, "cpu"))
    runtime_sec = time.perf_counter() - started
    artifact_payload = {
        "graph_index": graph_index,
        "sample_id": int(graph._SAMPLE.detach().cpu().max().item()) if hasattr(graph, "_SAMPLE") else graph_index,
        "edge_index": explanation.edge_index,
        "edge_weight": explanation.edge_weight,
        "pred": explanation.pred,
        "target_label": explanation.target_label,
    }
    output_sha256 = None
    output_bytes = None
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save([artifact_payload], output_path)
        output_bytes = output_path.stat().st_size
        output_sha256 = hashlib.sha256(output_path.read_bytes()).hexdigest()
    return {
        "seed": seed,
        "graph_index": graph_index,
        "sample_id": artifact_payload["sample_id"],
        "pred": int(explanation.pred),
        "target_label": int(explanation.target_label),
        "edge_count": int(explanation.edge_weight.numel()),
        "top_k": top_k,
        "top_k_edges": _topk_records(explanation, top_k),
        "mer_model_level_intervention_flip": mer_flip,
        "runtime_sec": runtime_sec,
        "output_path": str(output_path) if output_path is not None else None,
        "output_bytes": output_bytes,
        "output_sha256": output_sha256,
        "config": {
            "epochs": config.epochs,
            "lr": config.lr,
            "alpha": config.alpha,
            "solidification_factor": config.solidification_factor,
            "solidification_stage_start_ratio": config.solidification_stage_start_ratio,
            "confident_threshold_low": config.confident_threshold_low,
            "confident_threshold_high": config.confident_threshold_high,
            "use_l1_distance": config.use_l1_distance,
        },
        "checkpoint": str(checkpoint),
        "mer_semantics": "MODEL_LEVEL_INTERVENTION_FLIP_ONLY",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="R2 external seed control for the unchanged ProvX API")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--top-k", type=int, default=30)
    parser.add_argument("--graph-index", type=int, default=19)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    args = parser.parse_args()
    row = run_phase2_once(args.seed, args.output, args.top_k, args.graph_index)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(row, separators=(",", ":")))


if __name__ == "__main__":
    main()
