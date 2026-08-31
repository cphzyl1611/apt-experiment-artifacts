from __future__ import annotations

import hashlib
import json
from pathlib import Path

import torch
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from torch_geometric.loader import DataLoader
from torch_geometric.nn import global_max_pool
from torch_geometric.utils import add_remaining_self_loops, coalesce

from provx_usenix.checkpoints import checkpoint_detector_hparams, checkpoint_input_feature_dim, load_checkpoint
from provx_usenix.data import load_partition
from provx_usenix.detector import Detector, DetectorConfig


def main() -> None:
    root = Path(__file__).resolve().parent / "artifact"
    data_dir = root / "Datasets" / "Sample"
    checkpoint = root / "storage" / "cache" / "Sample" / "saved_models" / "GCNConv" / "checkpoint-best-acc" / "model.bin"
    graphs = load_partition(data_dir, "test_100nodes")
    input_feature_dim = int(graphs[0].x.size(1))
    checkpoint_dim = checkpoint_input_feature_dim(checkpoint)
    if input_feature_dim != checkpoint_dim:
        raise RuntimeError(f"feature dimension mismatch: data={input_feature_dim} checkpoint={checkpoint_dim}")
    model = Detector(DetectorConfig(**checkpoint_detector_hparams(checkpoint, "GCNConv")), input_feature_dim).to("cpu")
    load_checkpoint(model, checkpoint, "cpu")
    model.eval()

    loader = DataLoader(graphs, batch_size=32, shuffle=False, drop_last=False)
    labels: list[int] = []
    predictions: list[int] = []
    probabilities: list[float] = []
    with torch.inference_mode():
        for batch in loader:
            batch = batch.to("cpu")
            edge_index, _ = add_remaining_self_loops(batch.edge_index.long(), num_nodes=batch.x.size(0))
            edge_index = coalesce(edge_index)
            logits = model(batch.x, edge_index, batch.batch)
            probs = torch.softmax(logits, dim=1)
            labels.extend(global_max_pool(batch._VULN, batch.batch).long().cpu().tolist())
            predictions.extend(probs.argmax(dim=1).cpu().tolist())
            probabilities.extend(probs[:, 1].cpu().tolist())

    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    payload = {
        "dataset": "Sample",
        "partition": "test_100nodes",
        "checkpoint": str(checkpoint),
        "device": "cpu",
        "graph_count": len(graphs),
        "input_feature_dim": input_feature_dim,
        "first_graph_nodes": int(graphs[0].x.size(0)),
        "first_graph_edges": int(graphs[0].edge_index.size(1)),
        "detector_config": checkpoint_detector_hparams(checkpoint, "GCNConv"),
        "checkpoint_input_feature_dim": checkpoint_dim,
        "predictions": predictions,
        "labels": labels,
        "prediction_sha256": hashlib.sha256(json.dumps(predictions, separators=(",", ":")).encode()).hexdigest(),
        "metrics": {
            "accuracy": round(float(accuracy_score(labels, predictions)), 6),
            "precision": round(float(precision_score(labels, predictions, zero_division=0)), 6),
            "recall": round(float(recall_score(labels, predictions, zero_division=0)), 6),
            "f1": round(float(f1_score(labels, predictions, zero_division=0)), 6),
            "auc": round(float(roc_auc_score(labels, probabilities)), 6) if len(set(labels)) > 1 else 0.0,
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp)
        },
        "model_execution": "inference_only; no training or Phase-II execution"
    }
    print(json.dumps(payload, separators=(",", ":")))


if __name__ == "__main__":
    main()
