#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pickle
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate ProvX explanation files.")
    parser.add_argument("--dataset", default="Sample")
    parser.add_argument("--partition", default="test_100nodes")
    parser.add_argument("--gnn-model", default="GCNConv")
    parser.add_argument("--checkpoint", default=None)
    parser.add_argument("--input-feature-dim", type=int, default=0, help="0 means infer from the first graph")
    parser.add_argument("--explanations", default="outputs/provx_explanations.pt")
    parser.add_argument("--top-k", type=int, default=30)
    parser.add_argument("--labels", default=None, help="Optional line-label pkl for original localization metrics")
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--original-root", default=None)
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        import torch

        from provx_usenix.checkpoints import (
            best_checkpoint_path,
            checkpoint_detector_hparams,
            checkpoint_input_feature_dim,
            load_checkpoint,
        )
        from provx_usenix.data import load_partition
        from provx_usenix.detector import Detector, DetectorConfig
        from provx_usenix.evaluation import evaluate_pairs
        from provx_usenix.paths import dataset_dir
        from provx_usenix.provx import ProvXExplanation
    except ModuleNotFoundError as exc:
        print(f"dependency error: missing module {exc.name}", file=sys.stderr)
        return 2

    original_root = Path(args.original_root) if args.original_root else None
    data_dir = dataset_dir(args.dataset, original_root)
    graphs = load_partition(data_dir, args.partition)
    if not graphs:
        raise RuntimeError(f"no graphs found for {args.dataset}/{args.partition}")
    graph_feature_dim = int(graphs[0].x.size(1))
    checkpoint = Path(args.checkpoint) if args.checkpoint else best_checkpoint_path(args.dataset, args.gnn_model, original_root)
    checkpoint_dim = checkpoint_input_feature_dim(checkpoint)
    if graph_feature_dim != checkpoint_dim:
        raise RuntimeError(
            f"graph feature dim ({graph_feature_dim}) does not match checkpoint input dim "
            f"({checkpoint_dim}). Choose a matching dataset/checkpoint pair."
        )
    input_feature_dim = args.input_feature_dim or graph_feature_dim
    model = Detector(DetectorConfig(**checkpoint_detector_hparams(checkpoint, args.gnn_model)), input_feature_dim).to(args.device)
    load_checkpoint(model, checkpoint, args.device)
    model.eval()

    raw = torch.load(args.explanations, map_location="cpu")
    pairs = []
    for item in raw:
        graph = graphs[item["graph_index"]]
        explanation = ProvXExplanation(
            edge_index=item["edge_index"],
            edge_weight=item["edge_weight"],
            pred=int(item["pred"]),
            target_label=int(item["target_label"]),
        )
        pairs.append((graph, explanation))

    labels = None
    labels_path = Path(args.labels) if args.labels else None
    if labels_path is None:
        candidates = sorted(data_dir.glob("*_labels_all.pkl"))
        labels_path = candidates[0] if candidates else None
    if labels_path is not None and labels_path.exists():
        with labels_path.open("rb") as handle:
            labels = pickle.load(handle)

    metrics = evaluate_pairs(model, pairs, args.top_k, args.device, labels=labels)
    print(f"count={metrics.count}")
    print(f"accuracy={metrics.accuracy:.4f}")
    print(f"precision={metrics.precision:.4f}")
    print(f"recall={metrics.recall:.4f}")
    print(f"f1={metrics.f1:.4f}")
    print(f"mer={metrics.mer:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
