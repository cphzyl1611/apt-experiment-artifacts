#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def parse_args():
    parser = argparse.ArgumentParser(description="Run ProvX explanations on local graphs.")
    parser.add_argument("--dataset", default="Sample")
    parser.add_argument("--partition", default="test_100nodes")
    parser.add_argument("--gnn-model", default="GCNConv")
    parser.add_argument("--checkpoint", default=None)
    parser.add_argument("--input-feature-dim", type=int, default=0, help="0 means infer from the first graph")
    parser.add_argument("--epochs", type=int, default=200)
    parser.add_argument("--alpha", type=float, default=0.9)
    parser.add_argument("--solidification-factor", type=float, default=0.6)
    parser.add_argument("--solidification-stage-start-ratio", type=float, default=0.6)
    parser.add_argument("--limit-graphs", type=int, default=10)
    parser.add_argument("--only-alerts", action="store_true")
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--output", default="outputs/provx_explanations.pt")
    parser.add_argument("--original-root", default=None)
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        import torch
        from torch_geometric.utils import add_remaining_self_loops, coalesce

        from provx_usenix.checkpoints import (
            best_checkpoint_path,
            checkpoint_detector_hparams,
            checkpoint_input_feature_dim,
            load_checkpoint,
        )
        from provx_usenix.data import graph_batch, graph_label, load_partition, sample_id
        from provx_usenix.detector import Detector, DetectorConfig
        from provx_usenix.paths import dataset_dir
        from provx_usenix.provx import ProvXConfig, ProvXExplainer
    except ModuleNotFoundError as exc:
        print(f"dependency error: missing module {exc.name}", file=sys.stderr)
        return 2

    original_root = Path(args.original_root) if args.original_root else None
    graphs = load_partition(dataset_dir(args.dataset, original_root), args.partition)
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

    explainer = ProvXExplainer(
        model,
        ProvXConfig(
            epochs=args.epochs,
            alpha=args.alpha,
            solidification_factor=args.solidification_factor,
            solidification_stage_start_ratio=args.solidification_stage_start_ratio,
        ),
    )

    results = []
    visited = 0
    for graph_index, graph in enumerate(graphs):
        if visited >= args.limit_graphs:
            break
        if graph_label(graph) != 1:
            continue

        graph = graph.to(args.device)
        if args.only_alerts:
            edge_index, _ = add_remaining_self_loops(graph.edge_index.long(), num_nodes=graph.x.size(0))
            edge_index = coalesce(edge_index)
            batch = graph_batch(graph).to(args.device)
            with torch.no_grad():
                pred = int(model(graph.x, edge_index, batch).argmax(dim=-1)[0].item())
            if pred != 1:
                continue

        explanation = explainer.explain(graph)
        results.append(
            {
                "graph_index": graph_index,
                "sample_id": sample_id(graph, graph_index),
                "edge_index": explanation.edge_index,
                "edge_weight": explanation.edge_weight,
                "pred": explanation.pred,
                "target_label": explanation.target_label,
            }
        )
        visited += 1
        print(f"explained graph_index={graph_index} sample_id={results[-1]['sample_id']} pred={explanation.pred}")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    torch.save(results, output)
    print(f"saved={output}")
    print(f"count={len(results)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
