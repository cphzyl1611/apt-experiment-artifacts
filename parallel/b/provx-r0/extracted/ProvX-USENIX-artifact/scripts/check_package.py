#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def parse_args():
    parser = argparse.ArgumentParser(description="Inspect the packaged ProvX data and detector checkpoint.")
    parser.add_argument("--dataset", default="Sample")
    parser.add_argument("--partition", default="test_100nodes")
    parser.add_argument("--gnn-model", default="GCNConv")
    parser.add_argument("--checkpoint", default=None)
    parser.add_argument("--input-feature-dim", type=int, default=0, help="0 means infer from the first graph")
    parser.add_argument("--limit-graphs", type=int, default=1)
    parser.add_argument("--device", default="cpu")
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
        from provx_usenix.data import graph_batch, load_partition
        from provx_usenix.detector import Detector, DetectorConfig
        from provx_usenix.paths import dataset_dir
    except RuntimeError as exc:
        print(f"dependency error: {exc}", file=sys.stderr)
        return 2
    except ModuleNotFoundError as exc:
        print(f"dependency error: missing module {exc.name}", file=sys.stderr)
        return 2

    original_root = Path(args.original_root) if args.original_root else None
    data_dir = dataset_dir(args.dataset, original_root)
    graphs = load_partition(data_dir, args.partition)
    if not graphs:
        raise RuntimeError(f"no graphs found in {data_dir}/{args.partition}.pt")

    graph = graphs[0].to(args.device)
    graph_feature_dim = int(graph.x.size(1))
    checkpoint = Path(args.checkpoint) if args.checkpoint else best_checkpoint_path(args.dataset, args.gnn_model, original_root)
    checkpoint_dim = checkpoint_input_feature_dim(checkpoint)
    if graph_feature_dim != checkpoint_dim:
        raise RuntimeError(
            f"graph feature dim ({graph_feature_dim}) does not match checkpoint input dim "
            f"({checkpoint_dim}). Choose a matching dataset/checkpoint pair."
        )
    input_feature_dim = args.input_feature_dim or graph_feature_dim
    config = DetectorConfig(**checkpoint_detector_hparams(checkpoint, args.gnn_model))
    model = Detector(config, input_feature_dim=input_feature_dim).to(args.device)
    load_checkpoint(model, checkpoint, args.device)
    model.eval()

    edge_index, _ = add_remaining_self_loops(graph.edge_index.long(), num_nodes=graph.x.size(0))
    edge_index = coalesce(edge_index)
    batch = graph_batch(graph).to(args.device)
    with torch.no_grad():
        logits = model(graph.x, edge_index, batch)

    print(f"dataset={args.dataset}")
    print(f"partition={args.partition}")
    print(f"checkpoint={checkpoint}")
    print(f"graphs_loaded={len(graphs)}")
    print(f"first_graph_nodes={graph.x.size(0)}")
    print(f"first_graph_edges={graph.edge_index.size(1)}")
    print(f"input_feature_dim={input_feature_dim}")
    print(f"logits_shape={tuple(logits.shape)}")
    print(f"pred={int(logits.argmax(dim=-1)[0].item())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
