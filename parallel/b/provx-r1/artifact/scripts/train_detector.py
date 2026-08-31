#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def parse_args():
    parser = argparse.ArgumentParser(description="Train a ProvX detector from local .pt graph partitions.")
    parser.add_argument("--dataset", default="Sample")
    parser.add_argument("--train-partition", default="train_100nodes")
    parser.add_argument("--val-partition", default="val_100nodes")
    parser.add_argument("--test-partition", default="test_100nodes")
    parser.add_argument("--gnn-model", default="GCNConv")
    parser.add_argument("--gnn-hidden-size", type=int, default=64)
    parser.add_argument("--gnn-feature-dim-size", type=int, default=256)
    parser.add_argument("--gat-heads", type=int, default=8)
    parser.add_argument("--graphsage-aggr", default="mean")
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--learning-rate", type=float, default=5e-3)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--limit-train-batches", type=int, default=0)
    parser.add_argument("--limit-eval-batches", type=int, default=0)
    parser.add_argument("--no-weighted-sampler", action="store_true")
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--output-dir", default="outputs/checkpoints")
    parser.add_argument("--original-root", default=None)
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        from provx_usenix.data import load_partition
        from provx_usenix.detector import Detector, DetectorConfig
        from provx_usenix.paths import dataset_dir
        from provx_usenix.training import TrainConfig, train_detector
    except ModuleNotFoundError as exc:
        print(f"dependency error: missing module {exc.name}", file=sys.stderr)
        return 2

    original_root = Path(args.original_root) if args.original_root else None
    data_dir = dataset_dir(args.dataset, original_root)
    train_data = load_partition(data_dir, args.train_partition)
    valid_data = load_partition(data_dir, args.val_partition)
    test_data = load_partition(data_dir, args.test_partition)
    if not train_data or not valid_data or not test_data:
        raise RuntimeError("train, validation, and test partitions must all contain graphs")

    input_feature_dim = int(train_data[0].x.size(1))
    detector_config = DetectorConfig(
        gnn_model=args.gnn_model,
        gnn_hidden_size=args.gnn_hidden_size,
        gnn_feature_dim_size=args.gnn_feature_dim_size,
        gat_heads=args.gat_heads,
        graphsage_aggr=args.graphsage_aggr,
    )
    train_config = TrainConfig(
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        seed=args.seed,
        use_weighted_sampler=not args.no_weighted_sampler,
        limit_train_batches=args.limit_train_batches,
        limit_eval_batches=args.limit_eval_batches,
    )
    model = Detector(detector_config, input_feature_dim)
    output_dir = Path(args.output_dir) / args.dataset / args.gnn_model
    checkpoint, metrics = train_detector(
        model,
        train_data,
        valid_data,
        test_data,
        detector_config,
        train_config,
        output_dir,
        args.device,
    )

    print(f"checkpoint={checkpoint}")
    print(f"test_acc={metrics.eval_acc:.4f}")
    print(f"test_precision={metrics.binary_precision:.4f}")
    print(f"test_recall={metrics.binary_recall:.4f}")
    print(f"test_f1={metrics.binary_f1:.4f}")
    print(f"test_auc={metrics.eval_auc:.4f}")
    print(f"test_fpr={metrics.FPR:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
