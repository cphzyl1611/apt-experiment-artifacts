#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def parse_args():
    parser = argparse.ArgumentParser(description="Run an artifact train -> explain -> evaluate ProvX pipeline.")
    parser.add_argument("--dataset", default="Sample")
    parser.add_argument("--gnn-model", default="GCNConv")
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--train-epochs", type=int, default=1)
    parser.add_argument("--train-batches", type=int, default=2)
    parser.add_argument("--eval-batches", type=int, default=2)
    parser.add_argument("--explain-graphs", type=int, default=1)
    parser.add_argument("--explain-epochs", type=int, default=2)
    parser.add_argument("--top-k", type=int, default=30)
    parser.add_argument("--output-root", default="outputs/pipeline")
    parser.add_argument("--use-existing-checkpoint", default=None)
    return parser.parse_args()


def run(cmd: list[str]) -> None:
    print("+ " + " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def main():
    args = parse_args()
    python = sys.executable
    output_root = Path(args.output_root)
    checkpoint = Path(args.use_existing_checkpoint) if args.use_existing_checkpoint else None

    if checkpoint is None:
        checkpoint_root = output_root / "checkpoints"
        run(
            [
                python,
                "scripts/train_detector.py",
                "--dataset",
                args.dataset,
                "--gnn-model",
                args.gnn_model,
                "--epochs",
                str(args.train_epochs),
                "--limit-train-batches",
                str(args.train_batches),
                "--limit-eval-batches",
                str(args.eval_batches),
                "--device",
                args.device,
                "--output-dir",
                str(checkpoint_root),
            ]
        )
        checkpoint = checkpoint_root / args.dataset / args.gnn_model / "checkpoint-best-acc" / "model.bin"

    explanations = output_root / f"{args.dataset}_{args.gnn_model}_explanations.pt"
    run(
        [
            python,
            "scripts/run_provx.py",
            "--dataset",
            args.dataset,
            "--gnn-model",
            args.gnn_model,
            "--checkpoint",
            str(checkpoint),
            "--limit-graphs",
            str(args.explain_graphs),
            "--only-alerts",
            "--epochs",
            str(args.explain_epochs),
            "--output",
            str(explanations),
            "--device",
            args.device,
        ]
    )
    run(
        [
            python,
            "scripts/evaluate_explanations.py",
            "--dataset",
            args.dataset,
            "--gnn-model",
            args.gnn_model,
            "--checkpoint",
            str(checkpoint),
            "--explanations",
            str(explanations),
            "--top-k",
            str(args.top_k),
            "--device",
            args.device,
        ]
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
