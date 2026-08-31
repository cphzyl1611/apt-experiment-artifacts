from __future__ import annotations

import json
import os
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from torch.utils.data import WeightedRandomSampler
from torch_geometric.loader import DataLoader
from torch_geometric.nn import global_max_pool
from torch_geometric.utils import add_remaining_self_loops, coalesce

from .data import graph_label
from .detector import Detector, DetectorConfig


@dataclass
class TrainConfig:
    epochs: int = 50
    batch_size: int = 32
    learning_rate: float = 5e-3
    weight_decay: float = 0.0
    adam_epsilon: float = 1e-8
    max_grad_norm: float = 1.0
    seed: int = 1
    use_weighted_sampler: bool = True
    sampler_multiplier: int = 3
    limit_train_batches: int = 0
    limit_eval_batches: int = 0


@dataclass
class DetectorMetrics:
    eval_acc: float
    binary_precision: float
    binary_recall: float
    binary_f1: float
    eval_auc: float
    FPR: float
    TPR: float
    TP: int
    TN: int
    FP: int
    FN: int


def set_seed(seed: int) -> None:
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed(seed)


def make_loader(dataset, config: TrainConfig, shuffle: bool, training: bool) -> DataLoader:
    sampler = None
    if training and config.use_weighted_sampler:
        labels = [graph_label(graph) for graph in dataset]
        counts = {0: labels.count(0), 1: labels.count(1)}
        if counts[0] > 0 and counts[1] > 0:
            weights = [1.0 / counts[label] for label in labels]
            sampler = WeightedRandomSampler(
                torch.tensor(weights, dtype=torch.double),
                num_samples=len(weights) * config.sampler_multiplier,
                replacement=True,
            )
            shuffle = False

    return DataLoader(
        dataset,
        batch_size=config.batch_size,
        shuffle=shuffle if sampler is None else False,
        sampler=sampler,
        drop_last=training,
    )


def _limited(loader: Iterable, limit_batches: int):
    for index, batch in enumerate(loader):
        if limit_batches and index >= limit_batches:
            break
        yield batch


def evaluate_detector(model: Detector, loader: DataLoader, device: str, limit_batches: int = 0) -> DetectorMetrics:
    model.eval()
    y_true: list[int] = []
    y_pred: list[int] = []
    y_prob: list[float] = []

    with torch.no_grad():
        for batch_data in _limited(loader, limit_batches):
            batch_data = batch_data.to(device)
            edge_index, _ = add_remaining_self_loops(batch_data.edge_index.long(), num_nodes=batch_data.x.size(0))
            edge_index = coalesce(edge_index)
            labels = global_max_pool(batch_data._VULN, batch_data.batch).long()
            logits = model(batch_data.x, edge_index, batch_data.batch)
            probs = F.softmax(logits, dim=1)

            y_true.extend(labels.cpu().tolist())
            y_pred.extend(probs.argmax(dim=1).cpu().tolist())
            y_prob.extend(probs[:, 1].cpu().tolist())

    if not y_true:
        return DetectorMetrics(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0, 0, 0)

    acc = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    auc = roc_auc_score(y_true, y_prob) if len(set(y_true)) > 1 else 0.0
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return DetectorMetrics(
        eval_acc=round(float(acc), 4),
        binary_precision=round(float(precision), 4),
        binary_recall=round(float(recall), 4),
        binary_f1=round(float(f1), 4),
        eval_auc=round(float(auc), 4),
        FPR=round(float(fpr), 4),
        TPR=round(float(recall), 4),
        TP=int(tp),
        TN=int(tn),
        FP=int(fp),
        FN=int(fn),
    )


def save_training_artifacts(
    output_dir: Path,
    model: Detector,
    detector_config: DetectorConfig,
    train_config: TrainConfig,
    metrics: DetectorMetrics,
    checkpoint_name: str,
) -> Path:
    checkpoint_dir = output_dir / checkpoint_name
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), checkpoint_dir / "model.bin")
    metadata = {
        "detector_config": asdict(detector_config),
        "train_config": asdict(train_config),
        "metrics": asdict(metrics),
    }
    (checkpoint_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return checkpoint_dir / "model.bin"


def train_detector(
    model: Detector,
    train_data,
    valid_data,
    test_data,
    detector_config: DetectorConfig,
    train_config: TrainConfig,
    output_dir: Path,
    device: str,
) -> tuple[Path, DetectorMetrics]:
    set_seed(train_config.seed)
    model.to(device)
    train_loader = make_loader(train_data, train_config, shuffle=True, training=True)
    valid_loader = make_loader(valid_data, train_config, shuffle=False, training=False)
    test_loader = make_loader(test_data, train_config, shuffle=False, training=False)

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=train_config.learning_rate,
        eps=train_config.adam_epsilon,
        weight_decay=train_config.weight_decay,
    )

    best_metric = -1.0
    best_path: Optional[Path] = None
    best_test_metrics = DetectorMetrics(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0, 0, 0)

    for epoch in range(1, train_config.epochs + 1):
        model.train()
        losses: list[float] = []
        for batch_data in _limited(train_loader, train_config.limit_train_batches):
            batch_data = batch_data.to(device)
            edge_index, _ = add_remaining_self_loops(batch_data.edge_index.long(), num_nodes=batch_data.x.size(0))
            edge_index = coalesce(edge_index)
            labels = global_max_pool(batch_data._VULN, batch_data.batch).long()
            logits = model(batch_data.x, edge_index, batch_data.batch)
            loss = F.cross_entropy(logits, labels)

            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), train_config.max_grad_norm)
            optimizer.step()
            losses.append(float(loss.detach().cpu().item()))

        valid_metrics = evaluate_detector(model, valid_loader, device, train_config.limit_eval_batches)
        test_metrics = evaluate_detector(model, test_loader, device, train_config.limit_eval_batches)
        avg_loss = float(np.mean(losses)) if losses else 0.0
        print(
            f"epoch={epoch} loss={avg_loss:.5f} "
            f"valid_acc={valid_metrics.eval_acc:.4f} valid_f1={valid_metrics.binary_f1:.4f} "
            f"test_acc={test_metrics.eval_acc:.4f} test_f1={test_metrics.binary_f1:.4f}"
        )

        if valid_metrics.eval_acc > best_metric:
            best_metric = valid_metrics.eval_acc
            best_test_metrics = test_metrics
            best_path = save_training_artifacts(
                output_dir,
                model,
                detector_config,
                train_config,
                test_metrics,
                "checkpoint-best-acc",
            )

        save_training_artifacts(
            output_dir,
            model,
            detector_config,
            train_config,
            test_metrics,
            "checkpoint-last",
        )

    if best_path is None:
        best_path = save_training_artifacts(
            output_dir,
            model,
            detector_config,
            train_config,
            best_test_metrics,
            "checkpoint-best-acc",
        )
    return best_path, best_test_metrics
