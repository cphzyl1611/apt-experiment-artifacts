from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import torch
from torch_geometric.utils import add_self_loops

from .data import graph_batch, graph_label
from .provx import ProvXExplanation


@dataclass
class ExplanationMetrics:
    accuracy: float
    precision: float
    recall: float
    f1: float
    mer: float
    count: int


def attack_edge_mask(graph, edge_index) -> torch.Tensor:
    if not hasattr(graph, "_VULN"):
        return torch.zeros(edge_index.size(1), dtype=torch.bool)
    vuln = graph._VULN.detach().cpu().bool()
    src = edge_index[0].detach().cpu()
    dst = edge_index[1].detach().cpu()
    return vuln[src] | vuln[dst]


def localization_for_graph(graph, explanation: ProvXExplanation, top_k: int) -> tuple[int, float, float, float]:
    indices = explanation.topk(top_k).cpu()
    truth = attack_edge_mask(graph, explanation.edge_index)
    if indices.numel() == 0:
        return 0, 0.0, 0.0, 0.0
    hits = int(truth[indices].sum().item())
    accuracy = 1 if hits > 0 else 0
    precision = hits / int(indices.numel())
    total_attack_edges = int(truth.sum().item())
    recall = hits / total_attack_edges if total_attack_edges else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return accuracy, precision, recall, f1


def explanation_lines(graph, explanation: ProvXExplanation, top_k: int) -> list[int]:
    indices = explanation.topk(top_k).cpu()
    if indices.numel() == 0 or not hasattr(graph, "_LINE"):
        return []

    edge_index = explanation.edge_index.detach().cpu()
    edge_weight = explanation.edge_weight.detach().cpu()
    selected_weight = torch.zeros_like(edge_weight)
    selected_weight[indices] = edge_weight[indices]
    node_count = int(graph.x.size(0))

    adjacency = torch.sparse_coo_tensor(edge_index, selected_weight, (node_count, node_count))
    selected_edges = edge_index[:, selected_weight != 0]
    if selected_edges.numel() == 0:
        return []

    binary_adjacency = torch.zeros((node_count, node_count), dtype=torch.float32)
    binary_adjacency[selected_edges[0], selected_edges[1]] = 1.0
    out_degree = binary_adjacency.sum(dim=1)
    out_degree[out_degree == 0] = 1e-8
    in_degree = binary_adjacency.sum(dim=0)
    in_degree[in_degree == 0] = 1e-8

    base = torch.ones(node_count, 1)
    importance_out = torch.sparse.mm(adjacency, base) / out_degree.unsqueeze(-1)
    importance_in = torch.sparse.mm(adjacency.t(), base) / in_degree.unsqueeze(-1)
    importance = (importance_out + importance_in).squeeze(-1)

    lines = graph._LINE.detach().cpu().tolist()
    ranked = sorted(zip(importance.tolist(), lines), reverse=True)
    return [int(line) for score, line in ranked if score > 0]


def line_based_localization_for_graph(
    graph,
    explanation: ProvXExplanation,
    top_k: int,
    labels: dict[int, dict[str, list[int]]],
) -> tuple[int, float, float, float] | None:
    if not hasattr(graph, "_SAMPLE"):
        return None
    sample_id = int(graph._SAMPLE.detach().cpu().max().item())
    if sample_id not in labels:
        return None

    expected_lines = list(labels[sample_id].get("removed", []))
    if not expected_lines:
        return None

    lines = explanation_lines(graph, explanation, top_k)
    hits = sum(1 for line in lines if line in expected_lines)
    accuracy = 1 if hits else 0
    precision = hits / len(lines) if lines else 0.0
    recall = hits / len(expected_lines)
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return accuracy, precision, recall, f1


def mitigation_flip(model, graph, explanation: ProvXExplanation, top_k: int, device: str) -> int:
    graph = graph.to(device)
    edge_index = explanation.edge_index.to(device)
    edge_weight = explanation.edge_weight.to(device)
    indices = explanation.topk(top_k).to(device)
    keep = torch.ones(edge_weight.size(0), dtype=torch.bool, device=device)
    keep[indices] = False

    x = graph.x.clone()
    if indices.numel() > 0:
        important_nodes = torch.unique(edge_index[:, indices])
        x[important_nodes] = 0.0

    batch = graph_batch(graph).to(device)
    cf_edge_index = edge_index[:, keep]
    cf_edge_index, _ = add_self_loops(cf_edge_index, num_nodes=x.size(0))
    with torch.no_grad():
        cf_pred = int(model(x, cf_edge_index, batch).argmax(dim=-1)[0].item())
    return int(cf_pred != explanation.pred)


def evaluate_pairs(
    model,
    pairs: Iterable[tuple[object, ProvXExplanation]],
    top_k: int,
    device: str,
    labels: dict[int, dict[str, list[int]]] | None = None,
) -> ExplanationMetrics:
    rows = []
    flips = []
    for graph, explanation in pairs:
        if graph_label(graph) != 1:
            continue
        if labels is not None:
            row = line_based_localization_for_graph(graph, explanation, top_k, labels)
            if row is None:
                continue
            rows.append(row)
        else:
            rows.append(localization_for_graph(graph, explanation, top_k))
        flips.append(mitigation_flip(model, graph, explanation, top_k, device))

    if not rows:
        return ExplanationMetrics(0.0, 0.0, 0.0, 0.0, 0.0, 0)

    count = len(rows)
    accuracy = sum(row[0] for row in rows) / count
    precision = sum(row[1] for row in rows) / count
    recall = sum(row[2] for row in rows) / count
    f1 = sum(row[3] for row in rows) / count
    mer = sum(flips) / len(flips) if flips else 0.0
    return ExplanationMetrics(accuracy, precision, recall, f1, mer, count)
