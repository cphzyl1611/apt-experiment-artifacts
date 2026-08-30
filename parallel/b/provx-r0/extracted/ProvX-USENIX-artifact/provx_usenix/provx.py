from __future__ import annotations

from dataclasses import dataclass

import torch
import torch.nn.functional as F
from torch import Tensor
from torch_geometric.nn import MessagePassing
from torch_geometric.utils import add_remaining_self_loops, coalesce, remove_self_loops

from .data import graph_batch


@dataclass
class ProvXConfig:
    epochs: int = 200
    lr: float = 0.05
    alpha: float = 0.9
    solidification_factor: float = 0.6
    solidification_stage_start_ratio: float = 0.6
    confident_threshold_low: float = 0.05
    confident_threshold_high: float = 0.95
    use_l1_distance: bool = False


@dataclass
class ProvXExplanation:
    edge_index: Tensor
    edge_weight: Tensor
    pred: int
    target_label: int

    def topk(self, k: int) -> Tensor:
        if self.edge_weight.numel() <= k:
            return torch.arange(self.edge_weight.numel(), device=self.edge_weight.device)
        return torch.topk(self.edge_weight, k=k).indices


class ProvXExplainer:
    """Counterfactual edge-mask explainer with staged solidification."""

    def __init__(self, model: torch.nn.Module, config: ProvXConfig):
        self.model = model
        self.config = config
        self.edge_mask: torch.nn.Parameter | None = None

    def _set_masks(self, edge_index: Tensor, num_nodes: int):
        edge_count = edge_index.size(1)
        std = torch.nn.init.calculate_gain("relu") * (2.0 / max(2 * num_nodes, 1)) ** 0.5
        self.edge_mask = torch.nn.Parameter(
            torch.randn(edge_count, device=edge_index.device) * std
        )
        loop_mask = edge_index[0] != edge_index[1]
        for module in self.model.modules():
            if isinstance(module, MessagePassing):
                module.explain = True
                module._edge_mask = self.edge_mask
                module._loop_mask = loop_mask
                module._apply_sigmoid = True

    def _clear_masks(self):
        for module in self.model.modules():
            if isinstance(module, MessagePassing):
                module.explain = False
                module._edge_mask = None
                module._loop_mask = None
                module._apply_sigmoid = True
        self.edge_mask = None

    def _loss(self, logits: Tensor, target_label: int) -> Tensor:
        assert self.edge_mask is not None
        prediction_loss = torch.relu(logits[:, target_label]).sum()
        mask = self.edge_mask.sigmoid()
        if self.config.use_l1_distance:
            distance_loss = torch.linalg.norm(1 - mask, ord=1)
        else:
            distance_loss = F.binary_cross_entropy(mask, torch.ones_like(mask))
        return self.config.alpha * prediction_loss + (1 - self.config.alpha) * distance_loss

    def explain(self, graph, target_label: int | None = None) -> ProvXExplanation:
        self.model.eval()
        x = graph.x
        batch = graph_batch(graph).to(x.device)
        edge_index = coalesce(remove_self_loops(graph.edge_index.long())[0])
        if edge_index.size(1) == 0:
            raise ValueError("cannot explain a graph with no edges")

        edge_index, _ = add_remaining_self_loops(edge_index, num_nodes=x.size(0))
        with torch.no_grad():
            original_logits = self.model(x, edge_index, batch)
            pred = int(original_logits.argmax(dim=-1)[0].item())
        label = pred if target_label is None else int(target_label)

        self._clear_masks()
        self._set_masks(edge_index, x.size(0))
        assert self.edge_mask is not None
        optimizer = torch.optim.Adam([self.edge_mask], lr=self.config.lr)

        snapshot = None
        low_indices = None
        high_indices = None
        start_epoch = max(1, int(self.config.epochs * self.config.solidification_stage_start_ratio))

        for epoch in range(1, self.config.epochs + 1):
            if epoch == start_epoch and self.config.solidification_factor > 0:
                with torch.no_grad():
                    snapshot = self.edge_mask.sigmoid().detach().clone()
                    low_indices = (snapshot < self.config.confident_threshold_low).nonzero(as_tuple=True)[0]
                    high_indices = (snapshot > self.config.confident_threshold_high).nonzero(as_tuple=True)[0]

            logits = self.model(x, edge_index, batch)
            loss = self._loss(logits, label)

            if epoch > start_epoch and snapshot is not None and self.config.solidification_factor > 0:
                current = self.edge_mask.sigmoid()
                penalty = torch.tensor(0.0, device=x.device)
                if low_indices is not None and low_indices.numel() > 0:
                    penalty = penalty + (current[low_indices] - snapshot[low_indices]).pow(2).sum()
                if high_indices is not None and high_indices.numel() > 0:
                    penalty = penalty + (current[high_indices] - snapshot[high_indices]).pow(2).sum()
                loss = loss + self.config.solidification_factor * penalty

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        assert self.edge_mask is not None
        edge_weight = 1.0 - self.edge_mask.sigmoid().detach()
        final_edge_index, final_edge_weight = remove_self_loops(edge_index.detach(), edge_weight)
        self._clear_masks()
        return ProvXExplanation(
            edge_index=final_edge_index.cpu(),
            edge_weight=final_edge_weight.cpu(),
            pred=pred,
            target_label=label,
        )
