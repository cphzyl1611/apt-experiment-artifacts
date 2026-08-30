from __future__ import annotations

from dataclasses import dataclass

import torch
import torch.nn as nn
from torch.nn import Dropout, Linear, ReLU
from torch_geometric.nn import (
    GATConv,
    GCNConv,
    SAGEConv,
    global_add_pool,
    global_max_pool,
    global_mean_pool,
)


@dataclass
class DetectorConfig:
    gnn_model: str = "GCNConv"
    gnn_hidden_size: int = 64
    gnn_feature_dim_size: int = 256
    num_gnn_layers: int = 2
    graph_pooling: str = "mean"
    dropout_rate: float = 0.1
    num_classes: int = 2
    residual: bool = False
    gat_heads: int = 8
    graphsage_aggr: str = "mean"


class Detector(nn.Module):
    """GNN graph classifier compatible with the original ProvX checkpoints."""

    def __init__(self, config: DetectorConfig, input_feature_dim: int):
        super().__init__()
        self.config = config

        self.feature_transform = nn.Sequential(
            nn.Linear(input_feature_dim, 64),
            nn.ReLU(),
            nn.Linear(64, config.gnn_feature_dim_size),
        )
        self.linear = nn.Sequential(
            Linear(config.gnn_feature_dim_size, config.gnn_hidden_size),
            nn.ReLU(),
            nn.Dropout(config.dropout_rate),
        )

        self.gnn_layers = nn.ModuleList(
            self._build_gnn_layer() for _ in range(config.num_gnn_layers)
        )
        self.relu = ReLU()
        self.dropout = Dropout(config.dropout_rate)
        self.pooling_name = config.graph_pooling
        self.classifier = nn.Sequential(
            nn.Linear(config.gnn_hidden_size, config.gnn_hidden_size),
            nn.ReLU(),
            nn.Dropout(config.dropout_rate),
            nn.Linear(config.gnn_hidden_size, config.num_classes),
        )

    def _build_gnn_layer(self):
        cfg = self.config
        hidden = cfg.gnn_hidden_size
        if cfg.gnn_model == "GCNConv":
            return GCNConv(hidden, hidden)
        if cfg.gnn_model == "GAT":
            if hidden % cfg.gat_heads != 0:
                raise ValueError("gnn_hidden_size must be divisible by gat_heads")
            return GATConv(
                hidden,
                hidden // cfg.gat_heads,
                heads=cfg.gat_heads,
                dropout=cfg.dropout_rate,
                concat=True,
            )
        if cfg.gnn_model == "GraphSAGE":
            return SAGEConv(hidden, hidden, aggr=cfg.graphsage_aggr)
        raise ValueError(f"unsupported GNN model: {cfg.gnn_model}")

    def get_node_embeddings(self, x, edge_index):
        out = self.feature_transform(x)
        out = self.linear(out)
        for layer in self.gnn_layers:
            next_out = layer(out, edge_index)
            out = out + next_out if self.config.residual else next_out
            out = self.relu(out)
            out = self.dropout(out)
        return out

    def get_graph_embedding(self, x, edge_index, batch):
        node_embeddings = self.get_node_embeddings(x, edge_index)
        if self.pooling_name == "sum":
            return global_add_pool(node_embeddings, batch)
        if self.pooling_name == "mean":
            return global_mean_pool(node_embeddings, batch)
        if self.pooling_name == "max":
            return global_max_pool(node_embeddings, batch)
        raise ValueError(f"invalid graph pooling: {self.pooling_name}")

    def forward(self, x, edge_index, batch=None, **kwargs):
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
        graph_embedding = self.get_graph_embedding(x, edge_index, batch)
        logits = self.classifier(graph_embedding)
        return logits
