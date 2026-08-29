# EXP-E0-B PROVX Mininet Integration Gap

## Finding

The original paper does **not** provide a live Mininet execution pipeline. It defines PROVX downstream of an alert-associated provenance subgraph. In the evaluation instantiation, host audit records are converted to an offline provenance graph, Louvain partitions produce evaluation subgraphs, and a graph-level GNN identifies malicious subgraphs. The paper explicitly states that this approximates SOC input and does not fully reproduce live alert generation, correlation, and expansion (Secs. 3.1, 4.1, and 7).

Therefore the requested live path is a new adapter boundary:

```text
APT raw action
  -> Mininet / controlled host execution
  -> host audit/provenance collection
  -> process/file/socket causal events
  -> provenance graph
  -> alert-associated subgraph
  -> Phase-I differentiable GNN
  -> PROVX Phase II
  -> core edge list
```

No adapter is implemented in this preflight.

## Required adapters and unresolved contracts

| Boundary | Required transformation | Paper support | Gap/risk |
|---|---|---|---|
| APT action -> Mininet | Execute each raw action in an isolated, controlled host and preserve action identity, timing, exit status, and host identity | None; Mininet is not described | FA1B2de orchestration and safety policy must be specified separately |
| Host execution -> audit | Collect complete process, file, and network/socket causal records without losing ordering or identifiers | Paper names host audit logs and gives process/file/network examples; assumes complete trusted logging | Collector, kernel hooks, privileges, clocking, loss detection, and format are absent |
| Audit -> entities/events | Normalize process, file, socket, and event records into stable node identities and event records | Paper says nodes are system entities or events | Exact identity rules, lifecycle handling, event typing, and deduplication are absent |
| Events -> causal edges | Build directed causal dependencies such as process creates file and process sends network data | Paper defines causal edges conceptually | Causality rules, edge direction, multiplicity, timestamps, and socket semantics are absent |
| Graph -> features | Produce `A_k` and `X_k`; preserve any edge data required by the artifact | `G_k=(A_k,X_k)` is formalized; only node feature matrix is named | Feature dimensions, encodings, normalization, and edge-feature support are absent |
| Graph -> alert subgraph | Associate an alert with the relevant graph region and expand enough context | Paper allows PIDS/EDR/SIEM/network/analyst sources; evaluation uses Louvain | Live alert source, seed mapping, time window, expansion policy, and hub duplication are absent |
| Subgraph -> Phase I | Serialize exactly what the trained differentiable GNN expects | Graph-level GNN and class-probability semantics are specified | Framework, tensor layout, batching, checkpoint API, and preprocessing are absent |
| Phase I -> Phase II | Pass only detector-positive alerted subgraphs to fixed-detector mask optimization | Explicitly specified | Artifact invocation and mask tensor conventions are unavailable |
| Core edge -> host action | Map model edge identifiers back to process/file/socket evidence and analyst-readable actions | Paper says output is analyst-prioritized guidance; enforcement is deployment-specific | No automatic process termination, file quarantine, syscall blocking, or network restriction is supplied or authorized |

## Graph schema that can be pinned now

- Graph object: provenance subgraph `G_k`.
- Structure: binary adjacency matrix `A_k in {0,1}^{n x n}` for Phase II.
- Nodes: system entities or events, with paper examples/figure categories Process, File, and Socket.
- Edges: causal dependencies between entities/events.
- Node features: matrix `X_k` is consumed by the detector and incident endpoint features are suppressed during MER intervention.
- Edge features: **not specified by the paper**; do not assume they exist.
- Entity/event typing: only broad Process/File/Socket examples are evidenced; exact enum and serialization are **not specified**.
- Labels: graph-level `0` benign and `1` malicious as defined in Sec. 3.1; labels are evaluation metadata, not a live sensor output.

## Transformation needed for an exact live input

An eventual adapter must produce, for every scored subgraph, a reproducible manifest containing: source action IDs; host and clock metadata; raw audit record hashes; normalized node IDs and types; causal edge IDs and direction; node feature tensor and preprocessing version; adjacency tensor; alert seed/source; subgraph expansion parameters; and a reversible mapping from model edge IDs to raw event records. The exact tensor dimensions, feature vocabulary, and serializer must come from the authenticated artifact at `PROVX-R0/R2`, not from assumptions here.

The adapter must be validated first with non-scored Mininet smoke tests. It must not be tuned against the 53-playbook/1796-action formal set.

