# ProvX Artifact

This archive accompanies the USENIX Security artifact release for ProvX.
ProvX studies explanations for provenance-graph intrusion detectors and provides a code implementation of the core detector, explanation, and evaluation components used in the work.

The archive is intended to make the research prototype and its code structure available in a compact form. It includes preprocessed sample graph data, a reference detector checkpoint, and the Python source code for the main ProvX workflow.


## Archive Contents

```text
provx_usenix/                Core Python package
scripts/                     Auxiliary command-line entry points
Datasets/Sample/             Preprocessed sample graph data
storage/cache/Sample/        Reference checkpoint files
requirements.txt             Python dependency list
```

## Code Organization

The package separates the prototype into the following modules:

```text
data.py          Graph loading utilities
detector.py      GNN detector model
training.py      Detector training and evaluation helpers
provx.py         ProvX explanation procedure
evaluation.py    Explanation evaluation helpers
checkpoints.py   Checkpoint discovery and loading
paths.py         Artifact path utilities
```

## Data Format

The packaged `Sample` data is derived from DARPA Transparent Computing provenance data and is stored as preprocessed PyTorch Geometric graph objects.
The packaged graph partition files are:

```text
Datasets/Sample/train_100nodes.pt
Datasets/Sample/val_100nodes.pt
Datasets/Sample/test_100nodes.pt
Datasets/Sample/sample_labels_all.pkl
```

The `.pt` files contain Python lists of PyTorch Geometric `Data` objects. The prototype consumes these fields:

```text
x           Node feature matrix
edge_index  Graph connectivity in PyG COO format
_VULN       Node-level labels
_LINE       Original node identifiers
_SAMPLE     Subgraph sample identifier
```

The pickle file stores auxiliary line-label information keyed by sample identifier. The raw audit logs are not included; original DARPA TC data remains subject to the dataset provider's access and redistribution terms.
