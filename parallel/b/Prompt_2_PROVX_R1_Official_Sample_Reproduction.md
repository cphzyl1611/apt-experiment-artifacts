# Prompt 2 — PROVX-R1 Official Sample Reproduction

Continue the existing PROVX session from authenticated R0.

R0 verdict:

`PROVX_R0_ARTIFACT_AUTHENTICATION = PASS_READY_FOR_R1_REPRODUCTION`

Official artifact root:

`provx-r0/extracted/ProvX-USENIX-artifact`

Archive SHA256:

`a46fe7dec840ea28d9f8acf8771879af7204e0d622e24d12a99ad95f4187e3ff`

## Goal

Reproduce the **artifact-as-shipped sample path** in an isolated CPU-only environment.

This is not the formal 53-playbook experiment.

## 1. Freeze R0 bytes

Verify extracted source/data/checkpoint files against R0 SHA256SUMS.
Do not modify the R0 extracted directory.

Create a separate R1 working directory.

## 2. Create isolated runtime

Use `/usr/bin/python3.10` if available.

Create a dedicated venv under R1.

Do not install into system Python or conda base.

Install exact artifact requirements:

```text
torch==2.8.0
torch-geometric==2.6.1
numpy==2.0.2
scikit-learn==1.6.1
```

Prefer the official CPU-only PyTorch wheel/index because the artifact uses CPU and the host has limited disk.
Record exact package versions.

If exact dependencies cannot be resolved, fail closed; do not silently change versions.

## 3. Artifact package check

Run the artifact's own `scripts/check_package.py`.

Capture command, stdout/stderr, exit code, dataset dimensions, checkpoint load result, and detector forward-pass result.

No training yet.

## 4. Packaged checkpoint inference

Using only the packaged Sample test partition and packaged GCNConv reference checkpoint,
run the smallest supported detector inference/evaluation path.

Record model/config metadata, graph count, predictions, metrics, and repeat result.

## 5. Phase-II PROVX sample run

Run `scripts/run_provx.py` on a bounded packaged sample using shipped artifact defaults first.

Pin:
- epochs;
- lr;
- alpha;
- solidification factor;
- stage start ratio;
- thresholds;
- top-K if applicable.

Capture output artifact and SHA256.

Run the artifact evaluation utility if supported.

Record MER as:

`MODEL_LEVEL_INTERVENTION_FLIP_ONLY`

Never as real prevention/blocking.

## 6. Repetition/determinism

Repeat bounded inference/Phase-II at least twice with identical inputs/config.

Compare predictions, explanation edges, metrics, and artifact hashes.

If Phase-II is nondeterministic because no seed is exposed, quantify it rather than hiding it.

## 7. Paper-vs-artifact baseline split

Keep:

```text
ARTIFACT_AS_SHIPPED_BASELINE
PAPER_STATED_PARAMETER_BASELINE
```

distinct.

R1 executes only the first.

## Outputs

- `PROVX_R1_ENVIRONMENT_LOCK.json`
- `PROVX_R1_PACKAGE_CHECK.json`
- `PROVX_R1_GCN_SAMPLE_INFERENCE.json`
- `PROVX_R1_PHASE2_SAMPLE_RUN.json`
- `PROVX_R1_REPEATABILITY_AUDIT.json`
- `PROVX_R1_OUTPUT_SHA256SUMS.txt`
- `PROVX_R1_REPRODUCTION_REPORT.md`

## Hard boundaries

No DARPA raw dataset acquisition, Mininet APT actions, formal benchmark execution,
FA1B2de model tuning, or binding/scoring mutation.

## Terminal

```text
PROVX_R1_ARTIFACT_SAMPLE_REPRODUCTION =
PASS | BLOCKED

PACKAGE_CHECK = PASS | BLOCKED
GCN_SAMPLE_INFERENCE = PASS | BLOCKED
PHASE2_SAMPLE_RUN = PASS | BLOCKED
REPEATABILITY = PASS | VARIABLE_RECORDED | BLOCKED

FORMAL_EXPERIMENT_EXECUTED = NO

NEXT_ACTION =
FRESH_REVIEW_OF_PROVX_R1_SAMPLE_REPRODUCTION

STOP = true
```
