# FA-1B2de Current86 B-SO-A2 Authority Candidate R2 Independent Verification

Verification date: `2026-08-27`  
Mode: `READ_ONLY / INDEPENDENT_AUTHORITY_CANDIDATE_VERIFICATION_ONLY`

## Verdict

The exact prospective R2 authority candidate was independently verified. Gates A through G pass.
The candidate remains prospective only: this verification does not activate, supersede, publish,
adjudicate, or modify any authority. No H2 acceptance text was created.

```text
AUTHORITY_CANDIDATE_VERIFICATION_VERDICT=PASS

A_PACKAGE_INTEGRITY=PASS
B_H1_PROVENANCE_INDEPENDENT_RECOMPUTATION=PASS
C_REVIEWED_R2_DESIGN_BINDING=PASS
D_CURRENT86_SCOPE_AND_OLD_LINEAGE=PASS
E_PROSPECTIVE_AUTHORITY_ID_RECOMPUTATION=PASS
F_SEMANTIC_NONREGRESSION=PASS
G_NON_ACTIVATION_BOUNDARY=PASS

H1_EVIDENCE_ID_RECOMPUTED=
22dbeb4700808e049ff001281caf1ae8ed5102fbcf2078991b27c0039e0dd6ba

PROSPECTIVE_AUTHORITY_CANDIDATE_ID_RECOMPUTED=
36831020b75a201420bd5cfce97a54ada12d44246f56a7812455bc21b99f9477

AUTHORITY_INDEPENDENTLY_VERIFIED=YES

NEW_AUTHORITY_ACTIVATION=NO
SUPERSESSION_ACTIVATION=NO
BINDING_PUBLICATION=NO
H2_PERFORMED=NO

NEXT_ACTION=REQUEST_H2_HUMAN_AUTHORITY_ACTIVATION
STOP_FOR_HUMAN_BSO_A2_AUTHORITY_H2_DECISION
```

## Gate A - Package integrity

`01_transition_manifest.json` independently hashes to
`4810a1b5336d1672290e46f55eae056f0d1a963f4972548f5d097d1c7dd3baae`.
`12_sha256sums.txt` independently hashes to
`dc5ef34353243fbf6e23f1383d3f9fdd111b86080ae4e7b9b8d4140796d1c86f`.

All 11 entries in the candidate checksum file verify. The candidate directory contains exactly the
expected 12 regular files: components `01` through `11`, plus the checksum file itself. The checksum
file intentionally excludes itself. There are no unexpected or unpinned candidate files, and every
manifest component pin equals the independently observed component hash.

The self-contained input handoff also verifies: 29 regular files, 28 checksum entries, with only its
own `SHA256SUMS.txt` excluded from its checksum scope. Its archive SHA-256 is
`024fde26cc71a4caf260772ac1fa908232e9ba03bbc7818616c6769db7e3240e`.

## Gate B - H1 provenance

The frozen native evidence schema and human-origin contract objects independently recompute to:

- `0201dc07ace5189b7ae9094910b0fff0fc173e2be374ec75e0b0a658dce42f64`
- `c1d92c96cc02495d4e4ddcc7686d0e489803a275e68bd009f2f8afab4f6a79dd`

The exact H1 reattestation literal independently hashes to
`e5c38936cee6f6b926ae003ea57f622db4d8b7561082d8a76600d1566a4a2952`.
The H1 evidence object, canonicalized with only `evidence_id` omitted, independently recomputes to
`22dbeb4700808e049ff001281caf1ae8ed5102fbcf2078991b27c0039e0dd6ba`.

The native session `01a042de-ac09-7fb3-87a6-fa9badbd52d6` contains exactly one qualifying H1
reattestation USER event at one-based native JSONL record ordinal 9 and exactly one distinct later
invocation USER event at ordinal 148. Both records assert `payload.role = user`; text alone was not
used to infer role. Their exact native-record hashes are, respectively:

- `c67f0e01fb44d6bb0864c28f58cb95f9c20ddbde468a94968accda501b1820a4`
- `80cdffc0861bdcac7dcb06d953f15d1045b3d8826acfcb7092b9ff489a1bb01d`

The 3,619,869-byte capture snapshot hashes to
`e62fc7d2a23c7a775587a088f53c696d49c7df949e96041cfb83107acc63d0de` and is a byte-identical
prefix of the live append-only native session file. The transcript prefix through the invocation
recomputes to `8452352ff89686ca4022b6d26bd26bdd29f81e15e54af420f8985cf630496d69`.
The invocation literal binds the exact H1 literal hash. No assistant/model event, timestamp-only,
file-only, or copied-literal provenance was accepted.

One unrelated malformed JSONL record exists elsewhere in the current 108-file native session store.
Its raw bytes contain no H1 marker, so it does not introduce ambiguity into the unique exact ordered
USER-event pair and does not weaken the fail-closed H1 result.

## Gate C - Reviewed R2 design

The reviewed R2 design hashes exactly to
`5bef1445705e323115ce071f616f53e218202d1d5cfcac13d2febee295956ed4`. The patch summary, R2
checksum file, targeted-review Markdown, targeted-review JSON, and targeted-review checksum file all
match their reported hashes. The authenticated targeted review verdict is `PASS`; B1, B2, B3, B4,
and every targeted non-regression check pass. Both the candidate manifest and supersession-lineage
component bind the exact reviewed R2 design hash.

## Gate D - Current86 scope and old lineage

The frozen handoff archive hashes to
`0af337acc731595167d75f922dd39bbbb48dd1b1b9d3b31723d01408501040de`. All 16 entries in its
`SHA256SUMS.txt` verify. Its inventory convention is explicit: `FILE_LIST.txt` lists every archive
member except `SHA256SUMS.txt`, which is the checksum inventory file itself.

Independent canonical recomputation from frozen source objects produced:

- old workflow architecture authority: `442b5aecd651b320b94eb47b190bf239ba0157634e0a635042ca4d252c65dc40`
- old freeze precondition verification: `80653cc96d1e3612d5809bd6a6a091f79fe5cd1081c769ec51366b99646faac1`
- old Current86 scope: `34551e904bafa71fb2fb6db33162e94ad41a08eca6c747d429c83760e09c1306`

The candidate scope object exactly equals the authenticated frozen reconstructed scope object, not
merely its counts. All 4,219 relation identities were independently recomputed from their canonical
raw/candidate identity payloads. The exact membership conservation result is:

```text
RAW_COUNT=86
STRUCTURALLY_ELIGIBLE_RELATIONS=4219
AUTHENTICATED_HARD_NEGATIVES=58
FORMER_HUMAN_EQ_REVIEW_RELATIONS=4161
NEW_RAWS=0
REMOVED_RAWS=0
ADDED_RELATIONS=0
REMOVED_RELATIONS=0
CANDIDATE_PRUNING=NO
```

Every per-raw candidate registry set, relation-set hash, and candidate-universe hash independently
reconstructs from that exact scope.

## Gate E - Candidate identity

The candidate identity rule is SHA-256 over canonical UTF-8 JSON of every manifest field except the
derived `prospective_authority_candidate_id`. The independent result is
`36831020b75a201420bd5cfce97a54ada12d44246f56a7812455bc21b99f9477`.

The R1 rejection notice ID independently recomputes to
`98813efdd9b05e0e9008fe7aadca27e1c61389b88612957ade3ec1a55751b700`. It binds the historical
R1 candidate ID `930a4c59bf7588b069cc68f359d2869cbb6731389f6b2ea2d0d77608f675a0d6`, declares it rejected,
non-authoritative, non-activatable, and ineligible for candidate verification. The active handoff
selector points only to the corrected R2 candidate. R1 remains historical evidence only.

## Gate F - Semantic non-regression

The candidate freezes the complete candidate universe and the exact non-authoritative proposal
regime. Hidden pruning, top-k truncation, proposal score/rank authority, and new scoring, binding, or
ranking semantics are prohibited.

The proposal-evidence regime binds exactly to the independently recomputed V4/R2 objects:

- normative source profile: `e24746c96c5f741cc35df8d992d93936911dd1de2ce7f1a0f00035cda3b33deb`
- historical output denylist: `f2f48a3142bf192c08cfa2bffbb722e0131bfd4a1ba55623caf5af72748b94c7`
- R2 source registry ID: `8cef6206dfc3581c3e7b6358bde7a36e90f4ba99078176cc0e5aff4b238298a7`

Owner and escalation terminal classes remain distinct in class, nullability, unresolved state,
verification counting, and publication eligibility. No candidate-level exhaustive human EQ
requirement reappears, and no manual evidence-ID copying burden is introduced.

## Gate G - Non-activation boundary

```text
NEW_AUTHORITY_ACTIVATION=NO
SUPERSESSION_ACTIVATION=NO
BINDING_PUBLICATION=NO
ACCEPTED_BINDING_CHANGE=NO
SCORING_AUTHORITY_MUTATION=NO
BINDING_AUTHORITY_MUTATION=NO
DENOMINATOR_CHANGE=NO
BSO_A2_RAW_LEVEL_ADJUDICATION_EXECUTION=NO
BSO_V_EXECUTION=NO
BSO_P_EXECUTION=NO
H2_PERFORMED=NO
```

The old frozen B-SO-EQ authority archive remains byte-preserved and active for the Current86
critical path. The verified R2 object remains a prospective candidate requiring a separate explicit
human H2 activation decision.

## Corroboration boundary

The materializer-reported eight tests and two prior read-only implementation reviews were not used
as substitutes for any part of Gates A through G. The verdict above is based on fresh independent
hashing, canonical recomputation, native-event reconstruction, exact set/object equality, semantic
inspection, and non-activation auditing.
