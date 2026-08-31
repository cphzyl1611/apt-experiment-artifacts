# E0C-R5 Human Template Review Sheets

Presentation-only sheets for the exact R4 shared-template candidates. Each template retains its R4 member authority; all decision fields remain unselected.

## r5-review-batch-01

Templates: 10. Member rows represented: 48.

### r4-template-002-credential_store_access

- Member count: `3`
- Member-set SHA256: `4d7d61f0aea4ded3848389c99d369f254371b7809a1a054d92cf90ac5edbdd24`
- Representative raw keys: `6000006::S09::A005, 6000011::S07::A003, 6000013::S08::A004`
- Archetype / platform / service: `CREDENTIAL_STORE_ACCESS` / `windows` / `FTP, MSSQL, MYSQL, RDP, SMB, SSH`
- Blocker summary: `credential_sensitive, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-003-credential_store_access

- Member count: `3`
- Member-set SHA256: `bfda067e78d561787c086b1c1679f28fb28aae186c4336127bf5f325e0be00f1`
- Representative raw keys: `6000056::S04::A002, 6000058::S05::A004, 6000062::S04::A001`
- Archetype / platform / service: `CREDENTIAL_STORE_ACCESS` / `windows` / `FTP, SFTP, SSH`
- Blocker summary: `credential_sensitive, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-015-credential_store_access

- Member count: `3`
- Member-set SHA256: `62e9e9f499c3959e42e7237f563375505143e1ebc192234959be1858da86581b`
- Representative raw keys: `6000008::S05::A006, 6000027::S08::A007, 6000048::S06::A003`
- Archetype / platform / service: `CREDENTIAL_STORE_ACCESS` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, destructive_state, multi_step_composite, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-016-credential_store_access

- Member count: `4`
- Member-set SHA256: `cea672eb1f8a2a36198b2be2225510d4ec34e591c9fcd6684121f3a6af2b998e`
- Representative raw keys: `6000002::S05::A005, 6000009::S08::A004, 6000011::S06::A005`
- Archetype / platform / service: `CREDENTIAL_STORE_ACCESS` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, destructive_state, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-017-credential_store_access

- Member count: `2`
- Member-set SHA256: `a26be30a152f83418f1ef307f7932588ee5b426d4b59668fa7a9eacdc1584f13`
- Representative raw keys: `6000009::S08::A001, 6000019::S05::A002`
- Archetype / platform / service: `CREDENTIAL_STORE_ACCESS` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-006-credential_store_access

- Member count: `9`
- Member-set SHA256: `776cc6ca57d025ad62efeed4d6f55f8a34a6dafe4517cc6a8a388519de3e6e8d`
- Representative raw keys: `6000002::S05::A004, 6000003::S06::A003, 6000027::S08::A005`
- Archetype / platform / service: `CREDENTIAL_STORE_ACCESS` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `FILE, PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-009-credential_store_access

- Member count: `9`
- Member-set SHA256: `9ae166dab66173192bbcbcd89bc86757c290e9d8db2d23a0350cd6df890636f4`
- Representative raw keys: `6000003::S06::A004, 6000004::S08::A004, 6000006::S09::A006`
- Archetype / platform / service: `CREDENTIAL_STORE_ACCESS` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-010-credential_store_access

- Member count: `6`
- Member-set SHA256: `07369d92fe0767325359dea47af3cc3d64d629fb3e4a7dbfde4555d46bcd3f84`
- Representative raw keys: `6000002::S08::A006, 6000006::S08::A008, 6000011::S07::A005`
- Archetype / platform / service: `CREDENTIAL_STORE_ACCESS` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-019-credential_store_access

- Member count: `3`
- Member-set SHA256: `5b63ac08b921282f988b870d8d57de6666149b901e714b0c2280ec0f8d2115d3`
- Representative raw keys: `6000003::S06::A006, 6000004::S08::A003, 6000043::S05::A001`
- Archetype / platform / service: `CREDENTIAL_STORE_ACCESS` / `windows` / `UNKNOWN`
- Blocker summary: `credential_sensitive, destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-014-credential_store_access

- Member count: `6`
- Member-set SHA256: `1512a7b31d7ed903e19a71c601903068a4f4f2aefe6fa9a878b87f89d0841c5d`
- Representative raw keys: `6000006::S09::A003, 6000010::S11::A005, 6000019::S05::A005`
- Archetype / platform / service: `CREDENTIAL_STORE_ACCESS` / `windows` / `UNKNOWN`
- Blocker summary: `credential_sensitive, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

## r5-review-batch-02

Templates: 10. Member rows represented: 42.

### r4-template-013-credential_store_access

- Member count: `4`
- Member-set SHA256: `1ef92139281d27bd3a0acd29d3a51abcbbc15355a053cfeb07c3dfb4f97f7912`
- Representative raw keys: `6000009::S08::A002, 6000011::S06::A004, 6000029::S06::A002`
- Archetype / platform / service: `CREDENTIAL_STORE_ACCESS` / `windows` / `UNKNOWN`
- Blocker summary: `credential_sensitive, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-035-file_resource_operation

- Member count: `8`
- Member-set SHA256: `ae5c70bcbce560f3194a63c6336b1021b4a3f947601958b75ae98245331b8a52`
- Representative raw keys: `6000002::S05::A007, 6000004::S04::A010, 6000036::S07::A004`
- Archetype / platform / service: `FILE_RESOURCE_OPERATION` / `windows` / `FTP`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `FILE, PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-034-file_resource_operation

- Member count: `4`
- Member-set SHA256: `c67ed9f98b8b19d5eb50e153eaf0df33bb68740a7299df5f3ff5a2d99a6b1802`
- Representative raw keys: `6000007::S07::A003, 6000008::S05::A007, 6000010::S07::A005`
- Archetype / platform / service: `FILE_RESOURCE_OPERATION` / `windows` / `FTP`
- Blocker summary: `credential_sensitive, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `FILE, PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-040-file_resource_operation

- Member count: `6`
- Member-set SHA256: `d5c538cdf776789fba509c93789df3e8a236e3cd7b419a169ef1e55d71cc0168`
- Representative raw keys: `6000010::S03::A005, 6000014::S04::A002, 6000036::S02::A001`
- Archetype / platform / service: `FILE_RESOURCE_OPERATION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `FILE, PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-041-file_resource_operation

- Member count: `2`
- Member-set SHA256: `03799e209f175334dbe46530238978a6851cb5f1b2fc0925954ee9c8680b68d9`
- Representative raw keys: `6000029::S05::A001, 6000049::S04::A002`
- Archetype / platform / service: `FILE_RESOURCE_OPERATION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `FILE, PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-042-file_resource_operation

- Member count: `7`
- Member-set SHA256: `8e48be974c8c07da7f539f49d1b633a62a113d4ef46634e281dc402c9216cc0c`
- Representative raw keys: `6000010::S12::A001, 6000014::S02::A001, 6000028::S07::A005`
- Archetype / platform / service: `FILE_RESOURCE_OPERATION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `FILE, PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-043-file_resource_operation

- Member count: `2`
- Member-set SHA256: `9d4bd225b56d405ab6da21037ea0291f4552a991977a00044464b66331b7fa88`
- Representative raw keys: `6000025::S07::A003, 6000025::S07::A004`
- Archetype / platform / service: `FILE_RESOURCE_OPERATION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, missing_exact_command_semantics, multi_step_composite, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `FILE, PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-044-file_resource_operation

- Member count: `4`
- Member-set SHA256: `53f46669afcabe0603829daa3b8f50a50e0947dcadcf9d9d8de0f36eba57c16c`
- Representative raw keys: `6000014::S05::A003, 6000015::S10::A005, 6000042::S08::A004`
- Archetype / platform / service: `FILE_RESOURCE_OPERATION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `FILE, PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-045-file_resource_operation

- Member count: `3`
- Member-set SHA256: `85749adc5ec7b3f280f909f512047774edf9e29ae7b3d946b71e0841741b001a`
- Representative raw keys: `6000009::S11::A004, 6000028::S07::A004, 6000036::S02::A002`
- Archetype / platform / service: `FILE_RESOURCE_OPERATION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `FILE, PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-046-file_resource_operation

- Member count: `2`
- Member-set SHA256: `98bae6bff3b2811d5b62f226407091300ae08a2b6bd0dfdeed99032f9e8a63eb`
- Representative raw keys: `6000014::S08::A001, 6000015::S10::A002`
- Archetype / platform / service: `FILE_RESOURCE_OPERATION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `FILE, PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

## r5-review-batch-03

Templates: 10. Member rows represented: 40.

### r4-template-049-network_c2_beacon

- Member count: `2`
- Member-set SHA256: `eee45d1fdda3165d8a326d926a4ccddef84b374b574ebdd995a96cd58c164fea`
- Representative raw keys: `6000011::S02::A003, 6000029::S03::A001`
- Archetype / platform / service: `NETWORK_C2_BEACON` / `windows` / `DNS`
- Blocker summary: `destructive_state, service_environment_absent, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-048-network_c2_beacon

- Member count: `9`
- Member-set SHA256: `f7ea287ecdda9343ad41d24096b9a4ab8a4a567d0f40c0d3b708a384e65c9db4`
- Representative raw keys: `6000011::S02::A004, 6000011::S02::A005, 6000016::S03::A001`
- Archetype / platform / service: `NETWORK_C2_BEACON` / `windows` / `DNS, HTTP`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, multi_step_composite, service_environment_absent, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-047-network_c2_beacon

- Member count: `2`
- Member-set SHA256: `55a22d749442342f056389b89e6d7d5576b46ab7d2143a745652486d291692dc`
- Representative raw keys: `6000015::S02::A003, 6000050::S02::A003`
- Archetype / platform / service: `NETWORK_C2_BEACON` / `windows` / `DNS, HTTP`
- Blocker summary: `destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-050-network_c2_beacon

- Member count: `2`
- Member-set SHA256: `620e1849542899da633c83c389250627be5e7838fbd53b7eeee5f2ee523fa5e0`
- Representative raw keys: `6000056::S06::A003, 6000060::S08::A001`
- Archetype / platform / service: `NETWORK_C2_BEACON` / `windows` / `FTP, HTTP, SMTP, SSH`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, multi_step_composite, service_environment_absent, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-051-network_c2_beacon

- Member count: `6`
- Member-set SHA256: `8b6c9ef1058947c28e94f1f10dbfab20fc0b8c95f1f619e52a9dc825a939fd58`
- Representative raw keys: `6000002::S08::A005, 6000035::S08::A002, 6000041::S07::A002`
- Archetype / platform / service: `NETWORK_C2_BEACON` / `windows` / `RDP`
- Blocker summary: `credential_sensitive, service_environment_absent, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-052-network_c2_beacon

- Member count: `7`
- Member-set SHA256: `abf3031da445cdfad0190d596f01b1092fc1a5b850e8bc75b6b07e4ac02f46db`
- Representative raw keys: `6000002::S08::A004, 6000006::S09::A004, 6000007::S08::A006`
- Archetype / platform / service: `NETWORK_C2_BEACON` / `windows` / `SMB`
- Blocker summary: `credential_sensitive, service_environment_absent, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-053-network_c2_beacon

- Member count: `2`
- Member-set SHA256: `6e05f45041d56a2db88c723b3e429b1743025b891c567fca0a5f8e93f5ac5c5c`
- Representative raw keys: `6000041::S07::A004, 6000056::S06::A002`
- Archetype / platform / service: `NETWORK_C2_BEACON` / `windows` / `SSH`
- Blocker summary: `credential_sensitive, service_environment_absent, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-056-persistence_configuration

- Member count: `2`
- Member-set SHA256: `2dd4571868ba086c63388b0a0369eb966a1ec7239f253bcca56b7447255d9454`
- Representative raw keys: `6000018::S05::A002, 6000018::S05::A004`
- Archetype / platform / service: `PERSISTENCE_CONFIGURATION` / `linux` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-059-persistence_configuration

- Member count: `5`
- Member-set SHA256: `3c2bdb7a4109cb9933d7d787c39ef92b1099aa6122d1844a836cfb7fcdbfc66a`
- Representative raw keys: `6000003::S08::A003, 6000006::S08::A004, 6000011::S08::A002`
- Archetype / platform / service: `PERSISTENCE_CONFIGURATION` / `windows` / `FTP`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-058-persistence_configuration

- Member count: `3`
- Member-set SHA256: `89ede49783c5e69a766bd6511f074b55cc6b7bead3259b76da4367d231560858`
- Representative raw keys: `6000007::S07::A004, 6000013::S07::A001, 6000017::S05::A005`
- Archetype / platform / service: `PERSISTENCE_CONFIGURATION` / `windows` / `FTP, SMTP`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

## r5-review-batch-04

Templates: 10. Member rows represented: 45.

### r4-template-063-persistence_configuration

- Member count: `2`
- Member-set SHA256: `45106210801a762b78839d1f2d6dce3715b42490f542061598429320fe7721a4`
- Representative raw keys: `6000034::S06::A001, 6000062::S05::A002`
- Archetype / platform / service: `PERSISTENCE_CONFIGURATION` / `windows` / `HTTP`
- Blocker summary: `credential_sensitive, destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-062-persistence_configuration

- Member count: `4`
- Member-set SHA256: `317073c43cfa914cd767499e6674ab2ce71738f63399ca4034ca96f37aaa8e7f`
- Representative raw keys: `6000028::S07::A003, 6000034::S06::A003, 6000049::S06::A001`
- Archetype / platform / service: `PERSISTENCE_CONFIGURATION` / `windows` / `HTTP`
- Blocker summary: `destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `FILE, PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-072-persistence_configuration

- Member count: `2`
- Member-set SHA256: `aab577c062f306cff7c14137892560c25c5fcd098edeeaca3010759fa9a4681f`
- Representative raw keys: `6000024::S04::A004, 6000056::S04::A004`
- Archetype / platform / service: `PERSISTENCE_CONFIGURATION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-066-persistence_configuration

- Member count: `5`
- Member-set SHA256: `1121dde5a3340465eb8cd78ba3dc24102e88082a99c65284e836e52155de3733`
- Representative raw keys: `6000017::S04::A004, 6000025::S06::A003, 6000041::S06::A001`
- Archetype / platform / service: `PERSISTENCE_CONFIGURATION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-069-persistence_configuration

- Member count: `10`
- Member-set SHA256: `7347ef4f412bf89b0ee6fad51fe44eabb96c64606d8b7d293b0b656ed8e86b42`
- Representative raw keys: `6000002::S03::A003, 6000002::S06::A002, 6000004::S05::A003`
- Archetype / platform / service: `PERSISTENCE_CONFIGURATION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `FILE, PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-071-persistence_configuration

- Member count: `8`
- Member-set SHA256: `939db086e6af0f4a8c6fb04d039ff8a379b0b0dc9cf5ebe9cbd76bb4e3b9cb28`
- Representative raw keys: `6000015::S06::A002, 6000028::S07::A006, 6000029::S04::A001`
- Archetype / platform / service: `PERSISTENCE_CONFIGURATION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-075-privilege_account_action

- Member count: `5`
- Member-set SHA256: `1d6fc262c458243e991956a150c9df5c3a91ef52235116433976364cd2da93a5`
- Representative raw keys: `6000009::S05::A002, 6000016::S05::A004, 6000026::S04::A001`
- Archetype / platform / service: `PRIVILEGE_ACCOUNT_ACTION` / `windows` / `HTTP`
- Blocker summary: `credential_sensitive, destructive_state, multi_step_composite, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-077-privilege_account_action

- Member count: `4`
- Member-set SHA256: `077acdaef942a425e5be508855647d60d815cece9ce12ac9ff63b6514ecf366c`
- Representative raw keys: `6000002::S03::A002, 6000004::S02::A009, 6000025::S05::A001`
- Archetype / platform / service: `PRIVILEGE_ACCOUNT_ACTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, multi_step_composite, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-079-privilege_account_action

- Member count: `3`
- Member-set SHA256: `95c3916892224be9b5c08fbd174002008375344d60c46696081c587fd9a61d1e`
- Representative raw keys: `6000003::S03::A005, 6000007::S04::A003, 6000029::S05::A003`
- Archetype / platform / service: `PRIVILEGE_ACCOUNT_ACTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, multi_step_composite, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-078-privilege_account_action

- Member count: `2`
- Member-set SHA256: `63d40569d6f34e59cf437d1a487d328f2994aa36fcb70ddd4fffe2f658f3e232`
- Representative raw keys: `6000013::S05::A002, 6000026::S04::A002`
- Archetype / platform / service: `PRIVILEGE_ACCOUNT_ACTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, multi_step_composite, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

## r5-review-batch-05

Templates: 10. Member rows represented: 36.

### r4-template-080-privilege_account_action

- Member count: `3`
- Member-set SHA256: `7e38d2431082d0accdbb5ffbc07f9fcda079a46a0a58106e9ff08a889a387f46`
- Representative raw keys: `6000008::S04::A004, 6000009::S05::A001, 6000032::S05::A001`
- Archetype / platform / service: `PRIVILEGE_ACCOUNT_ACTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-081-privilege_account_action

- Member count: `3`
- Member-set SHA256: `85f8f3512b06e012c3a61d589fa1c7aa14f08f3f8495948ed84a4458a5e2baa1`
- Representative raw keys: `6000002::S03::A001, 6000007::S04::A002, 6000029::S05::A002`
- Archetype / platform / service: `PRIVILEGE_ACCOUNT_ACTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-083-privilege_account_action

- Member count: `4`
- Member-set SHA256: `d53898fc0a50acf6b299ea038dca342a4892c7cdd73a737c0d960f634f711420`
- Representative raw keys: `6000006::S05::A001, 6000010::S04::A004, 6000025::S05::A002`
- Archetype / platform / service: `PRIVILEGE_ACCOUNT_ACTION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, multi_step_composite, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-085-process_command_execution

- Member count: `4`
- Member-set SHA256: `3086fc45c1328f717864a3be87543854d5b6aa63cc2cf93945e5e8ab753e4d5e`
- Representative raw keys: `6000018::S07::A003, 6000040::S03::A004, 6000040::S07::A002`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `linux` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-090-process_command_execution

- Member count: `2`
- Member-set SHA256: `fe2d5a038ba4e4fdb1a5a8fd87cebf2366315e0161cc3492e16d559bdc95a90e`
- Representative raw keys: `6000018::S04::A003, 6000040::S06::A003`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `linux` / `UNKNOWN`
- Blocker summary: `credential_sensitive, multi_step_composite`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-089-process_command_execution

- Member count: `2`
- Member-set SHA256: `cb55475cfe67a3d5540aa80cf050378cf98487fc295593b26ed7f73782665209`
- Representative raw keys: `6000040::S03::A003, 6000040::S05::A003`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `linux` / `UNKNOWN`
- Blocker summary: `destructive_state, multi_step_composite, privileged_action`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-093-process_command_execution

- Member count: `8`
- Member-set SHA256: `e3b49333080544816c031edbfee143cfd93425676e56d3eec120b334d7bef56b`
- Representative raw keys: `6000006::S07::A004, 6000009::S10::A001, 6000010::S07::A002`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `FTP`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-094-process_command_execution

- Member count: `3`
- Member-set SHA256: `317cf468339501dda2901090b0d1581ab955e5272e6804e79db32b464e131b25`
- Representative raw keys: `6000003::S07::A003, 6000025::S04::A004, 6000034::S05::A005`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `HTTP`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-095-process_command_execution

- Member count: `5`
- Member-set SHA256: `06ef1af7e474725d4ed6496cfda014fa386100665a4f207f7365cef8132f8e44`
- Representative raw keys: `6000009::S06::A001, 6000010::S05::A003, 6000034::S03::A004`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `HTTP`
- Blocker summary: `credential_sensitive, destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-154-process_command_execution

- Member count: `2`
- Member-set SHA256: `9298a0d2b63ee93d2692aae43a70a81faf06c1ba51ab4520b08a4137ed05ae83`
- Representative raw keys: `6000025::S07::A005, 6000036::S06::A003`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

## r5-review-batch-06

Templates: 10. Member rows represented: 64.

### r4-template-155-process_command_execution

- Member count: `5`
- Member-set SHA256: `e6d006d4724c6758aa4aa69b1d86a5c9346b1be290765600a1cfe51170981418`
- Representative raw keys: `6000003::S06::A001, 6000004::S08::A001, 6000011::S07::A004`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, destructive_state, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-157-process_command_execution

- Member count: `5`
- Member-set SHA256: `902eb0f32d49e7f188b96775e702e81e2e03c6c2129ad36b8216cbfa818d429e`
- Representative raw keys: `6000009::S08::A006, 6000015::S07::A002, 6000021::S07::A001`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-156-process_command_execution

- Member count: `2`
- Member-set SHA256: `8f48a6b1770061bc0dc487d6bdf5b88b9caa1311f76b2ed6479c1ad473fa223d`
- Representative raw keys: `6000010::S03::A008, 6000014::S04::A004`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-145-process_command_execution

- Member count: `4`
- Member-set SHA256: `4461d558d6a845473e100c4566365d12a7f788fa67144e73b7b5477fde40d677`
- Representative raw keys: `6000002::S05::A001, 6000034::S05::A003, 6000058::S05::A001`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-142-process_command_execution

- Member count: `2`
- Member-set SHA256: `df652fa4f880bfb294205fbffb541fe1d07347bac03b5314eddedc6efbd85aee`
- Representative raw keys: `6000007::S07::A005, 6000013::S07::A002`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-144-process_command_execution

- Member count: `2`
- Member-set SHA256: `9ef32c859bf8f7fcb5aa9479cd98b44bfb848e8bf065e90dcbe8e1adb11d54ef`
- Representative raw keys: `6000021::S07::A003, 6000036::S07::A003`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-147-process_command_execution

- Member count: `5`
- Member-set SHA256: `98359a71b5710d81d66ca1744f7e2ca5dec91225bbc7767065e2fc87f4a7e037`
- Representative raw keys: `6000004::S04::A006, 6000017::S06::A003, 6000032::S03::A004`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, credential_sensitive, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-104-process_command_execution

- Member count: `4`
- Member-set SHA256: `f1fcc66789832aea6054ae086d951a963db504251b84c2c0080b22ec0f6367b1`
- Representative raw keys: `6000017::S08::A003, 6000020::S07::A002, 6000042::S08::A001`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, missing_exact_command_semantics, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-105-process_command_execution

- Member count: `8`
- Member-set SHA256: `fca9094437e65a54b4e241f3b71af0f9ab92689f1e5198031f3c67993fa27246`
- Representative raw keys: `6000006::S05::A002, 6000013::S05::A004, 6000017::S03::A002`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, multi_step_composite, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-107-process_command_execution

- Member count: `27`
- Member-set SHA256: `aeead35be23d0b2f06d1b7085ce3c33e1cdc08c87f92fe9e972eea608809ee0e`
- Representative raw keys: `6000002::S02::A003, 6000002::S07::A001, 6000004::S05::A004`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

## r5-review-batch-07

Templates: 10. Member rows represented: 91.

### r4-template-108-process_command_execution

- Member count: `4`
- Member-set SHA256: `503fa11b28393aa62bbc7811f363d2378dc13f05e11fdcc357abf1cdc71f52b4`
- Representative raw keys: `6000008::S03::A008, 6000010::S03::A007, 6000013::S03::A005`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-109-process_command_execution

- Member count: `5`
- Member-set SHA256: `518053eb5f8784ac4a69cfa2a7282fb66114b9036f01a854c67f5a3b91433e97`
- Representative raw keys: `6000010::S04::A005, 6000016::S06::A001, 6000035::S05::A002`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, privileged_action, service_environment_absent, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-110-process_command_execution

- Member count: `7`
- Member-set SHA256: `c66d64518cd91197d0c77b8e0a9fc9bd28100de67255ee737501d3ba75c4f2cf`
- Representative raw keys: `6000007::S08::A007, 6000017::S06::A005, 6000019::S04::A004`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-111-process_command_execution

- Member count: `6`
- Member-set SHA256: `de10c787424adac8a2ebe070282a5263ee0100554bb10a3b867b412ea108c30b`
- Representative raw keys: `6000006::S12::A005, 6000008::S09::A003, 6000009::S11::A003`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-120-process_command_execution

- Member count: `49`
- Member-set SHA256: `3ceca8928cf0c95f4006ffbf91d677cf3cee9287d7beea4996adfa752703bc33`
- Representative raw keys: `6000003::S03::A001, 6000003::S03::A008, 6000006::S04::A001`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-115-process_command_execution

- Member count: `6`
- Member-set SHA256: `4c71bffb6be23af389a80875ec6428d37f5e82b6811ec8964ad28c2802a42eb7`
- Representative raw keys: `6000007::S05::A002, 6000007::S05::A003, 6000010::S12::A003`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-114-process_command_execution

- Member count: `4`
- Member-set SHA256: `f9f77bcd6a8606c8cd1b5b4933b50f2f285f8980d418fb784d70fd8579e8d705`
- Representative raw keys: `6000003::S04::A001, 6000006::S04::A006, 6000013::S04::A005`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-116-process_command_execution

- Member count: `4`
- Member-set SHA256: `c5feab8a848b964d246abd847c6f2394ac2da81c00e3149a7c1f72ff3dbfaf5c`
- Representative raw keys: `6000013::S04::A001, 6000050::S04::A002, 6000061::S05::A005`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-117-process_command_execution

- Member count: `3`
- Member-set SHA256: `b6411d97debebb78ce33af23d94806a6ab031ef8feaa2880d57d196db0a8023f`
- Representative raw keys: `6000008::S03::A007, 6000029::S04::A003, 6000063::S04::A003`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-119-process_command_execution

- Member count: `3`
- Member-set SHA256: `4668e63ec9dc0ecd5ce8e858a8826adf1d98b13a68d73f21b071853118ab8302`
- Representative raw keys: `6000013::S03::A004, 6000014::S02::A002, 6000024::S03::A003`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `ambiguous_source_wording, destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

## r5-review-batch-08

Templates: 10. Member rows represented: 60.

### r4-template-158-process_command_execution

- Member count: `4`
- Member-set SHA256: `0db14f6605caecfc850705dc284f902989d14fe603847b000162d32729b68dc0`
- Representative raw keys: `6000011::S04::A003, 6000015::S05::A002, 6000023::S05::A003`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `credential_sensitive, destructive_state, multi_step_composite, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-159-process_command_execution

- Member count: `17`
- Member-set SHA256: `e5f22f069e236fde74af499ec46117c82ea2ce067d39b759421f6865cd548439`
- Representative raw keys: `6000007::S11::A002, 6000010::S12::A002, 6000011::S10::A004`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `credential_sensitive, destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-160-process_command_execution

- Member count: `4`
- Member-set SHA256: `20d91494c439c06e3e65fca6621f012e21c210ec3fe887e001717d2b6eede5e5`
- Representative raw keys: `6000006::S08::A003, 6000009::S10::A003, 6000011::S08::A001`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `credential_sensitive, destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-149-process_command_execution

- Member count: `5`
- Member-set SHA256: `1d60b0de395f8e88f59e72c4f028f10889b81c2623086ff19353a1de050b41af`
- Representative raw keys: `6000009::S08::A007, 6000011::S08::A006, 6000033::S06::A002`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `credential_sensitive, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-150-process_command_execution

- Member count: `4`
- Member-set SHA256: `ef6d443273d3459cd7ad938dc702d874b6c089dde82296d56d15235c4f13e681`
- Representative raw keys: `6000004::S04::A003, 6000006::S07::A005, 6000032::S06::A001`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `credential_sensitive, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-152-process_command_execution

- Member count: `12`
- Member-set SHA256: `ed38669390f755e5d316080187f6eff0d819475d59c828fa527d0ec66755ce35`
- Representative raw keys: `6000006::S08::A005, 6000008::S05::A008, 6000011::S06::A007`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `credential_sensitive, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-151-process_command_execution

- Member count: `2`
- Member-set SHA256: `6ad746802c60be182bc8850a3cc00abb0da21e18b6360bc96e4bd882ff65fd44`
- Representative raw keys: `6000049::S05::A001, 6000054::S06::A001`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `credential_sensitive, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-124-process_command_execution

- Member count: `2`
- Member-set SHA256: `f1334bc6c367f35fe8f490b3753c190a97b03ad2866e995ae0a1bd730e95972a`
- Representative raw keys: `6000023::S10::A002, 6000043::S07::A002`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, missing_exact_command_semantics, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-125-process_command_execution

- Member count: `3`
- Member-set SHA256: `97d08199317381d9d280b15a7784581907991146490d6822eb32a38b3f1776bd`
- Representative raw keys: `6000011::S10::A005, 6000019::S08::A006, 6000020::S07::A003`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, missing_exact_command_semantics, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-126-process_command_execution

- Member count: `7`
- Member-set SHA256: `da7703ea791d0afdcb41e615380748b83e9d4983e3f20ba0702e3666852acef2`
- Representative raw keys: `6000009::S05::A003, 6000009::S05::A004, 6000011::S04::A002`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, multi_step_composite, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

## r5-review-batch-09

Templates: 9. Member rows represented: 68.

### r4-template-127-process_command_execution

- Member count: `3`
- Member-set SHA256: `2373c27fc5fa198e0bade5005fb9bfe65f275569789b14f0e0304fd878586699`
- Representative raw keys: `6000003::S07::A006, 6000006::S12::A003, 6000046::S06::A001`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, multi_step_composite, privileged_action, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-130-process_command_execution

- Member count: `17`
- Member-set SHA256: `b9e9db68106f21ada95ece8e6158f9954372e9e28b908b1e98d886a679280449`
- Representative raw keys: `6000002::S09::A004, 6000008::S05::A002, 6000009::S07::A005`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-128-process_command_execution

- Member count: `2`
- Member-set SHA256: `45fef82e9b57a32c2b6e013eb8013925cdad552ffe8d1bc9f3ac8758400dd205`
- Representative raw keys: `6000042::S02::A002, 6000055::S04::A001`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-136-process_command_execution

- Member count: `28`
- Member-set SHA256: `fc076c1fbcef34272b7bb80b611fa0b3a560a940833e960976d45388355d100a`
- Representative raw keys: `6000006::S04::A007, 6000008::S03::A001, 6000009::S11::A001`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-134-process_command_execution

- Member count: `4`
- Member-set SHA256: `ca08913e00a33e2e28bfc3b8eccfb9b984753ee1226010f1c16f9c169c9b9276`
- Representative raw keys: `6000002::S07::A005, 6000010::S03::A002, 6000015::S04::A003`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-138-process_command_execution

- Member count: `4`
- Member-set SHA256: `ea6ffdceec4e2785c8f4f18c7f81f622db48bc8d32cd7dc6b740bd07d7735ced`
- Representative raw keys: `6000020::S04::A005, 6000028::S03::A001, 6000050::S06::A002`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-135-process_command_execution

- Member count: `3`
- Member-set SHA256: `8eb51042f474615abdd5aa13ed82a64fac5f75ece4cc2ba7f57506f0794629d7`
- Representative raw keys: `6000007::S11::A001, 6000019::S08::A004, 6000024::S09::A002`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-137-process_command_execution

- Member count: `3`
- Member-set SHA256: `4d21ae0b28223a6fb0cbf4dd9bc7ae1828739394fd624895f7863ca074881b3d`
- Representative raw keys: `6000009::S03::A002, 6000017::S05::A001, 6000042::S02::A003`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `destructive_state, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `HIGH`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-102-process_command_execution

- Member count: `4`
- Member-set SHA256: `68cb8be1336f8a07164e216a1056a328be6284258b3d874b4386f0c37b4bbdd3`
- Representative raw keys: `6000008::S06::A003, 6000016::S07::A003, 6000023::S07::A003`
- Archetype / platform / service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Blocker summary: `multi_step_composite, windows_only_semantics`
- Defensive-equivalence summary: `R4_TEMPLATE_INVARIANTS_AND_MECHANICAL_SOURCE_SIGNATURE_PRESENT`; preserve R4 source-visible invariants only.
- Telemetry-equivalence summary: `SOURCE_DERIVED_TELEMETRY_SURFACES_ONLY`; candidate surfaces `PROCESS`; PROVX remains UNKNOWN.
- Environment availability: `NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT`
- Reset/safety complexity: `MODERATE`
- Raw-specific parameters:
  - `raw_key`
  - `source_locator`
  - `source action name/description`
  - `raw-specific OS/service/protocol values`
  - `raw-specific blocker evidence`
  - `approved fixture identifier`
  - `run_id binding`
- Unresolved human questions:
  - What exact source-visible semantics must remain equivalent for this raw?
  - Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?
  - Which side effects are necessary for the defensive decision point, and which must be excluded?
- Negative cases:
  - Do not infer missing command syntax, credentials, target behavior, or exploitability.
  - Do not use public endpoints, real malware, destructive effects, or uncontrolled services.
  - Do not mark PROVX detection/localization or formal outcomes from a design packet.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

