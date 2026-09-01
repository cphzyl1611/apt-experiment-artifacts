# E0C-R8 Structured Cohesion Review Sheets

Evidence-only support for exactly 12 authenticated templates covering exactly 203 raw actions. No decision or split is selected.

Allowed human actions: `APPROVE_TEMPLATE_FOR_MEMBER_SET`, `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`, `REQUEST_SPLIT_OR_MORE_EVIDENCE`. The decision remains null.

## r4-template-120-process_command_execution

- Members: `49`; member-set SHA256: `3ceca8928cf0c95f4006ffbf91d677cf3cee9287d7beea4996adfa752703bc33`
- Strongest cohesion evidence: source action type / OS / telemetry distributions are shown exactly below; no free-text semantics were inferred.
- Strongest structured heterogeneity evidence: `NONE`
- UNKNOWN burden: `147` cells (`0.231` of structured cells)
- Candidate split evidence: `NO_STRUCTURED_SPLIT_EVIDENCE` (`0` candidates)
- Consequence of keeping template: retain the exact member set for explicit human review; all members remain `MANUAL_DESIGN_REQUIRED`.
- Consequence of splitting: only a later explicit human request could define a split; no split is applied by R8.
- Representative authenticated source evidence:
  - `6000003::S03::A001`: action name `Host command line - Gathering Information Using the Nishang Framework`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000003.json#$.pipeline[2].actions[0]`
  - `6000003::S03::A008`: action name `Host Command Line - Disable Windows Defender Task`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000003.json#$.pipeline[2].actions[7]`
  - `6000006::S04::A001`: action name `Host Command Line - Bypassing Constrained Language Mode Enforcement via Powershell Runspace`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000006.json#$.pipeline[3].actions[0]`
- Structured field distributions:
  - `source_action_type`: host_cli=49
  - `os_platform`: windows=49
  - `explicit_protocol_service`: ["UNKNOWN"]=49
  - `explicit_required_protocol`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=49
  - `explicit_required_service_class`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=49
  - `service_prerequisites`: ["UNKNOWN"]=49
  - `telemetry_surface_flags`: {"requires_external_service_emulation":"STRUCTURED_EVIDENCE_PRESENT","requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDEN...=49
  - `host_process_file_socket_network_requirements`: {"requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_network_fabric":"STRUCTURED_EVIDENCE_PRESENT",...=49
  - `destructive_state_flag`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=49
  - `reset_safety_complexity`: HIGH=49
  - `environment_blocker`: ["NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION"]=49
  - `source_detail_completeness`: COMPLETE=49
  - `controlled_environment_feasibility`: NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION=49

Decision: `null` (awaiting explicit human action).

## r4-template-136-process_command_execution

- Members: `28`; member-set SHA256: `fc076c1fbcef34272b7bb80b611fa0b3a560a940833e960976d45388355d100a`
- Strongest cohesion evidence: source action type / OS / telemetry distributions are shown exactly below; no free-text semantics were inferred.
- Strongest structured heterogeneity evidence: `NONE`
- UNKNOWN burden: `84` cells (`0.231` of structured cells)
- Candidate split evidence: `NO_STRUCTURED_SPLIT_EVIDENCE` (`0` candidates)
- Consequence of keeping template: retain the exact member set for explicit human review; all members remain `MANUAL_DESIGN_REQUIRED`.
- Consequence of splitting: only a later explicit human request could define a split; no split is applied by R8.
- Representative authenticated source evidence:
  - `6000006::S04::A007`: action name `Host Command Line - Encoded PowerShell command`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000006.json#$.pipeline[3].actions[6]`
  - `6000008::S03::A001`: action name `Host Command Line - Get computer system information via PowerShell parameter tricks triggered from the command line`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000008.json#$.pipeline[2].actions[0]`
  - `6000009::S11::A001`: action name `Host Command Line - Deleting shadow copies via the shadow.bat script`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000009.json#$.pipeline[10].actions[0]`
- Structured field distributions:
  - `source_action_type`: host_cli=28
  - `os_platform`: windows=28
  - `explicit_protocol_service`: ["UNKNOWN"]=28
  - `explicit_required_protocol`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=28
  - `explicit_required_service_class`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=28
  - `service_prerequisites`: ["UNKNOWN"]=28
  - `telemetry_surface_flags`: {"requires_external_service_emulation":"STRUCTURED_EVIDENCE_PRESENT","requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDEN...=28
  - `host_process_file_socket_network_requirements`: {"requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_network_fabric":"STRUCTURED_EVIDENCE_PRESENT",...=28
  - `destructive_state_flag`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=28
  - `reset_safety_complexity`: HIGH=28
  - `environment_blocker`: ["NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION"]=28
  - `source_detail_completeness`: COMPLETE=28
  - `controlled_environment_feasibility`: NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION=28

Decision: `null` (awaiting explicit human action).

## r4-template-107-process_command_execution

- Members: `27`; member-set SHA256: `aeead35be23d0b2f06d1b7085ce3c33e1cdc08c87f92fe9e972eea608809ee0e`
- Strongest cohesion evidence: source action type / OS / telemetry distributions are shown exactly below; no free-text semantics were inferred.
- Strongest structured heterogeneity evidence: `NONE`
- UNKNOWN burden: `81` cells (`0.231` of structured cells)
- Candidate split evidence: `NO_STRUCTURED_SPLIT_EVIDENCE` (`0` candidates)
- Consequence of keeping template: retain the exact member set for explicit human review; all members remain `MANUAL_DESIGN_REQUIRED`.
- Consequence of splitting: only a later explicit human request could define a split; no split is applied by R8.
- Representative authenticated source evidence:
  - `6000002::S02::A003`: action name `Host Command Line - Network local groups, user discovery`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000002.json#$.pipeline[1].actions[2]`
  - `6000002::S07::A001`: action name `Host Command Line - Use Adfind to gather information about the target domain and operating system`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000002.json#$.pipeline[6].actions[0]`
  - `6000004::S05::A004`: action name `Protected Sandbox - Clear Windows Security Event Log, PowerShell`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000004.json#$.pipeline[4].actions[3]`
- Structured field distributions:
  - `source_action_type`: host_cli=27
  - `os_platform`: windows=27
  - `explicit_protocol_service`: ["UNKNOWN"]=27
  - `explicit_required_protocol`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=27
  - `explicit_required_service_class`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=27
  - `service_prerequisites`: ["UNKNOWN"]=27
  - `telemetry_surface_flags`: {"requires_external_service_emulation":"STRUCTURED_EVIDENCE_PRESENT","requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDEN...=27
  - `host_process_file_socket_network_requirements`: {"requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_network_fabric":"STRUCTURED_EVIDENCE_PRESENT",...=27
  - `destructive_state_flag`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=27
  - `reset_safety_complexity`: HIGH=27
  - `environment_blocker`: ["NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION"]=27
  - `source_detail_completeness`: COMPLETE=27
  - `controlled_environment_feasibility`: NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION=27

Decision: `null` (awaiting explicit human action).

## r4-template-159-process_command_execution

- Members: `17`; member-set SHA256: `e5f22f069e236fde74af499ec46117c82ea2ce067d39b759421f6865cd548439`
- Strongest cohesion evidence: source action type / OS / telemetry distributions are shown exactly below; no free-text semantics were inferred.
- Strongest structured heterogeneity evidence: `NONE`
- UNKNOWN burden: `51` cells (`0.231` of structured cells)
- Candidate split evidence: `NO_STRUCTURED_SPLIT_EVIDENCE` (`0` candidates)
- Consequence of keeping template: retain the exact member set for explicit human review; all members remain `MANUAL_DESIGN_REQUIRED`.
- Consequence of splitting: only a later explicit human request could define a split; no split is applied by R8.
- Representative authenticated source evidence:
  - `6000007::S11::A002`: action name `Host command line - Remove local account access via Command Prompt, benign`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000007.json#$.pipeline[10].actions[1]`
  - `6000010::S12::A002`: action name `Host command line - Remove local account access via Command Prompt, benign`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000010.json#$.pipeline[11].actions[1]`
  - `6000011::S10::A004`: action name `Host command line - Remove local account access via Command Prompt, benign`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000011.json#$.pipeline[9].actions[3]`
- Structured field distributions:
  - `source_action_type`: host_cli=17
  - `os_platform`: windows=17
  - `explicit_protocol_service`: ["UNKNOWN"]=17
  - `explicit_required_protocol`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=17
  - `explicit_required_service_class`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=17
  - `service_prerequisites`: ["UNKNOWN"]=17
  - `telemetry_surface_flags`: {"requires_external_service_emulation":"STRUCTURED_EVIDENCE_PRESENT","requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDEN...=17
  - `host_process_file_socket_network_requirements`: {"requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_network_fabric":"STRUCTURED_EVIDENCE_PRESENT",...=17
  - `destructive_state_flag`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=17
  - `reset_safety_complexity`: HIGH=17
  - `environment_blocker`: ["NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION"]=17
  - `source_detail_completeness`: COMPLETE=17
  - `controlled_environment_feasibility`: NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION=17

Decision: `null` (awaiting explicit human action).

## r4-template-130-process_command_execution

- Members: `17`; member-set SHA256: `b9e9db68106f21ada95ece8e6158f9954372e9e28b908b1e98d886a679280449`
- Strongest cohesion evidence: source action type / OS / telemetry distributions are shown exactly below; no free-text semantics were inferred.
- Strongest structured heterogeneity evidence: `NONE`
- UNKNOWN burden: `51` cells (`0.231` of structured cells)
- Candidate split evidence: `NO_STRUCTURED_SPLIT_EVIDENCE` (`0` candidates)
- Consequence of keeping template: retain the exact member set for explicit human review; all members remain `MANUAL_DESIGN_REQUIRED`.
- Consequence of splitting: only a later explicit human request could define a split; no split is applied by R8.
- Representative authenticated source evidence:
  - `6000002::S09::A004`: action name `Host command line - POWERSPLOIT, Audio Capture, Variant -2`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000002.json#$.pipeline[8].actions[3]`
  - `6000008::S05::A002`: action name `Host command line - Add Windows Defender Exception Path, Variant -2`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000008.json#$.pipeline[4].actions[1]`
  - `6000009::S07::A005`: action name `Host Command Line - Private Key, PowerShell`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000009.json#$.pipeline[6].actions[4]`
- Structured field distributions:
  - `source_action_type`: host_cli=17
  - `os_platform`: windows=17
  - `explicit_protocol_service`: ["UNKNOWN"]=17
  - `explicit_required_protocol`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=17
  - `explicit_required_service_class`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=17
  - `service_prerequisites`: ["UNKNOWN"]=17
  - `telemetry_surface_flags`: {"requires_external_service_emulation":"STRUCTURED_EVIDENCE_PRESENT","requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDEN...=17
  - `host_process_file_socket_network_requirements`: {"requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_network_fabric":"STRUCTURED_EVIDENCE_PRESENT",...=17
  - `destructive_state_flag`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=17
  - `reset_safety_complexity`: HIGH=17
  - `environment_blocker`: ["NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION"]=17
  - `source_detail_completeness`: COMPLETE=17
  - `controlled_environment_feasibility`: NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION=17

Decision: `null` (awaiting explicit human action).

## r4-template-152-process_command_execution

- Members: `12`; member-set SHA256: `ed38669390f755e5d316080187f6eff0d819475d59c828fa527d0ec66755ce35`
- Strongest cohesion evidence: source action type / OS / telemetry distributions are shown exactly below; no free-text semantics were inferred.
- Strongest structured heterogeneity evidence: `NONE`
- UNKNOWN burden: `36` cells (`0.231` of structured cells)
- Candidate split evidence: `NO_STRUCTURED_SPLIT_EVIDENCE` (`0` candidates)
- Consequence of keeping template: retain the exact member set for explicit human review; all members remain `MANUAL_DESIGN_REQUIRED`.
- Consequence of splitting: only a later explicit human request could define a split; no split is applied by R8.
- Representative authenticated source evidence:
  - `6000006::S08::A005`: action name `Host Command Line - Search WSL Bash History for Credentials`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000006.json#$.pipeline[7].actions[4]`
  - `6000008::S05::A008`: action name `Host Command Line - Search WSL Bash History for Credentials`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000008.json#$.pipeline[4].actions[7]`
  - `6000011::S06::A007`: action name `Host Command Line - Keylogger`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000011.json#$.pipeline[5].actions[6]`
- Structured field distributions:
  - `source_action_type`: host_cli=12
  - `os_platform`: windows=12
  - `explicit_protocol_service`: ["UNKNOWN"]=12
  - `explicit_required_protocol`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=12
  - `explicit_required_service_class`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=12
  - `service_prerequisites`: ["UNKNOWN"]=12
  - `telemetry_surface_flags`: {"requires_external_service_emulation":"STRUCTURED_EVIDENCE_PRESENT","requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDEN...=12
  - `host_process_file_socket_network_requirements`: {"requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_network_fabric":"STRUCTURED_EVIDENCE_PRESENT",...=12
  - `destructive_state_flag`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=12
  - `reset_safety_complexity`: HIGH=12
  - `environment_blocker`: ["NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION"]=12
  - `source_detail_completeness`: COMPLETE=12
  - `controlled_environment_feasibility`: NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION=12

Decision: `null` (awaiting explicit human action).

## r4-template-069-persistence_configuration

- Members: `10`; member-set SHA256: `7347ef4f412bf89b0ee6fad51fe44eabb96c64606d8b7d293b0b656ed8e86b42`
- Strongest cohesion evidence: source action type / OS / telemetry distributions are shown exactly below; no free-text semantics were inferred.
- Strongest structured heterogeneity evidence: `NONE`
- UNKNOWN burden: `30` cells (`0.231` of structured cells)
- Candidate split evidence: `NO_STRUCTURED_SPLIT_EVIDENCE` (`0` candidates)
- Consequence of keeping template: retain the exact member set for explicit human review; all members remain `MANUAL_DESIGN_REQUIRED`.
- Consequence of splitting: only a later explicit human request could define a split; no split is applied by R8.
- Representative authenticated source evidence:
  - `6000002::S03::A003`: action name `Host Command Line - Use PowerShell to modify group policy to disable Windows Defender`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000002.json#$.pipeline[2].actions[2]`
  - `6000002::S06::A002`: action name `Host command line - create persistence via scheduled task named "Classic Sound"`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000002.json#$.pipeline[5].actions[1]`
  - `6000004::S05::A003`: action name `Host Command Line - Winlogon Registry Changes`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000004.json#$.pipeline[4].actions[2]`
- Structured field distributions:
  - `source_action_type`: host_cli=10
  - `os_platform`: windows=10
  - `explicit_protocol_service`: ["UNKNOWN"]=10
  - `explicit_required_protocol`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=10
  - `explicit_required_service_class`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=10
  - `service_prerequisites`: ["UNKNOWN"]=10
  - `telemetry_surface_flags`: {"requires_external_service_emulation":"STRUCTURED_EVIDENCE_PRESENT","requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDEN...=10
  - `host_process_file_socket_network_requirements`: {"requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_network_fabric":"STRUCTURED_EVIDENCE_PRESENT",...=10
  - `destructive_state_flag`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=10
  - `reset_safety_complexity`: HIGH=10
  - `environment_blocker`: ["NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION"]=10
  - `source_detail_completeness`: COMPLETE=10
  - `controlled_environment_feasibility`: NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION=10

Decision: `null` (awaiting explicit human action).

## r4-template-009-credential_store_access

- Members: `9`; member-set SHA256: `9ae166dab66173192bbcbcd89bc86757c290e9d8db2d23a0350cd6df890636f4`
- Strongest cohesion evidence: source action type / OS / telemetry distributions are shown exactly below; no free-text semantics were inferred.
- Strongest structured heterogeneity evidence: `NONE`
- UNKNOWN burden: `27` cells (`0.231` of structured cells)
- Candidate split evidence: `NO_STRUCTURED_SPLIT_EVIDENCE` (`0` candidates)
- Consequence of keeping template: retain the exact member set for explicit human review; all members remain `MANUAL_DESIGN_REQUIRED`.
- Consequence of splitting: only a later explicit human request could define a split; no split is applied by R8.
- Representative authenticated source evidence:
  - `6000003::S06::A004`: action name `Host Command Line - Passing Exported Tickets Using Mimikatz`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000003.json#$.pipeline[5].actions[3]`
  - `6000004::S08::A004`: action name `Host Command Line - Passing Exported Tickets Using Mimikatz`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000004.json#$.pipeline[7].actions[3]`
  - `6000006::S09::A006`: action name `Host Command Line - Passing Exported Tickets Using Mimikatz`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000006.json#$.pipeline[8].actions[5]`
- Structured field distributions:
  - `source_action_type`: host_cli=9
  - `os_platform`: windows=9
  - `explicit_protocol_service`: ["UNKNOWN"]=9
  - `explicit_required_protocol`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=9
  - `explicit_required_service_class`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=9
  - `service_prerequisites`: ["UNKNOWN"]=9
  - `telemetry_surface_flags`: {"requires_external_service_emulation":"STRUCTURED_EVIDENCE_PRESENT","requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDEN...=9
  - `host_process_file_socket_network_requirements`: {"requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_network_fabric":"STRUCTURED_EVIDENCE_PRESENT",...=9
  - `destructive_state_flag`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=9
  - `reset_safety_complexity`: HIGH=9
  - `environment_blocker`: ["NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION"]=9
  - `source_detail_completeness`: COMPLETE=9
  - `controlled_environment_feasibility`: NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION=9

Decision: `null` (awaiting explicit human action).

## r4-template-006-credential_store_access

- Members: `9`; member-set SHA256: `776cc6ca57d025ad62efeed4d6f55f8a34a6dafe4517cc6a8a388519de3e6e8d`
- Strongest cohesion evidence: source action type / OS / telemetry distributions are shown exactly below; no free-text semantics were inferred.
- Strongest structured heterogeneity evidence: `NONE`
- UNKNOWN burden: `27` cells (`0.231` of structured cells)
- Candidate split evidence: `NO_STRUCTURED_SPLIT_EVIDENCE` (`0` candidates)
- Consequence of keeping template: retain the exact member set for explicit human review; all members remain `MANUAL_DESIGN_REQUIRED`.
- Consequence of splitting: only a later explicit human request could define a split; no split is applied by R8.
- Representative authenticated source evidence:
  - `6000002::S05::A004`: action name `Host command line - MIMIKATZ (2.1.1), Valid Accounts from SAM NTLM Hash Dump, Variant -2`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000002.json#$.pipeline[4].actions[3]`
  - `6000003::S06::A003`: action name `Host command line - MIMIKATZ PowerShell, download obfuscated file by appending to JPEG, execute in memory`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000003.json#$.pipeline[5].actions[2]`
  - `6000027::S08::A005`: action name `Host command line - MIMIKATZ (2.1.1), Valid Accounts from SAM NTLM Hash Dump, Variant -2`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000027.json#$.pipeline[7].actions[4]`
- Structured field distributions:
  - `source_action_type`: host_cli=9
  - `os_platform`: windows=9
  - `explicit_protocol_service`: ["UNKNOWN"]=9
  - `explicit_required_protocol`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=9
  - `explicit_required_service_class`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=9
  - `service_prerequisites`: ["UNKNOWN"]=9
  - `telemetry_surface_flags`: {"requires_external_service_emulation":"STRUCTURED_EVIDENCE_PRESENT","requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDEN...=9
  - `host_process_file_socket_network_requirements`: {"requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_network_fabric":"STRUCTURED_EVIDENCE_PRESENT",...=9
  - `destructive_state_flag`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=9
  - `reset_safety_complexity`: HIGH=9
  - `environment_blocker`: ["NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION"]=9
  - `source_detail_completeness`: COMPLETE=9
  - `controlled_environment_feasibility`: NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION=9

Decision: `null` (awaiting explicit human action).

## r4-template-048-network_c2_beacon

- Members: `9`; member-set SHA256: `f7ea287ecdda9343ad41d24096b9a4ab8a4a567d0f40c0d3b708a384e65c9db4`
- Strongest cohesion evidence: source action type / OS / telemetry distributions are shown exactly below; no free-text semantics were inferred.
- Strongest structured heterogeneity evidence: `NONE`
- UNKNOWN burden: `27` cells (`0.231` of structured cells)
- Candidate split evidence: `NO_STRUCTURED_SPLIT_EVIDENCE` (`0` candidates)
- Consequence of keeping template: retain the exact member set for explicit human review; all members remain `MANUAL_DESIGN_REQUIRED`.
- Consequence of splitting: only a later explicit human request could define a split; no split is applied by R8.
- Representative authenticated source evidence:
  - `6000011::S02::A004`: action name `Host command line - Beacon, DNS Beacon A Record, C2 traffic`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000011.json#$.pipeline[1].actions[3]`
  - `6000011::S02::A005`: action name `Host Command Line - Beacon, DNS Beacon TXT Record, C2 traffic`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000011.json#$.pipeline[1].actions[4]`
  - `6000016::S03::A001`: action name `Host Command Line - Beacon, DNS Beacon TXT Record, C2 traffic`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000016.json#$.pipeline[2].actions[0]`
- Structured field distributions:
  - `source_action_type`: host_cli=9
  - `os_platform`: windows=9
  - `explicit_protocol_service`: ["DNS","HTTP"]=9
  - `explicit_required_protocol`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=9
  - `explicit_required_service_class`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=9
  - `service_prerequisites`: ["DNS","HTTP"]=9
  - `telemetry_surface_flags`: {"requires_external_service_emulation":"STRUCTURED_EVIDENCE_PRESENT","requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDEN...=9
  - `host_process_file_socket_network_requirements`: {"requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_network_fabric":"STRUCTURED_EVIDENCE_PRESENT",...=9
  - `destructive_state_flag`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=9
  - `reset_safety_complexity`: HIGH=9
  - `environment_blocker`: ["NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION"]=9
  - `source_detail_completeness`: COMPLETE=9
  - `controlled_environment_feasibility`: NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION=9

Decision: `null` (awaiting explicit human action).

## r4-template-035-file_resource_operation

- Members: `8`; member-set SHA256: `ae5c70bcbce560f3194a63c6336b1021b4a3f947601958b75ae98245331b8a52`
- Strongest cohesion evidence: source action type / OS / telemetry distributions are shown exactly below; no free-text semantics were inferred.
- Strongest structured heterogeneity evidence: `NONE`
- UNKNOWN burden: `24` cells (`0.231` of structured cells)
- Candidate split evidence: `NO_STRUCTURED_SPLIT_EVIDENCE` (`0` candidates)
- Consequence of keeping template: retain the exact member set for explicit human review; all members remain `MANUAL_DESIGN_REQUIRED`.
- Consequence of splitting: only a later explicit human request could define a split; no split is applied by R8.
- Representative authenticated source evidence:
  - `6000002::S05::A007`: action name `Host Command Line - URSNIF, using iexplore.exe to transfer collected data`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000002.json#$.pipeline[4].actions[6]`
  - `6000004::S04::A010`: action name `Host Command Line - URSNIF, using iexplore.exe to transfer collected data`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000004.json#$.pipeline[3].actions[9]`
  - `6000036::S07::A004`: action name `Host Command Line - URSNIF, using iexplore.exe to transfer collected data`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000036.json#$.pipeline[6].actions[3]`
- Structured field distributions:
  - `source_action_type`: host_cli=8
  - `os_platform`: windows=8
  - `explicit_protocol_service`: ["FTP"]=8
  - `explicit_required_protocol`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=8
  - `explicit_required_service_class`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=8
  - `service_prerequisites`: ["FTP"]=8
  - `telemetry_surface_flags`: {"requires_external_service_emulation":"STRUCTURED_EVIDENCE_PRESENT","requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDEN...=8
  - `host_process_file_socket_network_requirements`: {"requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_network_fabric":"STRUCTURED_EVIDENCE_PRESENT",...=8
  - `destructive_state_flag`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=8
  - `reset_safety_complexity`: HIGH=8
  - `environment_blocker`: ["NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION"]=8
  - `source_detail_completeness`: COMPLETE=8
  - `controlled_environment_feasibility`: NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION=8

Decision: `null` (awaiting explicit human action).

## r4-template-071-persistence_configuration

- Members: `8`; member-set SHA256: `939db086e6af0f4a8c6fb04d039ff8a379b0b0dc9cf5ebe9cbd76bb4e3b9cb28`
- Strongest cohesion evidence: source action type / OS / telemetry distributions are shown exactly below; no free-text semantics were inferred.
- Strongest structured heterogeneity evidence: `NONE`
- UNKNOWN burden: `24` cells (`0.231` of structured cells)
- Candidate split evidence: `NO_STRUCTURED_SPLIT_EVIDENCE` (`0` candidates)
- Consequence of keeping template: retain the exact member set for explicit human review; all members remain `MANUAL_DESIGN_REQUIRED`.
- Consequence of splitting: only a later explicit human request could define a split; no split is applied by R8.
- Representative authenticated source evidence:
  - `6000015::S06::A002`: action name `Host command line - WMI Persistence`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000015.json#$.pipeline[5].actions[1]`
  - `6000028::S07::A006`: action name `Host Command Line - Add program to Windows startup script for all users`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000028.json#$.pipeline[6].actions[5]`
  - `6000029::S04::A001`: action name `Host Command Line - Benign: Discovering Group Policy via Command Prompt`, type `host_cli`, OS `windows`; source `APT数据集/playbooks/6000029.json#$.pipeline[3].actions[0]`
- Structured field distributions:
  - `source_action_type`: host_cli=8
  - `os_platform`: windows=8
  - `explicit_protocol_service`: ["UNKNOWN"]=8
  - `explicit_required_protocol`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=8
  - `explicit_required_service_class`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=8
  - `service_prerequisites`: ["UNKNOWN"]=8
  - `telemetry_surface_flags`: {"requires_external_service_emulation":"STRUCTURED_EVIDENCE_PRESENT","requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDEN...=8
  - `host_process_file_socket_network_requirements`: {"requires_file_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_host_process_telemetry":"STRUCTURED_EVIDENCE_PRESENT","requires_network_fabric":"STRUCTURED_EVIDENCE_PRESENT",...=8
  - `destructive_state_flag`: UNKNOWN_NOT_DERIVABLE_FROM_AUTHENTICATED_SOURCE=8
  - `reset_safety_complexity`: HIGH=8
  - `environment_blocker`: ["NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION"]=8
  - `source_detail_completeness`: COMPLETE=8
  - `controlled_environment_feasibility`: NO_AUTHENTICATED_CONTROLLED_REPLAY_ENVIRONMENT_OR_ACTION_IMPLEMENTATION=8

Decision: `null` (awaiting explicit human action).

R8_BOUNDARY = EVIDENCE_ONLY_NOT_APPLIED
HUMAN_DECISIONS_CREATED = 0
APPLIED_SPLITS = 0
STATUS_MUTATIONS = 0
STOP = true
