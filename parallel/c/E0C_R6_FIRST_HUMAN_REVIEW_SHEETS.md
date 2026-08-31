# E0C-R6 First Human Review Sheets

First-tranche presentation only. No decision is prefilled; each exact member set remains R3 `MANUAL_DESIGN_REQUIRED`.

### r4-template-120-process_command_execution

- Exact covered raw count: `49`
- Exact member SHA256: `3ceca8928cf0c95f4006ffbf91d677cf3cee9287d7beea4996adfa752703bc33`
- Representative raw keys: `6000003::S03::A001, 6000003::S03::A008, 6000006::S04::A001`
- Archetype / known platform / protocol-service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Source evidence:
  - `6000003::S03::A001` at `APT数据集/playbooks/6000003.json::$.pipeline[2].actions[0]` — `Host command line - Gathering Information Using the Nishang Framework`; exact description: 此验证动作还原了攻击者试图使用 Nishang 后利用框架收集
  - `6000003::S03::A008` at `APT数据集/playbooks/6000003.json::$.pipeline[2].actions[7]` — `Host Command Line - Disable Windows Defender Task`; exact description: 此验证动作还原了攻击者试图禁用 Windows Defender 相关的计划任务。
  - `6000006::S04::A001` at `APT数据集/playbooks/6000006.json::$.pipeline[3].actions[0]` — `Host Command Line - Bypassing Constrained Language Mode Enforcement via Powershell Runspace`; exact description: 此验证动作还原了攻击者试图通过创建 powershell 运行空间来绕过 powershell 受限语言模式强制执行。
- Proposed reusable design contract: `R4 template invariants plus exact source evidence references; no semantic embedding`
- Unresolved UNKNOWN fields: `named_protocols_or_services, service_prerequisites, required_protocol, required_service_class, required_preconditions, cleanup_reset_requirement, defensive_equivalence_requirements, provx_expected_causal_edge_classes, provx_expected_entity_types`
- Unresolved human questions: What exact source-visible semantics must remain equivalent for this raw?; Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?; Which side effects are necessary for the defensive decision point, and which must be excluded?
- Consequences of approval: Human approval would authorize this template candidate for its exact member set as a design decision only; it would not alter R3 MANUAL_DESIGN_REQUIRED status, execute actions, assert PROVX outcomes, or change the denominator.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-136-process_command_execution

- Exact covered raw count: `28`
- Exact member SHA256: `fc076c1fbcef34272b7bb80b611fa0b3a560a940833e960976d45388355d100a`
- Representative raw keys: `6000006::S04::A007, 6000008::S03::A001, 6000009::S11::A001`
- Archetype / known platform / protocol-service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Source evidence:
  - `6000006::S04::A007` at `APT数据集/playbooks/6000006.json::$.pipeline[3].actions[6]` — `Host Command Line - Encoded PowerShell command`; exact description: 此验证动作还原了受害主机上 Powershell 命令“whoami”的编码。在受害者的机器上编码 Powershell 命令是攻击者可以混淆恶意代码以逃避检测的一种方式。

在 Powershell 中对命令进行编码是攻击者利用这些离地策略来执行各种活动（例如执行代码、下载或上传文件、保持持久化等）的一种方式。
  - `6000008::S03::A001` at `APT数据集/playbooks/6000008.json::$.pipeline[2].actions[0]` — `Host Command Line - Get computer system information via PowerShell parameter tricks triggered from the command line`; exact description: 此验证动作还原了攻击者通过从命令行触发的 PowerShell 中的斜杠参数技巧来获取计算机系统信息。
  - `6000009::S11::A001` at `APT数据集/playbooks/6000009.json::$.pipeline[10].actions[0]` — `Host Command Line - Deleting shadow copies via the shadow.bat script`; exact description: 此验证动作还原了卷影副本将通过shadow.bat 脚本删除。
- Proposed reusable design contract: `R4 template invariants plus exact source evidence references; no semantic embedding`
- Unresolved UNKNOWN fields: `named_protocols_or_services, service_prerequisites, required_protocol, required_service_class, required_preconditions, cleanup_reset_requirement, defensive_equivalence_requirements, provx_expected_causal_edge_classes, provx_expected_entity_types`
- Unresolved human questions: What exact source-visible semantics must remain equivalent for this raw?; Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?; Which side effects are necessary for the defensive decision point, and which must be excluded?
- Consequences of approval: Human approval would authorize this template candidate for its exact member set as a design decision only; it would not alter R3 MANUAL_DESIGN_REQUIRED status, execute actions, assert PROVX outcomes, or change the denominator.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-107-process_command_execution

- Exact covered raw count: `27`
- Exact member SHA256: `aeead35be23d0b2f06d1b7085ce3c33e1cdc08c87f92fe9e972eea608809ee0e`
- Representative raw keys: `6000002::S02::A003, 6000002::S07::A001, 6000004::S05::A004`
- Archetype / known platform / protocol-service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Source evidence:
  - `6000002::S02::A003` at `APT数据集/playbooks/6000002.json::$.pipeline[1].actions[2]` — `Host Command Line - Network local groups, user discovery`; exact description: 此验证动作还原了使用“net localgroup”命令查询用户。虽然此验证动作本身并不是恶意的，但此活动与数据泄漏或未经授权的用户执行的活动相结合可能是恶意的。
  - `6000002::S07::A001` at `APT数据集/playbooks/6000002.json::$.pipeline[6].actions[0]` — `Host Command Line - Use Adfind to gather information about the target domain and operating system`; exact description: 此验证动作还原了攻击者使用 Adfind.exe 尝试组合
  - `6000004::S05::A004` at `APT数据集/playbooks/6000004.json::$.pipeline[4].actions[3]` — `Protected Sandbox - Clear Windows Security Event Log, PowerShell`; exact description: 此验证动作还原了一个尝试使用 PowerShell 清除主机上的安全窗口事件日志的攻击者的模拟。在此示例中，-WhatIf 命令用于防止事件日志在生产机器上被意外清除。这将允许基于命令行的检测发出警报，但可能不会触发围绕事件日志的任何基于事件 ID 的检测。
清除 Windows 事件日志可以删除主机上的危害指标。攻击者通常会尝试删除危害指标，以降低检测的可能性并阻碍潜在的事件响应工作。如果没有特定的危害指标，事件响应者可能无法完全确定危害程度，从而使攻击者能够在环境中站稳脚跟。
- Proposed reusable design contract: `R4 template invariants plus exact source evidence references; no semantic embedding`
- Unresolved UNKNOWN fields: `named_protocols_or_services, service_prerequisites, required_protocol, required_service_class, required_preconditions, cleanup_reset_requirement, defensive_equivalence_requirements, provx_expected_causal_edge_classes, provx_expected_entity_types`
- Unresolved human questions: What exact source-visible semantics must remain equivalent for this raw?; Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?; Which side effects are necessary for the defensive decision point, and which must be excluded?
- Consequences of approval: Human approval would authorize this template candidate for its exact member set as a design decision only; it would not alter R3 MANUAL_DESIGN_REQUIRED status, execute actions, assert PROVX outcomes, or change the denominator.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-159-process_command_execution

- Exact covered raw count: `17`
- Exact member SHA256: `e5f22f069e236fde74af499ec46117c82ea2ce067d39b759421f6865cd548439`
- Representative raw keys: `6000007::S11::A002, 6000010::S12::A002, 6000011::S10::A004`
- Archetype / known platform / protocol-service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Source evidence:
  - `6000007::S11::A002` at `APT数据集/playbooks/6000007.json::$.pipeline[10].actions[1]` — `Host command line - Remove local account access via Command Prompt, benign`; exact description: 此验证动作还原了一个验证机器人 利用 Window 的内置实用程序“网络”来更改本地用户的密码以禁止访问。设计此良性实验任务的目的是测试 CLI 操作的执行，这种方式不会使安全产品判断它为恶意。
  - `6000010::S12::A002` at `APT数据集/playbooks/6000010.json::$.pipeline[11].actions[1]` — `Host command line - Remove local account access via Command Prompt, benign`; exact description: 此验证动作还原了一个验证机器人 利用 Window 的内置实用程序“网络”来更改本地用户的密码以禁止访问。设计此良性实验任务的目的是测试 CLI 操作的执行，这种方式不会使安全产品判断它为恶意。
  - `6000011::S10::A004` at `APT数据集/playbooks/6000011.json::$.pipeline[9].actions[3]` — `Host command line - Remove local account access via Command Prompt, benign`; exact description: 此验证动作还原了一个验证机器人 利用 Window 的内置实用程序“网络”来更改本地用户的密码以禁止访问。设计此良性实验任务的目的是测试 CLI 操作的执行，这种方式不会使安全产品判断它为恶意。
- Proposed reusable design contract: `R4 template invariants plus exact source evidence references; no semantic embedding`
- Unresolved UNKNOWN fields: `named_protocols_or_services, service_prerequisites, required_protocol, required_service_class, required_preconditions, cleanup_reset_requirement, defensive_equivalence_requirements, provx_expected_causal_edge_classes, provx_expected_entity_types`
- Unresolved human questions: What exact source-visible semantics must remain equivalent for this raw?; Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?; Which side effects are necessary for the defensive decision point, and which must be excluded?
- Consequences of approval: Human approval would authorize this template candidate for its exact member set as a design decision only; it would not alter R3 MANUAL_DESIGN_REQUIRED status, execute actions, assert PROVX outcomes, or change the denominator.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-130-process_command_execution

- Exact covered raw count: `17`
- Exact member SHA256: `b9e9db68106f21ada95ece8e6158f9954372e9e28b908b1e98d886a679280449`
- Representative raw keys: `6000002::S09::A004, 6000008::S05::A002, 6000009::S07::A005`
- Archetype / known platform / protocol-service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Source evidence:
  - `6000002::S09::A004` at `APT数据集/playbooks/6000002.json::$.pipeline[8].actions[3]` — `Host command line - POWERSPLOIT, Audio Capture, Variant -2`; exact description: 此验证动作还原了如何使用 POWERSPLOIT 的"Get-MicrophoneAudio.ps1"脚本从受感染主机捕获音频。该脚本利用连接的外围设备，允许对手在受害者不知情的情况下记录对话。**如果在机器上找不到录音设备，则不会运行此验证动作。**请注意，此验证动作中使用的"Get-MicrophoneAudio.ps1"脚本已被验证动作清理删除。
  - `6000008::S05::A002` at `APT数据集/playbooks/6000008.json::$.pipeline[4].actions[1]` — `Host command line - Add Windows Defender Exception Path, Variant -2`; exact description: 此验证动作还原了将 Windows Defender 排除项添加到 %USERPROFILE%。该命令禁用 Windows Defender 对此文件夹中文件的计划扫描和实时扫描。
  - `6000009::S07::A005` at `APT数据集/playbooks/6000009.json::$.pipeline[6].actions[4]` — `Host Command Line - Private Key, PowerShell`; exact description: 此验证动作还原了恶意用户或程序如何从受感染主机收集加密密钥。 运行 PowerShell 脚本以搜索各种关键文件，例如 .cer 和 .pgp。 在主机的本地、可移动、光驱或网络驱动器上识别的任何关键文件都将被添加到存档中，以便以后进行渗透。 
- Proposed reusable design contract: `R4 template invariants plus exact source evidence references; no semantic embedding`
- Unresolved UNKNOWN fields: `named_protocols_or_services, service_prerequisites, required_protocol, required_service_class, required_preconditions, cleanup_reset_requirement, defensive_equivalence_requirements, provx_expected_causal_edge_classes, provx_expected_entity_types`
- Unresolved human questions: What exact source-visible semantics must remain equivalent for this raw?; Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?; Which side effects are necessary for the defensive decision point, and which must be excluded?
- Consequences of approval: Human approval would authorize this template candidate for its exact member set as a design decision only; it would not alter R3 MANUAL_DESIGN_REQUIRED status, execute actions, assert PROVX outcomes, or change the denominator.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-152-process_command_execution

- Exact covered raw count: `12`
- Exact member SHA256: `ed38669390f755e5d316080187f6eff0d819475d59c828fa527d0ec66755ce35`
- Representative raw keys: `6000006::S08::A005, 6000008::S05::A008, 6000011::S06::A007`
- Archetype / known platform / protocol-service: `PROCESS_COMMAND_EXECUTION` / `windows` / `UNKNOWN`
- Source evidence:
  - `6000006::S08::A005` at `APT数据集/playbooks/6000006.json::$.pipeline[7].actions[4]` — `Host Command Line - Search WSL Bash History for Credentials`; exact description: 此验证动作还原了用户如何查看以前输入 Windows Linux 子系统的命令的 bash 历史记录。虽然 bash 历史记录有助于普通用户参考，但它也是对手可以利用的东西。例如，如果用户不小心在命令行输入了密码，或者故意将其作为其他命令的参数，则此信息存储在 ~/.bash_history 下。如果历史没有被清除，对手将能够通过查看文件的内容来收集凭据。
  - `6000008::S05::A008` at `APT数据集/playbooks/6000008.json::$.pipeline[4].actions[7]` — `Host Command Line - Search WSL Bash History for Credentials`; exact description: 此验证动作还原了用户如何查看以前输入 Windows Linux 子系统的命令的 bash 历史记录。虽然 bash 历史记录有助于普通用户参考，但它也是对手可以利用的东西。例如，如果用户不小心在命令行输入了密码，或者故意将其作为其他命令的参数，则此信息存储在 ~/.bash_history 下。如果历史没有被清除，对手将能够通过查看文件的内容来收集凭据。
  - `6000011::S06::A007` at `APT数据集/playbooks/6000011.json::$.pipeline[5].actions[6]` — `Host Command Line - Keylogger`; exact description: 此验证动作还原了攻击者在本地计算机上安装键盘记录器。 入侵者使用一种技术在不接触硬盘的情况下加载键盘记录器键（写入输出除外）。 此外，编码用于混淆 PowerShell 命令。 虽然这种技术的优点是很难在本地检测，但它也带来了局限性。 例如，ps1 文件必须通过互联网传输，让防御者有机会识别网络上的脚本。 此外，由于键盘记录器在内存中运行，因此在 PowerShell 会话关闭时其功能将终止。

请注意，此验证动作中安装的键盘记录器在清理过程中会被移除。
- Proposed reusable design contract: `R4 template invariants plus exact source evidence references; no semantic embedding`
- Unresolved UNKNOWN fields: `named_protocols_or_services, service_prerequisites, required_protocol, required_service_class, required_preconditions, cleanup_reset_requirement, defensive_equivalence_requirements, provx_expected_causal_edge_classes, provx_expected_entity_types`
- Unresolved human questions: What exact source-visible semantics must remain equivalent for this raw?; Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?; Which side effects are necessary for the defensive decision point, and which must be excluded?
- Consequences of approval: Human approval would authorize this template candidate for its exact member set as a design decision only; it would not alter R3 MANUAL_DESIGN_REQUIRED status, execute actions, assert PROVX outcomes, or change the denominator.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-069-persistence_configuration

- Exact covered raw count: `10`
- Exact member SHA256: `7347ef4f412bf89b0ee6fad51fe44eabb96c64606d8b7d293b0b656ed8e86b42`
- Representative raw keys: `6000002::S03::A003, 6000002::S06::A002, 6000004::S05::A003`
- Archetype / known platform / protocol-service: `PERSISTENCE_CONFIGURATION` / `windows` / `UNKNOWN`
- Source evidence:
  - `6000002::S03::A003` at `APT数据集/playbooks/6000002.json::$.pipeline[2].actions[2]` — `Host Command Line - Use PowerShell to modify group policy to disable Windows Defender`; exact description: 此验证动作还原了一个对手试图创建一个新的组策略对象来禁用 Windows Defender。组策略对象 (GPO) 是一组可应用于 AD 容器(例如域和组织单位、OU)的设置。这些设置的范围从计划任务到为用户禁用或启用软件。攻击者可能会尝试修改或创建新的 GPO，以在受损环境中建立持久化、规避防御或提升特权。此验证动作需要域绑定主机才能成功执行。此验证动作还需要在主机上安装远程服务器管理工具 (RSAT)：组策略管理工具和 RSAT：AD 域服务和轻型目录服务工具。**警告：**此验证动作将修改组策略以禁用安全工具。尽管有清理步骤来撤消此验证动作创建的更改，但不建议在属于生产或敏感域的成员或有权访问生产域或敏感域的主机上运行此验证动作。>**依赖条件：**验证机器人必须加入域才能正确配置 AD 环境
  - `6000002::S06::A002` at `APT数据集/playbooks/6000002.json::$.pipeline[5].actions[1]` — `Host command line - create persistence via scheduled task named "Classic Sound"`; exact description: 此验证动作还原了将创建一个名为“Classic Sound”的计划任务。此任务尝试执行恶意软件的某些部分。
  - `6000004::S05::A003` at `APT数据集/playbooks/6000004.json::$.pipeline[4].actions[2]` — `Host Command Line - Winlogon Registry Changes`; exact description: 此验证动作还原了一个恶意攻击者更改 Winlogon 注册表项以建立持久化。 Winlogon.exe 在登录/注销时运行操作，并且可以通过将其放置在注册表中来操纵以运行恶意可执行文件、DLL 或脚本。

在此验证动作中，注册表中放置了一个名为“malicious.bat”的bat文件。 当用户使用这些注册表设置登录时，将执行 bat 文件。 Malicious.bat 只是在 C:\Users\Public\Documents 中创建了一个名为 proof.txt 的文本文档，但更多的恶意文件可用于创建后门。
- Proposed reusable design contract: `R4 template invariants plus exact source evidence references; no semantic embedding`
- Unresolved UNKNOWN fields: `named_protocols_or_services, service_prerequisites, required_protocol, required_service_class, required_preconditions, cleanup_reset_requirement, defensive_equivalence_requirements, provx_expected_causal_edge_classes, provx_expected_entity_types`
- Unresolved human questions: What exact source-visible semantics must remain equivalent for this raw?; Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?; Which side effects are necessary for the defensive decision point, and which must be excluded?
- Consequences of approval: Human approval would authorize this template candidate for its exact member set as a design decision only; it would not alter R3 MANUAL_DESIGN_REQUIRED status, execute actions, assert PROVX outcomes, or change the denominator.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-009-credential_store_access

- Exact covered raw count: `9`
- Exact member SHA256: `9ae166dab66173192bbcbcd89bc86757c290e9d8db2d23a0350cd6df890636f4`
- Representative raw keys: `6000003::S06::A004, 6000004::S08::A004, 6000006::S09::A006`
- Archetype / known platform / protocol-service: `CREDENTIAL_STORE_ACCESS` / `windows` / `UNKNOWN`
- Source evidence:
  - `6000003::S06::A004` at `APT数据集/playbooks/6000003.json::$.pipeline[5].actions[3]` — `Host Command Line - Passing Exported Tickets Using Mimikatz`; exact description: 此验证动作还原了攻击者尝试使用 mimikatz 工具在当前会话中传递导出的票证。
  - `6000004::S08::A004` at `APT数据集/playbooks/6000004.json::$.pipeline[7].actions[3]` — `Host Command Line - Passing Exported Tickets Using Mimikatz`; exact description: 此验证动作还原了攻击者尝试使用 mimikatz 工具在当前会话中传递导出的票证。
  - `6000006::S09::A006` at `APT数据集/playbooks/6000006.json::$.pipeline[8].actions[5]` — `Host Command Line - Passing Exported Tickets Using Mimikatz`; exact description: 此验证动作还原了攻击者尝试使用 mimikatz 工具在当前会话中传递导出的票证。
- Proposed reusable design contract: `R4 template invariants plus exact source evidence references; no semantic embedding`
- Unresolved UNKNOWN fields: `named_protocols_or_services, service_prerequisites, required_protocol, required_service_class, required_preconditions, cleanup_reset_requirement, defensive_equivalence_requirements, provx_expected_causal_edge_classes, provx_expected_entity_types`
- Unresolved human questions: What exact source-visible semantics must remain equivalent for this raw?; Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?; Which side effects are necessary for the defensive decision point, and which must be excluded?
- Consequences of approval: Human approval would authorize this template candidate for its exact member set as a design decision only; it would not alter R3 MANUAL_DESIGN_REQUIRED status, execute actions, assert PROVX outcomes, or change the denominator.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-006-credential_store_access

- Exact covered raw count: `9`
- Exact member SHA256: `776cc6ca57d025ad62efeed4d6f55f8a34a6dafe4517cc6a8a388519de3e6e8d`
- Representative raw keys: `6000002::S05::A004, 6000003::S06::A003, 6000027::S08::A005`
- Archetype / known platform / protocol-service: `CREDENTIAL_STORE_ACCESS` / `windows` / `UNKNOWN`
- Source evidence:
  - `6000002::S05::A004` at `APT数据集/playbooks/6000002.json::$.pipeline[4].actions[3]` — `Host command line - MIMIKATZ (2.1.1), Valid Accounts from SAM NTLM Hash Dump, Variant -2`; exact description: 此验证动作还原了攻击者如何使用 Invoke-Mimikatz PowerShell 脚本提取密码。在此验证动作中，"lsadump::sam"模块用于从安全帐户管理器 (SAM) 数据库获取 NTLM 哈希。此信息可用于登录其他帐户或用于 NTLM 哈希传递攻击。MIMIKATZ 是由安全研究员 Benjamin Delpy 开发的 Windows 安全审计工具。MIMIKATZ 可用于窃取密码哈希值并Dump从内存中提取的明文密码。MIMIKATZ 可以Dump来自 LSASS 的凭据以及 Kerberos 密码。Linux 和 Unix 系统将 Kerberos 凭证Dump在缓存文件中，MIMIKATZ 也可以提取该文件。 请注意，此 验证动作中使用的 Invoke-Mimikatz 脚本使用旧版本的 Mimikatz，可能无法在较新的系统(某些版本的 Windows 10 及更高版本)上正常运行。
  - `6000003::S06::A003` at `APT数据集/playbooks/6000003.json::$.pipeline[5].actions[2]` — `Host command line - MIMIKATZ PowerShell, download obfuscated file by appending to JPEG, execute in memory`; exact description: 此验证动作还原了主机尝试下载 MIMIKATZ PowerShell 脚本的变种并从内存中执行示例。通过将脚本附加到合法图像来混淆此示例。 MIMIKATZ 是一个 Windows 安全审计工具。 MIMIKATZ 可用于窃取密码哈希并Dump从内存中提取的明文密码。 MIMIKATZ 可以从 LSASS Dump凭据以及 Kerberos 密码。 Linux 和 Unix 系统将 Kerberos 凭据存储在缓存文件中，MIMIKATZ 也可以提取该文件。
  - `6000027::S08::A005` at `APT数据集/playbooks/6000027.json::$.pipeline[7].actions[4]` — `Host command line - MIMIKATZ (2.1.1), Valid Accounts from SAM NTLM Hash Dump, Variant -2`; exact description: 此验证动作还原了攻击者如何使用 Invoke-Mimikatz PowerShell 脚本提取密码。在此验证动作中，"lsadump::sam"模块用于从安全帐户管理器 (SAM) 数据库获取 NTLM 哈希。此信息可用于登录其他帐户或用于 NTLM 哈希传递攻击。MIMIKATZ 是由安全研究员 Benjamin Delpy 开发的 Windows 安全审计工具。MIMIKATZ 可用于窃取密码哈希值并Dump从内存中提取的明文密码。MIMIKATZ 可以Dump来自 LSASS 的凭据以及 Kerberos 密码。Linux 和 Unix 系统将 Kerberos 凭证Dump在缓存文件中，MIMIKATZ 也可以提取该文件。 请注意，此 验证动作中使用的 Invoke-Mimikatz 脚本使用旧版本的 Mimikatz，可能无法在较新的系统(某些版本的 Windows 10 及更高版本)上正常运行。
- Proposed reusable design contract: `R4 template invariants plus exact source evidence references; no semantic embedding`
- Unresolved UNKNOWN fields: `named_protocols_or_services, service_prerequisites, required_protocol, required_service_class, required_preconditions, cleanup_reset_requirement, defensive_equivalence_requirements, provx_expected_causal_edge_classes, provx_expected_entity_types`
- Unresolved human questions: What exact source-visible semantics must remain equivalent for this raw?; Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?; Which side effects are necessary for the defensive decision point, and which must be excluded?
- Consequences of approval: Human approval would authorize this template candidate for its exact member set as a design decision only; it would not alter R3 MANUAL_DESIGN_REQUIRED status, execute actions, assert PROVX outcomes, or change the denominator.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-048-network_c2_beacon

- Exact covered raw count: `9`
- Exact member SHA256: `f7ea287ecdda9343ad41d24096b9a4ab8a4a567d0f40c0d3b708a384e65c9db4`
- Representative raw keys: `6000011::S02::A004, 6000011::S02::A005, 6000016::S03::A001`
- Archetype / known platform / protocol-service: `NETWORK_C2_BEACON` / `windows` / `DNS, HTTP`
- Source evidence:
  - `6000011::S02::A004` at `APT数据集/playbooks/6000011.json::$.pipeline[1].actions[3]` — `Host command line - Beacon, DNS Beacon A Record, C2 traffic`; exact description: 此验证动作还原了 信标 后门使用 DNS 信标方法与其命令与控制基础设施通信。在此验证动作中，感染了 信标 变种的受感染机器会联系控制器以获取更多命令，以便通过 DNS 在机器上运行。通信和发出的命令在 DNS 请求中进行编码，以隐藏监视工具的任何显着行为。信标 是一个用 C/C++ 编写的后门，它是 Cobalt Strike 框架的一部分。支持的后门命令包括shell命令执行、文件传输、文件执行和文件管理。信标 还可以键盘记录和截屏以及充当代理服务器。信标 还可能负责收集系统凭证、端口扫描和枚举网络上的系统。信标 通过 http 或 DNS 与 C&C 服务器通信。 注意：为了减轻用户面临的任何风险，我们提供了一个选项来输入一个域作为模拟 DNS 信标通信的目标。
  - `6000011::S02::A005` at `APT数据集/playbooks/6000011.json::$.pipeline[1].actions[4]` — `Host Command Line - Beacon, DNS Beacon TXT Record, C2 traffic`; exact description: 此验证动作还原了 信标 后门使用 DNS 信标方法与其命令与控制基础设施通信。在此验证动作中，感染了 信标 变种的受感染机器会联系控制器以获取更多命令，以便通过 DNS 在机器上运行。通信和发出的命令在 DNS 请求中进行编码，以隐藏监视工具的任何显着行为。信标 是一个用 C/C++ 编写的后门，它是 Cobalt Strike 框架的一部分。支持的后门命令包括shell命令执行、文件传输、文件执行和文件管理。信标 还可以键盘记录和截屏以及充当代理服务器。信标 还可能负责收集系统凭证、端口扫描和枚举网络上的系统。信标 通过 http 或 DNS 与 C&C 服务器通信。 注意：为了减轻用户面临的任何风险，我们提供了一个选项来输入一个域作为模拟 DNS 信标通信的目标。
  - `6000016::S03::A001` at `APT数据集/playbooks/6000016.json::$.pipeline[2].actions[0]` — `Host Command Line - Beacon, DNS Beacon TXT Record, C2 traffic`; exact description: 此验证动作还原了 信标 后门使用 DNS 信标方法与其命令与控制基础设施通信。在此验证动作中，感染了 信标 变种的受感染机器会联系控制器以获取更多命令，以便通过 DNS 在机器上运行。通信和发出的命令在 DNS 请求中进行编码，以隐藏监视工具的任何显着行为。信标 是一个用 C/C++ 编写的后门，它是 Cobalt Strike 框架的一部分。支持的后门命令包括shell命令执行、文件传输、文件执行和文件管理。信标 还可以键盘记录和截屏以及充当代理服务器。信标 还可能负责收集系统凭证、端口扫描和枚举网络上的系统。信标 通过 http 或 DNS 与 C&C 服务器通信。 注意：为了减轻用户面临的任何风险，我们提供了一个选项来输入一个域作为模拟 DNS 信标通信的目标。
- Proposed reusable design contract: `R4 template invariants plus exact source evidence references; no semantic embedding`
- Unresolved UNKNOWN fields: `required_protocol, required_service_class, required_preconditions, cleanup_reset_requirement, defensive_equivalence_requirements, provx_expected_causal_edge_classes, provx_expected_entity_types`
- Unresolved human questions: What exact source-visible semantics must remain equivalent for this raw?; Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?; Which side effects are necessary for the defensive decision point, and which must be excluded?
- Consequences of approval: Human approval would authorize this template candidate for its exact member set as a design decision only; it would not alter R3 MANUAL_DESIGN_REQUIRED status, execute actions, assert PROVX outcomes, or change the denominator.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-035-file_resource_operation

- Exact covered raw count: `8`
- Exact member SHA256: `ae5c70bcbce560f3194a63c6336b1021b4a3f947601958b75ae98245331b8a52`
- Representative raw keys: `6000002::S05::A007, 6000004::S04::A010, 6000036::S07::A004`
- Archetype / known platform / protocol-service: `FILE_RESOURCE_OPERATION` / `windows` / `FTP`
- Source evidence:
  - `6000002::S05::A007` at `APT数据集/playbooks/6000002.json::$.pipeline[4].actions[6]` — `Host Command Line - URSNIF, using iexplore.exe to transfer collected data`; exact description: 此验证动作还原了通过 iexplore.exe (Internet Explorer) 泄露数据。"CoCreateInstance" API 函数用于创建 Internet Explorer 的 COM 实例。然后使用"Navigate()"方法向服务器发送数据。已经观察到 URSNIF 的一个变种使用这种技术将收集到的数据发送回其 C&C 服务器。
URSNIF 是一种经过修改的模块化银行恶意软件，具有后门功能。其功能包括拦截和修改浏览器流量、文件下载和上传、建立 SOCKS 代理、系统重启和关闭、系统信息收集和域生成算法 (DGA)。该恶意软件还能够从流行的电子邮件和 FTP 客户端以及浏览器中窃取数据和凭据。还
  - `6000004::S04::A010` at `APT数据集/playbooks/6000004.json::$.pipeline[3].actions[9]` — `Host Command Line - URSNIF, using iexplore.exe to transfer collected data`; exact description: 此验证动作还原了通过 iexplore.exe (Internet Explorer) 泄露数据。"CoCreateInstance" API 函数用于创建 Internet Explorer 的 COM 实例。然后使用"Navigate()"方法向服务器发送数据。已经观察到 URSNIF 的一个变种使用这种技术将收集到的数据发送回其 C&C 服务器。
URSNIF 是一种经过修改的模块化银行恶意软件，具有后门功能。其功能包括拦截和修改浏览器流量、文件下载和上传、建立 SOCKS 代理、系统重启和关闭、系统信息收集和域生成算法 (DGA)。该恶意软件还能够从流行的电子邮件和 FTP 客户端以及浏览器中窃取数据和凭据。还
  - `6000036::S07::A004` at `APT数据集/playbooks/6000036.json::$.pipeline[6].actions[3]` — `Host Command Line - URSNIF, using iexplore.exe to transfer collected data`; exact description: 此验证动作还原了通过 iexplore.exe (Internet Explorer) 泄露数据。"CoCreateInstance" API 函数用于创建 Internet Explorer 的 COM 实例。然后使用"Navigate()"方法向服务器发送数据。已经观察到 URSNIF 的一个变种使用这种技术将收集到的数据发送回其 C&C 服务器。
URSNIF 是一种经过修改的模块化银行恶意软件，具有后门功能。其功能包括拦截和修改浏览器流量、文件下载和上传、建立 SOCKS 代理、系统重启和关闭、系统信息收集和域生成算法 (DGA)。该恶意软件还能够从流行的电子邮件和 FTP 客户端以及浏览器中窃取数据和凭据。还
- Proposed reusable design contract: `R4 template invariants plus exact source evidence references; no semantic embedding`
- Unresolved UNKNOWN fields: `required_protocol, required_service_class, required_preconditions, cleanup_reset_requirement, defensive_equivalence_requirements, provx_expected_causal_edge_classes, provx_expected_entity_types`
- Unresolved human questions: What exact source-visible semantics must remain equivalent for this raw?; Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?; Which side effects are necessary for the defensive decision point, and which must be excluded?
- Consequences of approval: Human approval would authorize this template candidate for its exact member set as a design decision only; it would not alter R3 MANUAL_DESIGN_REQUIRED status, execute actions, assert PROVX outcomes, or change the denominator.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

### r4-template-071-persistence_configuration

- Exact covered raw count: `8`
- Exact member SHA256: `939db086e6af0f4a8c6fb04d039ff8a379b0b0dc9cf5ebe9cbd76bb4e3b9cb28`
- Representative raw keys: `6000015::S06::A002, 6000028::S07::A006, 6000029::S04::A001`
- Archetype / known platform / protocol-service: `PERSISTENCE_CONFIGURATION` / `windows` / `UNKNOWN`
- Source evidence:
  - `6000015::S06::A002` at `APT数据集/playbooks/6000015.json::$.pipeline[5].actions[1]` — `Host command line - WMI Persistence`; exact description: 此验证动作还原了如何使用 WMI 事件过滤器和使用者来设置持久性。当系统正常运行时间在 300 到 400 秒之间或在 15:30:40 时，TURLA 恶意软件使用这些机制运行存储在注册表中的加密 PowerShell 命令。此验证动作还原了该机制使用"echo"命令启动 PowerShell。
  - `6000028::S07::A006` at `APT数据集/playbooks/6000028.json::$.pipeline[6].actions[5]` — `Host Command Line - Add program to Windows startup script for all users`; exact description: 此验证动作还原了将可执行文件添加到 Windows 启动文件夹。 添加到“C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup”的程序或脚本将在任何用户登录 Windows 时自动执行。 恶意攻击者利用此行为作为目标主机上的持久化机制。 如果通过组策略推送到其他系统，也可以利用此行为进行横向移动。
启动添加的程序是calc.exe的合法副本，被验证动作cleanup删除。
  - `6000029::S04::A001` at `APT数据集/playbooks/6000029.json::$.pipeline[3].actions[0]` — `Host Command Line - Benign: Discovering Group Policy via Command Prompt`; exact description: 此验证动作还原了一个验证机器人 利用内置命令提示符“gpresult”实用程序来显示远程用户和计算机的策略结果集 (RSoP) 信息。设计此良性操作的目的是测试 CLI 操作的执行，这种方式不会对安全控制显示为恶意。
- Proposed reusable design contract: `R4 template invariants plus exact source evidence references; no semantic embedding`
- Unresolved UNKNOWN fields: `named_protocols_or_services, service_prerequisites, required_protocol, required_service_class, required_preconditions, cleanup_reset_requirement, defensive_equivalence_requirements, provx_expected_causal_edge_classes, provx_expected_entity_types`
- Unresolved human questions: What exact source-visible semantics must remain equivalent for this raw?; Which inert fixture and telemetry artifacts satisfy the source-supported platform/service requirements?; Which side effects are necessary for the defensive decision point, and which must be excluded?
- Consequences of approval: Human approval would authorize this template candidate for its exact member set as a design decision only; it would not alter R3 MANUAL_DESIGN_REQUIRED status, execute actions, assert PROVX outcomes, or change the denominator.
- Allowed human actions (unselected):
  - `APPROVE_TEMPLATE_FOR_MEMBER_SET`
  - `REJECT_TEMPLATE_KEEP_MEMBERS_MANUAL`
  - `REQUEST_SPLIT_OR_MORE_EVIDENCE`

