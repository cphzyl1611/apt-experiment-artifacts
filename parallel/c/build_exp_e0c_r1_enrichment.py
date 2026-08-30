#!/usr/bin/env python3
"""Build the preparation-only E0C-R1 execution-archetype substrate."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from build_exp_e0_c_readiness import (
    EXPECTED_RAW_COUNT,
    UNKNOWN,
    audit_raw_authority,
    build_readiness_rows,
    canonical_json_hash,
    read_jsonl_strict,
    sha256_file,
)


R1_UNKNOWN = "UNKNOWN"
CURRENT_MATRIX_NAME = "EXP_E0_C_1796_PROVX_REPLAY_READINESS.jsonl"
DEFAULT_CORPUS = Path("/home/cph/experiment/APT数据集/playbooks")
DEFAULT_REGISTRY = Path(
    "/home/cph/experiment-worktrees/full-action-protocol-binding/"
    "data/full_action/raw_action_registry.jsonl"
)

LOCATOR_RE = re.compile(r"^\$\.pipeline\[(\d+)\]\.actions\[(\d+)\]$")
PROTOCOL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("HTTP", re.compile(r"\bHTTP\b", re.IGNORECASE)),
    ("HTTPS", re.compile(r"\bHTTPS\b", re.IGNORECASE)),
    ("DNS", re.compile(r"\bDNS\b", re.IGNORECASE)),
    ("SMB", re.compile(r"\bSMB\b", re.IGNORECASE)),
    ("SSH", re.compile(r"\bSSH\b", re.IGNORECASE)),
    ("RDP", re.compile(r"\bRDP\b", re.IGNORECASE)),
    ("FTP", re.compile(r"\bFTP\b", re.IGNORECASE)),
    ("SFTP", re.compile(r"\bSFTP\b", re.IGNORECASE)),
    ("SMTP", re.compile(r"\bSMTP\b", re.IGNORECASE)),
    ("LDAP", re.compile(r"\bLDAP\b", re.IGNORECASE)),
    ("TCP", re.compile(r"\bTCP\b", re.IGNORECASE)),
    ("UDP", re.compile(r"\bUDP\b", re.IGNORECASE)),
    ("ICMP", re.compile(r"\bICMP\b", re.IGNORECASE)),
    ("WINRM", re.compile(r"\b(?:WINRM|WIN\s*RM)\b", re.IGNORECASE)),
    ("MODBUS", re.compile(r"\bMODBUS(?:/TCP)?\b", re.IGNORECASE)),
    ("MYSQL", re.compile(r"\bMYSQL\b", re.IGNORECASE)),
    ("MSSQL", re.compile(r"\bMSSQL\b", re.IGNORECASE)),
    ("NFS", re.compile(r"\bNFS\b", re.IGNORECASE)),
    ("TLS", re.compile(r"\bTLS\b", re.IGNORECASE)),
)

NETWORK_TYPES = {
    "pcap",
    "socket",
    "dns",
    "port_scan",
    "captive_ioc_url",
    "website",
    "file_transfer",
    "email",
}
MANUAL_DESIGN_RE = re.compile(
    r"(?:malware|ransomware|credential\s+(?:theft|dump|harvest)|password\s+dump|"
    r"mimikatz|keylog|bypass|disable|delete|wipe|format|destructive|exploit|"
    r"remote\s+code\s+execution|\brce\b|sql\s+injection|brute\s+force|"
    r"任意文件|恶意|提权|绕过|禁用|删除|凭证|密码)",
    re.IGNORECASE,
)
PRIVILEGE_RE = re.compile(
    r"(?:privilege|privileged|administrator|admin|root|uac|elevation|escalat|"
    r"sudo|fodhelper|cmstplua|group\s+policy|提权|管理员|权限)",
    re.IGNORECASE,
)
CREDENTIAL_RE = re.compile(
    r"(?:credential|password|hash|browser\s+cookie|cookie|keylog|mimikatz|"
    r"credential\s+store|凭证|密码|哈希|浏览器)",
    re.IGNORECASE,
)
PERSISTENCE_RE = re.compile(
    r"(?:registry|service|scheduled\s+task|scheduled|startup|autorun|cron|"
    r"group\s+policy|persistence|注册表|服务|计划任务|启动项)",
    re.IGNORECASE,
)
ARCHIVE_RE = re.compile(r"(?:archive|compress|zip|rar|7z|tar|压缩|归档)", re.IGNORECASE)
DISCOVERY_RE = re.compile(
    r"(?:discover|discovery|enumerat|enumeration|list|query|collect|check|show|"
    r"display|scan|whoami|nltest|wmic|net\s+localgroup|information|recon|侦察|枚举|查询)",
    re.IGNORECASE,
)
FILE_RE = re.compile(
    r"(?:file|read|write|create|delete|download|upload|transfer|drop|loader|"
    r"document|attachment|文件|读取|写入|创建|删除|下载|上传)",
    re.IGNORECASE,
)
NETWORK_RE = re.compile(
    r"(?:c2|c&c|beacon|check.?in|heartbeat|connect|connection|reverse\s+shell|"
    r"download|upload|exfil|ftp|http|https|dns|smb|ssh|rdp|smtp|socket|scan|"
    r"网络|连接|通信)",
    re.IGNORECASE,
)
COMMAND_RE = re.compile(
    r"(?:command|command\s+line|shell|powershell|\bcmd\b|\bbash\b|execute|execution|"
    r"run|script|process|命令|执行|脚本)",
    re.IGNORECASE,
)
TOOL_WORD_RE = re.compile(
    r"(?:using|contains?|containing|with|tool|malware|trojan|backdoor|loader|dropper|"
    r"rat|使用|包含)",
    re.IGNORECASE,
)


def _json_text(value: Any) -> str:
    return "" if value is None else str(value)


def load_current_readiness(path: Path) -> list[dict[str, Any]]:
    rows, errors = read_jsonl_strict(path)
    if errors:
        raise ValueError("current E0-C readiness matrix parse errors: " + "; ".join(errors))
    if len(rows) != EXPECTED_RAW_COUNT:
        raise ValueError(f"current E0-C readiness matrix has {len(rows)} rows, expected 1796")
    keys = [str(row.get("raw_key") or "") for row in rows]
    if len(set(keys)) != EXPECTED_RAW_COUNT:
        raise ValueError("current E0-C readiness matrix has duplicate or missing raw keys")
    if any(row.get("formal_execution_authorized") is not False for row in rows):
        raise ValueError("current E0-C readiness matrix contains an authorized row")
    return rows


def _load_action_context(
    playbooks_root: Path, source_rows: Iterable[Mapping[str, Any]]
) -> dict[str, dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}
    for source in source_rows:
        source_file = str(source["source_file"])
        filename = Path(source_file).name
        if filename not in documents:
            with (playbooks_root / filename).open("r", encoding="utf-8-sig") as handle:
                documents[filename] = json.load(handle)

    contexts: dict[str, dict[str, Any]] = {}
    for source in source_rows:
        match = LOCATOR_RE.fullmatch(str(source["source_locator"]))
        if match is None:
            raise ValueError(f"invalid source locator for {source['raw_action_key']}")
        stage_index, action_index = (int(value) for value in match.groups())
        filename = Path(str(source["source_file"])).name
        document = documents[filename]
        stage = document["pipeline"][stage_index]
        action = stage["actions"][action_index]
        if not isinstance(action, Mapping):
            raise ValueError(f"source action is not an object for {source['raw_action_key']}")
        contexts[str(source["raw_action_key"])] = {
            "document": document,
            "stage": stage,
            "action": action,
            "locator": str(source["source_locator"]),
        }
    return contexts


def _evidence(
    source_path: str, source_value: Any, rule_id: str
) -> dict[str, Any]:
    return {
        "source_field_path": source_path,
        "exact_source_value": source_value,
        "derivation_rule_id": rule_id,
    }


def _add_provenance(
    provenance: dict[str, list[dict[str, Any]]],
    field: str,
    source_path: str,
    source_value: Any,
    rule_id: str,
) -> None:
    provenance.setdefault(field, []).append(_evidence(source_path, source_value, rule_id))


def _text_fields(action: Mapping[str, Any], locator: str) -> list[tuple[str, str]]:
    return [
        (f"{locator}.name", _json_text(action.get("name"))),
        (f"{locator}.desc", _json_text(action.get("desc"))),
    ]


def _combined_text(action: Mapping[str, Any]) -> str:
    return " ".join((_json_text(action.get("name")), _json_text(action.get("desc"))))


def _named_protocols(
    action: Mapping[str, Any], locator: str, provenance: dict[str, list[dict[str, Any]]]
) -> list[str]:
    found: list[str] = []
    for source_path, text in _text_fields(action, locator):
        for canonical, pattern in PROTOCOL_PATTERNS:
            if pattern.search(text) and canonical not in found:
                found.append(canonical)
                _add_provenance(
                    provenance,
                    "named_protocols_or_services",
                    source_path,
                    text,
                    "R1-NAMED-PROTOCOL-TOKEN",
                )
    args = action.get("args")
    if isinstance(args, Mapping):
        structured: list[tuple[str, Any, str]] = []
        if _json_text(args.get("is_http")).lower() in {"true", "1", "yes"}:
            structured.append((f"{locator}.is_http", args.get("is_http"), "HTTP"))
        if _json_text(action.get("is_http")).lower() in {"true", "1", "yes"}:
            structured.append((f"{locator}.is_http", action.get("is_http"), "HTTP"))
        if _json_text(args.get("use_https_connection")).lower() in {"true", "1", "yes"}:
            structured.append((f"{locator}.args.use_https_connection", args.get("use_https_connection"), "HTTPS"))
        for container_name in ("transfer", "tunnel"):
            container = args.get(container_name)
            if isinstance(container, Mapping):
                protocol = _json_text(container.get("protocol")).strip().upper()
                canonical = {"HTTP": "HTTP", "HTTPS": "HTTPS", "DNS": "DNS", "FTP": "FTP", "SFTP": "SFTP", "TCP": "TCP", "UDP": "UDP", "ICMP": "ICMP"}.get(protocol)
                if canonical:
                    structured.append((f"{locator}.args.{container_name}.protocol", container.get("protocol"), canonical))
        for source_path, source_value, canonical in structured:
            if canonical not in found:
                found.append(canonical)
            _add_provenance(
                provenance,
                "named_protocols_or_services",
                source_path,
                source_value,
                "R1-NAMED-PROTOCOL-STRUCTURED-FIELD",
            )
    return sorted(found)


def _explicit_tools(
    action: Mapping[str, Any], locator: str, provenance: dict[str, list[dict[str, Any]]]
) -> list[str]:
    """Extract software only where the action name supplies an explicit marker."""
    names: list[str] = []
    source_path = f"{locator}.name"
    name = _json_text(action.get("name"))
    patterns = (
        re.compile(r"\b([A-Z][A-Za-z0-9_.-]{2,})\s+(?:Tool|RAT|Malware|Backdoor|Loader|Dropper)\b"),
        re.compile(r"\b(?:using|with|contains?)\s+([A-Z][A-Za-z0-9_.-]{2,})\b", re.IGNORECASE),
    )
    for pattern in patterns:
        for match in pattern.finditer(name):
            token = match.group(1)
            if token.upper() in {"THE", "AND", "WITH", "USING", "TOOL", "MALWARE", "RAT", "CVE"}:
                continue
            if token not in names:
                names.append(token)
                _add_provenance(
                    provenance,
                    "explicit_tool_or_malware_names",
                    source_path,
                    name,
                    "R1-EXPLICIT-NAMED-SOFTWARE-MARKER",
                )
    return sorted(names)


def _resource_classes(action_type: str, name: str) -> list[str]:
    values: list[str] = []
    if action_type == "host_cli":
        values.append("PROCESS")
    if action_type == "file_transfer" or (action_type == "host_cli" and re.search(r"\b(?:file|read|write|create|delete|download|upload|transfer)\b", name, re.IGNORECASE)):
        values.append("FILE")
    if action_type == "email":
        values.append("EMAIL")
    if action_type == "host_cli" and re.search(r"\b(?:credential|password|hash|cookie|keylog|mimikatz)\b", name, re.IGNORECASE):
        values.append("CREDENTIAL")
    if action_type == "host_cli" and re.search(r"\b(?:registry|scheduled\s+task|cron|startup|autorun|persistence|service)\b", name, re.IGNORECASE):
        values.append("CONFIGURATION")
    if action_type in NETWORK_TYPES or (action_type == "host_cli" and re.search(r"\b(?:c2|c&c|beacon|heartbeat|connect|connection|reverse\s+shell|ftp|http|https|dns|smb|ssh|rdp|smtp|socket)\b", name, re.IGNORECASE)):
        values.append("NETWORK")
    if action_type == "host_cli" and re.search(r"\b(?:database|mysql|mssql|sql)\b", name, re.IGNORECASE):
        values.append("DATABASE")
    if action_type == "host_cli" and re.search(r"\b(?:archive|compress|zip|rar|7z|tar)\b", name, re.IGNORECASE):
        values.append("ARCHIVE")
    return sorted(set(values)) or [R1_UNKNOWN]


def _primary_archetype(action_type: str, name: str) -> tuple[str, str]:
    if action_type == "host_cli":
        if re.search(r"\b(?:credential|password|hash|cookie|keylog|mimikatz)\b", name, re.IGNORECASE):
            return "CREDENTIAL_STORE_ACCESS", "R1-ARCHETYPE-HOST-CREDENTIAL-LEXEME"
        if re.search(r"\b(?:registry|scheduled\s+task|cron|startup|autorun|persistence|group\s+policy)\b", name, re.IGNORECASE):
            return "PERSISTENCE_CONFIGURATION", "R1-ARCHETYPE-HOST-PERSISTENCE-LEXEME"
        if re.search(r"\b(?:privilege|administrator|admin|root|uac|elevation|escalat|sudo|fodhelper|cmstplua)\b", name, re.IGNORECASE):
            return "PRIVILEGE_ACCOUNT_ACTION", "R1-ARCHETYPE-HOST-PRIVILEGE-LEXEME"
        if re.search(r"\b(?:archive|compress|zip|rar|7z|tar)\b", name, re.IGNORECASE):
            return "ARCHIVE_COMPRESSION", "R1-ARCHETYPE-HOST-ARCHIVE-LEXEME"
        # A host command explicitly combining C2/network interaction with a
        # command must retain the network execution surface as its primary
        # archetype, even when the wording also mentions a file.
        if re.search(r"\b(?:c2|c&c|beacon|heartbeat|connect|connection|reverse\s+shell|ftp|http|https|dns|smb|ssh|rdp|smtp|socket)\b", name, re.IGNORECASE):
            return "NETWORK_C2_BEACON", "R1-ARCHETYPE-HOST-NETWORK-LEXEME"
        if re.search(r"\b(?:file|read|write|create|delete|download|upload|transfer)\b", name, re.IGNORECASE) and not re.search(r"\b(?:discover|enumerat|list|query|scan|whoami|nltest|wmic)\b", name, re.IGNORECASE):
            return "FILE_RESOURCE_OPERATION", "R1-ARCHETYPE-HOST-FILE-LEXEME"
        if re.search(r"\b(?:discover|enumerat|list|query|scan|whoami|nltest|wmic)\b", name, re.IGNORECASE):
            return "DISCOVERY_ENUMERATION", "R1-ARCHETYPE-HOST-DISCOVERY-LEXEME"
        if re.search(r"\b(?:c2|c&c|beacon|heartbeat|connect|connection|reverse\s+shell|ftp|http|https|dns|smb|ssh|rdp|smtp|socket)\b", name, re.IGNORECASE):
            return "NETWORK_C2_BEACON", "R1-ARCHETYPE-HOST-NETWORK-LEXEME"
        if re.search(r"(?:command|command\s+line|shell|powershell|\bcmd\b|\bbash\b|execute|run|script)", name, re.IGNORECASE):
            return "PROCESS_COMMAND_EXECUTION", "R1-ARCHETYPE-HOST-COMMAND-LEXEME"
        return "PROCESS_COMMAND_EXECUTION", "R1-ARCHETYPE-HOST-ACTION-TYPE"
    if action_type == "file_transfer":
        return "TRANSFER_DOWNLOAD_UPLOAD", "R1-ARCHETYPE-ACTION-TYPE-FILE-TRANSFER"
    if action_type == "email":
        return "EMAIL_DELIVERY", "R1-ARCHETYPE-ACTION-TYPE-EMAIL"
    if action_type == "dns":
        return "DNS_INTERACTION", "R1-ARCHETYPE-ACTION-TYPE-DNS"
    if action_type == "port_scan":
        return "NETWORK_SCAN_ENUMERATION", "R1-ARCHETYPE-ACTION-TYPE-PORT-SCAN"
    if action_type == "captive_ioc_url":
        return "NETWORK_C2_BEACON", "R1-ARCHETYPE-ACTION-TYPE-CAPTURED-IOC"
    if action_type == "socket":
        if re.search(r"(?:c2|c&c|beacon|check.?in|heartbeat|reverse\s+shell)", name, re.IGNORECASE):
            return "NETWORK_C2_BEACON", "R1-ARCHETYPE-SOCKET-NETWORK-LEXEME"
        return "NETWORK_SERVICE_INTERACTION", "R1-ARCHETYPE-ACTION-TYPE-SOCKET"
    if action_type == "website":
        return "NETWORK_SERVICE_INTERACTION", "R1-ARCHETYPE-ACTION-TYPE-WEBSITE"
    if action_type == "pcap":
        if re.search(r"\b(?:scanning|scan)\s+(?:activity|campaign|common|random|well-known|database|port)", name, re.IGNORECASE):
            return "NETWORK_SCAN_ENUMERATION", "R1-ARCHETYPE-PCAP-SCAN-LEXEME"
        if re.search(r"\bDNS\s+Query\b", name, re.IGNORECASE):
            return "DNS_INTERACTION", "R1-ARCHETYPE-PCAP-DNS-LEXEME"
        if re.search(r"(?:c2|c&c|beacon|check.?in|heartbeat|reverse\s+shell)", name, re.IGNORECASE):
            return "NETWORK_C2_BEACON", "R1-ARCHETYPE-PCAP-C2-LEXEME"
        return "NETWORK_SERVICE_INTERACTION", "R1-ARCHETYPE-ACTION-TYPE-PCAP"
    return "UNSUPPORTED_UNKNOWN", "R1-ARCHETYPE-UNSUPPORTED-ACTION-TYPE"


def _behavior_scope(action_type: str, name: str) -> tuple[str, str]:
    if action_type == "host_cli":
        if re.search(r"\b(?:c2|c&c|beacon|heartbeat|connect|connection|reverse\s+shell|ftp|http|https|dns|smb|ssh|rdp|smtp|socket)\b", name, re.IGNORECASE) and re.search(r"(?:command|shell|powershell|\bcmd\b|\bbash\b|execute|run|script)", name, re.IGNORECASE):
            return "MIXED_HOST_AND_NETWORK", "R1-BEHAVIOR-HOST-NETWORK-LEXEME"
        return "HOST_LOCAL", "R1-BEHAVIOR-HOST-ACTION-TYPE"
    if action_type in NETWORK_TYPES or re.search(r"\b(?:c2|c&c|beacon|heartbeat|connect|connection|reverse\s+shell|ftp|http|https|dns|smb|ssh|rdp|smtp|socket)\b", name, re.IGNORECASE):
        return "NETWORK_INTERACTION", "R1-BEHAVIOR-NETWORK-ACTION-TYPE"
    return R1_UNKNOWN, "R1-BEHAVIOR-UNSUPPORTED-ACTION-TYPE"


def _candidate_mode(
    action_type: str, text: str
) -> tuple[str, str, list[str], list[str], str]:
    manual_match = MANUAL_DESIGN_RE.search(text)
    if action_type == "host_cli" and manual_match:
        return (
            "REQUIRES_MANUAL_DESIGN",
            f"Source action_type=host_cli and source wording matched safety marker '{manual_match.group(0)}'.",
            [
                "Complete manual safety review before any controlled stimulus design.",
                "Use inert markers and never disable controls or execute real malware.",
            ],
            [
                "Define host process/file/socket telemetry equivalence from an approved design.",
                "Capture reset evidence without retaining secrets or destructive state.",
            ],
            "R1-CANDIDATE-MANUAL-SAFETY-MARKER",
        )
    if action_type == "host_cli":
        return (
            "NATIVE_CANDIDATE",
            "Source action_type=host_cli supports a native local-command design candidate; execution remains unauthorized.",
            [
                "Use a benign local command or inert marker with equivalent command semantics.",
                "Keep the host isolated and preserve PROVX telemetry collection configuration.",
            ],
            [
                "Capture process creation and command-line telemetry where available.",
                "Record cleanup/reset evidence for every repetition.",
            ],
            "R1-CANDIDATE-HOST-CLI-NATIVE",
        )
    if action_type in {"website", "pcap", "socket", "dns", "port_scan", "captive_ioc_url"}:
        return (
            "EMULATED_CANDIDATE",
            f"Source action_type={action_type} indicates a network or service stimulus suitable for a local isolated emulator candidate.",
            [
                "Use only Mininet-connected dummy services or offline packet fixtures.",
                "Do not target public systems, external C2, or real vulnerable services.",
            ],
            [
                "Capture packet/socket/service telemetry and preserve timing/sequence requirements.",
                "Keep host provenance and PROVX localization unclaimed until observed.",
            ],
            "R1-CANDIDATE-NETWORK-EMULATED",
        )
    if action_type in {"file_transfer", "email"}:
        return (
            "SYNTHETIC_CANDIDATE",
            f"Source action_type={action_type} supports an inert synthetic artifact/message candidate without executing payloads.",
            [
                "Use dummy files, messages, and markers only; never execute malware or real attachments.",
                "Preserve the source-visible transfer/message shape and isolate all recipients/targets.",
            ],
            [
                "Capture file/message and network metadata needed to compare defensive telemetry.",
                "Record cleanup/reset evidence for generated artifacts.",
            ],
            "R1-CANDIDATE-INERT-SYNTHETIC-ARTIFACT",
        )
    return (
        R1_UNKNOWN,
        "No supported source action_type rule establishes a design candidate.",
        [],
        [],
        "R1-CANDIDATE-UNKNOWN-ACTION-TYPE",
    )


def _planning_flags(
    action_type: str, source_os: str, name: str
) -> tuple[dict[str, bool], dict[str, str]]:
    network_name = re.search(r"\b(?:c2|c&c|beacon|heartbeat|connect|connection|reverse\s+shell|ftp|http|https|dns|smb|ssh|rdp|smtp|socket)\b", name, re.IGNORECASE)
    file_name = re.search(r"\b(?:file|read|write|create|delete|download|upload|transfer)\b", name, re.IGNORECASE)
    service_name = re.search(r"\b(?:service|server|rdp|ssh|smb|ftp|http|https|dns)\b", name, re.IGNORECASE)
    privileged = bool(re.search(r"\b(?:privilege|administrator|admin|root|uac|elevation|escalat|sudo|fodhelper|cmstplua)\b", name, re.IGNORECASE))
    network = action_type in NETWORK_TYPES or bool(network_name)
    host_process = action_type == "host_cli"
    file = action_type in {"file_transfer", "email"} or bool(file_name)
    socket = action_type in {"pcap", "socket", "dns", "port_scan", "captive_ioc_url"} or bool(network_name)
    service = action_type == "website" or bool(service_name)
    values = {
        "requires_network_fabric": network,
        "requires_host_process_telemetry": host_process,
        "requires_file_telemetry": file,
        "requires_socket_telemetry": socket,
        "requires_external_service_emulation": service,
        "requires_windows_semantics": source_os.lower() == "windows",
        "requires_linux_semantics": source_os.lower() == "linux",
        "requires_privileged_host_action": privileged,
    }
    return values, {
        "network": "R1-FLAG-NETWORK-ACTION-TYPE-OR-LEXEME",
        "host_process": "R1-FLAG-PROCESS-ACTION-TYPE-OR-LEXEME",
        "file": "R1-FLAG-FILE-ACTION-TYPE-OR-LEXEME",
        "socket": "R1-FLAG-SOCKET-ACTION-TYPE-OR-LEXEME",
        "service": "R1-FLAG-SERVICE-ACTION-TYPE",
        "windows": "R1-FLAG-OS-EXPLICIT",
        "linux": "R1-FLAG-OS-EXPLICIT",
        "privileged": "R1-FLAG-PRIVILEGE-LEXEME",
    }


def _observation_surface(
    action_type: str, flags: Mapping[str, bool], resources: list[str]
) -> list[str]:
    surface: list[str] = []
    if flags["requires_host_process_telemetry"]:
        surface.append("PROCESS")
    if flags["requires_file_telemetry"]:
        surface.append("FILE")
    if action_type == "socket":
        surface.append("SOCKET")
    if action_type == "email":
        surface.append("OTHER_EMAIL_MESSAGE")
    if action_type in {"website", "dns", "pcap", "port_scan", "captive_ioc_url"}:
        surface.append("OTHER_NETWORK_METADATA_ONLY")
    if not surface and resources != [R1_UNKNOWN]:
        surface.append("OTHER")
    return sorted(set(surface)) or [R1_UNKNOWN]


def _service_prerequisites(action_type: str, protocols: list[str]) -> list[str]:
    values = list(protocols)
    if action_type == "website":
        values.append("WEB_APPLICATION_SERVICE")
    if action_type == "email":
        values.append("EMAIL_SERVICE")
    return sorted(set(values)) or [R1_UNKNOWN]


def _enrich_one(source: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, Any]:
    action = context["action"]
    locator = str(source["source_locator"])
    action_type = _json_text(action.get("action_type"))
    source_os = _json_text(action.get("os"))
    name = _json_text(action.get("name"))
    text = _combined_text(action)
    provenance: dict[str, list[dict[str, Any]]] = {}

    protocols = _named_protocols(action, locator, provenance)
    service_prerequisites = _service_prerequisites(action_type, protocols)
    if service_prerequisites != [R1_UNKNOWN]:
        protocol_evidence = provenance.get("named_protocols_or_services", [])
        for prerequisite in service_prerequisites:
            if prerequisite in protocols:
                matching_evidence = [
                    item
                    for item in protocol_evidence
                    if prerequisite in _json_text(item.get("exact_source_value")).upper()
                    or prerequisite in item.get("source_field_path", "").upper()
                ]
                for item in matching_evidence or protocol_evidence:
                    _add_provenance(
                        provenance,
                        "service_prerequisites",
                        item["source_field_path"],
                        item["exact_source_value"],
                        "R1-SERVICE-PREREQUISITE-PROTOCOL",
                    )
            else:
                _add_provenance(
                    provenance,
                    "service_prerequisites",
                    f"{locator}.action_type",
                    action_type,
                    "R1-SERVICE-PREREQUISITE-ACTION-TYPE",
                )
    tools = _explicit_tools(action, locator, provenance)
    resources = _resource_classes(action_type, name)
    if resources != [R1_UNKNOWN]:
        _add_provenance(
            provenance,
            "resource_classes",
            f"{locator}.action_type",
            action_type,
            "R1-RESOURCE-ACTION-TYPE-OR-LEXEME",
        )
        _add_provenance(
            provenance,
            "resource_classes",
            f"{locator}.name",
            _json_text(action.get("name")),
            "R1-RESOURCE-ACTION-TYPE-OR-LEXEME",
        )

    primary, primary_rule = _primary_archetype(action_type, name)
    if primary != R1_UNKNOWN:
        _add_provenance(
            provenance,
            "primary_execution_archetype",
            f"{locator}.action_type",
            action_type,
            primary_rule,
        )
        _add_provenance(
            provenance,
            "primary_execution_archetype",
            f"{locator}.name",
            _json_text(action.get("name")),
            primary_rule,
        )

    scope, scope_rule = _behavior_scope(action_type, name)
    if scope != R1_UNKNOWN:
        _add_provenance(
            provenance,
            "behavior_scope",
            f"{locator}.action_type",
            action_type,
            scope_rule,
        )

    flags, flag_rules = _planning_flags(action_type, source_os, name)
    if source_os:
        _add_provenance(
            provenance,
            "os_platform_hints",
            f"{locator}.os",
            source_os,
            "R1-OS-EXPLICIT-SOURCE-FIELD",
        )
    for field, value in flags.items():
        source_field = f"{locator}.os" if field in {"requires_windows_semantics", "requires_linux_semantics"} else f"{locator}.action_type"
        source_value = source_os if source_field.endswith(".os") else action_type
        if field in {"requires_network_fabric", "requires_file_telemetry", "requires_socket_telemetry", "requires_external_service_emulation"} and source_field.endswith(".action_type"):
            lexical_support = {
                "requires_network_fabric": re.search(r"\b(?:c2|c&c|beacon|heartbeat|connect|connection|reverse\s+shell|ftp|http|https|dns|smb|ssh|rdp|smtp|socket)\b", name, re.IGNORECASE),
                "requires_file_telemetry": re.search(r"\b(?:file|read|write|create|delete|download|upload|transfer)\b", name, re.IGNORECASE),
                "requires_socket_telemetry": re.search(r"\b(?:c2|c&c|beacon|heartbeat|connect|connection|reverse\s+shell|ftp|http|https|dns|smb|ssh|rdp|smtp|socket)\b", name, re.IGNORECASE),
                "requires_external_service_emulation": re.search(r"\b(?:service|server|rdp|ssh|smb|ftp|http|https|dns)\b", name, re.IGNORECASE),
            }[field]
            if lexical_support:
                source_field = f"{locator}.name"
                source_value = name
        rule_key = {
            "requires_network_fabric": "network",
            "requires_host_process_telemetry": "host_process",
            "requires_file_telemetry": "file",
            "requires_socket_telemetry": "socket",
            "requires_external_service_emulation": "service",
            "requires_windows_semantics": "windows",
            "requires_linux_semantics": "linux",
            "requires_privileged_host_action": "privileged",
        }[field]
        _add_provenance(provenance, field, source_field, source_value, flag_rules[rule_key])
        if field == "requires_privileged_host_action" and value:
            _add_provenance(
                provenance,
                field,
                f"{locator}.name",
                name,
                flag_rules[rule_key],
            )

    secondary: list[str] = []
    for field, tag in (
        ("requires_network_fabric", "NETWORK_FABRIC"),
        ("requires_host_process_telemetry", "HOST_PROCESS_TELEMETRY"),
        ("requires_file_telemetry", "FILE_TELEMETRY"),
        ("requires_socket_telemetry", "SOCKET_TELEMETRY"),
        ("requires_external_service_emulation", "EXTERNAL_SERVICE_EMULATION"),
        ("requires_windows_semantics", "WINDOWS_SEMANTICS"),
        ("requires_linux_semantics", "LINUX_SEMANTICS"),
        ("requires_privileged_host_action", "PRIVILEGED_HOST_ACTION"),
    ):
        if flags[field]:
            secondary.append(tag)
            _add_provenance(
                provenance,
                "secondary_prerequisite_tags",
                f"{locator}.action_type" if "semantics" not in tag else f"{locator}.os",
                action_type if "semantics" not in tag else source_os,
                "R1-SECONDARY-TAG-FROM-PLANNING-FLAG",
            )
    for protocol in protocols:
        tag = f"EXPLICIT_SERVICE_OR_PROTOCOL:{protocol}"
        secondary.append(tag)
        protocol_evidence = provenance.get("named_protocols_or_services", [])
        matching_evidence = [
            item
            for item in protocol_evidence
            if protocol in _json_text(item.get("exact_source_value")).upper()
            or protocol in item.get("source_field_path", "").upper()
        ]
        if not matching_evidence:
            matching_evidence = protocol_evidence
        for item in matching_evidence:
            provenance.setdefault("secondary_prerequisite_tags", []).append(
                {
                    "source_field_path": item["source_field_path"],
                    "exact_source_value": item["exact_source_value"],
                    "derivation_rule_id": "R1-SECONDARY-TAG-EXPLICIT-PROTOCOL",
                }
            )

    mode, rationale, defensive, telemetry, mode_rule = _candidate_mode(action_type, text)
    if mode != R1_UNKNOWN:
        _add_provenance(
            provenance,
            "candidate_execution_mode_for_design",
            f"{locator}.action_type",
            action_type,
            mode_rule,
        )
        _add_provenance(
            provenance,
            "candidate_execution_mode_for_design",
            f"{locator}.name",
            _json_text(action.get("name")),
            mode_rule,
        )
        if mode == "REQUIRES_MANUAL_DESIGN" and MANUAL_DESIGN_RE.search(_json_text(action.get("desc"))):
            _add_provenance(
                provenance,
                "candidate_execution_mode_for_design",
                f"{locator}.desc",
                _json_text(action.get("desc")),
                mode_rule,
            )
        _add_provenance(
            provenance,
            "candidate_execution_rationale",
            f"{locator}.action_type",
            action_type,
            mode_rule,
        )
        if mode == "REQUIRES_MANUAL_DESIGN" and MANUAL_DESIGN_RE.search(_json_text(action.get("desc"))):
            _add_provenance(
                provenance,
                "candidate_execution_rationale",
                f"{locator}.desc",
                _json_text(action.get("desc")),
                mode_rule,
            )
        _add_provenance(
            provenance,
            "defensive_equivalence_constraints",
            f"{locator}.action_type",
            action_type,
            mode_rule,
        )
        if mode == "REQUIRES_MANUAL_DESIGN" and MANUAL_DESIGN_RE.search(_json_text(action.get("desc"))):
            _add_provenance(
                provenance,
                "defensive_equivalence_constraints",
                f"{locator}.desc",
                _json_text(action.get("desc")),
                mode_rule,
            )
        _add_provenance(
            provenance,
            "telemetry_equivalence_constraints",
            f"{locator}.action_type",
            action_type,
            mode_rule,
        )
        if mode == "REQUIRES_MANUAL_DESIGN" and MANUAL_DESIGN_RE.search(_json_text(action.get("desc"))):
            _add_provenance(
                provenance,
                "telemetry_equivalence_constraints",
                f"{locator}.desc",
                _json_text(action.get("desc")),
                mode_rule,
            )

    surface = _observation_surface(action_type, flags, resources)
    if surface != [R1_UNKNOWN]:
        _add_provenance(
            provenance,
            "provx_candidate_observation_surface",
            f"{locator}.action_type",
            action_type,
            "R1-PROVX-CANDIDATE-SURFACE-FROM-SOURCE-TYPE",
        )

    values = {
        "os_platform_hints": [source_os] if source_os else [R1_UNKNOWN],
        "explicit_tool_or_malware_names": tools or [R1_UNKNOWN],
        "named_protocols_or_services": protocols or [R1_UNKNOWN],
        "service_prerequisites": service_prerequisites,
        "behavior_scope": scope,
        "resource_classes": resources,
        "primary_execution_archetype": primary,
        "secondary_prerequisite_tags": sorted(set(secondary)) or [R1_UNKNOWN],
        **flags,
        "provx_candidate_observation_surface": surface,
        "candidate_execution_mode_for_design": mode,
        "candidate_execution_rationale": rationale if mode != R1_UNKNOWN else R1_UNKNOWN,
        "defensive_equivalence_constraints": defensive or [R1_UNKNOWN],
        "telemetry_equivalence_constraints": telemetry or [R1_UNKNOWN],
        "planning_field_provenance": provenance,
    }
    return values


def _reference_artifacts() -> list[dict[str, Any]]:
    candidates = [
        Path("/home/cph/experiment/data/feasibility/feasibility_labels.csv"),
        Path("/home/cph/experiment/data/run_plans/run_plan.csv"),
        Path("/home/cph/experiment/data/run_plans/run_plan_summary.md"),
        Path("/home/cph/experiment/data/reports/environment_requirements.csv"),
    ]
    metadata: list[dict[str, Any]] = []
    for path in candidates:
        if not path.is_file():
            continue
        row_count = None
        if path.suffix.lower() == ".csv":
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                row_count = max(sum(1 for _ in handle) - 1, 0)
        metadata.append(
            {
                "path": str(path),
                "sha256": sha256_file(path),
                "row_count_excluding_header": row_count,
                "status": "REFERENCE_ONLY_NOT_CURRENT_AUTHORITY",
            }
        )
    return metadata


def build_r1_enrichment(
    audit: Mapping[str, Any],
    current_rows: list[dict[str, Any]],
    playbooks_root: Path = DEFAULT_CORPUS,
) -> dict[str, Any]:
    if not audit.get("passed"):
        raise ValueError("raw authority is not PASS_1796: " + "; ".join(audit.get("failure_reasons", [])))
    source_rows = list(audit["source_rows"])
    source_by_key = {str(row["raw_action_key"]): row for row in source_rows}
    current_by_key = {str(row["raw_key"]): row for row in current_rows}
    source_keys = set(source_by_key)
    current_keys = set(current_by_key)
    if source_keys != current_keys:
        raise ValueError(
            f"current readiness matrix key drift: missing={len(source_keys-current_keys)} extra={len(current_keys-source_keys)}"
        )
    contexts = _load_action_context(playbooks_root, source_rows)
    rows: list[dict[str, Any]] = []
    for source in source_rows:
        key = str(source["raw_action_key"])
        row = dict(current_by_key[key])
        enrichment = _enrich_one(source, contexts[key])
        row["r1_enrichment"] = enrichment
        row.update(enrichment)
        rows.append(row)

    keys = [row["raw_key"] for row in rows]
    source_keys = set(source_by_key)
    row_keys = set(keys)
    conservation = {
        "raw_record_count": len(rows),
        "unique_raw_key_count": len(set(keys)),
        "missing_raw_count": len(source_keys - row_keys),
        "extra_raw_count": len(row_keys - source_keys),
        "duplicate_raw_key_count": sum(count - 1 for count in Counter(keys).values() if count > 1),
    }
    archetypes = Counter(
        row["r1_enrichment"]["primary_execution_archetype"] for row in rows
    )
    manual_count = sum(
        row["r1_enrichment"]["candidate_execution_mode_for_design"] == "REQUIRES_MANUAL_DESIGN"
        for row in rows
    )
    unknown_count = sum(
        row["r1_enrichment"]["candidate_execution_mode_for_design"] == R1_UNKNOWN
        for row in rows
    )
    return {
        "rows": rows,
        "conservation": conservation,
        "execution_archetype_count": len(archetypes),
        "requires_manual_design_count": manual_count,
        "unknown_planning_count": unknown_count,
        "reference_artifacts": _reference_artifacts(),
        "source_playbook_count": audit["source_playbook_count"],
        "source_stage_count": audit["source_stage_count"],
        "historical_manifest_recomputed_sha256": audit["historical_manifest_recomputed_sha256"],
    }


def _group_values(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    return dict(sorted(Counter(str(row["r1_enrichment"][field]) for row in rows).items()))


def build_catalog(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["r1_enrichment"]["primary_execution_archetype"]].append(row)
    archetypes: dict[str, Any] = {}
    for archetype in sorted(grouped):
        members = grouped[archetype]
        e = [row["r1_enrichment"] for row in members]
        archetypes[archetype] = {
            "raw_count": len(members),
            "playbooks": sorted({row["playbook_id"] for row in members}),
            "action_types": dict(sorted(Counter(row["action_type"] for row in members).items())),
            "os_platform_hints": dict(sorted(Counter(item for x in e for item in x["os_platform_hints"]).items())),
            "named_protocols_or_services": dict(sorted(Counter(item for x in e for item in x["named_protocols_or_services"]).items())),
            "candidate_execution_modes": dict(sorted(Counter(x["candidate_execution_mode_for_design"] for x in e).items())),
            "behavior_scopes": dict(sorted(Counter(x["behavior_scope"] for x in e).items())),
            "resource_classes": dict(sorted(Counter(item for x in e for item in x["resource_classes"]).items())),
            "representative_raw_keys": sorted(row["raw_key"] for row in members)[:8],
            "source_rule_ids": sorted(
                {
                    evidence["derivation_rule_id"]
                    for x in e
                    for evidence in x["planning_field_provenance"].get("primary_execution_archetype", [])
                }
            ),
        }
    return {
        "schema_version": "exp-e0c-r1-execution-archetype-catalog-v1",
        "raw_record_count": len(rows),
        "execution_archetype_count": len(archetypes),
        "archetypes": archetypes,
        "derivation_basis": "Primary archetype is assigned mechanically from authenticated action_type and exact action name/description lexemes; no scoring or binding identity is created.",
    }


def _adapter_family_id(archetype: str) -> str:
    return "adapter::" + archetype.lower()


def build_adapter_backlog(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["r1_enrichment"]["primary_execution_archetype"]].append(row)
    families: list[dict[str, Any]] = []
    for archetype, members in grouped.items():
        enrichments = [row["r1_enrichment"] for row in members]
        manual_count = sum(
            x["candidate_execution_mode_for_design"] == "REQUIRES_MANUAL_DESIGN"
            for x in enrichments
        )
        surface_count = sum(
            x["provx_candidate_observation_surface"] != [R1_UNKNOWN] for x in enrichments
        )
        mininet_compatible = sum(
            x["candidate_execution_mode_for_design"] in {
                "NATIVE_CANDIDATE",
                "EMULATED_CANDIDATE",
                "SYNTHETIC_CANDIDATE",
            }
            for x in enrichments
        )
        unresolved = [
            "Define a controlled stimulus, action-success criterion, cleanup, and reset evidence before execution.",
        ]
        if any(R1_UNKNOWN in x["named_protocols_or_services"] for x in enrichments):
            unresolved.append("Resolve service/protocol prerequisites from an approved local design; UNKNOWN is retained for unsupported source wording.")
        if manual_count:
            unresolved.append("Complete manual safety and defensive/telemetry-equivalence review for high-risk source wording.")
        if any(
            x["behavior_scope"] in {"NETWORK_INTERACTION", "MIXED_HOST_AND_NETWORK"}
            and x["provx_candidate_observation_surface"] == ["OTHER_NETWORK_METADATA_ONLY"]
            for x in enrichments
        ):
            unresolved.append("Determine whether host provenance is intentionally unavailable; never fabricate a causal edge.")
        families.append(
            {
                "adapter_family_id": _adapter_family_id(archetype),
                "primary_execution_archetype": archetype,
                "raw_count": len(members),
                "playbooks_covered": sorted({row["playbook_id"] for row in members}),
                "os_or_host_prerequisites": dict(sorted(Counter(item for x in enrichments for item in x["os_platform_hints"]).items())),
                "service_or_protocol_prerequisites": dict(sorted(Counter(item for x in enrichments for item in x["service_prerequisites"]).items())),
                "telemetry_requirements": sorted(
                    {
                        field
                        for x in enrichments
                        for field in (
                            "requires_network_fabric",
                            "requires_external_service_emulation",
                        )
                        if x[field]
                    }
                    | {
                        field
                        for x in enrichments
                        for field in (
                            "requires_host_process_telemetry",
                            "requires_file_telemetry",
                            "requires_socket_telemetry",
                        )
                        if x[field]
                    }
                    | {
                        surface
                        for x in enrichments
                        for surface in x["provx_candidate_observation_surface"]
                        if surface != R1_UNKNOWN
                    }
                ),
                "candidate_execution_modes": dict(sorted(Counter(x["candidate_execution_mode_for_design"] for x in enrichments).items())),
                "representative_raw_keys": sorted(row["raw_key"] for row in members)[:8],
                "unresolved_design_questions": unresolved,
                "planning_metrics": {
                    "raw_coverage": len(members),
                    "playbook_reuse": len({row["playbook_id"] for row in members}),
                    "mininet_candidate_rows": mininet_compatible,
                    "provx_candidate_surface_rows": surface_count,
                    "manual_design_rows": manual_count,
                },
            }
        )
    families.sort(
        key=lambda item: (
            -item["planning_metrics"]["raw_coverage"],
            -item["planning_metrics"]["playbook_reuse"],
            -item["planning_metrics"]["mininet_candidate_rows"],
            -item["planning_metrics"]["provx_candidate_surface_rows"],
            item["planning_metrics"]["manual_design_rows"],
            item["adapter_family_id"],
        )
    )
    for rank, family in enumerate(families, start=1):
        family["priority_rank"] = rank
        family["priority_basis"] = [
            "raw coverage",
            "playbook reuse",
            "Mininet candidate compatibility",
            "future PROVX candidate observation surface",
            "lower manual-design burden",
        ]
    return {
        "schema_version": "exp-e0c-r1-adapter-backlog-v1",
        "raw_record_count": len(rows),
        "adapter_family_count": len(families),
        "prioritization_policy": "Sort by descending raw coverage, playbook reuse, Mininet candidate compatibility, candidate PROVX surface coverage, then ascending manual-design burden; ties use adapter_family_id. This is not scoring-weight prioritization.",
        "adapter_families": families,
    }


def derivation_rules() -> dict[str, Any]:
    return {
        "schema_version": "exp-e0c-r1-derivation-rules-v1",
        "unsupported_value": R1_UNKNOWN,
        "provenance_contract": "Every non-UNKNOWN r1_enrichment field has planning_field_provenance entries containing source_field_path, exact_source_value, and derivation_rule_id.",
        "rules": [
            {"id": "R1-NAMED-PROTOCOL-TOKEN", "fields": ["named_protocols_or_services"], "source_fields": ["name", "desc"], "rule": "Match an allow-listed protocol/service token in exact source wording; return canonical token."},
            {"id": "R1-EXPLICIT-NAMED-SOFTWARE-MARKER", "fields": ["explicit_tool_or_malware_names"], "source_fields": ["name", "desc"], "rule": "Retain only visibly named uppercase/mixed software terms adjacent to explicit tool/malware marker wording; otherwise UNKNOWN."},
            {"id": "R1-ARCHETYPE-*", "fields": ["primary_execution_archetype"], "source_fields": ["action_type", "name", "desc"], "rule": "Apply deterministic action_type branch and conservative lexical precedence; do not create scoring units."},
            {"id": "R1-BEHAVIOR-*", "fields": ["behavior_scope"], "source_fields": ["action_type", "name", "desc"], "rule": "Classify host-local, network, or mixed scope only from source action type and exact network/command lexemes."},
            {"id": "R1-RESOURCE-ACTION-TYPE-OR-LEXEME", "fields": ["resource_classes"], "source_fields": ["action_type", "name", "desc"], "rule": "Add only resource classes indicated by action type or exact source lexemes."},
            {"id": "R1-FLAG-*", "fields": ["requires_*"], "source_fields": ["action_type", "os", "name", "desc"], "rule": "Set conservative planning booleans from source type, explicit OS, and exact lexical indicators; flags are requirements, not observations."},
            {"id": "R1-SECONDARY-TAG-*", "fields": ["secondary_prerequisite_tags"], "source_fields": ["action_type", "os", "name"], "rule": "Project true planning flags and explicit protocol tokens into reusable prerequisite tags."},
            {"id": "R1-CANDIDATE-*", "fields": ["candidate_execution_mode_for_design", "candidate_execution_rationale", "defensive_equivalence_constraints", "telemetry_equivalence_constraints"], "source_fields": ["action_type", "name", "desc"], "rule": "Select native, emulated, synthetic, manual, or UNKNOWN design candidate by source action type and safety markers; never authorize execution."},
            {"id": "R1-PROVX-CANDIDATE-SURFACE-FROM-SOURCE-TYPE", "fields": ["provx_candidate_observation_surface"], "source_fields": ["action_type", "name", "desc"], "rule": "List candidate telemetry surface labels without asserting PROVX detectability, localization, or causal edges."},
        ],
    }


def conservation_report(result: Mapping[str, Any]) -> dict[str, Any]:
    conservation = result["conservation"]
    passed = conservation == {
        "raw_record_count": EXPECTED_RAW_COUNT,
        "unique_raw_key_count": EXPECTED_RAW_COUNT,
        "missing_raw_count": 0,
        "extra_raw_count": 0,
        "duplicate_raw_key_count": 0,
    }
    return {
        "schema_version": "exp-e0c-r1-conservation-audit-v1",
        "exp_e0c_r1_conservation": "PASS_1796" if passed else "BLOCKED",
        "raw_authority": "AUTHENTICATED_SOURCE_CORPUS_PLUS_VERIFIED_DERIVED_REGISTRY",
        "raw_record_count": conservation["raw_record_count"],
        "unique_raw_key_count": conservation["unique_raw_key_count"],
        "missing_raw_count": conservation["missing_raw_count"],
        "extra_raw_count": conservation["extra_raw_count"],
        "duplicate_raw_key_count": conservation["duplicate_raw_key_count"],
        "execution_archetype_count": result["execution_archetype_count"],
        "requires_manual_design_count": result["requires_manual_design_count"],
        "unknown_planning_count": result["unknown_planning_count"],
        "source_playbook_count": result["source_playbook_count"],
        "source_stage_count": result["source_stage_count"],
        "historical_manifest_recomputed_sha256": result["historical_manifest_recomputed_sha256"],
        "historical_protocol_scoring_metadata": "NOT_CURRENT_AUTHORITY",
        "formal_experiment_executed": "NO",
        "denominator_change": "NO",
        "binding_authority_mutation": "NO",
        "scoring_authority_mutation": "NO",
        "next_action": "FRESH_REVIEW_OF_EXP_E0C_R1_EXECUTION_ARCHETYPE_ENRICHMENT",
        "stop": True,
        "all_rows_formal_execution_authorized_false": all(
            row["formal_execution_authorized"] is False for row in result["rows"]
        ),
    }


def planning_report(result: Mapping[str, Any], catalog: Mapping[str, Any], backlog: Mapping[str, Any]) -> str:
    lines = [
        "# EXP-E0C-R1 Execution-Archetype Enrichment",
        "",
        "Preparation-only planning substrate for the authenticated exact-1796 raw corpus.",
        "",
        "## Terminal State",
        "",
        "- `EXP_E0C_R1_CONSERVATION = PASS_1796`",
        f"- `RAW_RECORD_COUNT = {result['conservation']['raw_record_count']}`",
        f"- `UNIQUE_RAW_KEY_COUNT = {result['conservation']['unique_raw_key_count']}`",
        f"- `EXECUTION_ARCHETYPE_COUNT = {result['execution_archetype_count']}`",
        f"- `REQUIRES_MANUAL_DESIGN_COUNT = {result['requires_manual_design_count']}`",
        f"- `UNKNOWN_PLANNING_COUNT = {result['unknown_planning_count']}`",
        "- `FORMAL_EXPERIMENT_EXECUTED = NO`",
        "- `DENOMINATOR_CHANGE = NO`",
        "- `BINDING_AUTHORITY_MUTATION = NO`",
        "- `SCORING_AUTHORITY_MUTATION = NO`",
        "- `NEXT_ACTION = FRESH_REVIEW_OF_EXP_E0C_R1_EXECUTION_ARCHETYPE_ENRICHMENT`",
        "- `STOP = true`",
        "",
        "## Authority and Scope",
        "",
        "- Raw authority remains `AUTHENTICATED_SOURCE_CORPUS_PLUS_VERIFIED_DERIVED_REGISTRY`.",
        "- The accepted denominator remains 1,796; no scoring/binding identity or count was created.",
        "- Historical feasibility/run-plan artifacts are listed as reference evidence only; old VM choices are not requirements for Mininet/PROVX.",
        "- Every row retains `formal_execution_authorized = false`.",
        "",
        "## Archetype Catalog",
        "",
        "| Archetype | Raw count | Playbooks | Candidate modes |",
        "|---|---:|---:|---|",
    ]
    for archetype, item in catalog["archetypes"].items():
        modes = ", ".join(f"{key}:{value}" for key, value in item["candidate_execution_modes"].items())
        lines.append(f"| `{archetype}` | {item['raw_count']} | {len(item['playbooks'])} | {modes} |")
    lines.extend(["", "## Adapter Backlog Priority", "", "| Rank | Adapter family | Raw count | Playbooks | Manual rows |", "|---:|---|---:|---:|---:|"])
    for family in backlog["adapter_families"]:
        lines.append(
            f"| {family['priority_rank']} | `{family['adapter_family_id']}` | {family['raw_count']} | {len(family['playbooks_covered'])} | {family['planning_metrics']['manual_design_rows']} |"
        )
    lines.extend(
        [
            "",
            "Priority is based on raw coverage, playbook reuse, Mininet candidate compatibility, future PROVX candidate surface, and lower manual-design burden. It is not based on scoring weight.",
            "",
            "## PROVX Boundary",
            "",
            "Candidate observation surfaces are planning labels only. `provx_phase1_observable`, `provx_phase2_core_edge_localizable`, and all four result dimensions remain unchanged and unobserved. Network-only records retain an explicit metadata-only surface; no process/file/socket causal edge is fabricated.",
            "",
            "## Reference Artifacts",
            "",
        ]
    )
    for artifact in result["reference_artifacts"]:
        lines.append(f"- `{artifact['path']}` SHA-256 `{artifact['sha256']}`; `{artifact['status']}`.")
    lines.extend(["", "STOP = true", ""])
    return "\n".join(lines)


def _render_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _render_jsonl(rows: Iterable[Mapping[str, Any]]) -> str:
    return "".join(
        json.dumps(dict(row), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        for row in rows
    )


def _render_csv(rows: list[dict[str, Any]]) -> str:
    fields = list(rows[0]) if rows else []
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                field: json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                if isinstance(value, (list, dict))
                else value
                for field, value in row.items()
            }
        )
    return buffer.getvalue()


def build_r1_outputs(result: Mapping[str, Any]) -> dict[str, Any]:
    rows = result["rows"]
    catalog = build_catalog(rows)
    backlog = build_adapter_backlog(rows)
    rules = derivation_rules()
    audit = conservation_report(result)
    report = planning_report(result, catalog, backlog)
    return {
        "rows": rows,
        "catalog": catalog,
        "adapter_backlog": backlog,
        "derivation_rules": rules,
        "conservation_audit": audit,
        "planning_report": report,
    }


def write_outputs(output_dir: Path, outputs: Mapping[str, Any]) -> None:
    audit = outputs["conservation_audit"]
    if audit["exp_e0c_r1_conservation"] != "PASS_1796":
        raise ValueError("R1 conservation failed; refusing to write enriched matrix")
    rows = outputs["rows"]
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "EXP_E0C_R1_1796_ENRICHED_READINESS.jsonl").write_text(
        _render_jsonl(rows), encoding="utf-8", newline="\n"
    )
    (output_dir / "EXP_E0C_R1_1796_ENRICHED_READINESS.csv").write_text(
        _render_csv(rows), encoding="utf-8", newline="\n"
    )
    (output_dir / "EXP_E0C_R1_EXECUTION_ARCHETYPE_CATALOG.json").write_text(
        _render_json(outputs["catalog"]), encoding="utf-8", newline="\n"
    )
    (output_dir / "EXP_E0C_R1_ADAPTER_BACKLOG.json").write_text(
        _render_json(outputs["adapter_backlog"]), encoding="utf-8", newline="\n"
    )
    (output_dir / "EXP_E0C_R1_DERIVATION_RULES.json").write_text(
        _render_json(outputs["derivation_rules"]), encoding="utf-8", newline="\n"
    )
    (output_dir / "EXP_E0C_R1_CONSERVATION_AUDIT.json").write_text(
        _render_json(outputs["conservation_audit"]), encoding="utf-8", newline="\n"
    )
    (output_dir / "EXP_E0C_R1_PLANNING_REPORT.md").write_text(
        outputs["planning_report"], encoding="utf-8", newline="\n"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--playbooks-root", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--current-readiness", type=Path, default=Path.cwd() / CURRENT_MATRIX_NAME)
    parser.add_argument("--output-dir", type=Path, default=Path.cwd())
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    audit = audit_raw_authority(args.playbooks_root, args.registry)
    if not audit["passed"]:
        print("EXP_E0C_R1_CONSERVATION = BLOCKED")
        print("RAW_RECORD_COUNT = " + str(audit["source_derived_raw_count"]))
        print("UNIQUE_RAW_KEY_COUNT = " + str(audit["source_derived_unique_raw_keys"]))
        print("FORMAL_EXPERIMENT_EXECUTED = NO")
        print("DENOMINATOR_CHANGE = NO")
        print("BINDING_AUTHORITY_MUTATION = NO")
        print("SCORING_AUTHORITY_MUTATION = NO")
        print("NEXT_ACTION = FIX_EXACT_RAW_AUTHORITY_DEFECT")
        print("STOP = true")
        return 1
    try:
        current = load_current_readiness(args.current_readiness)
        result = build_r1_enrichment(audit, current, args.playbooks_root)
        outputs = build_r1_outputs(result)
        write_outputs(args.output_dir, outputs)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"EXP_E0C_R1_CONSERVATION = BLOCKED\nERROR = {error}")
        print("RAW_RECORD_COUNT = 0")
        print("UNIQUE_RAW_KEY_COUNT = 0")
        print("FORMAL_EXPERIMENT_EXECUTED = NO")
        print("DENOMINATOR_CHANGE = NO")
        print("BINDING_AUTHORITY_MUTATION = NO")
        print("SCORING_AUTHORITY_MUTATION = NO")
        print("NEXT_ACTION = FIX_EXACT_RAW_AUTHORITY_DEFECT")
        print("STOP = true")
        return 1
    audit_report = outputs["conservation_audit"]
    print("EXP_E0C_R1_CONSERVATION = PASS_1796")
    print(f"RAW_RECORD_COUNT = {audit_report['raw_record_count']}")
    print(f"UNIQUE_RAW_KEY_COUNT = {audit_report['unique_raw_key_count']}")
    print(f"EXECUTION_ARCHETYPE_COUNT = {audit_report['execution_archetype_count']}")
    print(f"REQUIRES_MANUAL_DESIGN_COUNT = {audit_report['requires_manual_design_count']}")
    print(f"UNKNOWN_PLANNING_COUNT = {audit_report['unknown_planning_count']}")
    print("FORMAL_EXPERIMENT_EXECUTED = NO")
    print("DENOMINATOR_CHANGE = NO")
    print("BINDING_AUTHORITY_MUTATION = NO")
    print("SCORING_AUTHORITY_MUTATION = NO")
    print("NEXT_ACTION = FRESH_REVIEW_OF_EXP_E0C_R1_EXECUTION_ARCHETYPE_ENRICHMENT")
    print("STOP = true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
