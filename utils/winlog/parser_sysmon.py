"""
Sysmon event parser — converts Sysmon EVTX/XML events into unified host_behavior dicts.

Supports Sysmon Event IDs:
  1  ProcessCreate        -> process_create
  2  FileCreateTime       -> file_create
  3  NetworkConnect       -> network_connection
  5  ProcessTerminate     -> process_terminate
  7  ImageLoad            -> image_load
  8  CreateRemoteThread   -> process_injection
  10  ProcessAccess       -> process_access
  11  FileCreate          -> file_create
  12  RegistryEvent (Key) -> registry_create_key
  13  RegistryEvent (Val) -> registry_set_value
  14  RegistryEvent (Key+Val) -> registry_rename_key
  17  PipeCreated         -> pipe_create
  18  PipeConnected       -> pipe_connect
  22  DnsQuery            -> dns_query
  23  FileDelete          -> file_delete
  26  FileDeleteLogged    -> file_delete
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ── Event ID → (event_type, action) mapping ──────────────────────────
EVENT_ID_MAP: dict[int, tuple[str, str]] = {
    1:  ("process_create", "execution"),
    2:  ("file_create", "creation"),
    3:  ("network_connection", "connection"),
    5:  ("process_terminate", "termination"),
    7:  ("image_load", "load"),
    8:  ("process_injection", "injection"),
    10: ("process_access", "access"),
    11: ("file_create", "creation"),
    12: ("registry_create_key", "registry_create"),
    13: ("registry_set_value", "registry_set"),
    14: ("registry_rename_key", "registry_rename"),
    17: ("pipe_create", "creation"),
    18: ("pipe_connect", "connection"),
    22: ("dns_query", "query"),
    23: ("file_delete", "deletion"),
    24: ("clipboard_change", "clipboard"),
    25: ("process_tampering", "tampering"),
    26: ("file_delete", "deletion"),
}


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _strip_ns(tag: str) -> str:
    """Strip XML namespace from tag."""
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _text_or_none(elem: ET.Element | None) -> str | None:
    if elem is None:
        return None
    return (elem.text or "").strip() or None


def _parse_sysmon_xml(xml_string: str) -> dict[str, Any]:
    """
    Parse a single Sysmon event XML string and return a unified event dict.

    Returns empty dict on parse failure — caller should check.
    """
    if not xml_string or not isinstance(xml_string, str):
        return {}

    xml_text = xml_string.strip()
    if not xml_text:
        return {}

    # Strip namespace prefixes to simplify parsing (Python stdlib etree doesn't support {*} wildcards)
    import re as _re
    xml_text = _re.sub(r'\s*xmlns="[^"]*"', '', xml_text, count=1)
    xml_text = _re.sub(r"\s*xmlns='[^']*'", '', xml_text, count=1)

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logger.debug("Failed to parse Sysmon XML")
        return {}

    # Extract System info
    system_node = root.find("System")
    event_id: int | None = None
    computer: str | None = None
    time_created: str | None = None

    if system_node is not None:
        for child in system_node:
            tag = _strip_ns(child.tag)
            if tag == "EventID":
                try:
                    event_id = int((child.text or "0").strip())
                except ValueError:
                    pass
            elif tag == "Computer":
                computer = (child.text or "").strip() or None
            elif tag == "TimeCreated":
                time_created = child.get("SystemTime") or (child.text or "").strip() or None

    if event_id is None:
        # Try to find EventID in EventData or as attribute
        ed = root.find("EventData")
        if ed is not None:
            for d in ed:
                if d.get("Name") == "EventID" or _strip_ns(d.tag) == "EventID":
                    try:
                        event_id = int((d.text or "0").strip())
                    except ValueError:
                        pass
                    break
    if event_id is None:
        return {}

    # Look up mapping
    mapped = EVENT_ID_MAP.get(event_id)
    if mapped is None:
        logger.debug("Unsupported Sysmon Event ID: %d", event_id)
        # Still try to produce a generic event
        mapped = ("unknown_sysmon_event", "unknown")

    event_type, action = mapped

    # Extract EventData fields
    data_fields: dict[str, str] = {}
    event_data = root.find("EventData")
    if event_data is not None:
        for d in event_data:
            name = d.get("Name") or _strip_ns(d.tag)
            value = (d.text or "").strip()
            if name:
                data_fields[name] = value

    # Normalize timestamp
    timestamp = time_created
    if not timestamp:
        timestamp = _now_iso()
    # Ensure Z suffix
    if timestamp and not timestamp.endswith("Z") and "T" in timestamp:
        timestamp = timestamp.replace(" ", "T")
        if "+" not in timestamp and timestamp.count(":") == 3:
            timestamp += "Z"

    # Build entities
    entities: dict[str, Any] = {}

    # Common fields across event types
    if "Image" in data_fields:
        entities["process_name"] = data_fields["Image"].split("\\")[-1] if "\\" in data_fields["Image"] else data_fields["Image"]
        entities["process_path"] = data_fields["Image"]
    if "ProcessId" in data_fields:
        try:
            entities["pid"] = int(data_fields["ProcessId"])
        except (ValueError, TypeError):
            entities["pid"] = data_fields["ProcessId"]
    if "ParentImage" in data_fields:
        entities["parent_process"] = data_fields["ParentImage"].split("\\")[-1] if "\\" in data_fields["ParentImage"] else data_fields["ParentImage"]
        entities["parent_process_path"] = data_fields["ParentImage"]
    if "ParentProcessId" in data_fields:
        try:
            entities["parent_pid"] = int(data_fields["ParentProcessId"])
        except (ValueError, TypeError):
            entities["parent_pid"] = data_fields["ParentProcessId"]
    if "CommandLine" in data_fields:
        entities["command_line"] = data_fields["CommandLine"]
    if "User" in data_fields:
        entities["user"] = data_fields["User"]
    if "Hashes" in data_fields:
        entities["hash"] = data_fields["Hashes"]

    # Event-specific fields
    if event_id == 3:  # NetworkConnect
        entities["src_ip"] = data_fields.get("SourceIp", "")
        entities["src_hostname"] = data_fields.get("SourceHostname", "")
        entities["dst_ip"] = data_fields.get("DestinationIp", "")
        entities["dst_hostname"] = data_fields.get("DestinationHostname", "")
        entities["dst_port"] = data_fields.get("DestinationPort", "")
        entities["protocol"] = data_fields.get("Protocol", "").lower()
    elif event_id in (11, 23, 26):  # FileCreate, FileDelete
        entities["file_path"] = data_fields.get("TargetFilename", "")
        if "CreationUtcTime" in data_fields:
            entities["file_creation_time"] = data_fields["CreationUtcTime"]
    elif event_id == 22:  # DnsQuery
        entities["dns_query"] = data_fields.get("QueryName", "")
        entities["query_status"] = data_fields.get("QueryStatus", "")
    elif event_id in (12, 13, 14):  # Registry
        entities["registry_key"] = data_fields.get("TargetObject", "")
        entities["registry_value"] = data_fields.get("Details", "")
    elif event_id == 8:  # CreateRemoteThread
        entities["source_process"] = data_fields.get("SourceImage", "").split("\\")[-1] if "\\" in data_fields.get("SourceImage", "") else data_fields.get("SourceImage", "")
        entities["target_process"] = data_fields.get("TargetImage", "").split("\\")[-1] if "\\" in data_fields.get("TargetImage", "") else data_fields.get("TargetImage", "")
        try:
            entities["source_pid"] = int(data_fields.get("SourceProcessId", "0"))
        except (ValueError, TypeError):
            pass
        try:
            entities["target_pid"] = int(data_fields.get("TargetProcessId", "0"))
        except (ValueError, TypeError):
            pass
    elif event_id == 1:  # ProcessCreate
        if "ParentCommandLine" in data_fields:
            entities["parent_command_line"] = data_fields["ParentCommandLine"]

    # Build features
    features: dict[str, Any] = {}
    if "IntegrityLevel" in data_fields:
        features["integrity_level"] = data_fields["IntegrityLevel"]
    if "UtcTime" in data_fields:
        features["utc_time"] = data_fields["UtcTime"]
    if "Signature" in data_fields:
        features["signature"] = data_fields["Signature"]
    if "Signed" in data_fields:
        features["signed"] = data_fields["Signed"].lower() == "true"
    if "ImageLoaded" in data_fields:
        features["image_loaded"] = data_fields["ImageLoaded"]

    # Detect suspicious patterns
    if event_id == 1 and entities.get("process_name", "").lower() in (
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    ) and entities.get("parent_process", "").lower() in (
        "winword.exe", "excel.exe", "outlook.exe",
    ):
        features["is_suspicious"] = True
        features["suspicious_reason"] = "Office app spawning script interpreter"

    if event_id == 1 and "-enc" in (entities.get("command_line") or "").lower():
        features["is_suspicious"] = True
        features["suspicious_reason"] = "Encoded PowerShell command"

    # Description
    if event_id == 1:
        pname = entities.get("process_name") or "unknown"
        pid = entities.get("pid", "?")
        desc = f"Sysmon: Process Create — {pname} (PID {pid})"
    elif event_id == 3:
        dst = f"{entities.get('dst_ip', '?')}:{entities.get('dst_port', '?')}"
        desc = f"Sysmon: Network Connect to {dst}"
    elif event_id == 22:
        desc = f"Sysmon: DNS Query — {entities.get('dns_query', '?')}"
    elif event_id == 11:
        desc = f"Sysmon: File Create — {entities.get('file_path', '?')}"
    elif event_id == 8:
        desc = f"Sysmon: Remote Thread — {entities.get('source_process', '?')} -> {entities.get('target_process', '?')}"
    else:
        desc = f"Sysmon: {event_type} (Event ID {event_id})"

    return {
        "timestamp": timestamp,
        "data_source": "sysmon",
        "host_ip": "",
        "host_name": computer or "",
        "event_type": event_type,
        "action": action,
        "raw_event_id": event_id,
        "entities": {k: v for k, v in entities.items() if v not in (None, "", 0) or k in ("pid", "parent_pid")},
        "features": features,
        "description": desc,
        "_raw_data_fields": data_fields if logger.isEnabledFor(logging.DEBUG) else {},
    }


def parse_sysmon_event(xml_string: str, host_ip: str | None = None, host_name: str | None = None) -> dict | None:
    """
    Public API: parse a single Sysmon event XML into a unified dict.

    Args:
        xml_string: Raw Sysmon event XML
        host_ip: Override host IP (otherwise uses Computer from event)
        host_name: Override host name

    Returns:
        Unified event dict or None on parse failure
    """
    result = _parse_sysmon_xml(xml_string)
    if not result:
        return None

    if host_ip:
        result["host_ip"] = host_ip
    if host_name:
        result["host_name"] = host_name

    # Remove internal debug fields from final output
    result.pop("_raw_data_fields", None)
    return result


def parse_sysmon_batch(events: list[dict | str], host_ip: str | None = None, host_name: str | None = None) -> list[dict]:
    """
    Public API: parse a batch of Sysmon events (XML strings or pre-parsed dicts).

    Args:
        events: List of XML strings or dict objects with '_raw_xml' key
        host_ip: Override host IP
        host_name: Override host name

    Returns:
        List of unified event dicts (skips failures silently)
    """
    results: list[dict] = []
    for item in events:
        try:
            if isinstance(item, str):
                parsed = parse_sysmon_event(item, host_ip=host_ip, host_name=host_name)
            elif isinstance(item, dict):
                xml = item.get("_raw_xml") or item.get("xml") or item.get("raw")
                if not xml and item.get("event_type"):
                    # Already parsed unified event — pass through
                    item.setdefault("data_source", "sysmon")
                    results.append(item)
                    continue
                parsed = parse_sysmon_event(str(xml), host_ip=host_ip, host_name=host_name)
            else:
                continue

            if parsed:
                results.append(parsed)
        except Exception:
            logger.debug("Failed to parse Sysmon event in batch", exc_info=True)
    return results
