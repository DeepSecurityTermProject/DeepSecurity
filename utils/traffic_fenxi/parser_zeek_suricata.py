"""
Zeek & Suricata network log parser — converts Zeek TSV logs and Suricata eve.json into unified NetworkTraffic dicts.

Zeek log format:
  #separator \x09
  #set_separator ,
  #empty_field (empty)
  #unset_field -
  #path conn
  #fields ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  service  ...
  #types time string addr port addr port enum string ...
  1234567890.123456  CAbc123...  192.168.1.100  49152  10.0.0.1  443  tcp  ssl  ...

Suricata eve.json format (one JSON object per line):
  {"timestamp":"2026-07-09T14:30:00.123456+0800","event_type":"alert","src_ip":"...",...}

Unified output:
  {timestamp, data_source, src_ip, dst_ip, src_port, dst_port, protocol, event_type, entities, features, description}
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ── Zeek log type → event_type mapping ───────────────────────────────
ZEEK_LOG_TYPE_MAP: dict[str, str] = {
    "conn": "tcp_connection",
    "dns": "dns_query",
    "http": "http_request",
    "files": "file_transfer",
    "ssl": "tls_handshake",
    "x509": "tls_handshake",
    "ssh": "ssh_session",
    "ftp": "ftp_session",
    "smtp": "smtp_session",
    "dhcp": "dhcp_event",
    "notice": "network_alert",
    "weird": "network_anomaly",
}

# ── Suricata event_type → event_type mapping ─────────────────────────
SURICATA_EVENT_MAP: dict[str, str] = {
    "alert": "network_alert",
    "dns": "dns_query",
    "http": "http_request",
    "tls": "tls_handshake",
    "flow": "tcp_connection",
    "fileinfo": "file_transfer",
    "ssh": "ssh_session",
    "smtp": "smtp_session",
    "ftp": "ftp_session",
    "dhcp": "dhcp_event",
    "anomaly": "network_anomaly",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_zeek_timestamp(ts_str: str) -> str | None:
    """Convert Zeek epoch timestamp (float) to ISO8601 Z string."""
    if not ts_str or ts_str in ("-", "(empty)"):
        return None
    try:
        ts = float(ts_str)
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OSError):
        return None


# ═══════════════════════════════════════════════════════════════════════
# Zeek parser
# ═══════════════════════════════════════════════════════════════════════


def _parse_zeek_header(text: str) -> dict[str, Any]:
    """
    Parse Zeek header lines to extract separator, fields list, and log path.

    Returns dict with keys: separator, set_sep, empty_field, unset_field, path, fields (list)
    """
    info: dict[str, Any] = {
        "separator": "\t",
        "set_sep": ",",
        "empty_field": "(empty)",
        "unset_field": "-",
        "path": "unknown",
        "fields": [],
    }

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#separator"):
            sep = line.split(maxsplit=1)
            if len(sep) > 1:
                info["separator"] = sep[1].encode().decode("unicode_escape")
        elif line.startswith("#set_separator"):
            parts = line.split(maxsplit=1)
            if len(parts) > 1:
                info["set_sep"] = parts[1]
        elif line.startswith("#empty_field"):
            parts = line.split(maxsplit=1)
            if len(parts) > 1:
                info["empty_field"] = parts[1]
        elif line.startswith("#unset_field"):
            parts = line.split(maxsplit=1)
            if len(parts) > 1:
                info["unset_field"] = parts[1]
        elif line.startswith("#path"):
            parts = line.split(maxsplit=1)
            if len(parts) > 1:
                info["path"] = parts[1].strip()
        elif line.startswith("#fields"):
            fields_str = line.split("\t", 1)
            if len(fields_str) > 1:
                info["fields"] = fields_str[1].split(info["separator"])
        elif line.startswith("#open"):
            # End of header; stop parsing
            break

    return info


def parse_zeek_log(
    log_line: str,
    log_type: str | None = None,
    fields: list[str] | None = None,
    host_name: str | None = None,
) -> dict | None:
    """
    Parse a single Zeek TSV log line into a unified NetworkTraffic event dict.

    Args:
        log_line: A single TSV data line (NOT the header)
        log_type: One of "conn", "dns", "http", "files", "ssl", etc.
                  If None, defaults to "conn".
        fields: Pre-parsed field name list (from #fields header).
                If None, uses built-in defaults per log_type.
        host_name: Hostname / sensor name for this data.

    Returns unified dict or None.
    """
    if not log_line or not isinstance(log_line, str):
        return None

    line = log_line.strip()
    if not line or line.startswith("#"):
        return None

    lt = (log_type or "conn").strip().lower()

    # Use built-in field lists if none provided
    if not fields:
        fields = _get_default_zeek_fields(lt)
    if not fields:
        logger.debug("No Zeek fields available for log_type=%s", lt)
        return None

    values = line.split("\t")
    if len(values) < len(fields):
        # Pad with unset
        values = values + ["-"] * (len(fields) - len(values))

    # Build field dict
    data: dict[str, str] = {}
    for i, field_name in enumerate(fields):
        if i < len(values):
            val = values[i]
            # Normalize empty/unset
            if val in ("-", "(empty)"):
                val = ""
            data[field_name] = val
        else:
            data[field_name] = ""

    # Parse timestamp
    ts_raw = data.get("ts", "")
    timestamp = _parse_zeek_timestamp(ts_raw) or _now_iso()

    # Extract common network fields
    src_ip = data.get("id.orig_h", "")
    dst_ip = data.get("id.resp_h", "")
    src_port = data.get("id.orig_p", "")
    dst_port = data.get("id.resp_p", "")
    proto = data.get("proto", "").lower()

    # Determine event_type
    event_type = ZEEK_LOG_TYPE_MAP.get(lt, "network_event")

    # Build entities
    entities: dict[str, Any] = {}
    if src_ip:
        entities["src_ip"] = src_ip
    if dst_ip:
        entities["dst_ip"] = dst_ip
    if src_port:
        entities["src_port"] = src_port
    if dst_port:
        entities["dst_port"] = dst_port
    if proto:
        entities["protocol"] = proto
    if "service" in data and data["service"]:
        entities["service"] = data["service"]
    if "uid" in data:
        entities["uid"] = data["uid"]

    # Log-type-specific entities
    if lt == "dns":
        entities["dns_query"] = data.get("query", "")
        entities["query_type"] = data.get("qtype_name", "") or data.get("qtype", "")
        if "answers" in data and data["answers"]:
            entities["dns_answers"] = data["answers"]
    elif lt == "http":
        entities["http_method"] = data.get("method", "")
        entities["http_uri"] = data.get("uri", "") or data.get("host", "")
        entities["http_host"] = data.get("host", "")
        entities["http_user_agent"] = data.get("user_agent", "")
        entities["http_status"] = data.get("status_code", "")
    elif lt == "files":
        entities["file_name"] = data.get("filename", "") or data.get("fuid", "")
        entities["file_mime"] = data.get("mime_type", "")
        if "seen_bytes" in data:
            entities["file_size"] = data["seen_bytes"]

    # Build features
    features: dict[str, Any] = {}
    if "duration" in data and data["duration"]:
        try:
            features["duration"] = float(data["duration"])
        except ValueError:
            pass
    if "orig_bytes" in data and data["orig_bytes"]:
        try:
            features["bytes_out"] = int(data["orig_bytes"])
        except ValueError:
            features["bytes_out"] = data["orig_bytes"]
    if "resp_bytes" in data and data["resp_bytes"]:
        try:
            features["bytes_in"] = int(data["resp_bytes"])
        except ValueError:
            features["bytes_in"] = data["resp_bytes"]
    if "orig_pkts" in data and data["orig_pkts"]:
        try:
            features["pkt_count"] = int(data["orig_pkts"])
        except ValueError:
            pass
    if "conn_state" in data:
        features["conn_state"] = data["conn_state"]
    if "history" in data:
        features["history"] = data["history"]

    features["zeek_log_type"] = lt

    # Build description
    desc_parts = []
    desc_parts.append(f"Zeek [{lt}]")
    if src_ip and dst_ip:
        conn_str = f"{src_ip}"
        if src_port:
            conn_str += f":{src_port}"
        conn_str += f" -> {dst_ip}"
        if dst_port:
            conn_str += f":{dst_port}"
        desc_parts.append(conn_str)
    if proto:
        desc_parts.append(f"proto={proto}")
    if lt == "dns" and entities.get("dns_query"):
        desc_parts.append(f"query={entities['dns_query']}")
    elif lt == "http" and entities.get("http_uri"):
        desc_parts.append(f"{entities.get('http_method', 'GET')} {entities['http_uri']}")

    return {
        "timestamp": timestamp,
        "data_source": "zeek",
        "host_ip": "",
        "host_name": host_name or "",
        "src_ip": src_ip or "",
        "dst_ip": dst_ip or "",
        "src_port": src_port or None,
        "dst_port": dst_port or None,
        "protocol": proto or "tcp",
        "event_type": event_type,
        "entities": {k: v for k, v in entities.items() if v not in (None, "", 0)},
        "features": features,
        "description": " — ".join(desc_parts),
    }


def _get_default_zeek_fields(log_type: str) -> list[str]:
    """Return built-in Zeek field lists for common log types."""
    defaults: dict[str, list[str]] = {
        "conn": [
            "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
            "proto", "service", "duration", "orig_bytes", "resp_bytes",
            "conn_state", "local_orig", "local_resp", "missed_bytes",
            "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
        ],
        "dns": [
            "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
            "proto", "trans_id", "rtt", "query", "qclass", "qclass_name",
            "qtype", "qtype_name", "rcode", "rcode_name", "AA", "TC", "RD",
            "RA", "Z", "answers", "TTLs", "rejected",
        ],
        "http": [
            "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
            "trans_depth", "method", "host", "uri", "referrer", "version",
            "user_agent", "origin", "request_body_len", "response_body_len",
            "status_code", "status_msg", "info_code", "info_msg",
            "tags", "username", "password", "proxied",
        ],
        "files": [
            "ts", "fuid", "tx_hosts", "rx_hosts", "conn_uids",
            "source", "depth", "analyzers", "mime_type", "filename",
            "duration", "local_orig", "is_orig", "seen_bytes",
            "total_bytes", "missing_bytes", "overflow_bytes",
            "timedout", "parent_fuid", "md5", "sha1", "sha256",
        ],
        "ssl": [
            "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
            "version", "cipher", "curve", "server_name",
            "session_id", "resumed", "next_protocol",
            "established", "cert_chain_fuids", "client_cert_chain_fuids",
            "subject", "issuer",
        ],
    }
    return defaults.get(log_type, [])


def parse_zeek_file(
    file_path: str,
    log_type: str | None = None,
    host_name: str | None = None,
) -> list[dict]:
    """
    Parse an entire Zeek log file (with #fields header).

    Args:
        file_path: Path to the Zeek .log file
        log_type: Override log type (auto-detected from path if not set)
        host_name: Sensor name
    """
    if not os.path.isfile(file_path):
        logger.warning("Zeek log file not found: %s", file_path)
        return []

    # Auto-detect log type from filename
    if log_type is None:
        basename = os.path.basename(file_path)
        # e.g., "conn.log", "dns.14:00:00-15:00:00.log"
        name_part = basename.split(".")[0]
        if name_part in ZEEK_LOG_TYPE_MAP:
            log_type = name_part
        else:
            log_type = "conn"

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    # Parse header
    header = _parse_zeek_header(content)
    fields_list: list[str] = header["fields"]
    if not fields_list:
        fields_list = _get_default_zeek_fields(log_type)

    results: list[dict] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parsed = parse_zeek_log(line, log_type=log_type, fields=fields_list, host_name=host_name)
            if parsed:
                results.append(parsed)
        except Exception:
            logger.debug("Failed to parse Zeek log line", exc_info=True)
    return results


# ═══════════════════════════════════════════════════════════════════════
# Suricata parser
# ═══════════════════════════════════════════════════════════════════════


def parse_suricata_eve(
    json_string: str,
    host_name: str | None = None,
) -> dict | None:
    """
    Parse a single Suricata eve.json event into a unified NetworkTraffic event dict.

    Args:
        json_string: One JSON object from eve.json (one line)
        host_name: Sensor name

    Returns unified dict or None on parse failure.
    """
    if not json_string or not isinstance(json_string, str):
        return None

    try:
        data = json.loads(json_string.strip())
    except json.JSONDecodeError:
        logger.debug("Failed to parse Suricata eve.json line")
        return None

    if not isinstance(data, dict):
        return None

    sev_type = str(data.get("event_type") or "").strip()

    # Extract network fields
    src_ip = str(data.get("src_ip") or "")
    dst_ip = str(data.get("dest_ip") or "")
    src_port = data.get("src_port")
    dst_port = data.get("dest_port")
    proto = str(data.get("proto") or "").lower()

    # Parse timestamp
    ts_raw = data.get("timestamp")
    timestamp: str | None = None
    if ts_raw:
        try:
            # Suricata: "2026-07-09T14:30:00.123456+0800"
            ts_str = str(ts_raw)
            if "+" in ts_str or ts_str.endswith("Z"):
                # Parse with timezone
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                timestamp = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            else:
                # Assume UTC
                ts_clean = ts_str.split(".")[0]
                timestamp = ts_clean + "Z"
        except (ValueError, OSError):
            timestamp = _now_iso()
    else:
        timestamp = _now_iso()

    # Determine event_type
    event_type = SURICATA_EVENT_MAP.get(sev_type, f"suricata_{sev_type}" if sev_type else "network_event")

    # Build entities
    entities: dict[str, Any] = {}
    if src_ip:
        entities["src_ip"] = src_ip
    if dst_ip:
        entities["dst_ip"] = dst_ip
    if src_port is not None:
        entities["src_port"] = str(src_port)
    if dst_port is not None:
        entities["dst_port"] = str(dst_port)
    if proto:
        entities["protocol"] = proto

    # Flow ID for correlation
    if "flow_id" in data:
        entities["flow_id"] = str(data["flow_id"])

    # Event-type-specific extraction
    if sev_type == "dns":
        dns_data = data.get("dns", {})
        if isinstance(dns_data, dict):
            # Format 1: {"dns": {"query": {"rrname": "...", "rrtype": "..."}}}
            qry = dns_data.get("query", {})
            if isinstance(qry, dict):
                entities["dns_query"] = str(qry.get("rrname") or "")
                entities["query_type"] = str(qry.get("rrtype") or "")
            elif isinstance(qry, str):
                entities["dns_query"] = qry
            # Format 2: {"dns": {"rrname": "...", "rrtype": "..."}} (flat)
            if not entities.get("dns_query") and dns_data.get("rrname"):
                entities["dns_query"] = str(dns_data["rrname"])
            if not entities.get("query_type") and dns_data.get("rrtype"):
                entities["query_type"] = str(dns_data["rrtype"])
    elif sev_type == "http":
        http_data = data.get("http", {})
        if isinstance(http_data, dict):
            entities["http_method"] = str(http_data.get("http_method") or "")
            entities["http_uri"] = str(http_data.get("url") or http_data.get("http_uri") or "")
            entities["http_host"] = str(http_data.get("hostname") or "")
            entities["http_user_agent"] = str(http_data.get("http_user_agent") or "")
            entities["http_status"] = str(http_data.get("status") or "")
    elif sev_type == "tls":
        tls_data = data.get("tls", {})
        if isinstance(tls_data, dict):
            entities["tls_sni"] = str(tls_data.get("sni") or "")
            entities["tls_version"] = str(tls_data.get("version") or "")
            entities["tls_subject"] = str(tls_data.get("subject") or "")
            entities["tls_issuerdn"] = str(tls_data.get("issuerdn") or "")
    elif sev_type == "alert":
        alert_data = data.get("alert", {})
        if isinstance(alert_data, dict):
            entities["alert_signature"] = str(alert_data.get("signature") or "")
            entities["alert_category"] = str(alert_data.get("category") or "")
            entities["alert_severity"] = alert_data.get("severity")
            entities["alert_signature_id"] = str(alert_data.get("signature_id") or "")

    # Build features
    features: dict[str, Any] = {}
    if "flow" in data:
        flow = data["flow"]
        if isinstance(flow, dict):
            for fk in ("pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient", "age"):
                if fk in flow:
                    features[fk.replace("toserver", "out").replace("toclient", "in")] = flow[fk]

    if sev_type == "alert":
        features["is_suspicious"] = True
        alert_obj = data.get("alert", {})
        if isinstance(alert_obj, dict):
            maybe_sev = alert_obj.get("severity", 0)
            if isinstance(maybe_sev, (int, float)) and maybe_sev >= 2:
                features["suspicious_reason"] = f"Suricata alert severity {maybe_sev}: {alert_obj.get('signature', '')}"

    features["suricata_event_type"] = sev_type
    if "app_proto" in data:
        features["app_proto"] = data["app_proto"]

    # Build description
    desc_parts = [f"Suricata [{sev_type}]"]
    if sev_type == "alert":
        sig = entities.get("alert_signature", "")
        if sig:
            desc_parts.append(sig)
    elif src_ip and dst_ip:
        conn = f"{src_ip}"
        if src_port:
            conn += f":{src_port}"
        conn += f" -> {dst_ip}"
        if dst_port:
            conn += f":{dst_port}"
        desc_parts.append(conn)
        if proto:
            desc_parts.append(f"proto={proto}")

    return {
        "timestamp": timestamp,
        "data_source": "suricata",
        "host_ip": "",
        "host_name": host_name or "",
        "src_ip": src_ip or "",
        "dst_ip": dst_ip or "",
        "src_port": str(src_port) if src_port is not None else None,
        "dst_port": str(dst_port) if dst_port is not None else None,
        "protocol": proto or "tcp",
        "event_type": event_type,
        "entities": {k: v for k, v in entities.items() if v not in (None, "", 0)},
        "features": features,
        "description": " — ".join(desc_parts),
    }


def parse_suricata_file(
    file_path: str,
    host_name: str | None = None,
) -> list[dict]:
    """
    Parse an entire Suricata eve.json file (JSON lines format).

    Args:
        file_path: Path to eve.json
        host_name: Sensor name
    """
    if not os.path.isfile(file_path):
        logger.warning("Suricata eve.json not found: %s", file_path)
        return []

    results: list[dict] = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                parsed = parse_suricata_eve(line, host_name=host_name)
                if parsed:
                    results.append(parsed)
            except Exception:
                logger.debug("Failed to parse Suricata eve.json line", exc_info=True)
    return results
