"""
Auditd & Falco ingest service — orchestrates parsing and inserting into HostBehaviors table.
Follows the pattern of hostbehaviors_ingest.py.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from utils.behavior_monitor.storage.hostbehaviors_sqlserver import insert_hostbehavior
from utils.behavior_monitor.parser_auditd_falco import parse_auditd_line, parse_falco_event
from utils.datasource_status import get_status_tracker

logger = logging.getLogger(__name__)

BEIJING_TZ = timezone(timedelta(hours=8))


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_iso8601(timestamp_value: str | None) -> datetime | None:
    if not timestamp_value:
        return None
    text = str(timestamp_value).strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _to_beijing_naive(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.astimezone(BEIJING_TZ).replace(tzinfo=None)


def _insert_single(event: dict, raw_content: str | None, host_name: str | None) -> tuple[int, int, int]:
    """Insert one parsed event. Returns (inserted, skipped, errors)."""
    try:
        result_json = json.dumps(event, ensure_ascii=False, sort_keys=True)
        event_hash = _sha256_hex(result_json)

        event_dt = _parse_iso8601(str(event.get("timestamp") or ""))
        event_time_beijing = _to_beijing_naive(event_dt)

        insert_hostbehavior(
            result_json=result_json,
            content=raw_content or json.dumps(event, ensure_ascii=False, indent=2),
            event_hash=event_hash,
            host_name=host_name or event.get("host_name"),
            event_time_utc=event_time_beijing,
        )
        return 1, 0, 0
    except Exception as exc:
        msg = str(exc)
        if "2601" in msg or "2627" in msg or "UNIQUE" in msg:
            return 0, 1, 0
        logger.warning("插入行为事件失败: %s", exc)
        return 0, 0, 1


# ── Auditd ────────────────────────────────────────────────────────────


def ingest_auditd_events(
    *,
    events: list[str],
    raw_content: str | None = None,
    host_name: str | None = None,
    host_ip: str | None = None,
) -> dict[str, int]:
    """
    Parse and ingest Auditd raw log lines into HostBehaviors.

    Args:
        events: List of raw Auditd log lines (strings)
        raw_content: Original raw content
        host_name: Override host name
        host_ip: Override host IP

    Returns:
        {collected, inserted, skipped, errors}
    """
    total_collected = 0
    inserted = 0
    skipped = 0
    errors = 0

    for line in events:
        if not line or not isinstance(line, str):
            continue
        total_collected += 1

        parsed = parse_auditd_line(line.strip(), host_ip=host_ip, host_name=host_name)
        if not parsed:
            # Line format not recognized — not an error
            continue

        parsed.setdefault("data_source", "auditd")
        if host_name:
            parsed["host_name"] = host_name
        if host_ip:
            parsed["host_ip"] = host_ip

        ins, skp, err = _insert_single(parsed, raw_content or line, host_name)
        inserted += ins
        skipped += skp
        errors += err

    tracker = get_status_tracker()
    if errors > 0:
        tracker.record_error("auditd", f"{errors} errors during Auditd ingestion")
    tracker.record_ingestion(
        "auditd", inserted=inserted, skipped=skipped, errors=0, host_name=host_name,
    )

    return {"collected": total_collected, "inserted": inserted, "skipped": skipped, "errors": errors}


# ── Falco ─────────────────────────────────────────────────────────────


def ingest_falco_events(
    *,
    events: list[str],
    raw_content: str | None = None,
    host_name: str | None = None,
    host_ip: str | None = None,
) -> dict[str, int]:
    """
    Parse and ingest Falco JSON alert lines into HostBehaviors.

    Args:
        events: List of Falco JSON strings (one per line)
        raw_content: Original raw content
        host_name: Override host name
        host_ip: Override host IP

    Returns:
        {collected, inserted, skipped, errors}
    """
    total_collected = 0
    inserted = 0
    skipped = 0
    errors = 0

    for line in events:
        if not line or not isinstance(line, str):
            continue
        total_collected += 1

        parsed = parse_falco_event(line.strip(), host_ip=host_ip, host_name=host_name)
        if not parsed:
            continue

        parsed.setdefault("data_source", "falco")
        if host_name:
            parsed["host_name"] = host_name
        if host_ip:
            parsed["host_ip"] = host_ip

        ins, skp, err = _insert_single(parsed, raw_content or line, host_name)
        inserted += ins
        skipped += skp
        errors += err

    tracker = get_status_tracker()
    if errors > 0:
        tracker.record_error("falco", f"{errors} errors during Falco ingestion")
    tracker.record_ingestion(
        "falco", inserted=inserted, skipped=skipped, errors=0, host_name=host_name,
    )

    return {"collected": total_collected, "inserted": inserted, "skipped": skipped, "errors": errors}
