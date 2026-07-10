"""
Sysmon ingest service — orchestrates parsing Sysmon events into HostBehaviors table.
Follows the pattern of hostlogs_ingest.py and hostbehaviors_ingest.py.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from utils.behavior_monitor.storage.hostbehaviors_sqlserver import insert_hostbehavior
from utils.winlog.parser_sysmon import parse_sysmon_batch
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


def ingest_sysmon_events(
    *,
    events: list[dict | str],
    raw_content: str | None = None,
    host_name: str | None = None,
    host_ip: str | None = None,
) -> dict[str, int]:
    """
    Parse and ingest Sysmon events into the HostBehaviors table.

    Args:
        events: List of XML strings or pre-parsed unified dicts
        raw_content: Original raw content (XML file content, etc.)
        host_name: Override host name
        host_ip: Override host IP

    Returns:
        {collected, inserted, skipped, errors}
    """
    parsed = parse_sysmon_batch(events, host_ip=host_ip, host_name=host_name)

    inserted = 0
    skipped = 0
    errors = 0

    for ev in parsed:
        try:
            ev.setdefault("data_source", "sysmon")
            if host_name:
                ev["host_name"] = host_name
            if host_ip:
                ev["host_ip"] = host_ip

            result_json = json.dumps(ev, ensure_ascii=False, sort_keys=True)
            event_hash = _sha256_hex(result_json)

            event_dt = _parse_iso8601(str(ev.get("timestamp") or ""))
            event_time_beijing = _to_beijing_naive(event_dt)

            insert_hostbehavior(
                result_json=result_json,
                content=raw_content or json.dumps(ev, ensure_ascii=False, indent=2),
                event_hash=event_hash,
                host_name=host_name or ev.get("host_name"),
                event_time_utc=event_time_beijing,
            )
            inserted += 1
        except Exception as exc:
            msg = str(exc)
            if "2601" in msg or "2627" in msg or "UNIQUE" in msg:
                skipped += 1
                continue
            errors += 1
            logger.warning("插入 Sysmon 事件失败: %s", exc)

    # Update status tracker (record_error + record_ingestion with errors=0 to avoid double-counting)
    tracker = get_status_tracker()
    if errors > 0:
        tracker.record_error("sysmon", f"{errors} errors during Sysmon ingestion")
    tracker.record_ingestion(
        "sysmon",
        inserted=inserted,
        skipped=skipped,
        errors=0,
        host_name=host_name,
    )

    return {
        "collected": len(events),
        "inserted": inserted,
        "skipped": skipped,
        "errors": errors,
    }
