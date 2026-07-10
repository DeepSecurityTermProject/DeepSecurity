"""
Data source health tracker — thread-safe singleton.
Tracks ingestion health for all data sources (sysmon, auditd, falco, zeek, suricata, etc.)
Used by the /datasource API to report collection health, last ingestion time, and errors.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_HEALTHY_WINDOW_SECONDS = 86400   # 24 hours — data is "healthy" if ingested within this window
_WARNING_WINDOW_SECONDS = 604800  # 7 days — older than this → "warning"


class DataSourceStatusTracker:
    """Tracks collection health for all data sources. Thread-safe singleton."""

    _instance: DataSourceStatusTracker | None = None
    _lock = threading.Lock()

    def __init__(self):
        self._sources: dict[str, dict[str, Any]] = {}

    @classmethod
    def instance(cls) -> DataSourceStatusTracker:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = DataSourceStatusTracker()
        return cls._instance

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------
    def register_source(
        self,
        source_name: str,
        *,
        data_category: str = "host_behavior",
        display_name: str = "",
        description: str = "",
    ) -> None:
        """Register a data source so it shows up in status even before any data arrives."""
        with self._lock:
            if source_name not in self._sources:
                self._sources[source_name] = {
                    "source_name": source_name,
                    "display_name": display_name or source_name,
                    "data_category": data_category,
                    "description": description,
                    "status": "unknown",
                    "last_ingestion_time": None,
                    "last_error": None,
                    "last_error_time": None,
                    "total_inserted": 0,
                    "total_skipped": 0,
                    "total_errors": 0,
                    "consecutive_errors": 0,
                    "host_name": None,
                }

    # ------------------------------------------------------------------
    # Record operations
    # ------------------------------------------------------------------
    def record_ingestion(
        self,
        source_name: str,
        *,
        inserted: int = 0,
        skipped: int = 0,
        errors: int = 0,
        host_name: str | None = None,
    ) -> None:
        """Record an ingestion batch result.

        IMPORTANT: Callers that already called record_error() for the same batch
        MUST pass errors=0 to avoid double-counting. Use one of these patterns:

          Pattern A (preferred): record_error() then record_ingestion(errors=0)
          Pattern B (simple):     record_ingestion(errors=N) without record_error

        Error state (last_error, last_error_time) and consecutive_errors are
        only cleared when inserted > 0 AND errors == 0 (fully successful batch).
        """
        now = _utc_now_iso()
        with self._lock:
            src = self._sources.setdefault(source_name, {})
            src.setdefault("source_name", source_name)
            src.setdefault("display_name", source_name)
            src.setdefault("data_category", "unknown")
            src["last_ingestion_time"] = now
            src["total_inserted"] = src.get("total_inserted", 0) + inserted
            src["total_skipped"] = src.get("total_skipped", 0) + skipped
            src["host_name"] = host_name or src.get("host_name")
            src["total_errors"] = src.get("total_errors", 0) + errors

            if inserted > 0 and errors == 0:
                # Fully successful batch — reset error state
                src["consecutive_errors"] = 0
                src["last_error"] = None
                src["last_error_time"] = None
            elif errors > 0:
                src["consecutive_errors"] = src.get("consecutive_errors", 0) + 1
            # else: inserted == 0 and errors == 0 — no change to error state

            src["status"] = self._compute_health(src)

    def record_error(self, source_name: str, error_msg: str) -> None:
        """Record an ingestion error.

        Call this BEFORE record_ingestion() for the same batch with errors=0,
        so that total_errors is not double-counted.

        Alternatively, just call record_ingestion(errors=N) without record_error.
        """
        now = _utc_now_iso()
        with self._lock:
            src = self._sources.setdefault(source_name, {})
            src.setdefault("source_name", source_name)
            src.setdefault("display_name", source_name)
            src.setdefault("data_category", "unknown")
            src["last_error"] = error_msg[:500]
            src["last_error_time"] = now
            src["consecutive_errors"] = src.get("consecutive_errors", 0) + 1
            src["total_errors"] = src.get("total_errors", 0) + 1
            src["status"] = self._compute_health(src)

    # ------------------------------------------------------------------
    # Health query
    # ------------------------------------------------------------------
    def _compute_health(self, src: dict[str, Any]) -> str:
        consecutive = src.get("consecutive_errors", 0)
        last_time = src.get("last_ingestion_time")

        if last_time is None:
            if src.get("total_inserted", 0) > 0:
                # Has data but no timestamp — treat as warning
                return "warning"
            return "unknown"

        # Consecutive errors >= 3 → "error"
        if consecutive >= 3:
            return "error"

        # Check freshness
        try:
            if last_time.endswith("Z"):
                ts = datetime.strptime(last_time, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            else:
                ts = datetime.fromisoformat(last_time.replace("+00:00", ""))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            return "unknown"

        age_sec = (datetime.now(timezone.utc) - ts).total_seconds()
        if age_sec < _HEALTHY_WINDOW_SECONDS:
            return "healthy"
        elif age_sec < _WARNING_WINDOW_SECONDS:
            return "warning"
        else:
            return "error"

    def get_status(self, source_name: str | None = None) -> dict[str, Any]:
        """Return status for one source (or all if source_name is None)."""
        with self._lock:
            if source_name:
                src = self._sources.get(source_name)
                if src is None:
                    return {}
                return dict(src)
            return {name: dict(s) for name, s in self._sources.items()}

    def get_all_status_list(self) -> list[dict[str, Any]]:
        """Return list of all source statuses (for API responses)."""
        with self._lock:
            return [dict(s) for s in self._sources.values()]

    def get_summary(self) -> dict[str, Any]:
        """Return a high-level summary suitable for dashboard."""
        with self._lock:
            total = len(self._sources)
            healthy = sum(1 for s in self._sources.values() if s.get("status") == "healthy")
            warning = sum(1 for s in self._sources.values() if s.get("status") == "warning")
            error = sum(1 for s in self._sources.values() if s.get("status") == "error")
            unknown = total - healthy - warning - error
            total_inserted = sum(s.get("total_inserted", 0) for s in self._sources.values())
            return {
                "total_sources": total,
                "healthy": healthy,
                "warning": warning,
                "error": error,
                "unknown": unknown,
                "total_events_inserted": total_inserted,
            }

    # ------------------------------------------------------------------
    # Reset
    # ------------------------------------------------------------------
    def clear(self):
        with self._lock:
            self._sources.clear()

    def reset_source(self, source_name: str):
        with self._lock:
            self._sources.pop(source_name, None)


# Global singleton accessor
def get_status_tracker() -> DataSourceStatusTracker:
    return DataSourceStatusTracker.instance()


# Pre-register the known data sources so they show up in status immediately
def _register_default_sources():
    tracker = get_status_tracker()
    defaults = [
        ("sysmon", "Sysmon (Windows)", "host_behavior", "Windows Sysmon endpoint monitoring"),
        ("auditd", "Linux Auditd", "host_behavior", "Linux Auditd system call auditing"),
        ("falco", "Falco (Linux)", "host_behavior", "Falco runtime security monitoring"),
        ("zeek", "Zeek (Network)", "network_traffic", "Zeek network security monitor"),
        ("suricata", "Suricata (Network)", "network_traffic", "Suricata IDS/IPS/NSM"),
        ("windows_eventlog", "Windows Event Log", "host_log", "Windows Event Log collection"),
        ("pcap", "PCAP (Network)", "network_traffic", "PCAP file / live capture ingestion"),
    ]
    for name, display, category, desc in defaults:
        tracker.register_source(name, data_category=category, display_name=display, description=desc)


_register_default_sources()
