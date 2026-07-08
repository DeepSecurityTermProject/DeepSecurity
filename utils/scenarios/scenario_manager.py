"""
场景管理器 v2 - 事件自动桥接到统一数据层
"""
import json
import threading
import hashlib
from datetime import datetime
from typing import Any

from .apt_full_chain import APTFullChainScenario
from .ai_agent_abuse import AIAgentAbuseScenario
from .ransomware_scenario import RansomwareScenario
from utils.data_bridge import get_bridge


class ScenarioManager:
    def __init__(self):
        self._scenarios: dict[str, Any] = {}
        self._event_store: list[dict] = []
        self._alert_store: list[dict] = []
        self._lock = threading.Lock()
        self._bridge = get_bridge()
        self._register_default_scenarios()

    def _register_default_scenarios(self):
        apt = APTFullChainScenario()
        ai = AIAgentAbuseScenario()
        rw = RansomwareScenario()
        apt.on_event(self._on_event)
        ai.on_event(self._on_event)
        rw.on_event(self._on_event)
        self._scenarios = {"apt_full_chain": apt, "ai_agent_abuse": ai, "ransomware": rw}

    def _on_event(self, event: dict):
        with self._lock:
            self._event_store.append(event)
            # 自动桥接到统一数据层
            ds = event.get("data_source", "host_behavior")
            table_map = {
                "host_behavior": "HostBehaviors",
                "network_traffic": "NetworkTraffic",
                "host_log": "HostLogs",
                "network_flow": "NetworkTraffic",
            }
            table = table_map.get(ds, "HostBehaviors")
            event_hash = hashlib.sha256(
                json.dumps(event, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
            ).hexdigest()
            row = {
                "id": len(self._bridge._memory_store[table]) + 1,
                "result": event,
                "content": json.dumps(event, ensure_ascii=False),
                "create_time": event.get("timestamp", datetime.now().isoformat()),
                "event_time_utc": event.get("timestamp", ""),
                "event_hash": event_hash,
                "host_ip": event.get("host_ip", ""),
                "host_name": event.get("host_name", event.get("host_ip", "")),
            }
            self._bridge.insert(table, row)
            event.setdefault("source_table", table)
            event.setdefault("source_record_id", row["id"])
            event.setdefault("event_hash", event_hash)

    def get_scenarios(self) -> list[dict]:
        return [
            {"id": sid, "name": s.name, "description": s.description,
             "type": s.scenario_type, "status": s.get_status()}
            for sid, s in self._scenarios.items()
        ]

    def start_scenario(self, scenario_id: str) -> dict:
        s = self._scenarios.get(scenario_id)
        if not s: return {"ok": False, "error": f"Unknown: {scenario_id}"}
        return s.start(delay_between_stages=2.0)

    def stop_scenario(self, scenario_id: str) -> dict:
        s = self._scenarios.get(scenario_id)
        if not s: return {"ok": False, "error": f"Unknown: {scenario_id}"}
        return s.stop()

    def stop_all(self) -> dict:
        stopped = []
        for sid, s in self._scenarios.items():
            if s._running: s.stop(); stopped.append(sid)
        return {"ok": True, "stopped": stopped}

    def get_scenario_status(self, scenario_id: str) -> dict:
        s = self._scenarios.get(scenario_id)
        if not s: return {"ok": False, "error": f"Unknown: {scenario_id}"}
        return {"ok": True, "status": s.get_status()}

    def get_all_status(self) -> dict:
        return {
            "scenarios": {sid: s.get_status() for sid, s in self._scenarios.items()},
            "total_events": len(self._event_store),
            "total_alerts": len(self._alert_store)
        }

    def get_events(self, limit: int = 100, scenario_type: str | None = None) -> list[dict]:
        with self._lock:
            events = self._event_store.copy()
        if scenario_type:
            events = [e for e in events if e.get("scenario_type") == scenario_type]
        return events[-limit:]

    def add_alert(self, alert: dict):
        with self._lock:
            alert["id"] = f"alert_{len(self._alert_store) + 1:04d}"
            alert["created_at"] = datetime.now().isoformat()
            self._alert_store.append(alert)
            self._bridge.insert("Alerts", alert)

    def get_alerts(self, limit: int = 50, severity: str | None = None,
                   scenario_type: str | None = None) -> list[dict]:
        with self._lock:
            alerts = self._alert_store.copy()
        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity]
        if scenario_type:
            alerts = [a for a in alerts if a.get("scenario_type") == scenario_type]
        return sorted(alerts, key=lambda a: a.get("created_at", ""), reverse=True)[:limit]

    def clear_events(self):
        with self._lock:
            self._event_store.clear()
            self._alert_store.clear()
            self._bridge.clear_all()

    def get_detection_stats(self) -> dict:
        with self._lock:
            alerts = self._alert_store.copy()
        by_severity = {"high": 0, "medium": 0, "low": 0}
        by_tactic: dict[str, int] = {}
        by_technique: dict[str, int] = {}
        for a in alerts:
            sev = (a.get("severity") or "low").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1
            tactic = a.get("tactic", "Unknown")
            by_tactic[tactic] = by_tactic.get(tactic, 0) + 1
            tech = a.get("technique_id", "Unknown")
            by_technique[tech] = by_technique.get(tech, 0) + 1
        return {
            "total_alerts": len(alerts),
            "by_severity": by_severity,
            "by_tactic": by_tactic,
            "by_technique": by_technique,
            "total_events": len(self._event_store)
        }


_mgr: ScenarioManager | None = None


def get_scenario_manager() -> ScenarioManager:
    global _mgr
    if _mgr is None:
        _mgr = ScenarioManager()
    return _mgr
