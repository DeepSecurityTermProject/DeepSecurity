"""
统一数据访问层 - 桥接模拟模式与真实数据库模式
当 SQL Server / Neo4j 不可用时，自动降级为内存模拟模式
"""
import json
import uuid
import threading
from datetime import datetime
from typing import Any


class DataBridge:
    """统一数据访问桥接器"""

    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self.mode = "simulation"  # simulation | real
        self._memory_store: dict[str, list[dict]] = {
            "HostLogs": [],
            "HostBehaviors": [],
            "NetworkTraffic": [],
            "AttackReports": [],
            "Alerts": [],
            "EvidenceCases": [],
            "EvidenceRecords": [],
        }
        self._checkpoints: dict[str, int] = {}

    @classmethod
    def instance(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = DataBridge()
        return cls._instance

    # ---- Write ----
    def insert(self, table: str, data: dict | list[dict]):
        items = data if isinstance(data, list) else [data]
        for item in items:
            item.setdefault("id", len(self._memory_store.get(table, [])) + 1)
            item.setdefault("create_time", datetime.now().isoformat())
            if table in self._memory_store:
                self._memory_store[table].append(item)

    # ---- Read ----
    def query(self, table: str, where: dict | None = None,
              order_by: str = "id", desc: bool = True,
              limit: int = 100, offset: int = 0) -> list[dict]:
        rows = self._memory_store.get(table, [])
        if where:
            rows = [r for r in rows if all(
                str(r.get(k)) == str(v) for k, v in where.items()
            )]
        rows = sorted(rows, key=lambda r: r.get(order_by, 0), reverse=desc)
        return rows[offset:offset + limit]

    def count(self, table: str, where: dict | None = None) -> int:
        return len(self.query(table, where, limit=999999))

    # ---- Checkpoints ----
    def get_checkpoint(self, table: str) -> int:
        return self._checkpoints.get(table, 0)

    def set_checkpoint(self, table: str, checkpoint: int):
        self._checkpoints[table] = checkpoint

    # ---- New data fetch (simulating incremental reads) ----
    def fetch_new(self, table: str, last_id: int) -> tuple[list[dict], int]:
        rows = self._memory_store.get(table, [])
        new_rows = [r for r in rows if r.get("id", 0) > last_id]
        new_id = max([r.get("id", 0) for r in rows]) if rows else last_id
        return new_rows, new_id

    # ---- Dashboard KPI ----
    def get_kpi(self) -> dict:
        return {
            "HostLogs": self.count("HostLogs"),
            "HostBehaviors": self.count("HostBehaviors"),
            "NetworkTraffic": self.count("NetworkTraffic"),
            "AttackReports": self.count("AttackReports"),
            "Alerts": self.count("Alerts"),
            "EvidenceCases": self.count("EvidenceCases"),
            "freshness": {
                "HostLogs": datetime.now().isoformat(),
                "HostBehaviors": datetime.now().isoformat(),
                "NetworkTraffic": datetime.now().isoformat(),
            }
        }

    # ---- Clear all ----
    def clear_all(self):
        for k in self._memory_store:
            self._memory_store[k] = []
        self._checkpoints = {}

    # ---- Get events for detection ----
    def get_all_events(self) -> list[dict]:
        """合并所有数据源的事件"""
        events = []
        for row in self._memory_store.get("HostBehaviors", []):
            evt = row.get("result", row)
            if isinstance(evt, str):
                try: evt = json.loads(evt)
                except: continue
            evt.setdefault("data_source", "host_behavior")
            events.append(evt)
        for row in self._memory_store.get("NetworkTraffic", []):
            evt = row.get("result", row)
            if isinstance(evt, str):
                try: evt = json.loads(evt)
                except: continue
            evt.setdefault("data_source", "network_traffic")
            events.append(evt)
        for row in self._memory_store.get("HostLogs", []):
            evt = row.get("result", row)
            if isinstance(evt, str):
                try: evt = json.loads(evt)
                except: continue
            evt.setdefault("data_source", "host_log")
            events.append(evt)
        return events


# 全局单例
def get_bridge() -> DataBridge:
    return DataBridge.instance()
