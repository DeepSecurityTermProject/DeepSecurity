"""
SQL Server + DataBridge fallback
When pyodbc/SQL Server is unavailable, auto-degrades to in-memory DataBridge mode.
"""
import logging
import re
import json
import time
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    import pyodbc
    from config import Config
    _HAS_PYODBC = True
except ImportError:
    _HAS_PYODBC = False
    logger.warning("pyodbc not installed, using in-memory DataBridge fallback")

from utils.data_bridge import get_bridge

_SQL_UNAVAILABLE_UNTIL = 0.0
_SQL_RETRY_COOLDOWN_SECONDS = 3.0


def _mark_sql_unavailable():
    global _SQL_UNAVAILABLE_UNTIL
    _SQL_UNAVAILABLE_UNTIL = time.monotonic() + _SQL_RETRY_COOLDOWN_SECONDS


def _clear_sql_unavailable():
    global _SQL_UNAVAILABLE_UNTIL
    _SQL_UNAVAILABLE_UNTIL = 0.0


def _get_conn(conn_str: str | None = None):
    """Get pyodbc connection, or raise if unavailable"""
    if not _HAS_PYODBC:
        raise RuntimeError("pyodbc not installed")
    if time.monotonic() < _SQL_UNAVAILABLE_UNTIL:
        raise RuntimeError("sql server temporarily unavailable")
    cstr = conn_str or Config.SQL_CONN_STR
    try:
        conn = pyodbc.connect(cstr, timeout=1)
        _clear_sql_unavailable()
        return conn
    except Exception:
        _mark_sql_unavailable()
        raise


def _parse_table(sql: str) -> str:
    """Extract table name from SQL"""
    m = re.search(r'(?:FROM|INTO|UPDATE)\s+(?:dbo\.)?(\w+)', sql, re.IGNORECASE)
    return m.group(1) if m else "unknown"


def _parse_where_equal(sql: str, params: list) -> tuple[dict, int]:
    m = re.search(r'\bWHERE\b(.*?)(?:\bORDER\b|\bGROUP\b|\bOFFSET\b|\bFETCH\b|$)', sql, re.IGNORECASE | re.DOTALL)
    if not m:
        return {}, 0
    where_sql = m.group(1).strip()
    if not where_sql:
        return {}, 0
    start_index = sql[:m.start(1)].count("?")
    parts = re.split(r'\bAND\b', where_sql, flags=re.IGNORECASE)
    where: dict[str, object] = {}
    used = 0
    for part in parts:
        p = part.strip().strip("()")
        mm = re.match(r'(?:(?:dbo\.)?(\w+))\s*=\s*\?', p, flags=re.IGNORECASE)
        if not mm:
            continue
        col = mm.group(1)
        idx = start_index + used
        if idx < len(params):
            where[col] = params[idx]
            used += 1
    return where, used


def _parse_order(sql: str) -> tuple[str, bool]:
    m = re.search(r'\bORDER\s+BY\s+(?:dbo\.)?(\w+)(?:\s+(ASC|DESC))?', sql, re.IGNORECASE)
    if not m:
        return "id", True
    col = m.group(1)
    direction = (m.group(2) or "DESC").upper()
    return col, direction != "ASC"


def _parse_limit_offset(sql: str, params: list) -> tuple[int, int]:
    top = re.search(r'\bTOP\s*\(?\s*\?\s*\)?', sql, re.IGNORECASE)
    if top:
        top_index = sql[:top.start()].count("?")
        if top_index < len(params):
            return int(params[top_index] or 0), 0

    offset_val = 0
    limit_val = 2000
    mo = re.search(r'\bOFFSET\s+(\?|\d+)\s+ROWS', sql, re.IGNORECASE)
    if mo:
        if mo.group(1) == "?":
            offset_index = sql[:mo.start(1)].count("?")
            if offset_index < len(params):
                offset_val = int(params[offset_index] or 0)
        else:
            offset_val = int(mo.group(1))

        mf = re.search(r'\bFETCH\s+NEXT\s+(\?|\d+)\s+ROWS\s+ONLY', sql, re.IGNORECASE)
        if mf:
            if mf.group(1) == "?":
                fetch_index = sql[:mf.start(1)].count("?")
                if fetch_index < len(params):
                    limit_val = int(params[fetch_index] or 0)
            else:
                limit_val = int(mf.group(1))
    else:
        m = re.search(r'TOP\s*[\(\s]*(\d+)', sql, re.IGNORECASE)
        if m:
            limit_val = int(m.group(1))
    return limit_val, offset_val



def _parse_insert_values(sql: str, params: list) -> dict:
    """Parse INSERT INTO ... VALUES and return {column: value} dict"""
    bridge = get_bridge()
    table = _parse_table(sql)

    # Extract columns
    cols_match = re.search(r'\((.*?)\)\s*VALUES', sql, re.IGNORECASE)
    if not cols_match:
        return {"_table": table, "_raw_sql": sql, "_params": str(params)}

    cols = [c.strip() for c in cols_match.group(1).split(',')]
    values = params or []

    row = {}
    for i, col in enumerate(cols):
        if i < len(values):
            row[col] = values[i]
        else:
            row[col] = None

    row["id"] = len(bridge._memory_store.get(table, [])) + 1
    row["create_time"] = str(row.get("create_time") or datetime.now().isoformat())
    return {"_table": table, "_row": row}


def execute(sql: str, params=None, conn_str: str | None = None) -> int:
    """
    Execute INSERT/UPDATE/DELETE. Tries SQL Server first, falls back to DataBridge.
    Returns affected row count.
    """
    try:
        conn = _get_conn(conn_str)
        cursor = conn.cursor()
        cursor.execute(sql, params or [])
        conn.commit()
        affected = cursor.rowcount
        cursor.close()
        conn.close()
        return affected
    except Exception as e:
        logger.debug("SQL Server execute failed, using DataBridge: %s", e)
        bridge = get_bridge()
        parsed = _parse_insert_values(sql, params or [])
        table = parsed.pop("_table", "unknown")
        row = parsed.pop("_row", parsed)
        bridge.insert(table, row)
        return 1


def fetch_one(sql: str, params=None, conn_str: str | None = None) -> dict | None:
    """Fetch one row. Tries SQL Server first, falls back to DataBridge."""
    try:
        conn = _get_conn(conn_str)
        cursor = conn.cursor()
        cursor.execute(sql, params or [])
        columns = [col[0] for col in cursor.description]
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if row:
            return dict(zip(columns, row))
        return None
    except Exception as e:
        logger.debug("SQL Server fetch_one failed, using DataBridge: %s", e)
        bridge = get_bridge()
        p = params or []
        table = _parse_table(sql)
        where, _used = _parse_where_equal(sql, p)
        order_by, desc = _parse_order(sql)
        limit, offset = _parse_limit_offset(sql, p)
        rows = bridge.query(table, where=where or None, order_by=order_by, desc=desc, limit=max(1, min(limit, 1)), offset=offset)
        return rows[0] if rows else None


def fetch_all(sql: str, params=None, conn_str: str | None = None) -> list[dict]:
    """Fetch all rows. Tries SQL Server first, falls back to DataBridge."""
    try:
        conn = _get_conn(conn_str)
        cursor = conn.cursor()
        cursor.execute(sql, params or [])
        columns = [col[0] for col in cursor.description]
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        logger.debug("SQL Server fetch_all failed, using DataBridge: %s", e)
        bridge = get_bridge()
        p = params or []
        table = _parse_table(sql)
        where, _used = _parse_where_equal(sql, p)
        order_by, desc = _parse_order(sql)
        limit, offset = _parse_limit_offset(sql, p)
        if limit <= 0:
            limit = 2000
        return bridge.query(table, where=where or None, order_by=order_by, desc=desc, limit=limit, offset=offset)


if __name__ == "__main__":
    print("Test db connect:", fetch_one("SELECT DB_NAME() AS db_name"))
    print("Test traffic query:", fetch_one("SELECT TOP 1 * FROM dbo.NetworkTraffic ORDER BY create_time DESC"))
