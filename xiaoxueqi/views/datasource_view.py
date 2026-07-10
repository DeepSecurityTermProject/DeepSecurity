"""
数据源状态与接入视图

提供 API：
  GET  /datasource/api/status                   所有数据源健康状态
  GET  /datasource/api/status/<source_name>      单个数据源状态
  POST /datasource/api/ingest/sysmon             上传 Sysmon 数据
  POST /datasource/api/ingest/auditd             上传 Auditd 数据
  POST /datasource/api/ingest/falco              上传 Falco 数据
  POST /datasource/api/ingest/zeek               上传 Zeek 数据
  POST /datasource/api/ingest/suricata           上传 Suricata 数据
  POST /datasource/api/ingest/sample             加载样例数据（单源或全部）
   GET  /datasource/                              数据源状态页面
"""
from __future__ import annotations

import json
import logging
import os
import tempfile

from flask import Blueprint, current_app, jsonify, render_template, request

from utils.datasource_status import get_status_tracker
from utils.sample_data_loader import load_sample, load_all_samples

bp = Blueprint("datasource", __name__)
logger = logging.getLogger(__name__)


def _get_logger() -> logging.Logger:
    try:
        return current_app.logger
    except RuntimeError:
        return logger


# ═══════════════════════════════════════════════════════════════════════
# Status API
# ═══════════════════════════════════════════════════════════════════════


@bp.route("/api/status", methods=["GET"])
def api_status():
    """返回所有已注册数据源的健康状态"""
    tracker = get_status_tracker()
    sources = tracker.get_all_status_list()
    summary = tracker.get_summary()
    return jsonify({"ok": True, "sources": sources, "summary": summary})


@bp.route("/api/status/<source_name>", methods=["GET"])
def api_status_source(source_name: str):
    """返回单个数据源状态"""
    tracker = get_status_tracker()
    status = tracker.get_status(source_name)
    if not status:
        return jsonify({"ok": False, "error": f"unknown source: {source_name}"}), 404
    return jsonify({"ok": True, "source": status})


# ═══════════════════════════════════════════════════════════════════════
# Ingestion APIs (raw data)
# ═══════════════════════════════════════════════════════════════════════


def _parse_source_result(result: dict, source_name: str) -> tuple[dict, int]:
    """Normalize ingest result dict for API response.

    Returns (body, http_status).
    - 200: at least one event was inserted successfully
    - 400: input was collected but nothing could be parsed/inserted
    """
    inserted = result.get("inserted", 0)
    collected = result.get("collected", result.get("inserted", 0))
    errors = result.get("errors", 0)
    error_msg = result.get("error", "")

    ok = inserted > 0
    if not ok:
        if collected > 0 and inserted == 0:
            error_msg = error_msg or "所有输入事件均无法解析，未入库任何数据"
        elif collected == 0 and errors > 0:
            error_msg = error_msg or "数据加载失败"

    body = {
        "ok": ok,
        "source": source_name,
        "inserted": inserted,
        "skipped": result.get("skipped", 0),
        "errors": errors,
        "collected": collected,
    }
    if error_msg:
        body["error"] = error_msg

    status_code = 400 if not ok else 200
    return body, status_code


@bp.route("/api/ingest/sysmon", methods=["POST"])
def api_ingest_sysmon():
    """
    接收 Sysmon XML 数据并入库。
    支持格式:
      - JSON body: {"events": ["<xml>...", ...], "host_name": "..."}
      - File upload: multipart/form-data with "file" field
    """
    from utils.winlog.service.sysmon_ingest import ingest_sysmon_events

    host_name = None
    events: list[str] = []

    if request.is_json:
        data = request.get_json(silent=True) or {}
        host_name = (data.get("host_name") or "").strip() or None
        raw_events = data.get("events") or data.get("data") or []
        if isinstance(raw_events, list):
            events = [str(e) for e in raw_events if e]
    elif "file" in request.files:
        host_name = (request.form.get("host_name") or "").strip() or None
        f = request.files["file"]
        content = f.read().decode("utf-8", errors="replace")
        # Try JSON array, else treat as newline-separated XML
        try:
            arr = json.loads(content)
            if isinstance(arr, list):
                events = [item.get("xml", "") or json.dumps(item) for item in arr]
            else:
                events = [content]
        except json.JSONDecodeError:
            events = [content]
    else:
        return jsonify({"ok": False, "error": "no JSON body or file upload"}), 400

    if not events:
        return jsonify({"ok": False, "error": "no events provided"}), 400

    try:
        result = ingest_sysmon_events(events=events, host_name=host_name or "sysmon-upload")
        body, status = _parse_source_result(result, "sysmon")
        return jsonify(body), status
    except Exception as exc:
        _get_logger().exception("Sysmon ingestion failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/api/ingest/auditd", methods=["POST"])
def api_ingest_auditd():
    """接收 Auditd 原始日志行并入库"""
    from utils.behavior_monitor.service.auditd_ingest import ingest_auditd_events

    if not request.is_json:
        return jsonify({"ok": False, "error": "JSON body required"}), 400

    data = request.get_json(silent=True) or {}
    host_name = (data.get("host_name") or "").strip() or None
    raw = data.get("events") or data.get("lines") or data.get("data") or []

    lines: list[str] = []
    if isinstance(raw, str):
        lines = raw.splitlines()
    elif isinstance(raw, list):
        lines = [str(item.get("line", item)) if isinstance(item, dict) else str(item) for item in raw]
    else:
        return jsonify({"ok": False, "error": "invalid events format"}), 400

    if not lines:
        return jsonify({"ok": False, "error": "no events provided"}), 400

    try:
        result = ingest_auditd_events(events=lines, host_name=host_name or "linux-auditd")
        body, status = _parse_source_result(result, "auditd")
        return jsonify(body), status
    except Exception as exc:
        _get_logger().exception("Auditd ingestion failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/api/ingest/falco", methods=["POST"])
def api_ingest_falco():
    """接收 Falco JSON 告警并入库"""
    from utils.behavior_monitor.service.auditd_ingest import ingest_falco_events

    if not request.is_json:
        return jsonify({"ok": False, "error": "JSON body required"}), 400

    data = request.get_json(silent=True) or {}
    host_name = (data.get("host_name") or "").strip() or None
    raw = data.get("events") or data.get("data") or []

    lines: list[str] = []
    if isinstance(raw, str):
        lines = [raw]
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                lines.append(item.get("json", "") or json.dumps(item))
            elif isinstance(item, str):
                lines.append(item)

    if not lines:
        return jsonify({"ok": False, "error": "no events provided"}), 400

    try:
        result = ingest_falco_events(events=lines, host_name=host_name or "linux-falco")
        body, status = _parse_source_result(result, "falco")
        return jsonify(body), status
    except Exception as exc:
        _get_logger().exception("Falco ingestion failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/api/ingest/zeek", methods=["POST"])
def api_ingest_zeek():
    """接收 Zeek .log 文件上传并入库"""
    from utils.traffic_fenxi.ingest_zeek_suricata import ingest_zeek_log_lines

    host_name = None
    log_type = "conn"
    lines: list[str] = []

    if "file" in request.files:
        host_name = (request.form.get("host_name") or "").strip() or None
        log_type = (request.form.get("log_type") or "conn").strip()
        f = request.files["file"]
        content = f.read().decode("utf-8", errors="replace")
        lines = content.splitlines()
    elif request.is_json:
        data = request.get_json(silent=True) or {}
        host_name = (data.get("host_name") or "").strip() or None
        log_type = (data.get("log_type") or "conn").strip()
        raw = data.get("lines") or data.get("data") or []
        if isinstance(raw, str):
            lines = raw.splitlines()
        elif isinstance(raw, list):
            lines = [str(item) for item in raw]
    else:
        return jsonify({"ok": False, "error": "no file upload or JSON body"}), 400

    if not lines:
        return jsonify({"ok": False, "error": "no log lines provided"}), 400

    try:
        result = ingest_zeek_log_lines(lines=lines, host_name=host_name or "zeek-sensor", log_type=log_type)
        body, status = _parse_source_result(result, "zeek")
        return jsonify(body), status
    except Exception as exc:
        _get_logger().exception("Zeek ingestion failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/api/ingest/suricata", methods=["POST"])
def api_ingest_suricata():
    """接收 Suricata eve.json 上传并入库"""
    from utils.traffic_fenxi.ingest_zeek_suricata import ingest_suricata_lines

    host_name = None
    lines: list[str] = []

    if "file" in request.files:
        host_name = (request.form.get("host_name") or "").strip() or None
        f = request.files["file"]
        content = f.read().decode("utf-8", errors="replace")
        lines = content.splitlines()
    elif request.is_json:
        data = request.get_json(silent=True) or {}
        host_name = (data.get("host_name") or "").strip() or None
        raw = data.get("lines") or data.get("data") or []
        if isinstance(raw, str):
            lines = raw.splitlines()
        elif isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    lines.append(item.get("json", "") or json.dumps(item))
                elif isinstance(item, str):
                    lines.append(item)
    else:
        return jsonify({"ok": False, "error": "no file upload or JSON body"}), 400

    if not lines:
        return jsonify({"ok": False, "error": "no events provided"}), 400

    try:
        result = ingest_suricata_lines(lines=lines, host_name=host_name or "suricata-sensor")
        body, status = _parse_source_result(result, "suricata")
        return jsonify(body), status
    except Exception as exc:
        _get_logger().exception("Suricata ingestion failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


# ═══════════════════════════════════════════════════════════════════════
# Sample data loader
# ═══════════════════════════════════════════════════════════════════════


@bp.route("/api/samples/load", methods=["POST"])
def api_load_samples():
    """
    加载样例数据入库（用于演示/验证）

    POST body:
      {"source": "sysmon"}   — 加载单个数据源
      {}                      — 加载所有数据源
      {"source": "all"}      — 加载所有数据源

    返回: {ok, results: {source_name: {inserted, skipped, errors}, ...}}
    """
    data = request.get_json(silent=True) or {}
    source = (data.get("source") or "").strip().lower()

    try:
        if source and source != "all":
            result = load_sample(source)
            ok = result.get("inserted", 0) > 0
            return jsonify({"ok": ok, "results": {source: result}})
        else:
            results = load_all_samples()
            # A batch is fully successful only if every source inserted > 0
            all_ok = all(
                r.get("inserted", 0) > 0
                for r in results.values()
            )
            # Build per-source error details for failed sources
            failed_sources = [
                name for name, r in results.items()
                if r.get("inserted", 0) == 0
            ]
            body = {"ok": all_ok, "results": results}
            if failed_sources:
                body["failed_sources"] = failed_sources
                body["error"] = f"以下数据源加载失败: {', '.join(failed_sources)}"
            return jsonify(body)
    except Exception as exc:
        _get_logger().exception("Sample data loading failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@bp.route("/api/samples/list", methods=["GET"])
def api_list_samples():
    """列出可用的样例数据文件"""
    sample_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "data", "samples",
    )
    samples: dict[str, list[str]] = {}
    if os.path.isdir(sample_dir):
        for fname in os.listdir(sample_dir):
            full = os.path.join(sample_dir, fname)
            if os.path.isfile(full):
                # Group by prefix
                prefix = fname.split("_")[0] if "_" in fname else fname.split(".")[0]
                samples.setdefault(prefix, []).append(fname)
    return jsonify({"ok": True, "samples": samples})


# ═══════════════════════════════════════════════════════════════════════
# HTML page
# ═══════════════════════════════════════════════════════════════════════


@bp.route("/", methods=["GET"])
def index():
    """数据源状态页面"""
    tracker = get_status_tracker()
    sources = tracker.get_all_status_list()
    summary = tracker.get_summary()
    return render_template(
        "datasource.html",
        sources=sources,
        summary=summary,
    )
