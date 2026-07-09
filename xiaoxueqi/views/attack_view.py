from __future__ import annotations

import threading
import os
import json

from flask import Blueprint, jsonify, render_template, request

from utils.trace.Graph_Serializer import GraphSerializer
import utils.trace.main_pipeline as main_pipeline
from utils.trace.service.attack_reports_store import get_latest_attack_reports, parse_report_json
from utils.db.db import fetch_all, fetch_one
from utils.data_bridge import get_bridge

bp = Blueprint("attack", __name__)

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASSWORD", "")

serializer = GraphSerializer(NEO4J_URI, NEO4J_USER, NEO4J_PASS)

_pipeline_thread: threading.Thread | None = None


@bp.route("/", methods=["GET"])
def index():
    return render_template("attack_chain.html")


@bp.route("/api/reports", methods=["GET"])
def api_reports():
    page = request.args.get("page", 1, type=int)
    page = max(page, 1)
    limit = request.args.get("limit", 10, type=int)
    limit = max(5, min(limit, 50))
    offset = (page - 1) * limit

    victim_ip = (request.args.get("ip") or "").strip() or None
    confidence = (request.args.get("confidence") or "").strip() or None

    filters = []
    params = []
    if victim_ip:
        filters.append("victim_ip = ?")
        params.append(victim_ip)
    if confidence:
        filters.append("confidence = ?")
        params.append(confidence)

    where_clause = ("WHERE " + " AND ".join(filters)) if filters else ""

    all_rows: list[dict] = []

    # 1) Try SQL Server
    try:
        total_row = fetch_one(f"SELECT COUNT(1) AS total FROM dbo.AttackReports {where_clause}", params)
        rows = fetch_all(
            f"""
            SELECT id, scenario_id, victim_ip, attacker_ip, start_time, end_time,
                   confidence, attribution_type, attribution_name, created_at
            FROM dbo.AttackReports
            {where_clause}
            ORDER BY created_at DESC
            OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
            """,
            params + [offset, limit],
        )
        all_rows.extend(rows)
    except Exception:
        pass

    # 2) Always merge DataBridge (memory) — captures scenario & multi-source reports
    try:
        bridge = get_bridge()
        db_rows = bridge.query("AttackReports", order_by="created_at", desc=True, limit=200)
        for r in db_rows:
            if not any(str(existing.get("id")) == str(r.get("id")) for existing in all_rows):
                all_rows.append(r)
        # Also merge AnalysisReports
        ar_rows = bridge.query("AnalysisReports", order_by="created_at", desc=True, limit=200)
        for r in ar_rows:
            all_rows.append({
                "id": r.get("id", 0) + 200000,
                "scenario_id": r.get("report_id", ""),
                "victim_ip": "",
                "attacker_ip": "",
                "confidence": r.get("confidence", ""),
                "attribution_type": "Multi-Source LLM",
                "attribution_name": r.get("data_sources", ""),
                "created_at": r.get("created_at", ""),
            })
    except Exception:
        pass

    # 3) Filter, sort, paginate
    if victim_ip:
        all_rows = [r for r in all_rows if str(r.get("victim_ip", "")) == victim_ip]
    if confidence:
        all_rows = [r for r in all_rows if str(r.get("confidence", "")) == confidence]
    all_rows.sort(key=lambda x: str(x.get("created_at", "")), reverse=True)
    total = len(all_rows)
    rows = all_rows[offset:offset + limit]
    return jsonify({"ok": True, "total": total, "page": page, "limit": limit, "data": rows})


@bp.route("/api/report/<scenario_id>", methods=["GET"])
def api_report_detail(scenario_id: str):
    # Search: AttackReports by scenario_id, AnalysisReports by report_id
    report_data = None

    # 1) Try SQL Server AttackReports
    try:
        row = fetch_one(
            "SELECT TOP 1 * FROM dbo.AttackReports WHERE scenario_id = ? ORDER BY created_at DESC",
            [scenario_id],
        )
        if row:
            return jsonify({"ok": True, "row": row, "report": parse_report_json(row.get("report_json", ""))})
    except Exception:
        pass

    # 2) Try DataBridge AttackReports
    bridge = get_bridge()
    for table in ["AttackReports", "AnalysisReports"]:
        rows = bridge.query(table, limit=100)
        for r in rows:
            rid = str(r.get("scenario_id") or r.get("report_id") or "")
            if rid == scenario_id:
                report_data = r
                break
        if report_data:
            break

    if not report_data:
        return jsonify({"ok": False, "error": "Report not found"}), 404

    report_json = report_data.get("report_json", {})
    if isinstance(report_json, str):
        try: report_json = json.loads(report_json)
        except: report_json = {}

    # Merge top-level fields from report_data into report for frontend consistency
    merged = dict(report_json) if isinstance(report_json, dict) else {}
    for k in ("report_id", "llm_analysis", "llm_model", "total_events", "techniques_found",
              "data_sources", "confidence", "time_start", "time_end",
              "scenario_id", "scenario_type", "victim_ip", "attacker_ip",
              "attack_chain", "iocs", "attribution_name", "attribution_type"):
        v = report_data.get(k)
        if v is not None and k not in merged:
            merged[k] = v

    return jsonify({"ok": True, "row": report_data, "report": merged})


@bp.route("/api/graph/<scenario_id>/summary", methods=["GET"])
def api_graph_summary(scenario_id: str):
    try:
        data = serializer.get_attack_chain_summary(scenario_id)
        # 如果有数据返回，加入 mode 标记
        if data.get("nodes") or data.get("edges"):
            return jsonify({"ok": True, "data": data, "mode": "neo4j"})
    except Exception as e:
        pass

    # Neo4j 不可用或没有数据，从 DataBridge 构建简单图
    bridge = get_bridge()
    reports = bridge.query("AttackReports", where={"scenario_id": scenario_id}, limit=1)
    nodes = []
    edges = []
    if reports:
        report = reports[0].get("report_json", {})
        if isinstance(report, str):
            try: report = json.loads(report)
            except: report = {}
        chain = report.get("attack_chain", [])
        for i, tech in enumerate(chain):
            node = {"id": f"tech_{i}", "label": tech, "type": "technique"}
            # 尝试从链式条目中提取技术ID
            if ": " in tech:
                parts = tech.split(": ", 1)
                node["label"] = parts[1]
                node["title"] = f"TID: {parts[0]}\nTechnique: {parts[1]}"
            nodes.append(node)
            if i > 0:
                edges.append({
                    "source": f"tech_{i-1}", "target": f"tech_{i}",
                    "label": "NEXT", "edge_type": "temporal",
                    "confidence": "Low", "evidence_source": "simulation"
                })
        victim = report.get("victim_ip", "?")
        attacker = report.get("attacker_ip", "?")
        nodes.append({"id": "victim", "label": f"Victim: {victim}", "type": "host"})
        nodes.append({"id": "attacker", "label": f"Attacker: {attacker}", "type": "threat"})
        if chain:
            edges.append({"source": "attacker", "target": "tech_0",
                          "label": "INITIATES", "edge_type": "init",
                          "confidence": "High", "evidence_source": "simulation"})
            edges.append({"source": f"tech_{len(chain)-1}", "target": "victim",
                          "label": "TARGETS", "edge_type": "target",
                          "confidence": "High", "evidence_source": "simulation"})
    return jsonify({"ok": True, "data": {"nodes": nodes, "edges": edges}, "mode": "simulation"})


@bp.route("/api/graph/<scenario_id>/topology", methods=["GET"])
def api_graph_topology(scenario_id: str):
    try:
        data = serializer.get_scenario_topology(scenario_id)
        if data.get("nodes") or data.get("edges"):
            return jsonify({"ok": True, "data": data, "mode": "neo4j"})
    except Exception:
        pass

    # Neo4j 不可用，降级
    return jsonify({"ok": True, "data": {"nodes": [], "edges": []}, "mode": "simulation"})


# =========================================================================
# [新增 API] 横向移动路径
# =========================================================================
@bp.route("/api/graph/<scenario_id>/lateral", methods=["GET"])
def api_graph_lateral(scenario_id: str):
    """获取指定场景的横向移动路径"""
    try:
        data = serializer.get_lateral_movement_paths(scenario_id)
        if data.get("lateral_paths"):
            return jsonify({"ok": True, "data": data, "mode": "neo4j"})
    except Exception:
        pass

    # Fallback: 从 DataBridge 报告提取
    bridge = get_bridge()
    reports = bridge.query("AttackReports", where={"scenario_id": scenario_id}, limit=1)
    lateral_paths = []
    if reports:
        report = reports[0].get("report_json", {})
        if isinstance(report, str):
            try: report = json.loads(report)
            except: report = {}
        rca = report.get("root_cause_analysis", {})
        intruder_ip = rca.get("intruder_ip", "")
        victim_ip = reports[0].get("victim_ip", "")
        if intruder_ip and victim_ip:
            lateral_paths.append({
                "source_host": intruder_ip,
                "target_host": victim_ip,
                "credential": rca.get("user", ""),
                "technique": "Remote Services (simulated)",
                "timestamp": reports[0].get("start_time", ""),
                "description": f"Simulated lateral movement from {intruder_ip} to {victim_ip}"
            })
    return jsonify({"ok": True, "data": {"lateral_paths": lateral_paths}, "mode": "simulation"})


# =========================================================================
# [新增 API] 边证据详情
# =========================================================================
@bp.route("/api/graph/edge/evidence", methods=["GET"])
def api_edge_evidence():
    """获取两条 AttackEvent 之间边的详细信息（证据来源、置信度、时间间隔）"""
    from_id = request.args.get("from_id", "")
    to_id = request.args.get("to_id", "")
    rel_type = request.args.get("rel_type", None)

    if not from_id or not to_id:
        return jsonify({"ok": False, "error": "Missing from_id or to_id"}), 400

    try:
        if rel_type:
            data = serializer.get_edge_evidence(from_id, to_id, rel_type)
        else:
            data = serializer.get_edge_evidence(from_id, to_id)
        if data.get("evidence"):
            return jsonify({"ok": True, "data": data})
    except Exception:
        pass

    # Fallback
    return jsonify({"ok": True, "data": {"evidence": {
        "type": "simulated",
        "confidence": "Medium",
        "evidence_source": "simulation_fallback",
        "description": "No detailed edge evidence available (Neo4j unavailable)"
    }}})


# =========================================================================
# [新增 API] 场景所有边详情
# =========================================================================
@bp.route("/api/graph/<scenario_id>/edges", methods=["GET"])
def api_scenario_edges(scenario_id: str):
    """获取场景中所有边的详细信息"""
    try:
        data = serializer.get_attack_chain_summary(scenario_id)
        edges = data.get("edges", [])
        return jsonify({"ok": True, "data": {"edges": edges}, "mode": "neo4j"})
    except Exception:
        return jsonify({"ok": True, "data": {"edges": []}, "mode": "simulation"})


@bp.route("/api/system/status", methods=["GET"])
def api_system_status():
    global _pipeline_thread
    is_running = _pipeline_thread is not None and _pipeline_thread.is_alive()
    failures = getattr(main_pipeline, '_consecutive_failures', 0)
    # 检查可用事件数
    event_count = 0
    report_count = 0
    try:
        bridge = get_bridge()
        event_count = len(bridge.get_all_events())
        report_count = bridge.count("AttackReports")
    except: pass
    return jsonify({
        "ok": True,
        "status": "running" if is_running else "stopped",
        "consecutive_failures": failures,
        "events_available": event_count,
        "reports_available": report_count,
    })


@bp.route("/api/system/start", methods=["POST"])
def api_system_start():
    global _pipeline_thread
    if _pipeline_thread is not None and _pipeline_thread.is_alive():
        return jsonify({"ok": False, "error": "任务已经在运行中，请先点击「停止」"}), 400

    payload = request.get_json(silent=True) or {}
    time_start = (payload.get("time_start") or "").strip()
    time_end = (payload.get("time_end") or "").strip()

    main_pipeline.STOP_FLAG = False
    main_pipeline._consecutive_failures = 0
    main_pipeline._current_time_start = time_start
    main_pipeline._current_time_end = time_end
    _pipeline_thread = threading.Thread(target=main_pipeline.pipeline_loop, daemon=True)
    _pipeline_thread.start()

    msg = "分析引擎已启动"
    if time_start:
        msg += f"（时间范围: {time_start[:16]} ~ {time_end[:16] if time_end else '现在'}）"
    return jsonify({"ok": True, "message": msg})


@bp.route("/api/system/stop", methods=["POST"])
def api_system_stop():
    main_pipeline.STOP_FLAG = True
    main_pipeline._consecutive_failures = 0
    return jsonify({"ok": True, "message": "正在停止分析引擎"})


@bp.route("/api/analyze/unified", methods=["POST"])
def api_unified_analysis():
    """
    统一多源分析接口：日志+行为+流量 + DeepSeek LLM
    供检测、归因、溯源、攻击链四个页面共用。
    POST body: { time_start: "2026-07-07T14:00", time_end: "2026-07-07T15:00" }
    """
    payload = request.get_json(silent=True) or {}
    time_start = (payload.get("time_start") or "").strip()
    time_end = (payload.get("time_end") or "").strip()

    try:
        result = main_pipeline.multi_source_llm_analysis(time_start, time_end)
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/api/analyze/reports", methods=["GET"])
def api_list_analysis_reports():
    """列出所有已保存的分析报告"""
    try:
        bridge = get_bridge()
        rows = bridge.query("AnalysisReports", order_by="created_at", desc=True, limit=50)
        return jsonify({"ok": True, "data": rows})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500