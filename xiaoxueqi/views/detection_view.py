"""检测仪表盘视图"""
from flask import Blueprint, jsonify, make_response, render_template, request

from utils.scenarios.scenario_manager import get_scenario_manager
from utils.detection.llm_detector import LLMDetector
from utils.detection.rag_knowledge_base import get_rag_kb
from utils.capture.agent_framework import get_capture_framework
from utils.attribution.attribution_engine import AttributionEngine
from utils.attribution.attacker_profiler import AttackerProfiler
from utils.attribution.report_generator import ReportGenerator
from utils.evidence import (
    create_evidence_case,
    export_evidence_case,
    get_evidence_case,
    list_evidence_cases,
    list_evidence_records,
    verify_evidence_case,
)

bp = Blueprint("detection", __name__)

# 初始化引擎
llm_detector = LLMDetector(use_llm=True)
attribution_engine = AttributionEngine()
attacker_profiler = AttackerProfiler()
report_generator = ReportGenerator()
rag_kb = get_rag_kb()


def _collect_fallback_iocs(events: list[dict], alerts: list[dict], evidence: list[dict], existing_iocs: dict | None) -> dict:
    iocs = {
        "ips": list((existing_iocs or {}).get("ips", [])),
        "domains": list((existing_iocs or {}).get("domains", [])),
        "processes": list((existing_iocs or {}).get("processes", [])),
        "file_hashes": list((existing_iocs or {}).get("file_hashes", [])),
        "techniques": list((existing_iocs or {}).get("techniques", [])),
    }
    seen_ips = set(iocs["ips"])
    seen_domains = set(iocs["domains"])
    seen_processes = set(iocs["processes"])
    seen_techs = set(iocs["techniques"])

    for alert in alerts:
        tid = alert.get("technique_id")
        if tid and tid not in seen_techs:
            seen_techs.add(tid)
            iocs["techniques"].append(tid)

    for ev in evidence:
        for ip in ev.get("ips_involved", []) or []:
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                iocs["ips"].append(ip)
        for proc in ev.get("processes_involved", []) or []:
            if proc and proc not in seen_processes:
                seen_processes.add(proc)
                iocs["processes"].append(proc)
        tid = ev.get("technique_id")
        if tid and tid not in seen_techs:
            seen_techs.add(tid)
            iocs["techniques"].append(tid)

    for evt in events:
        host_ip = evt.get("host_ip")
        if host_ip and host_ip not in seen_ips:
            seen_ips.add(host_ip)
            iocs["ips"].append(host_ip)

        entities = evt.get("entities", {}) if isinstance(evt.get("entities"), dict) else {}
        for key in ("src_ip", "dst_ip"):
            ip = entities.get(key) or evt.get(key)
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                iocs["ips"].append(ip)

        domain = entities.get("domain")
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            iocs["domains"].append(domain)

        proc = entities.get("process_name")
        if proc and proc not in seen_processes:
            seen_processes.add(proc)
            iocs["processes"].append(proc)

    return iocs


def _fallback_ttps_from_alerts(alerts: list[dict]) -> list[dict]:
    ttps = []
    seen: set[tuple[str, str]] = set()
    for alert in alerts:
        tid = str(alert.get("technique_id") or "").strip()
        tactic = str(alert.get("tactic") or "").strip()
        if not tid:
            continue
        key = (tid, tactic)
        if key in seen:
            continue
        seen.add(key)
        ttps.append({
            "technique_id": tid,
            "technique_name": alert.get("technique_name", ""),
            "tactic": tactic,
            "processes": [],
        })
    return ttps


@bp.route("/", methods=["GET"])
def index():
    return render_template("detection.html")


@bp.route("/api/stats", methods=["GET"])
def api_stats():
    """获取检测统计"""
    mgr = get_scenario_manager()
    stats = mgr.get_detection_stats()
    detector_stats = llm_detector.get_stats()
    stats["detector"] = detector_stats
    return jsonify({"ok": True, "data": stats})


@bp.route("/api/alerts", methods=["GET"])
def api_alerts():
    """获取告警列表"""
    limit = request.args.get("limit", 50, type=int)
    severity = request.args.get("severity")
    scenario = request.args.get("scenario")

    mgr = get_scenario_manager()
    alerts = mgr.get_alerts(limit=limit, severity=severity, scenario_type=scenario)
    return jsonify({"ok": True, "data": alerts, "count": len(alerts)})


@bp.route("/api/alerts/live", methods=["GET"])
def api_alerts_live():
    """获取最新告警(用于实时轮询)"""
    mgr = get_scenario_manager()
    all_alerts = mgr.get_alerts(limit=10)
    # SSE 格式的数据
    return jsonify({
        "ok": True,
        "data": all_alerts,
        "timestamp": __import__("datetime").datetime.now().isoformat()
    })


@bp.route("/api/events/live", methods=["GET"])
def api_events_live():
    """获取最新事件"""
    mgr = get_scenario_manager()
    events = mgr.get_events(limit=50)
    return jsonify({"ok": True, "data": events, "count": len(events)})


@bp.route("/api/analyze", methods=["POST"])
def api_analyze():
    """一键执行完整分析管线: 检测→捕获→溯源"""
    mgr = get_scenario_manager()
    events = mgr.get_events(limit=500)

    if not events:
        return jsonify({"ok": False, "error": "无事件数据，请先启动场景"}), 400

    # 1. 检测阶段
    alerts = llm_detector.batch_detect(events)
    for alert in alerts:
        mgr.add_alert(alert)

    # 2. 捕获阶段
    capture_fw = get_capture_framework()
    capture_result = capture_fw.run(events, alerts)
    capture_result["verdict"]["iocs"] = _collect_fallback_iocs(
        events,
        alerts,
        capture_result["evidence"],
        capture_result["verdict"].get("iocs", {}),
    )

    # 3. 溯源阶段
    attribution_result = attribution_engine.attribute(
        verdict=capture_result["verdict"],
        chains=capture_result["chains"],
        evidence=capture_result["evidence"]
    )

    # 4. 攻击者画像
    ttps = attribution_result.get("ttps_extracted", []) or _fallback_ttps_from_alerts(alerts)
    profile = attacker_profiler.build_profile(
        attribution_data=attribution_result,
        behavioral=attribution_result.get("attribution", {}).get("result", {}).get("behavioral_profile", {}),
        iocs=capture_result["verdict"].get("iocs", {}),
        ttps=ttps
    )

    # 5. 生成报告
    report = report_generator.generate_comprehensive_report(
        verdict=capture_result["verdict"],
        attribution=attribution_result,
        profile=profile,
        chains=capture_result["chains"],
        detection_stats=mgr.get_detection_stats(),
        evidence=capture_result["evidence"],
        alerts=alerts,
    )

    # 6. 导出可视化数据
    vis_data = report_generator.export_visualization_data(
        chains=capture_result["chains"],
        attribution=attribution_result,
        profile=profile
    )

    evidence_case = create_evidence_case(
        verdict=capture_result["verdict"],
        chains=capture_result["chains"],
        evidence=capture_result["evidence"],
        report=report,
    )
    return jsonify({
        "ok": True,
        "data": {
            "detection": {
                "alerts_count": len(alerts),
                "stats": llm_detector.get_stats()
            },
            "capture": {
                "verdict": capture_result["verdict"],
                "chains_count": len(capture_result["chains"]),
                "evidence_count": len(capture_result["evidence"])
            },
            "attribution": attribution_result,
            "profile": profile,
            "report": report,
            "visualization": vis_data,
            "evidence_case": evidence_case
        }
    })


@bp.route("/api/report", methods=["GET"])
def api_report():
    """获取最近一次分析报告"""
    return jsonify({"ok": True, "message": "使用 /api/analyze 生成报告"})


@bp.route("/api/rag/search", methods=["GET"])
def api_rag_search():
    """RAG知识库搜索"""
    query = request.args.get("q", "")
    if not query:
        return jsonify({"ok": False, "error": "请提供搜索词"}), 400

    results = rag_kb.search(query, top_k=5)
    return jsonify({"ok": True, "data": results})


@bp.route("/api/knowledge", methods=["GET"])
def api_knowledge():
    """获取知识库概览"""
    return jsonify({
        "ok": True,
        "data": {
            "documents_count": len(rag_kb.documents),
            "vocabulary_size": len(rag_kb.vocabulary),
            "categories": list(set(d.get("category", "") for d in rag_kb.documents))
        }
    })


@bp.route("/api/evidence/cases", methods=["GET"])
def api_evidence_cases():
    limit = request.args.get("limit", 50, type=int)
    return jsonify({"ok": True, "data": list_evidence_cases(limit=limit)})


@bp.route("/api/evidence/case/<case_id>", methods=["GET"])
def api_evidence_case(case_id: str):
    case = get_evidence_case(case_id)
    if not case:
        return jsonify({"ok": False, "error": "case not found"}), 404
    records = list_evidence_records(case_id)
    return jsonify({"ok": True, "case": case, "records": records})


@bp.route("/api/evidence/case/<case_id>/verify", methods=["GET"])
def api_evidence_verify(case_id: str):
    case = get_evidence_case(case_id)
    if not case:
        return jsonify({"ok": False, "error": "case not found"}), 404
    return jsonify({"ok": True, "data": verify_evidence_case(case_id)})


@bp.route("/api/evidence/case/<case_id>/export", methods=["GET"])
def api_evidence_export(case_id: str):
    case = get_evidence_case(case_id)
    if not case:
        return jsonify({"ok": False, "error": "case not found"}), 404
    fmt = (request.args.get("format") or "json").lower()
    if fmt not in {"json", "markdown"}:
        fmt = "json"
    content_type, body = export_evidence_case(case_id, fmt=fmt)
    if not body:
        return jsonify({"ok": False, "error": "export failed"}), 500
    resp = make_response(body)
    resp.headers["Content-Type"] = content_type
    filename = f"evidence_{case_id}.{ 'md' if fmt == 'markdown' else 'json' }"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp
