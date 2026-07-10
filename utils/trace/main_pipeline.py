# main_pipeline.py - supports fallback to DataBridge in-memory mode
import logging
import os
import time
import json
from datetime import datetime

from config import Config
from utils.trace.DB_Connector import SQLServerLoader
from utils.trace.Graph_construct import GraphIngestionEngine
from utils.trace.Attck_Map import ATTACKMapper
from utils.trace.StateManager import StateManager
from utils.trace.APT_Analysis_Engine import APTAnalysisEngine

from utils.trace.service.scenario_linker import ScenarioLinker, stable_scenario_id
from utils.data_bridge import get_bridge

STOP_FLAG = False
_consecutive_failures = 0
MAX_CONSECUTIVE_FAILURES = 3
ATTACK_RULES_FILE = os.getenv("ATTACK_RULES_FILE") or os.path.join(os.path.dirname(__file__), "attack_rules.yaml")


def _run_with_sql_server():
    """Try SQL Server + Neo4j (production mode)"""
    db_loader = SQLServerLoader(Config.DB_SERVER, Config.DB_USERNAME, Config.DB_PASSWORD, Config.DB_DATABASE)
    mapper = ATTACKMapper(ATTACK_RULES_FILE)
    state_mgr = StateManager()

    neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_pass = os.getenv("NEO4J_PASSWORD", "")

    graph_engine = GraphIngestionEngine(neo4j_uri, neo4j_user, neo4j_pass,
                                        initial_pid_cache=state_mgr.get_pid_cache())
    scenario_linker = ScenarioLinker(neo4j_uri, neo4j_user, neo4j_pass)

    try:
        logging.info("=== [production] Starting SQL Server data collection ===")

        # HostBehaviors
        last_id = state_mgr.get_checkpoint("HostBehaviors")
        behaviors, new_id = db_loader.fetch_new_data("HostBehaviors", last_id)
        if behaviors:
            logging.info("Read %d new host behavior records", len(behaviors))
            graph_engine.ingest_host_behavior(behaviors)
            detected = []
            for event in behaviors:
                detected.extend(mapper.analyze_event(event))
            if detected:
                graph_engine.ingest_attack_events(detected)
            state_mgr.update_checkpoint("HostBehaviors", new_id)

        # NetworkTraffic
        last_id_net = state_mgr.get_checkpoint("NetworkTraffic")
        traffic_data, new_id_net = db_loader.fetch_new_data("NetworkTraffic", last_id_net)
        if traffic_data:
            logging.info("Read %d new traffic records", len(traffic_data))
            graph_engine.ingest_network_traffic(traffic_data)
            detected = []
            for event in traffic_data:
                detected.extend(mapper.analyze_event(event))
            if detected:
                graph_engine.ingest_attack_events(detected)
            state_mgr.update_checkpoint("NetworkTraffic", new_id_net)

        # HostLogs
        last_id_logs = state_mgr.get_checkpoint("HostLogs")
        log_data, new_id_logs = db_loader.fetch_new_data("HostLogs", last_id_logs)
        if log_data:
            logging.info("Read %d new log records", len(log_data))
            graph_engine.ingest_host_log(log_data)
            detected = []
            for event in log_data:
                detected.extend(mapper.analyze_event(event))
            if detected:
                graph_engine.ingest_attack_events(detected)
            state_mgr.update_checkpoint("HostLogs", new_id_logs)

        # build chains
        graph_engine.build_causal_chains(time_window_seconds=7200)
        state_mgr.update_pid_cache(graph_engine.get_current_pid_cache())
        state_mgr.save_state()

        # APT analysis engine
        analysis_engine = APTAnalysisEngine(neo4j_uri, neo4j_user, neo4j_pass)
        reports = analysis_engine.run_pipeline()

        for report in reports:
            victim_ip = report.get("victim_ip") or ""
            time_window = report.get("time_window") or ""
            start_time = time_window.split(" to ", 1)[0] if " to " in time_window else ""
            end_time = time_window.split(" to ", 1)[1] if " to " in time_window else ""
            sid = stable_scenario_id(str(victim_ip), str(start_time))
            report["scenario_id"] = sid
            try:
                event_ids = _get_attackevent_ids_for_window(
                    uri=neo4j_uri, user=neo4j_user, password=neo4j_pass,
                    victim_ip=str(victim_ip), start_time=str(start_time), end_time=str(end_time))
                scenario_linker.set_scenario_id_for_attackevents(sid, event_ids)
            except Exception as exc:
                logging.warning("[scenario_link] write-back failed: %s", exc)
            db_loader.save_analysis_report(report)
        analysis_engine.close()
        return True

    finally:
        try: scenario_linker.close()
        except: pass
        try: db_loader.close()
        except: pass
        try: graph_engine.close()
        except: pass


def _run_with_databridge(time_start: str = "", time_end: str = ""):
    """Read events from DataBridge, analyze with ATT&CK rules, generate report.
    Supports time-range filtering for targeted analysis."""
    bridge = get_bridge()
    mapper = ATTACKMapper(ATTACK_RULES_FILE)

    logging.info("=== [simulation] Reading events from DataBridge (time: %s ~ %s) ===", time_start or "all", time_end or "all")

    all_events = bridge.get_all_events()

    # Deduplicate by event_hash (get_all_events already deduplicates within DataBridge,
    # but scenario_manager may return duplicates of DataBridge events)
    seen_hashes = {str(e.get("event_hash", "")): True for e in all_events if e.get("event_hash")}

    # Also read from scenario_manager
    try:
        from utils.scenarios.scenario_manager import get_scenario_manager
        mgr = get_scenario_manager()
        raw_events = mgr.get_events(limit=5000)
        for evt in raw_events:
            ds = evt.get("data_source", "host_behavior")
            evt.setdefault("data_source", ds)
            eh = str(evt.get("event_hash", ""))
            if eh and eh in seen_hashes:
                continue
            if eh:
                seen_hashes[eh] = True
            all_events.append(evt)
    except Exception:
        pass

    # Time-range filter
    if time_start:
        all_events = [e for e in all_events if str(e.get("timestamp", "")) >= time_start]
    if time_end:
        all_events = [e for e in all_events if str(e.get("timestamp", "")) <= time_end]
    # Default: last 1 hour if no range specified and events > 500
    if not time_start and not time_end and len(all_events) > 500:
        from datetime import datetime as _dt, timedelta as _td
        cutoff = (_dt.now() - _td(hours=1)).isoformat()
        recent = [e for e in all_events if str(e.get("timestamp", "")) >= cutoff]
        if len(recent) > 10:
            all_events = recent
            logging.info("[simulation] Auto-filtered to last 1 hour: %d events", len(all_events))

    if not all_events:
        logging.info("[simulation] No events available in selected time range")
        return False

    logging.info("[simulation] Read %d events", len(all_events))

    # Group events by scenario_type so different scenarios generate separate reports
    scenario_events: dict[str, list[dict]] = {}
    for evt in all_events:
        st = evt.get("scenario_type", "unknown")
        if st not in scenario_events:
            scenario_events[st] = []
        scenario_events[st].append(evt)

    # Clear ALL old AttackReports before generating new ones
    bridge._memory_store["AttackReports"] = []
    logging.info("[simulation] Cleared old reports, generating fresh for %d scenario type(s)", len(scenario_events))

    # Generate a report for EACH scenario type
    for scenario_type, events in scenario_events.items():
        _generate_report_for_events(scenario_type, events, mapper, bridge)

    return True


def _generate_report_for_events(scenario_type: str, events: list[dict], mapper, bridge):
    """Generate an AttackReport for a specific set of events (one scenario)."""
    if not events:
        return

    logging.info("[simulation] Scenario '%s': %d events", scenario_type, len(events))

    # ATT&CK rule matching
    detected_attacks = []
    for event in events:
        matches = mapper.analyze_event(event)
        detected_attacks.extend(matches)

    logging.info("[simulation] Rule matching found %d attack patterns for '%s'", len(detected_attacks), scenario_type)

    # Deduplicate by technique ID
    seen = set()
    unique_attacks = []
    for a in detected_attacks:
        tech = a.get("technique", {})
        tech_id = tech.get("id", "") if isinstance(tech, dict) else str(tech)
        if tech_id and tech_id not in seen:
            seen.add(tech_id)
            unique_attacks.append(a)

    # Build attack_chain (sorted by kill chain phase)
    tactic_order = {
        "Reconnaissance": 1, "Resource Development": 2, "Initial Access": 3,
        "Execution": 4, "Persistence": 5, "Privilege Escalation": 6,
        "Defense Evasion": 7, "Credential Access": 8, "Discovery": 9,
        "Lateral Movement": 10, "Collection": 11, "Command and Control": 12,
        "Exfiltration": 13, "Impact": 14,
    }
    def _get_tactic_name(a):
        t = a.get("tactic", {})
        return t.get("name", "") if isinstance(t, dict) else str(t)
    unique_attacks.sort(key=lambda a: tactic_order.get(_get_tactic_name(a), 99))

    def _get_tech_label(a):
        t = a.get("technique", {})
        tid = t.get("id", "?") if isinstance(t, dict) else "?"
        tname = t.get("name", "?") if isinstance(t, dict) else "?"
        return f"{tid}: {tname}"
    attack_chain = [_get_tech_label(a) for a in unique_attacks]

    # Collect all IPs from THIS scenario's events
    ips = set()
    for evt in events:
        ips.add(evt.get("host_ip", ""))
        ips.add(evt.get("src_ip", ""))
        ips.add(evt.get("dst_ip", ""))
    ips.discard("")
    internal_ips = [ip for ip in ips if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")]
    external_ips = [ip for ip in ips if ip not in internal_ips]

    victim_ip = internal_ips[0] if internal_ips else "unknown"
    attacker_ip = external_ips[0] if external_ips else "45.33.22.11"

    # Extract IOCs
    iocs = list(ips)
    for evt in events:
        if evt.get("entities", {}).get("domain"):
            iocs.append(evt["entities"]["domain"])

    # Generate report with scenario-specific ID
    now = datetime.now().isoformat()
    sid = stable_scenario_id(f"{scenario_type}:{victim_ip}", now)
    report = {
        "scenario_id": sid,
        "scenario_type": scenario_type,
        "victim_ip": victim_ip,
        "attacker_ip": attacker_ip,
        "start_time": now,
        "end_time": now,
        "confidence": "High" if len(unique_attacks) >= 8 else ("Medium" if len(unique_attacks) >= 4 else "Low"),
        "attribution_type": "Simulated Attack",
        "attribution_name": f"Scenario: {scenario_type}",
        "time_window": f"{now} to {now}",
        "attack_chain": attack_chain,
        "techniques_detected": len(unique_attacks),
        "events_analyzed": len(events),
        "iocs": iocs[:20],
        "root_cause_analysis": {
            "intruder_ip": attacker_ip,
            "entry_point": f"Initial intrusion detected from {attacker_ip}",
            "techniques_used": [(a.get("technique") or {}).get("id", "?") if isinstance(a.get("technique"), dict) else str(a.get("technique", "?")) for a in unique_attacks],
        },
        "attribution": {
            "type": "Simulated",
            "result": {"best_match": f"Scenario-generated attack chain ({scenario_type})"},
            "jaccard_similarity": 0.0,
            "matched_ttps": [],
        },
    }

    # Insert new report (old reports already cleared before the loop)
    report_row = {
        "id": len(bridge.query("AttackReports")) + 1,
        "scenario_id": sid,
        "scenario_type": scenario_type,
        "victim_ip": victim_ip,
        "attacker_ip": attacker_ip,
        "confidence": report["confidence"],
        "attribution_type": report["attribution_type"],
        "attribution_name": report["attribution_name"],
        "start_time": now,
        "end_time": now,
        "created_at": now,
        "report_json": json.dumps(report, ensure_ascii=False),
    }
    bridge.insert("AttackReports", report_row)
    logging.info("[simulation] Generated report %s for '%s': %d techniques, %d events", sid, scenario_type, len(unique_attacks), len(events))


def multi_source_llm_analysis(time_start: str = "", time_end: str = "") -> dict:
    """
    Unified multi-source analysis with DeepSeek LLM.
    Reads HostLogs + HostBehaviors + NetworkTraffic within time range,
    runs ATT&CK rules, calls LLM, and persists results.
    Returns the analysis report dict.
    """
    import traceback as _tb
    bridge = get_bridge()
    mapper = ATTACKMapper(ATTACK_RULES_FILE)

    def _attach_source_meta(event: dict, *, table: str, row_id, event_hash, host_name, event_time) -> dict:
        enriched = dict(event or {})
        source_name = {
            "HostLogs": "host_log",
            "HostBehaviors": "host_behavior",
            "NetworkTraffic": "network_traffic",
        }.get(table, enriched.get("data_source", "host_behavior"))
        enriched.setdefault("data_source", source_name)
        enriched.setdefault("source_table", table)
        enriched.setdefault("source_record_id", row_id)
        enriched.setdefault("event_hash", event_hash)
        enriched.setdefault("host_name", host_name)
        enriched.setdefault("timestamp", event_time or enriched.get("timestamp"))
        return enriched

    def _normalize_alerts(matches: list[dict], report_id: str) -> list[dict]:
        alerts: list[dict] = []
        for idx, match in enumerate(matches, start=1):
            tech = match.get("technique", {})
            tactic = match.get("tactic", {})
            confidence = float(match.get("confidence", 0.5) or 0.5)
            alerts.append({
                "rule_id": f"{report_id}-T{idx}",
                "technique_id": str(tech.get("id", "")) if isinstance(tech, dict) else str(tech),
                "technique_name": str(tech.get("name", "")) if isinstance(tech, dict) else str(tech),
                "tactic": str(tactic.get("name", "")) if isinstance(tactic, dict) else str(tactic),
                "severity": "high" if confidence >= 0.8 else ("medium" if confidence >= 0.5 else "low"),
                "confidence": confidence,
                "description": str(match.get("description", "")),
                "source": "rule_based",
            })
        return alerts

    # 1) Collect events from all 3 sources (SQL Server + DataBridge + scenario)
    all_events = bridge.get_all_events()

    # Track seen hashes to prevent duplicates across sources
    seen_hashes: dict[str, bool] = {}
    for e in all_events:
        eh = str(e.get("event_hash", ""))
        if eh:
            seen_hashes[eh] = True

    try:
        from utils.scenarios.scenario_manager import get_scenario_manager
        mgr = get_scenario_manager()
        for evt in mgr.get_events(limit=5000):
            eh = str(evt.get("event_hash", ""))
            if eh and eh in seen_hashes:
                continue
            if eh:
                seen_hashes[eh] = True
            all_events.append(evt)
    except: pass

    # Also try to read from SQL Server directly
    try:
        from utils.traffic_fenxi.storage_sqlserver import list_networktraffic, parse_result_json as _prj
        from utils.behavior_monitor.storage.hostbehaviors_sqlserver import list_hostbehaviors, parse_result_json as _prj2
        from utils.winlog.storage.hostlogs_sqlserver import list_hostlogs, parse_result_json as _prj3

        for row in list_hostbehaviors(offset=0, limit=2000, host_name=None):
            eh = str(row.event_hash or "")
            if eh and eh in seen_hashes:
                continue
            if eh:
                seen_hashes[eh] = True
            ev = _attach_source_meta(
                _prj2(row.result),
                table="HostBehaviors",
                row_id=row.id,
                event_hash=row.event_hash,
                host_name=row.host_name,
                event_time=row.event_time_utc or row.create_time,
            )
            all_events.append(ev)
        for row in list_networktraffic(offset=0, limit=2000, host_name=None):
            eh = str(row.event_hash or "")
            if eh and eh in seen_hashes:
                continue
            if eh:
                seen_hashes[eh] = True
            ev = _attach_source_meta(
                _prj(row.result),
                table="NetworkTraffic",
                row_id=row.id,
                event_hash=row.event_hash,
                host_name=row.host_name,
                event_time=row.event_time_utc or row.create_time,
            )
            all_events.append(ev)
        for row in list_hostlogs(offset=0, limit=2000, host_name=None):
            eh = str(getattr(row, "event_hash", "") or "")
            if eh and eh in seen_hashes:
                continue
            if eh:
                seen_hashes[eh] = True
            ev = _attach_source_meta(
                _prj3(row.result),
                table="HostLogs",
                row_id=row.id,
                event_hash=row.event_hash,
                host_name=row.host_name,
                event_time=getattr(row, "event_time_utc", None) or row.create_time,
            )
            all_events.append(ev)
        logging.info("[multi-source] SQL Server: %d total events after merge", len(all_events))
    except Exception as e:
        logging.warning("[multi-source] SQL Server read failed: %s", e)

    # Time filter
    if time_start:
        all_events = [e for e in all_events if str(e.get("timestamp", "")) >= time_start]
    if time_end:
        all_events = [e for e in all_events if str(e.get("timestamp", "")) <= time_end]
    if not time_start and not time_end and len(all_events) > 500:
        from datetime import timedelta as _td
        cutoff = (datetime.now() - _td(hours=1)).isoformat()
        recent = [e for e in all_events if str(e.get("timestamp", "")) >= cutoff]
        if len(recent) > 10: all_events = recent

    if not all_events:
        return {"ok": False, "error": "No events found in selected time range"}

    # 2) Count by source — map data_source values to analysis categories
    # Data sources that represent network traffic (even if stored elsewhere):
    _NETWORK_SOURCES = {"network_traffic", "zeek", "suricata", "pcap", "netflow"}
    # Data sources that represent host logs:
    _LOG_SOURCES = {"host_log", "windows_eventlog", "syslog"}
    # Everything else is treated as host behavior

    source_counts = {"HostLogs": 0, "HostBehaviors": 0, "NetworkTraffic": 0}
    for e in all_events:
        ds = str(e.get("data_source", "")).lower()
        src_table = str(e.get("source_table", "")).lower()

        # Prefer source_table for classification when available
        if src_table == "networktraffic":
            source_counts["NetworkTraffic"] += 1
        elif src_table == "hostlogs":
            source_counts["HostLogs"] += 1
        elif src_table == "hostbehaviors":
            source_counts["HostBehaviors"] += 1
        elif ds in _NETWORK_SOURCES:
            source_counts["NetworkTraffic"] += 1
        elif ds in _LOG_SOURCES:
            source_counts["HostLogs"] += 1
        else:
            source_counts["HostBehaviors"] += 1

    # 3) ATT&CK rule matching
    all_matches = []
    for evt in all_events:
        all_matches.extend(mapper.analyze_event(evt))

    seen_tech = set()
    unique_matches = []
    for m in all_matches:
        tech = m.get("technique", {})
        tid = tech.get("id", "") if isinstance(tech, dict) else str(tech)
        if tid and tid not in seen_tech:
            seen_tech.add(tid)
            unique_matches.append(m)

    tactic_order = {"Reconnaissance": 1, "Resource Development": 2, "Initial Access": 3,
        "Execution": 4, "Persistence": 5, "Privilege Escalation": 6,
        "Defense Evasion": 7, "Credential Access": 8, "Discovery": 9,
        "Lateral Movement": 10, "Collection": 11, "Command and Control": 12,
        "Exfiltration": 13, "Impact": 14}
    try:
        unique_matches.sort(key=lambda a: tactic_order.get(
            str((a.get("tactic", {}) if isinstance(a.get("tactic"), dict) else {}).get("name", "")), 99))
    except Exception:
        pass  # keep unsorted if tactic names are inconsistent

    attack_chain = []
    for a in unique_matches:
        t = a.get("technique", {})
        tid = t.get("id", "?") if isinstance(t, dict) else str(t)[:20]
        tn = t.get("name", "?") if isinstance(t, dict) else str(t)[:40]
        attack_chain.append(f"{tid}: {tn}")

    # 4) DeepSeek LLM analysis
    llm_text = ""
    llm_model = "deepseek-chat"
    try:
        import os as _os
        api_key = _os.getenv("LLM_API_KEY", "")
        if not api_key:
            raise RuntimeError("LLM_API_KEY is not configured")
        base_url = _os.getenv("LLM_BASE_URL", "https://api.deepseek.com")
        from openai import OpenAI
        client = OpenAI(api_key=api_key, base_url=base_url)

        summary_lines = [
            f"Analysis time range: {time_start or 'auto'} to {time_end or 'now'}",
            f"Total events: {len(all_events)} (HostLogs:{source_counts['HostLogs']}, HostBehaviors:{source_counts['HostBehaviors']}, NetworkTraffic:{source_counts['NetworkTraffic']})",
            f"ATT&CK techniques detected: {len(unique_matches)}",
            "Attack chain: " + " -> ".join(attack_chain[:10]),
        ]
        prompt = (
            "You are a senior incident response analyst at a Fortune 500 SOC. "
            "Analyze the following security telemetry data and ATT&CK detection results. "
            "The data comes from a production network with real endpoints. "
            "Provide a detailed structured analysis in Chinese with these sections:\n"
            "【威胁等级评估】Rate as CRITICAL/HIGH/MEDIUM/LOW with specific justification (cite at least 2 concrete indicators).\n"
            "【攻击类型判断】Identify the most likely attack campaign type (e.g. ransomware precursor, APT lateral movement, data exfiltration, crypto mining, botnet C2). Explain your reasoning with specific techniques observed.\n"
            "【攻击链还原】Reconstruct the likely attack timeline based on the ATT&CK techniques in order of execution.\n"
            "【影响范围评估】Which systems/users are likely compromised? What data may be at risk?\n"
            "【处置建议】Provide 5 specific, actionable mitigation steps prioritized by urgency.\n"
            "【置信度说明】State your confidence level (0.0-1.0) and explain any uncertainties.\n\n"
            + "\n".join(summary_lines)
        )
        resp = client.chat.completions.create(
            model=llm_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3, max_tokens=800,
        )
        llm_text = resp.choices[0].message.content or ""
        llm_model = resp.model or llm_model
        logging.info("[multi-source] DeepSeek LLM analysis returned %d chars", len(llm_text))
    except Exception as e:
        logging.warning("DeepSeek LLM call failed: %s", e)
        llm_text = f"[LLM unavailable: {str(e)[:200]}]"

    # 5) Build & save report
    now = datetime.now().isoformat()
    report_id = f"RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    ips = set()
    for e in all_events:
        for k in ("host_ip", "src_ip", "dst_ip"):
            v = e.get(k, "")
            if v: ips.add(str(v))
    iocs = list(ips)[:30]

    report = {
        "report_id": report_id,
        "time_start": time_start or "auto",
        "time_end": time_end or "now",
        "data_sources": f"HostLogs({source_counts['HostLogs']}),HostBehaviors({source_counts['HostBehaviors']}),NetworkTraffic({source_counts['NetworkTraffic']})",
        "total_events": len(all_events),
        "techniques_found": len(unique_matches),
        "attack_chain": attack_chain,
        "llm_analysis": llm_text,
        "llm_model": llm_model,
        "confidence": "High" if len(unique_matches) >= 8 else ("Medium" if len(unique_matches) >= 4 else "Low"),
        "attribution": json.dumps({"type": "Multi-Source LLM Analysis", "techniques": attack_chain[:10]}, ensure_ascii=False),
        "iocs": json.dumps(iocs, ensure_ascii=False),
        "report_json": json.dumps({
            "report_id": report_id, "time_range": f"{time_start} - {time_end}",
            "source_counts": source_counts, "techniques": attack_chain,
            "llm_analysis": llm_text, "iocs": iocs,
        }, ensure_ascii=False),
        "created_at": now,
    }

    evidence_case = None
    try:
        from utils.capture.agent_framework import get_capture_framework
        from utils.evidence import create_evidence_case

        capture_result = get_capture_framework().run(all_events, _normalize_alerts(unique_matches, report_id))
        capture_result["verdict"]["verdict_id"] = report_id
        capture_result["verdict"]["iocs"] = {
            "ips": iocs,
            "domains": [],
            "processes": [],
            "file_hashes": [],
            "techniques": [
                str((m.get("technique", {}) or {}).get("id", ""))
                for m in unique_matches
                if str((m.get("technique", {}) or {}).get("id", ""))
            ],
        }
        evidence_case = create_evidence_case(
            verdict=capture_result["verdict"],
            chains=capture_result["chains"],
            evidence=capture_result["evidence"],
            report=report["report_json"],
        )
    except Exception as exc:
        logging.warning("[multi-source] Evidence package generation skipped: %s", exc)

    # Save to DataBridge
    bridge._memory_store.setdefault("AnalysisReports", [])
    bridge._memory_store["AnalysisReports"] = [
        r for r in bridge._memory_store.get("AnalysisReports", [])
        if not (r.get("time_start") == time_start and r.get("time_end") == time_end)
    ]
    bridge.insert("AnalysisReports", report)

    # Also save to SQL Server for persistence
    try:
        from utils.db.db import execute as _db_exec
        _db_exec("""
            INSERT INTO dbo.AnalysisReports
            (report_id, time_start, time_end, data_sources, total_events, techniques_found,
             attack_chain, llm_analysis, llm_model, confidence, attribution, iocs, report_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, GETDATE())
        """, [
            str(report_id), str(time_start or None) if time_start else None,
            str(time_end or None) if time_end else None,
            str(report["data_sources"]), int(report["total_events"]),
            int(report["techniques_found"]), json.dumps(report["attack_chain"], ensure_ascii=False),
            str(report["llm_analysis"]), str(report["llm_model"]),
            str(report["confidence"]), str(report["attribution"]),
            str(report["iocs"]), json.dumps(report["report_json"], ensure_ascii=False),
        ])
        logging.info("[multi-source] Report also saved to SQL Server AnalysisReports")
    except Exception as e:
        logging.warning("[multi-source] SQL Server save skipped: %s", e)

    # Save detection details (wrapped for safety)
    for m in unique_matches:
        try:
            tech = m.get("technique", {})
            tac = m.get("tactic", {})
            detail = {
                "report_id": report_id,
                "data_source": str(m.get("data_source", "unknown")),
                "technique_id": str(tech.get("id", "")) if isinstance(tech, dict) else str(tech),
                "technique_name": str(tech.get("name", "")) if isinstance(tech, dict) else str(tech),
                "tactic": str(tac.get("name", "")) if isinstance(tac, dict) else str(tac),
                "severity": "high" if isinstance(m.get("confidence"), (int, float)) and float(m.get("confidence", 0)) > 0.8 else "medium",
                "confidence": float(m.get("confidence", 0.5)) if isinstance(m.get("confidence"), (int, float)) else 0.5,
                "source": "rule_based",
                "description": str(m.get("description", ""))[:2000],
                "detected_at": datetime.now().isoformat(),
            }
            bridge.insert("DetectionDetails", detail)
        except Exception:
            pass  # skip individual detail save failures

    logging.info("[multi-source] Report %s: %d techniques, %d events, LLM=%s",
                 report_id, len(unique_matches), len(all_events), str(llm_model)[:20])

    # Build clean dict for JSON response — ensure all values are serializable
    result = {
        "ok": True,
        "techniques_count": len(unique_matches),
        "report": {
            "report_id": str(report_id),
            "time_start": str(time_start or "auto"),
            "time_end": str(time_end or "now"),
            "data_sources": str(report.get("data_sources", "")),
            "total_events": int(report.get("total_events", 0)),
            "techniques_found": int(report.get("techniques_found", 0)),
            "attack_chain": [str(x) for x in (report.get("attack_chain") or [])],
            "llm_analysis": str(report.get("llm_analysis", "")),
            "llm_model": str(report.get("llm_model", "")),
            "confidence": str(report.get("confidence", "Low")),
            "iocs": report.get("iocs", "[]") if isinstance(report.get("iocs"), str) else json.dumps(report.get("iocs", [])),
            "created_at": str(report.get("created_at", "")),
        },
    }
    if evidence_case:
        result["evidence_case"] = evidence_case
    return result


def run_ingestion_cycle(time_start: str = "", time_end: str = ""):
    """Run one data collection+analysis cycle. Fall back to DataBridge if SQL Server unavailable."""
    try:
        return _run_with_sql_server()
    except Exception as e:
        logging.warning("SQL Server unavailable, falling back to DataBridge memory mode: %s", e)
        try:
            return _run_with_databridge(time_start, time_end)
        except Exception as e2:
            logging.error("DataBridge mode also failed: %s", e2)
            raise


def _get_attackevent_ids_for_window(*, uri: str, user: str, password: str, victim_ip: str, start_time: str, end_time: str) -> list[str]:
    """Bridge query: find AttackEvent IDs in Neo4j within the given time window."""
    from neo4j import GraphDatabase

    if not victim_ip or not start_time or not end_time:
        return []

    q = """
    MATCH (ae:AttackEvent)
    WHERE ae.victim_ip = $vip
      AND datetime(ae.timestamp_start) >= datetime($ts0)
      AND datetime(ae.timestamp_start) <= datetime($ts1)
    RETURN ae.id AS id
    ORDER BY ae.timestamp_start ASC
    """
    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session() as session:
            rows = session.run(q, vip=victim_ip, ts0=start_time, ts1=end_time).data()
            return [r["id"] for r in rows if r.get("id")]
    finally:
        driver.close()


_current_time_start = ""
_current_time_end = ""


def pipeline_loop():
    global STOP_FLAG, _consecutive_failures, _current_time_start, _current_time_end
    logging.info("Background analysis task started")
    while not STOP_FLAG:
        try:
            run_ingestion_cycle(_current_time_start, _current_time_end)
            _consecutive_failures = 0
        except Exception as e:
            _consecutive_failures += 1
            logging.error("Pipeline error (consecutive failures %d/%d): %s",
                          _consecutive_failures, MAX_CONSECUTIVE_FAILURES, e)
            if _consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                logging.error("Auto-stopping after %d consecutive failures. Check DB connection.", MAX_CONSECUTIVE_FAILURES)
                STOP_FLAG = True
                break
        for _ in range(60):
            if STOP_FLAG:
                break
            time.sleep(1)
    logging.info("Background analysis task stopped")
