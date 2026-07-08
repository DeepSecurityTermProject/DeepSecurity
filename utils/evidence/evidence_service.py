import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from utils.capture.evidence_chain import EvidencePackage
from utils.db.db import execute, fetch_all, fetch_one


def _now_iso() -> str:
    return datetime.now().isoformat()


def _sha256_hex_from_obj(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")).hexdigest()


def _safe_json_loads(v: Any) -> Any:
    if isinstance(v, (dict, list)):
        return v
    if not v:
        return None
    if isinstance(v, (bytes, bytearray)):
        try:
            v = v.decode("utf-8", errors="ignore")
        except Exception:
            return None
    if not isinstance(v, str):
        return None
    try:
        return json.loads(v)
    except Exception:
        return None


def _summarize_event(evt: dict) -> str:
    entities = evt.get("entities", {}) if isinstance(evt.get("entities"), dict) else {}
    pieces = [
        str(evt.get("event_type") or ""),
        str(evt.get("host_ip") or ""),
        str(entities.get("process_name") or ""),
        str(entities.get("command_line") or "")[:120],
        str(entities.get("dst_ip") or ""),
        str(entities.get("file_path") or ""),
    ]
    return " | ".join([p for p in pieces if p]).strip()[:400]


def _extract_techniques(chains: list[dict]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for c in chains or []:
        for s in c.get("stages", []) or []:
            tid = s.get("technique_id")
            if tid and tid not in seen:
                seen.add(tid)
                out.append(str(tid))
    return out


def create_evidence_case(*, verdict: dict, chains: list[dict], evidence: list[dict], report: Any) -> dict:
    case_id = str(uuid.uuid4())
    analyzed_at = _now_iso()

    pkg = EvidencePackage(case_name=str(verdict.get("verdict_id") or ""))
    chain = pkg.create_chain("analysis")

    evidence_blocks: list[dict] = []
    for ev in evidence or []:
        ev_id = str(ev.get("evidence_id") or uuid.uuid4())
        sources = ev.get("sources") if isinstance(ev.get("sources"), list) else []
        block = chain.add_evidence({
            "evidence_id": ev_id,
            "technique_id": ev.get("technique_id"),
            "technique_name": ev.get("technique_name"),
            "tactic": ev.get("tactic"),
            "severity": ev.get("severity"),
            "sources": sources[:200],
            "raw_events": (ev.get("raw_events") if isinstance(ev.get("raw_events"), list) else [])[:50],
        })
        evidence_blocks.append({"evidence_id": ev_id, "block": block})

    chain.seal()

    chain_id = chain.chain_id
    final_hash = chain.get_final_hash()
    verdict_id = str(verdict.get("verdict_id") or "")
    iocs = verdict.get("iocs", {})
    techniques = _extract_techniques(chains)
    report_text = report if isinstance(report, str) else json.dumps(report, ensure_ascii=False, default=str)

    execute(
        """
        INSERT INTO dbo.EvidenceCases (case_id, verdict_id, chain_id, final_hash, report_json, iocs_json, techniques_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            case_id,
            verdict_id,
            chain_id,
            final_hash,
            report_text,
            json.dumps(iocs, ensure_ascii=False, default=str),
            json.dumps(techniques, ensure_ascii=False, default=str),
            analyzed_at,
        ],
    )

    inserted = 0
    for item in evidence_blocks:
        ev_id = item["evidence_id"]
        block = item["block"]
        ev = next((x for x in evidence if str(x.get("evidence_id")) == ev_id), None) or {}
        sources = ev.get("sources") if isinstance(ev.get("sources"), list) else []
        base_type = str(ev.get("technique_id") or ev.get("technique_name") or "")
        for src in sources:
            if not isinstance(src, dict):
                continue
            source_table = str(src.get("source_table") or "")
            source_record_id = src.get("source_record_id")
            try:
                source_record_id_int = int(source_record_id)
            except Exception:
                continue
            event_hash = str(src.get("event_hash") or "")
            collected_at = str(src.get("collected_at") or "")
            evidence_type = str(src.get("evidence_type") or base_type)[:50]
            summary = _summarize_event(next((r for r in (ev.get("raw_events") or []) if r.get("source_record_id") == source_record_id), {})) or base_type
            execute(
                """
                INSERT INTO dbo.EvidenceRecords
                (case_id, evidence_id, block_id, block_hash, previous_hash, source_table, source_record_id, event_hash, collected_at, analyzed_at, evidence_type, summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    case_id,
                    ev_id,
                    getattr(block, "block_id", ""),
                    getattr(block, "block_hash", ""),
                    getattr(block, "previous_hash", ""),
                    source_table,
                    source_record_id_int,
                    event_hash,
                    collected_at,
                    analyzed_at,
                    evidence_type,
                    summary,
                ],
            )
            inserted += 1

    return {
        "case_id": case_id,
        "verdict_id": verdict_id,
        "chain_id": chain_id,
        "final_hash": final_hash,
        "records_count": inserted,
        "created_at": analyzed_at,
    }


def list_evidence_cases(limit: int = 50) -> list[dict]:
    rows = fetch_all(
        """
        SELECT TOP (?) case_id, verdict_id, chain_id, final_hash, created_at
        FROM dbo.EvidenceCases
        ORDER BY created_at DESC
        """,
        [limit],
    )
    for r in rows:
        r["case_id"] = str(r.get("case_id") or "")
    return rows


def get_evidence_case(case_id: str) -> dict | None:
    r = fetch_one(
        """
        SELECT case_id, verdict_id, chain_id, final_hash, report_json, iocs_json, techniques_json, created_at
        FROM dbo.EvidenceCases
        WHERE case_id = ?
        """,
        [case_id],
    )
    if not r:
        return None
    return {
        "case_id": str(r.get("case_id") or ""),
        "verdict_id": str(r.get("verdict_id") or ""),
        "chain_id": str(r.get("chain_id") or ""),
        "final_hash": str(r.get("final_hash") or ""),
        "report_json": str(r.get("report_json") or ""),
        "iocs": _safe_json_loads(r.get("iocs_json")) or {},
        "techniques": _safe_json_loads(r.get("techniques_json")) or [],
        "created_at": str(r.get("created_at") or ""),
    }


def list_evidence_records(case_id: str, limit: int = 2000) -> list[dict]:
    rows = fetch_all(
        """
        SELECT TOP (?)
            id, case_id, evidence_id, block_id, block_hash, previous_hash,
            source_table, source_record_id, event_hash, collected_at, analyzed_at, evidence_type, summary
        FROM dbo.EvidenceRecords
        WHERE case_id = ?
        ORDER BY id ASC
        """,
        [limit, case_id],
    )
    return [
        {
            "id": int(r.get("id") or 0),
            "case_id": str(r.get("case_id") or ""),
            "evidence_id": str(r.get("evidence_id") or ""),
            "block_id": str(r.get("block_id") or ""),
            "block_hash": str(r.get("block_hash") or ""),
            "previous_hash": str(r.get("previous_hash") or ""),
            "source_table": str(r.get("source_table") or ""),
            "source_record_id": int(r.get("source_record_id") or 0),
            "event_hash": str(r.get("event_hash") or ""),
            "collected_at": str(r.get("collected_at") or ""),
            "analyzed_at": str(r.get("analyzed_at") or ""),
            "evidence_type": str(r.get("evidence_type") or ""),
            "summary": str(r.get("summary") or ""),
        }
        for r in rows
    ]


def _fetch_source_row(source_table: str, source_record_id: int) -> dict | None:
    if source_table not in {"HostLogs", "HostBehaviors", "NetworkTraffic"}:
        return None
    return fetch_one(
        f"""
        SELECT id, result, content, create_time, event_hash, host_name, event_time_utc
        FROM dbo.{source_table}
        WHERE id = ?
        """,
        [source_record_id],
    )


def verify_evidence_case(case_id: str) -> dict:
    records = list_evidence_records(case_id)
    checks: list[dict] = []
    ok_count = 0
    for r in records:
        src = _fetch_source_row(r["source_table"], r["source_record_id"])
        src_obj = _safe_json_loads(src.get("result")) if src else None
        if isinstance(src_obj, dict):
            expected = _sha256_hex_from_obj(src_obj)
        else:
            expected = ""
        stored = r.get("event_hash") or ""
        matched = bool(expected) and stored.lower() == expected.lower()
        checks.append({
            "record_id": r["id"],
            "evidence_id": r["evidence_id"],
            "source_table": r["source_table"],
            "source_record_id": r["source_record_id"],
            "stored_hash": stored,
            "recomputed_hash": expected,
            "matched": matched,
        })
        if matched:
            ok_count += 1
    return {
        "case_id": case_id,
        "total": len(records),
        "matched": ok_count,
        "all_matched": ok_count == len(records) and len(records) > 0,
        "checks": checks,
        "verified_at": _now_iso(),
    }


def export_evidence_case(case_id: str, *, fmt: str = "json") -> tuple[str, str]:
    case = get_evidence_case(case_id)
    if not case:
        return "", ""

    records = list_evidence_records(case_id)
    verify_result = verify_evidence_case(case_id)

    export_obj = {
        "case": {
            "case_id": case["case_id"],
            "verdict_id": case["verdict_id"],
            "chain_id": case["chain_id"],
            "final_hash": case["final_hash"],
            "created_at": case["created_at"],
        },
        "verification": verify_result,
        "iocs": case["iocs"],
        "attck_techniques": case["techniques"],
        "report": case["report_json"],
        "evidence_records": records,
    }

    if fmt == "markdown":
        lines: list[str] = []
        lines.append("# 证据包导出")
        lines.append("")
        lines.append(f"- case_id: {case['case_id']}")
        lines.append(f"- verdict_id: {case['verdict_id']}")
        lines.append(f"- chain_id: {case['chain_id']}")
        lines.append(f"- final_hash: {case['final_hash']}")
        lines.append(f"- created_at: {case['created_at']}")
        lines.append(f"- hash_check_all_matched: {verify_result.get('all_matched')}")
        lines.append("")
        lines.append("## IOCs")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(case["iocs"], ensure_ascii=False, indent=2))
        lines.append("```")
        lines.append("")
        lines.append("## ATT&CK Techniques")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(case["techniques"], ensure_ascii=False, indent=2))
        lines.append("```")
        lines.append("")
        lines.append("## Evidence Index")
        lines.append("")
        lines.append("|id|evidence_id|source_table|source_record_id|matched|evidence_type|summary|")
        lines.append("|---:|---|---|---:|---|---|---|")
        matched_map = {c["record_id"]: c["matched"] for c in (verify_result.get("checks") or [])}
        for r in records:
            lines.append(
                f"|{r['id']}|{r['evidence_id']}|{r['source_table']}|{r['source_record_id']}|{matched_map.get(r['id'], False)}|{r['evidence_type']}|{(r.get('summary') or '').replace('|', ' ')}|"
            )
        lines.append("")
        lines.append("## Report")
        lines.append("")
        lines.append(str(case["report_json"] or ""))
        return "text/markdown; charset=utf-8", "\n".join(lines)

    return "application/json; charset=utf-8", json.dumps(export_obj, ensure_ascii=False, indent=2)

