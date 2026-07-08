"""
Multi-Agent Collaborative Capture Framework (AgentStalker-style, LLM-enhanced)
4 collaborative agents: Evidence Collector → Chain Builder → Verifier → Arbitrator
Each agent now leverages DeepSeek LLM for deep analysis.
"""
import uuid
import json
import hashlib
import logging
from datetime import datetime
from typing import Any
from collections import defaultdict

logger = logging.getLogger(__name__)


class BaseAgent:
    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self._findings: list[dict] = []

    def report(self, finding: dict):
        finding["agent"] = self.name
        finding["timestamp"] = datetime.now().isoformat()
        self._findings.append(finding)

    def get_findings(self) -> list[dict]:
        return self._findings.copy()

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Call DeepSeek LLM for agent analysis"""
        try:
            import os as _os
            api_key = _os.getenv("LLM_API_KEY", "")
            if not api_key:
                logger.info("[%s] LLM_API_KEY is not configured; skipping LLM call", self.name)
                return ""
            base_url = _os.getenv("LLM_BASE_URL", "https://api.deepseek.com")
            from openai import OpenAI
            client = OpenAI(api_key=api_key, base_url=base_url)
            resp = client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt[:3000]},
                ],
                temperature=0.2, max_tokens=600,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:
            logger.warning("[%s] LLM call failed: %s", self.name, e)
            return ""


class EvidenceCollectorAgent(BaseAgent):
    """Evidence Collector — extracts key evidence from raw events"""

    def __init__(self):
        super().__init__("EvidenceCollector", "collector")

    def collect(self, events: list[dict], alerts: list[dict]) -> list[dict]:
        evidence_items = []
        for alert in alerts:
            related = self._find_related_events(alert, events)
            evidence = self._extract_evidence(alert, related)
            evidence_items.append(evidence)
            self.report({"type": "evidence_collected", "alert_id": alert.get("rule_id"), "evidence_id": evidence["evidence_id"]})
        return evidence_items

    def _find_related_events(self, alert: dict, events: list[dict]) -> list[dict]:
        related = []
        tech_id = alert.get("technique_id", "")
        tech_name = alert.get("technique_name", "")
        for evt in events:
            entities = evt.get("entities", {})
            features = evt.get("features", {})
            cmdline = entities.get("command_line", "")
            evt_type = evt.get("event_type", "")
            # Match by technique name in command line, feature flags, or event type
            if tech_name and tech_name in cmdline:
                related.append(evt)
            elif features.get("is_covert_channel") and "tunnel" in tech_id.lower():
                related.append(evt)
            elif features.get("is_sensitive_path") and "T1003" in tech_id:
                related.append(evt)
            elif features.get("ai_pattern") and "AI" in alert.get("title", ""):
                related.append(evt)
            elif evt_type == "port_scan" and "T1046" in tech_id:
                related.append(evt)
            elif evt_type in ("data_exfiltration", "dns_tunnel_suspected", "icmp_tunnel_suspected") and tech_id:
                related.append(evt)
        return related[:20]

    def _extract_evidence(self, alert: dict, events: list[dict]) -> dict:
        evidence = {
            "evidence_id": str(uuid.uuid4()),
            "alert_id": alert.get("rule_id"),
            "technique_id": alert.get("technique_id"),
            "technique_name": alert.get("technique_name"),
            "tactic": alert.get("tactic"),
            "severity": alert.get("severity"),
            "sources": [],
            "timestamps": [],
            "ips_involved": set(),
            "processes_involved": set(),
            "files_accessed": set(),
            "network_connections": [],
            "raw_events": [],
            "chain_of_custody": [],  # SHA-256 evidence chain
        }
        for evt in events:
            evidence["timestamps"].append(str(evt.get("timestamp", "")))
            # SHA-256 hash for evidence chain of custody
            evt_hash = hashlib.sha256(json.dumps(evt, sort_keys=True, default=str).encode()).hexdigest()[:16]
            evidence["raw_events"].append({
                "event_type": evt.get("event_type"),
                "host_ip": evt.get("host_ip"),
                "timestamp": evt.get("timestamp"),
                "source_table": evt.get("source_table"),
                "source_record_id": evt.get("source_record_id"),
                "event_hash": evt.get("event_hash"),
                "entities": {k: v for k, v in evt.get("entities", {}).items()
                             if k in ("process_name", "pid", "file_path", "dst_ip", "command_line", "user", "domain")},
            })
            if evt.get("source_table") and evt.get("source_record_id"):
                evidence["sources"].append({
                    "source_table": evt.get("source_table"),
                    "source_record_id": evt.get("source_record_id"),
                    "event_hash": evt.get("event_hash") or hashlib.sha256(
                        json.dumps(evt, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
                    ).hexdigest(),
                    "collected_at": evt.get("timestamp") or "",
                    "evidence_type": evt.get("data_source") or evt.get("event_type") or "",
                })
            host_ip = evt.get("host_ip")
            if host_ip:
                evidence["ips_involved"].add(str(host_ip))
            dst_ip = evt.get("entities", {}).get("dst_ip") or evt.get("dst_ip")
            if dst_ip:
                evidence["ips_involved"].add(str(dst_ip))
                evidence["network_connections"].append({
                    "src": str(host_ip), "dst": str(dst_ip),
                    "port": evt.get("dst_port"), "protocol": str(evt.get("protocol", "TCP")),
                    "timestamp": evt.get("timestamp"),
                })
            process = evt.get("entities", {}).get("process_name")
            if process:
                evidence["processes_involved"].add(str(process))
            file_path = evt.get("entities", {}).get("file_path")
            if file_path:
                evidence["files_accessed"].add(str(file_path))
        evidence["ips_involved"] = list(evidence["ips_involved"])
        evidence["processes_involved"] = list(evidence["processes_involved"])
        evidence["files_accessed"] = list(evidence["files_accessed"])
        evidence["sources"] = evidence["sources"][:200]
        return evidence


class ChainBuilderAgent(BaseAgent):
    """Chain Builder — reconstructs causal attack chains from evidence"""

    def __init__(self):
        super().__init__("ChainBuilder", "builder")

    def build_chains(self, evidence_items: list[dict]) -> list[dict]:
        sorted_evidence = sorted(evidence_items, key=lambda e: len(e.get("timestamps", [])))
        chains = []
        current_chain = None
        for ev in sorted_evidence:
            tactic = ev.get("tactic", "Unknown")
            stage_order = self._tactic_order(tactic)
            if current_chain is None:
                current_chain = self._create_chain(ev, stage_order)
            else:
                prev_order = self._tactic_order(current_chain["stages"][-1]["tactic"])
                if stage_order >= prev_order:
                    current_chain["stages"].append(self._create_stage(ev, stage_order))
                else:
                    chains.append(current_chain)
                    current_chain = self._create_chain(ev, stage_order)
        if current_chain and current_chain["stages"]:
            chains.append(current_chain)
        for i, chain in enumerate(chains):
            chain["chain_id"] = f"chain_{i + 1:03d}"
            chain["confidence"] = self._calculate_chain_confidence(chain)
            self.report({"type": "chain_built", "chain_id": chain["chain_id"], "stages": len(chain["stages"])})
        return chains

    def _create_chain(self, evidence: dict, start_order: int) -> dict:
        ips = evidence.get("ips_involved", [])
        ts_list = evidence.get("timestamps", [])
        return {
            "victim_ip": ips[0] if ips else "unknown",
            "stages": [self._create_stage(evidence, start_order)],
            "ips_path": ips,
            "start_time": ts_list[0] if ts_list else "",
            "end_time": ts_list[-1] if ts_list else "",
        }

    def _create_stage(self, evidence: dict, order: int) -> dict:
        return {
            "stage_order": order,
            "tactic": evidence.get("tactic", "Unknown"),
            "technique_id": evidence.get("technique_id"),
            "technique_name": evidence.get("technique_name"),
            "processes": evidence.get("processes_involved", []),
            "ips": evidence.get("ips_involved", []),
            "files": evidence.get("files_accessed", []),
            "evidence_id": evidence.get("evidence_id"),
        }

    def _tactic_order(self, tactic: str) -> int:
        return {"Reconnaissance": 1, "Initial Access": 2, "Execution": 3,
                "Persistence": 4, "Privilege Escalation": 5, "Defense Evasion": 6,
                "Credential Access": 7, "Discovery": 8, "Lateral Movement": 9,
                "Collection": 10, "Command and Control": 11, "Exfiltration": 12, "Impact": 13}.get(tactic, 99)

    def _calculate_chain_confidence(self, chain: dict) -> float:
        stages = chain.get("stages", [])
        if not stages:
            return 0.0
        orders = [s.get("stage_order", 99) for s in stages]
        order_score = sum(1 for i in range(len(orders) - 1) if orders[i] <= orders[i + 1]) / max(len(orders) - 1, 1)
        unique_tactics = len(set(s.get("tactic") for s in stages))
        coverage = min(unique_tactics / 7.0, 1.0)
        return round(order_score * 0.4 + coverage * 0.6, 2)


class VerifierAgent(BaseAgent):
    """Verifier — validates chain authenticity against raw events"""

    def __init__(self):
        super().__init__("Verifier", "verifier")

    def verify(self, chains: list[dict], all_events: list[dict]) -> list[dict]:
        verified = []
        for chain in chains:
            verdict = self._verify_chain(chain, all_events)
            verified.append({**chain, "verification": verdict})
            self.report({"type": "verification", "chain_id": chain["chain_id"], "verdict": verdict})
        return verified

    def _verify_chain(self, chain: dict, events: list[dict]) -> dict:
        issues = []
        confirmations = []
        stages = chain.get("stages", [])
        ips_path = chain.get("ips_path", [])
        # IP connectivity check
        for i in range(len(ips_path) - 1):
            src, dst = ips_path[i], ips_path[i + 1]
            found = any(
                (str(e.get("host_ip")) == src and str(e.get("entities", {}).get("dst_ip")) == dst) or
                (str(e.get("src_ip")) == src and str(e.get("dst_ip")) == dst)
                for e in events
            )
            (confirmations if found else issues).append(f"IP {src}→{dst}: {'OK' if found else 'MISSING'}")
        # Time order check
        ts = chain.get("start_time", ""), chain.get("end_time", "")
        if ts[0] and ts[1] and ts[0] <= ts[1]:
            confirmations.append("Time order OK")
        else:
            issues.append("Time order anomaly")
        # Tactical phase logic check
        expected = ["Initial Access", "Execution", "Persistence", "Credential Access",
                    "Discovery", "Lateral Movement", "Command and Control", "Exfiltration"]
        stage_tactics = [s.get("tactic") for s in stages if s.get("tactic") in expected]
        if len(stage_tactics) > 1:
            ordered = all(expected.index(stage_tactics[i]) <= expected.index(stage_tactics[i + 1])
                          for i in range(len(stage_tactics) - 1))
            (confirmations if ordered else issues).append("Tactical phase order: OK" if ordered else "ANOMALY")
        total = len(confirmations) + len(issues)
        passed = len(confirmations)
        confidence = passed / max(total, 1)
        return {"is_valid": confidence >= 0.5, "confidence": round(confidence, 2),
                "confirmations": confirmations, "issues": issues,
                "verdict": "VERIFIED" if confidence >= 0.7 else ("PLAUSIBLE" if confidence >= 0.4 else "UNVERIFIED")}


class ArbitratorAgent(BaseAgent):
    """Arbitrator — LLM-powered final verdict and attribution"""

    def __init__(self):
        super().__init__("Arbitrator", "arbitrator")

    def arbitrate(self, verified_chains: list[dict], evidence_items: list[dict], alerts: list[dict]) -> dict:
        valid_chains = [c for c in verified_chains if c.get("verification", {}).get("is_valid", False)]
        all_ips = set()
        all_processes = set()
        all_techniques = set()
        for chain in valid_chains:
            for stage in chain.get("stages", []):
                all_ips.update(stage.get("ips", []))
                all_processes.update(stage.get("processes", []))
                if stage.get("technique_id"):
                    all_techniques.add(stage["technique_id"])
        ip_freq = defaultdict(int)
        for chain in valid_chains:
            for ip in chain.get("ips_path", []):
                ip_freq[ip] += 1
        pivot_nodes = [ip for ip, count in ip_freq.items() if count >= 2]

        verdict = {
            "verdict_id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "attack_confirmed": len(valid_chains) > 0,
            "confidence_level": self._overall_confidence(valid_chains),
            "chains_found": len(verified_chains),
            "chains_verified": len(valid_chains),
            "total_alerts": len(alerts),
            "iocs": {"ips": list(all_ips), "processes": list(all_processes), "techniques": list(all_techniques)},
            "pivot_nodes": pivot_nodes,
            "attack_type": self._classify_attack(valid_chains),
            "recommended_actions": self._generate_recommendations(valid_chains, pivot_nodes),
        }

        # DeepSeek LLM-powered verdict analysis
        chain_summary = json.dumps({
            "chains_verified": len(valid_chains),
            "chains_total": len(verified_chains),
            "techniques_detected": list(all_techniques),
            "ips_involved": list(all_ips)[:10],
            "processes_involved": list(all_processes)[:10],
            "pivot_nodes": pivot_nodes,
            "attack_type": verdict["attack_type"],
        }, ensure_ascii=False, indent=2)

        llm_response = self._call_llm(
            "You are a senior security incident arbitrator. Analyze the multi-agent chain verification results "
            "and provide: (1) Final attack confirmation verdict (2) Attack severity assessment "
            "(3) Key evidence supporting the conclusion (4) Attribution hints based on TTPs. "
            "Respond in Chinese, under 300 words.",
            f"Multi-agent framework results:\n{chain_summary}"
        )
        verdict["llm_arbitration"] = llm_response if llm_response else "[LLM unavailable]"
        verdict["summary"] = llm_response[:200] if llm_response else self._generate_summary(valid_chains, len(alerts))
        self.report({"type": "arbitration_complete", "verdict": verdict})
        return verdict

    def _generate_summary(self, chains: list[dict], alert_count: int) -> str:
        if not chains:
            return f"No confirmed attack chains. {alert_count} alerts analyzed."
        stages_total = sum(len(c.get("stages", [])) for c in chains)
        return (f"Confirmed {len(chains)} attack chain(s) with {stages_total} stages "
                f"from {alert_count} alerts. Confidence: {self._overall_confidence(chains):.0%}.")

    def _overall_confidence(self, chains: list[dict]) -> float:
        if not chains:
            return 0.0
        return round(sum(c.get("verification", {}).get("confidence", 0) for c in chains) / len(chains), 2)

    def _classify_attack(self, chains: list[dict]) -> str:
        all_tactics = set()
        for c in chains:
            for s in c.get("stages", []):
                all_tactics.add(s.get("tactic", ""))
        if "Exfiltration" in all_tactics and "Lateral Movement" in all_tactics:
            return "Advanced Persistent Threat (APT)"
        elif "Exfiltration" in all_tactics:
            return "Data Exfiltration Attack"
        elif "Lateral Movement" in all_tactics:
            return "Lateral Movement Attack"
        elif "Command and Control" in all_tactics:
            return "C2 Communication"
        return "Suspicious Activity"

    def _generate_recommendations(self, chains: list[dict], pivot_nodes: list[str]) -> list[str]:
        recs = []
        if pivot_nodes:
            recs.append(f"Isolate pivot nodes: {', '.join(pivot_nodes[:3])}")
        recs.extend([
            "Collect memory/disk images from affected hosts",
            "Block identified C2 IPs and domains",
            "Reset compromised credentials",
            "Deploy YARA/Sigma rules for detected malware",
            "Feed IOCs into SIEM/SOAR for continuous monitoring",
        ])
        return recs


class MultiAgentCaptureFramework:
    """Multi-agent collaborative capture framework (LLM-enhanced)"""

    def __init__(self):
        self.collector = EvidenceCollectorAgent()
        self.builder = ChainBuilderAgent()
        self.verifier = VerifierAgent()
        self.arbitrator = ArbitratorAgent()

    def run(self, events: list[dict], alerts: list[dict]) -> dict:
        evidence = self.collector.collect(events, alerts)
        chains = self.builder.build_chains(evidence)
        verified = self.verifier.verify(chains, events)
        verdict = self.arbitrator.arbitrate(verified, evidence, alerts)
        return {
            "verdict": verdict,
            "evidence": evidence,
            "chains": verified,
            "agent_reports": {
                "collector": self.collector.get_findings(),
                "builder": self.builder.get_findings(),
                "verifier": self.verifier.get_findings(),
                "arbitrator": self.arbitrator.get_findings(),
            },
        }


_capture_framework: MultiAgentCaptureFramework | None = None


def get_capture_framework() -> MultiAgentCaptureFramework:
    global _capture_framework
    if _capture_framework is None:
        _capture_framework = MultiAgentCaptureFramework()
    return _capture_framework
