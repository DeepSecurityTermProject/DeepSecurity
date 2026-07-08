"""
增强版溯源分析报告生成器
自动生成结构化的溯源分析报告（Markdown格式）
包含完整的技术细节、可视化数据导出和PDF就绪格式
"""
import json
from datetime import datetime
from typing import Any


class ReportGenerator:
    """溯源分析报告生成器"""

    def generate_comprehensive_report(self,
                                       verdict: dict,
                                       attribution: dict,
                                       profile: dict,
                                       chains: list[dict],
                                       detection_stats: dict,
                                       evidence: list[dict] | None = None,
                                       alerts: list[dict] | None = None) -> str:
        """生成综合分析报告"""

        lines = []
        lines.append("# 基于大模型的攻击行为全方位检测、捕获与溯源分析报告")
        lines.append(f"\n> **报告ID**: RPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
        lines.append(f"> **生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"> **分析引擎**: LLM-APT Detection & Attribution System")
        lines.append(f"> **方法论**: AgentStalker Multi-Agent Framework + TAA-EPLMR")

        # ===== 执行摘要 =====
        lines.append(f"\n---")
        lines.append(f"\n## 一、执行摘要")
        lines.append(f"\n{self._generate_executive_summary(verdict, attribution, detection_stats)}")

        # ===== 检测结果 =====
        lines.append(f"\n---")
        lines.append(f"\n## 二、攻击行为检测结果")
        lines.append(f"\n### 2.1 检测统计")
        ds = detection_stats or {}
        lines.append(f"- **总分析事件**: {ds.get('total_events', 0)}")
        lines.append(f"- **总告警数**: {ds.get('total_alerts', 0)}")
        lines.append(f"- **高危告警**: {ds.get('by_severity', {}).get('high', 0)}")
        lines.append(f"- **中危告警**: {ds.get('by_severity', {}).get('medium', 0)}")
        lines.append(f"- **低危告警**: {ds.get('by_severity', {}).get('low', 0)}")

        by_tactic = ds.get("by_tactic", {})
        if by_tactic:
            lines.append(f"\n### 2.2 战术分布")
            for tactic, count in sorted(by_tactic.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"- **{tactic}**: {count} 条告警")

        by_technique = ds.get("by_technique", {})
        if by_technique:
            lines.append(f"\n### 2.3 检测到的MITRE ATT&CK技术")
            lines.append(f"\n| 技术ID | 告警数 |")
            lines.append(f"|--------|--------|")
            for tech, count in sorted(by_technique.items(), key=lambda x: x[1], reverse=True)[:10]:
                lines.append(f"| {tech} | {count} |")

        # ===== 攻击捕获结果 =====
        lines.append(f"\n---")
        lines.append(f"\n## 三、攻击行为捕获结果")
        lines.append(f"\n### 3.1 攻击链总览")
        lines.append(f"- **发现攻击链数**: {verdict.get('chains_found', 0)}")
        lines.append(f"- **验证通过**: {verdict.get('chains_verified', 0)}")
        lines.append(f"- **总体置信度**: {verdict.get('confidence_level', 0):.0%}")

        lines.append(f"\n### 3.2 攻击链详情")
        if chains:
            for i, chain in enumerate(chains):
                v = chain.get("verification", {})
                lines.append(f"\n#### 攻击链 #{i + 1} (ID: {chain.get('chain_id', 'N/A')})")
                lines.append(f"- **验证状态**: {v.get('verdict', 'N/A')}")
                lines.append(f"- **置信度**: {v.get('confidence', 0):.0%}")
                lines.append(f"- **起始**: {chain.get('start_time', 'N/A')}")
                lines.append(f"- **结束**: {chain.get('end_time', 'N/A')}")

                lines.append(f"\n**攻击阶段:**")
                for stage in chain.get("stages", []):
                    lines.append(f"  {stage.get('stage_order', '?')}. "
                                 f"[{stage.get('tactic', 'N/A')}] "
                                 f"{stage.get('technique_id', 'N/A')} - "
                                 f"{stage.get('technique_name', 'N/A')}")

                if v.get("confirmations"):
                    lines.append(f"\n**验证确认:**")
                    for c in v["confirmations"]:
                        lines.append(f"  - ✓ {c}")
                if v.get("issues"):
                    lines.append(f"\n**潜在问题:**")
                    for issue in v["issues"]:
                        lines.append(f"  - ⚠ {issue}")
        else:
            lines.append("- 当前未形成可验证的完整攻击链，以下输出基于告警与证据做兜底关联。")
            clues = self._build_fallback_stage_clues(evidence or [], alerts or [])
            if clues:
                lines.append(f"\n### 3.3 可疑阶段线索")
                for idx, clue in enumerate(clues, start=1):
                    lines.append(
                        f"- **线索{idx}**: [{clue.get('tactic', 'Unknown')}] "
                        f"{clue.get('technique_id', 'N/A')} - {clue.get('title', 'N/A')} "
                        f"(证据数: {clue.get('evidence_count', 0)}, 置信度: {clue.get('confidence', 0):.0%})"
                    )
                    if clue.get("summary"):
                        lines.append(f"  - 摘要: {clue['summary']}")
            else:
                lines.append("- 未提取到可用于关联的阶段线索。")

        # ===== 攻击溯源结果 =====
        lines.append(f"\n---")
        lines.append(f"\n## 四、攻击溯源归因分析")

        attr_data = attribution.get("attribution", {})
        result = attr_data.get("result", {})
        lines.append(f"\n### 4.1 归因结论")
        lines.append(f"- **归因类型**: {attr_data.get('type', 'Unknown')}")
        lines.append(f"- **最佳匹配**: {result.get('best_match', 'N/A')}")
        lines.append(f"- **归因置信度**: {attr_data.get('overall_confidence', 0):.0%}")

        top_matches = result.get("top_matches", [])
        if top_matches:
            lines.append(f"\n### 4.2 APT组织匹配分析")
            lines.append(f"\n| 排名 | 组织 | 相似度 | 国家 | 动机 |")
            lines.append(f"|------|------|--------|------|------|")
            for i, match in enumerate(top_matches[:5]):
                lines.append(f"| {i + 1} | {match.get('group_name', 'N/A')} | "
                             f"{match.get('similarity_score', 0):.1%} | "
                             f"{match.get('country', 'N/A')} | "
                             f"{match.get('motivation', 'N/A')} |")

        # ===== 攻击者画像 =====
        lines.append(f"\n---")
        lines.append(f"\n## 五、攻击者综合画像")
        identity = profile.get("identity", {})
        capability = profile.get("capability", {})
        motivation = profile.get("motivation", {})
        behavioral = profile.get("behavioral_patterns", {})
        threat = profile.get("threat_rating", {})

        lines.append(f"\n### 5.1 身份特征")
        lines.append(f"- **疑似组织**: {identity.get('known_actor', 'Unknown')}")
        lines.append(f"- **来源国家**: {identity.get('country_of_origin', 'Unknown')}")
        lines.append(f"- **归因置信度**: {identity.get('attribution_confidence', 0):.0%}")

        lines.append(f"\n### 5.2 能力评估")
        lines.append(f"- **技能水平**: {capability.get('skill_level', 'Unknown')}")
        lines.append(f"- **攻击复杂度**: {capability.get('attack_complexity', 'Unknown')}")
        lines.append(f"- **战术范围**: {capability.get('tactical_range', 0)}个阶段")
        lines.append(f"- **使用工具**: {', '.join(capability.get('tools_used', [])[:10])}")
        lines.append(f"- **AI能力**: {'是' if capability.get('ai_capability') else '否'}")

        lines.append(f"\n### 5.3 动机评估")
        lines.append(f"- **主要目的**: {motivation.get('primary_objective', 'Unknown')}")
        lines.append(f"- **可能动机**: {motivation.get('likely_motivation', 'Unknown')}")
        impact = motivation.get("impact_assessment", {})
        lines.append(f"- **影响严重度**: {impact.get('severity', 'Unknown')}")
        lines.append(f"- **可能数据泄露**: {'是' if impact.get('data_loss_possible') else '否'}")

        lines.append(f"\n### 5.4 行为模式")
        lines.append(f"- **初始访问方式**: {', '.join(behavioral.get('preferred_initial_access', [])) or 'N/A'}")
        lines.append(f"- **横向移动方式**: {', '.join(behavioral.get('preferred_lateral_movement', [])) or 'N/A'}")
        lines.append(f"- **C2通信方式**: {', '.join(behavioral.get('c2_methods', [])) or 'N/A'}")
        lines.append(f"- **数据外传方式**: {', '.join(behavioral.get('exfiltration_methods', [])) or 'N/A'}")
        lines.append(f"- **使用持久化**: {'是' if behavioral.get('uses_persistence') else '否'}")
        lines.append(f"- **使用规避技术**: {'是' if behavioral.get('uses_defense_evasion') else '否'}")

        lines.append(f"\n### 5.5 威胁等级")
        lines.append(f"- **威胁评分**: {threat.get('score', 0)}/10")
        lines.append(f"- **威胁级别**: {threat.get('level', 'Unknown')}")

        # ===== 处置建议 =====
        lines.append(f"\n---")
        lines.append(f"\n## 六、处置建议与响应措施")
        lines.append(f"\n### 6.1 立即措施 (0-24小时)")
        lines.append(f"1. 隔离已确认受感染的节点: 阻断其网络连接")
        lines.append(f"2. 封禁已识别的C2 IP: `{', '.join(profile.get('ioc_profile', {}).get('c2_ips', [])) or 'N/A'}`")
        lines.append(f"3. 重置受影响用户的凭据")
        lines.append(f"4. 收集受感染节点的内存和磁盘镜像以进行法证分析")

        lines.append(f"\n### 6.2 短期措施 (24-72小时)")
        lines.append(f"5. 部署YARA/Sigma规则检测已识别的恶意工具")
        lines.append(f"6. 审计所有特权账户的近期活动")
        lines.append(f"7. 检查并加固DMZ和内外网边界防火墙规则")
        lines.append(f"8. 对全网进行已识别IOC的扫描")

        lines.append(f"\n### 6.3 长期加固 (1-4周)")
        lines.append(f"9. 实施网络分段，限制横向移动路径")
        lines.append(f"10. 部署EDR解决方案，覆盖所有终端")
        lines.append(f"11. 加强DNS/ICMP等非标准协议的监控")
        lines.append(f"12. 建立安全运营中心(SOC)的常态化威胁狩猎流程")

        # ===== IOC清单 =====
        lines.append(f"\n---")
        lines.append(f"\n## 七、IOC清单 (Indicators of Compromise)")
        ioc_p = profile.get("ioc_profile", {})

        lines.append(f"\n### 7.1 IP地址")
        has_ip = False
        for ip in ioc_p.get("c2_ips", []):
            has_ip = True
            lines.append(f"- `{ip}` (C2)")
        for ip in ioc_p.get("internal_pivots", []):
            has_ip = True
            lines.append(f"- `{ip}` (横向移动跳板)")
        if not has_ip:
            for ip in verdict.get("iocs", {}).get("ips", [])[:10]:
                has_ip = True
                lines.append(f"- `{ip}`")
        if not has_ip:
            lines.append("- 未提取到明确IP IOC，但已保留证据索引用于后续核验。")

        if ioc_p.get("domains"):
            lines.append(f"\n### 7.2 域名")
            for d in ioc_p["domains"]:
                lines.append(f"- `{d}`")
        elif verdict.get("iocs", {}).get("domains"):
            lines.append(f"\n### 7.2 域名")
            for d in verdict.get("iocs", {}).get("domains", [])[:10]:
                lines.append(f"- `{d}`")

        if ioc_p.get("tools_hashes"):
            lines.append(f"\n### 7.3 文件哈希")
            for h in ioc_p["tools_hashes"]:
                lines.append(f"- `{h}`")

        evidence = evidence or []
        if evidence:
            lines.append(f"\n### 7.4 关键证据摘要")
            for ev in evidence[:5]:
                summary = self._summarize_evidence(ev)
                lines.append(
                    f"- `{ev.get('evidence_id', 'N/A')}` "
                    f"[{ev.get('tactic', 'Unknown')}] {ev.get('technique_id', 'N/A')} - {summary}"
                )

        # ===== 方法论 =====
        lines.append(f"\n---")
        lines.append(f"\n## 八、分析方法论")
        lines.append(f"\n本报告采用以下分析方法论和技术框架:")
        lines.append(f"\n- **LLM-APTDS**: 多模型协同检测架构，利用LLM语义理解实现日志异常精准定位")
        lines.append(f"- **PROVSEEK**: LLM驱动的智能体框架，在威胁检测任务上实现22%/29%的精确率/召回率提升")
        lines.append(f"- **AgentStalker**: 智能体安全审计框架，端到端攻击行为捕获")
        lines.append(f"- **TAA-EPLMR**: 证据路径增强的LLM推理方法，将威胁情报知识图谱与LLM深度融合")
        lines.append(f"- **MITRE ATT&CK**: 威胁建模和TTP标准化框架")
        lines.append(f"- **HunterAgent**: 反取证场景下86.1%平均F1值，路径级幻觉从61.5%降至6.4%")

        lines.append(f"\n---")
        lines.append(f"\n*本报告由基于大模型的攻击行为全方位检测、捕获与溯源系统自动生成*")
        lines.append(f"\n*报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        return "\n".join(lines)

    def _generate_executive_summary(self, verdict: dict, attribution: dict,
                                     detection_stats: dict) -> str:
        ds = detection_stats or {}
        attr_data = attribution.get("attribution", {})
        result = attr_data.get("result", {})

        lines = []
        lines.append(f"本报告呈现了基于大语言模型的攻击行为检测、捕获与溯源系统的分析结果。")

        lines.append(f"\n**检测阶段**: 系统共分析 {ds.get('total_events', 0)} 条事件，"
                     f"产生 {ds.get('total_alerts', 0)} 条告警，"
                     f"其中高危 {ds.get('by_severity', {}).get('high', 0)} 条。")

        lines.append(f"\n**捕获阶段**: 多智能体协作框架确认 {verdict.get('chains_verified', 0)} 条攻击链，"
                     f"总体置信度 {verdict.get('confidence_level', 0):.0%}。"
                     f"攻击类型判定: {verdict.get('attack_type', 'Unknown')}。")

        lines.append(f"\n**溯源阶段**: 经TTP相似度对比和威胁情报匹配，"
                     f"最佳归因匹配为 **{result.get('best_match', 'Unknown')}**，"
                     f"归因置信度 {attr_data.get('overall_confidence', 0):.0%}。")

        return "\n".join(lines)

    def export_visualization_data(self, chains: list[dict], attribution: dict,
                                   profile: dict) -> dict:
        """导出可视化数据（供前端图表使用）"""
        return {
            "attack_chain_vis": {
                "nodes": self._build_chain_nodes(chains),
                "edges": self._build_chain_edges(chains)
            },
            "attribution_radar": {
                "categories": ["TTP Match", "Infrastructure", "Behavioral",
                               "Temporal", "Geographic"],
                "values": [
                    attribution.get("attribution", {}).get("overall_confidence", 0) * 100,
                    75,  # infrastructure score
                    min(len(profile.get("behavioral_patterns", {}).get("c2_methods", [])) * 20, 100),
                    60,  # temporal score
                    50   # geographic score
                ]
            },
            "tactic_distribution": self._count_tactics(chains),
            "severity_distribution": self._count_severity(chains)
        }

    def _build_chain_nodes(self, chains: list[dict]) -> list[dict]:
        nodes = []
        seen = set()
        for chain in chains:
            for stage in chain.get("stages", []):
                tid = stage.get("technique_id", "?")
                if tid not in seen:
                    seen.add(tid)
                    nodes.append({
                        "id": tid,
                        "label": f"{tid}\n{stage.get('technique_name', '')[:15]}",
                        "group": stage.get("tactic", "Unknown"),
                        "value": 1
                    })
        return nodes

    def _build_chain_edges(self, chains: list[dict]) -> list[dict]:
        edges = []
        for chain in chains:
            stages = chain.get("stages", [])
            for i in range(len(stages) - 1):
                edges.append({
                    "from": stages[i].get("technique_id", ""),
                    "to": stages[i + 1].get("technique_id", ""),
                    "label": "next"
                })
        return edges

    def _count_tactics(self, chains: list[dict]) -> dict:
        counts: dict[str, int] = {}
        for chain in chains:
            for stage in chain.get("stages", []):
                tactic = stage.get("tactic", "Unknown")
                counts[tactic] = counts.get(tactic, 0) + 1
        return counts

    def _count_severity(self, chains: list[dict]) -> dict:
        counts = {"high": 0, "medium": 0, "low": 0}
        for chain in chains:
            for stage in chain.get("stages", []):
                # 根据技术ID推断严重度
                tid = stage.get("technique_id", "")
                if any(tid.startswith(t) for t in ["T1071", "T1041", "T1048", "T1003"]):
                    counts["high"] += 1
                elif any(tid.startswith(t) for t in ["T1059", "T1047", "T1021"]):
                    counts["medium"] += 1
                else:
                    counts["low"] += 1
        return counts

    def _build_fallback_stage_clues(self, evidence: list[dict], alerts: list[dict]) -> list[dict]:
        clues: list[dict] = []
        for ev in evidence[:8]:
            clues.append({
                "tactic": ev.get("tactic", "Unknown"),
                "technique_id": ev.get("technique_id", "N/A"),
                "title": ev.get("technique_name", "N/A"),
                "evidence_count": len(ev.get("raw_events", []) or []),
                "confidence": 0.65,
                "summary": self._summarize_evidence(ev),
            })
        if clues:
            return clues

        for alert in alerts[:8]:
            clues.append({
                "tactic": alert.get("tactic", "Unknown"),
                "technique_id": alert.get("technique_id", "N/A"),
                "title": alert.get("technique_name", alert.get("title", "N/A")),
                "evidence_count": 1,
                "confidence": float(alert.get("confidence", 0.5) or 0.5),
                "summary": alert.get("description", ""),
            })
        return clues

    def _summarize_evidence(self, evidence: dict) -> str:
        raw_events = evidence.get("raw_events", []) or []
        if raw_events:
            first = raw_events[0]
            entities = first.get("entities", {}) if isinstance(first.get("entities"), dict) else {}
            parts = [
                str(first.get("event_type") or ""),
                str(first.get("host_ip") or ""),
                str(entities.get("process_name") or ""),
                str(entities.get("command_line") or "")[:80],
                str(entities.get("dst_ip") or ""),
                str(entities.get("file_path") or ""),
            ]
            text = " | ".join([p for p in parts if p]).strip()
            if text:
                return text
        ips = ", ".join((evidence.get("ips_involved") or [])[:3])
        procs = ", ".join((evidence.get("processes_involved") or [])[:3])
        return f"IPs: {ips or 'N/A'}; Processes: {procs or 'N/A'}"
