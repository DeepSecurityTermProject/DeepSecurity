from neo4j import GraphDatabase

#-------------------------------------------------------------------------------------------------
# 对接前端 vis-network。它负责执行 Cypher 查询，并将结果转化为 Nodes/Edges 结构。
# [增强] 增加边证据信息、置信度、时间间隔等属性用于前端展示
#-------------------------------------------------------------------------------------------------
class GraphSerializer:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def _run_query(self, query, **kwargs):
        """安全执行查询，失败返回空列表"""
        try:
            with self.driver.session() as session:
                result = session.run(query, **kwargs)
                return result.data()
        except Exception as e:
            from urllib.parse import urlparse
            from utils.data_bridge import get_bridge
            # 记录并返回空 - 前端会 fallback
            import logging
            logging.warning(f"Neo4j query failed, will fallback: {e}")
            return None

    def get_attack_chain_summary(self, scenario_id):
        """
        【宏观视图】仅展示 ATT&CK 战术/技术的流转
        [增强] 返回边上的 evidence_source, confidence, time_interval
        """
        query = """
        MATCH (ae:AttackEvent)
        WHERE ae.scenario_id = $sid
        MATCH (ae)-[:IS_TYPE]->(t:Technique)

        // 查找阶段间的流转关系
        OPTIONAL MATCH (ae)-[r:NEXT_STAGE]->(next_ae:AttackEvent)
        WHERE next_ae.scenario_id = $sid

        RETURN ae, t, r, next_ae
        ORDER BY ae.stage_order, ae.timestamp_start
        """
        nodes = []
        edges = []
        added_nodes = set()

        result = self._run_query(query, sid=scenario_id)
        if result is None:
            return {"nodes": [], "edges": []}

        for record in result:
            ae = record['ae']
            t = record['t']

            node_id = ae.get('id', '')
            if node_id and node_id not in added_nodes:
                nodes.append({
                    "id": node_id,
                    "label": t.get('name', '?'),
                    "group": "technique",
                    "title": (
                        f"TID: {t.get('id', '?')}\n"
                        f"Time: {ae.get('timestamp_start', '?')}\n"
                        f"Victim: {ae.get('victim_ip', '?')}\n"
                        f"Attacker: {ae.get('attacker_ip', '?')}\n"
                        f"Rule: {ae.get('rule_id', '?')}\n"
                        f"Confidence: {ae.get('confidence', '?')}"
                    ),
                    "stage": ae.get('stage_order', 0),
                    "victim_ip": ae.get('victim_ip', ''),
                    "attacker_ip": ae.get('attacker_ip', ''),
                })
                added_nodes.add(node_id)

            next_ae = record.get('next_ae')
            r = record.get('r')
            if next_ae and r:
                edge = {
                    "from": node_id,
                    "to": next_ae.get('id', ''),
                    "arrows": "to",
                    "label": r.get('type', 'next'),
                }
                # [增强] 边属性
                edge_data = dict(r)
                if 'type' in edge_data:
                    edge["edge_type"] = edge_data.get('type', 'next')
                if 'confidence' in edge_data:
                    edge["confidence"] = edge_data.get('confidence', 'Medium')
                if 'evidence_source' in edge_data:
                    edge["evidence_source"] = edge_data.get('evidence_source', '')
                if 'time_interval' in edge_data:
                    edge["time_interval"] = edge_data.get('time_interval', 0)
                if 'description' in edge_data:
                    edge["description"] = edge_data.get('description', '')
                if 'evidence_entity' in edge_data:
                    edge["evidence_entity"] = edge_data.get('evidence_entity', '')
                edges.append(edge)

        return {"nodes": nodes, "edges": edges}

    def get_scenario_topology(self, scenario_id):
        """
        【微观视图】展示底层的实体拓扑 (Process, File, IP)
        [增强] 包含所有边类型及证据信息
        """
        query = """
        MATCH (ae:AttackEvent {scenario_id: $sid})
        MATCH (entity)-[:TRIGGERED]->(ae)

        WITH collect(DISTINCT entity) AS core_entities

        UNWIND core_entities AS start_node
        OPTIONAL MATCH path = (start_node)-[r:Spawn|Write|Read|Connect|Inject|Resolve|Load|
                                            Traffic_Flow|Logon|Logon_Source|RUN_AS|USED_CREDENTIAL|
                                            STARTS_SESSION|LOGGED_INTO|FAILED_LOGON|FAILED_LOGON_SOURCE|
                                            LATERAL_MOVEMENT]-(related)

        RETURN start_node AS entity, collect(path) AS paths
        """

        nodes = {}
        edges_map = {}

        result = self._run_query(query, sid=scenario_id)
        if result is None:
            return {"nodes": [], "edges": []}

        for record in result:
            self._process_node(record['entity'], nodes)

            paths = record['paths']
            if paths:
                for p in paths:
                    for rel in p.relationships:
                        src = rel.start_node
                        dst = rel.end_node

                        self._process_node(src, nodes)
                        self._process_node(dst, nodes)

                        edge_key = f"{src.get('id', '')}_{rel.type}_{dst.get('id', '')}"
                        if edge_key not in edges_map:
                            edge_obj = {
                                "id": edge_key,
                                "from": src.get('id', ''),
                                "to": dst.get('id', ''),
                                "label": rel.type,
                                "arrows": "to",
                                "color": {"color": "#ff0000"} if rel.type in ['Inject', 'Connect', 'LATERAL_MOVEMENT'] else "#848484"
                            }
                            # [增强] 复制边属性
                            edge_data = dict(rel)
                            if 'confidence' in edge_data:
                                edge_obj["confidence"] = edge_data.get('confidence', 'Medium')
                            if 'evidence_source' in edge_data:
                                edge_obj["evidence_source"] = edge_data.get('evidence_source', '')
                            if 'timestamp' in edge_data:
                                edge_obj["timestamp"] = str(edge_data.get('timestamp', ''))
                            if 'dst_port' in edge_data:
                                edge_obj["dst_port"] = edge_data.get('dst_port', '')
                            if 'user' in edge_data:
                                edge_obj["user"] = edge_data.get('user', '')
                            if 'session_id' in edge_data:
                                edge_obj["session_id"] = edge_data.get('session_id', '')
                            if 'process' in edge_data:
                                edge_obj["process"] = edge_data.get('process', '')
                            if 'logon_time' in edge_data:
                                edge_obj["logon_time"] = str(edge_data.get('logon_time', ''))

                            # 生成证据摘要
                            evidence_parts = []
                            if edge_obj.get('evidence_source'):
                                evidence_parts.append(f"Source: {edge_obj['evidence_source']}")
                            if edge_obj.get('timestamp'):
                                evidence_parts.append(f"Time: {edge_obj['timestamp']}")
                            if edge_obj.get('confidence'):
                                evidence_parts.append(f"Conf: {edge_obj['confidence']}")
                            if evidence_parts:
                                edge_obj["evidence_summary"] = " | ".join(evidence_parts)

                            edges_map[edge_key] = edge_obj

        return {"nodes": list(nodes.values()), "edges": list(edges_map.values())}

    def get_lateral_movement_paths(self, scenario_id):
        """
        【横向移动路径】展示跨主机的横向移动链路
        返回：源主机 → 凭据 → 目标主机 → 登录方式 → 后续进程
        强制绑定到当前 scenario_id 的 AttackEvent，防止多场景数据串场
        """
        query = """
        MATCH (ae:AttackEvent {scenario_id: $sid})
        MATCH (ae)-[:LATERAL_TO]->(target_host:IP)
        MATCH (src_host:IP)-[:Logon_Source|LATERAL_MOVEMENT]->(target_host)
        OPTIONAL MATCH (src_host)-[:USED_CREDENTIAL]->(u:User)
        OPTIONAL MATCH (u)-[:Logon]->(target_host)
        RETURN DISTINCT src_host, target_host, u,
               ae.attack_id AS attack_id,
               ae.technique_name AS technique_name,
               ae.timestamp_start AS timestamp_start,
               ae.description AS description
        """
        result = self._run_query(query, sid=scenario_id)
        if not result:
            return {"lateral_paths": []}

        lateral_paths = []
        added = set()
        for record in result:
            src = record.get('src_host', {})
            tgt = record.get('target_host', {})
            user = record.get('u')

            # 去重
            src_ip = src.get('ip', src.get('id', '')) if src else ''
            tgt_ip = tgt.get('ip', tgt.get('id', '')) if tgt else ''
            username = user.get('username', '') if user else ''
            key = f"{src_ip}_{tgt_ip}_{username}"
            if key in added:
                continue
            added.add(key)

            path_info = {
                "source_host": src_ip,
                "target_host": tgt_ip,
                "credential": username,
                "attack_id": record.get('attack_id', ''),
                "technique": record.get('technique_name', 'Lateral Movement'),
                "timestamp": str(record.get('timestamp_start', '')),
                "description": record.get('description', ''),
            }
            lateral_paths.append(path_info)

        return {"lateral_paths": lateral_paths}

    def get_edge_evidence(self, from_id, to_id, relationship_type=None):
        """
        【边证据详情】查询两条 AttackEvent 之间的边，返回证据来源、置信度、时间间隔
        """
        if relationship_type:
            query = """
            MATCH (a1)-[r:NEXT_STAGE]->(a2)
            WHERE a1.id = $from_id AND a2.id = $to_id AND r.type = $rel_type
            RETURN r
            """
            params = {"from_id": from_id, "to_id": to_id, "rel_type": relationship_type}
        else:
            query = """
            MATCH (a1)-[r:NEXT_STAGE]->(a2)
            WHERE a1.id = $from_id AND a2.id = $to_id
            RETURN r
            """
            params = {"from_id": from_id, "to_id": to_id}

        result = self._run_query(query, **params)
        if not result:
            return {"evidence": None}

        r = result[0].get('r', {})
        evidence = dict(r)
        return {"evidence": evidence}

    def _process_node(self, neo4j_node, nodes_dict):
        """辅助函数：处理 Neo4j 节点转 Vis.js 格式，包含样式配置"""
        n_id = neo4j_node.get('id')
        if not n_id or n_id in nodes_dict:
            return

        labels = list(neo4j_node.labels)
        main_label = labels[0] if labels else "Unknown"

        # 样式映射
        icon_map = {
            "Process": "⚙️",
            "File": "📄",
            "IP": "🌐",
            "Domain": "🔗",
            "Registry": "®️",
            "User": "👤",
            "Session": "🔑",
        }

        # 构造 Label 显示
        display_label = n_id
        if main_label == "Process":
            display_label = f"{icon_map['Process']} {neo4j_node.get('name')}\n({neo4j_node.get('pid')})"
        elif main_label == "File":
            display_label = f"{icon_map['File']} {neo4j_node.get('name')}"
        elif main_label == "IP":
            display_label = f"{icon_map['IP']} {neo4j_node.get('ip')}"
        elif main_label == "User":
            display_label = f"{icon_map['User']} {neo4j_node.get('username')}"
        elif main_label == "Session":
            display_label = f"{icon_map['Session']} {neo4j_node.get('session_id')}"

        node_obj = {
            "id": n_id,
            "label": display_label,
            "group": main_label,
            "title": str(dict(neo4j_node)),
            "shape": "box",
        }

        # 特殊节点样式
        if main_label == "Session":
            node_obj["color"] = {"background": "#fff3cd", "border": "#ffc107"}
        elif main_label == "User":
            node_obj["color"] = {"background": "#d1ecf1", "border": "#0c5460"}

        nodes_dict[n_id] = node_obj