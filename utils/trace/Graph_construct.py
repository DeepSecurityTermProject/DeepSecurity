import logging
from neo4j import GraphDatabase

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class GraphIngestionEngine:
    def __init__(self, uri, user, password, initial_pid_cache=None):
        self.driver = GraphDatabase.driver(
            uri, auth=(user, password),
            connection_timeout=5,
            connection_acquisition_timeout=5,
        )
        self.pid_cache = initial_pid_cache if initial_pid_cache else {}

    def get_current_pid_cache(self):
        return self.pid_cache

    def close(self):
        self.driver.close()

    def _batch_execute(self, query, data_list, batch_size=1000, param_name="events", **kwargs):
        if not data_list: return
        total = len(data_list)
        with self.driver.session() as session:
            for i in range(0, total, batch_size):
                batch = data_list[i: i + batch_size]
                try:
                    params = {param_name: batch}
                    params.update(kwargs)
                    session.execute_write(lambda tx: tx.run(query, **params))
                except Exception as e:
                    logging.error(f"批量写入失败: {e}")

    def _run_massive_update(self, query, **kwargs):
        try:
            with self.driver.session() as session:
                session.run(query, **kwargs)
        except Exception as e:
            logging.error(f"大规模更新任务失败: {e}")

    # =========================================================================
    # [增强] 统一实体 ID 生成规则
    # =========================================================================
    def _generate_process_id(self, host_ip, pid, timestamp=None):
        """
        统一进程 ID 生成规则：
        优先使用缓存中的启动时间戳，确保同一进程在不同事件类型中 ID 一致。
        """
        key = f"{host_ip}_{pid}"
        if timestamp and timestamp != "unknown":
            self.pid_cache[key] = timestamp
            time_suffix = timestamp
        else:
            time_suffix = self.pid_cache.get(key, "unknown")
        return f"{host_ip}_{pid}_{time_suffix}"

    def _generate_user_id(self, host_ip, username):
        """统一用户节点 ID"""
        return f"{host_ip}_{username}"

    def _generate_session_id(self, host_ip, session_id):
        """统一登录会话 ID"""
        return f"{host_ip}_session_{session_id}"

    # =========================================================================
    # 主机行为写入 - [增强] 增加因果边
    # =========================================================================
    def ingest_host_behavior(self, data_list):
        if not data_list: return
        # 预处理：收集进程创建事件的时间戳用于 PID 缓存
        for item in data_list:
            if item.get("event_type") == "process_create":
                entities = item.get("entities", {})
                self._generate_process_id(item.get("host_ip"), entities.get("pid"), item.get("timestamp"))

        processed_data = []
        for item in data_list:
            entities = item.get("entities", {})
            features = item.get("behavior_features", {})
            host_ip = item.get("host_ip")
            ts_for_id = item.get("timestamp") if item.get("event_type") == "process_create" else None
            pid = entities.get("pid")
            proc_id = None
            if pid: proc_id = self._generate_process_id(host_ip, pid, ts_for_id)

            # 增强：提取用户名
            username = entities.get("user") or entities.get("username")

            processed_data.append({
                "host_ip": host_ip, "timestamp": item.get("timestamp"),
                "event_type": item.get("event_type"), "entities": entities, "features": features,
                "pid": pid, "proc_name": entities.get("process_name"), "proc_hash": entities.get("hash"),
                "proc_id": proc_id,
                "parent_pid": entities.get("parent_pid"),
                "username": username,
                "user_id": self._generate_user_id(host_ip, username) if host_ip and username else None,
                "parent_id": f"{host_ip}_{entities.get('parent_pid')}_unknown" if host_ip and entities.get("parent_pid") else None,
                "cmdline": entities.get("command_line") or entities.get("cmdline"),
            })

        # --- 1) 进程创建 (Spawn 边) ---
        spawn_query = """
        UNWIND $events AS event WITH event WHERE event.event_type = 'process_create' AND event.pid IS NOT NULL
        MERGE (p:Process {id: event.parent_id})
        ON CREATE SET p.name = event.entities.parent_process, p.host = event.host_ip
        MERGE (c:Process {id: event.proc_id})
        ON CREATE SET
            c.name = event.proc_name, c.pid = event.pid,
            c.cmdline = event.cmdline, c.host = event.host_ip,
            c.timestamp = event.timestamp, c.hash = event.proc_hash,
            c.ports = event.entities.listen_ports
        MERGE (p)-[r:Spawn]->(c)
        SET r.timestamp = event.timestamp,
            r.is_abnormal = event.features.is_abnormal_parent,
            r.evidence_source = event.event_type,
            r.confidence = CASE WHEN event.features.is_abnormal_parent = true THEN 'High' ELSE 'Medium' END
        """
        self._batch_execute(spawn_query, [d for d in processed_data if d["event_type"] == "process_create"],
                            param_name="events")

        # --- 2) 进程终止 ---
        terminate_query = """
        UNWIND $events AS event WITH event WHERE event.proc_id IS NOT NULL
        MATCH (p:Process {id: event.proc_id})
        SET p.timestamp_end = event.timestamp
        """
        self._batch_execute(terminate_query, [d for d in processed_data if d["event_type"] == "process_terminate"],
                            param_name="events")

        # --- 3) 文件操作 ---
        file_ops_map = {"file_create": "Write", "file_modify": "Write", "file_delete": "Delete",
                        "file_read": "Read", "image_load": "Load"}
        for evt_type, relation in file_ops_map.items():
            file_query = f"""
            UNWIND $events AS event WITH event
            MERGE (p:Process {{id: event.proc_id}})
            MERGE (f:File {{id: event.host_ip + '_' + event.entities.file_path}})
            ON CREATE SET
                f.path = event.entities.file_path,
                f.name = event.entities.file_name,
                f.host = event.host_ip,
                f.hash = event.entities.hash
            MERGE (p)-[r:{relation}]->(f)
            SET r.timestamp = event.timestamp,
                r.evidence_source = event.event_type,
                r.confidence = 'High',
                r.file_hash = event.entities.hash
            """
            self._batch_execute(file_query, [d for d in processed_data if
                                              d["event_type"] == evt_type and d["entities"].get("file_path")],
                                param_name="events")

        # --- 4) 注册表操作 ---
        reg_query = """
        UNWIND $events AS event WITH event
        MERGE (p:Process {id: event.proc_id})
        MERGE (r:Registry {id: event.entities.registry_key})
        ON CREATE SET
            r.key = event.entities.registry_key,
            r.value_name = event.entities.registry_value_name,
            r.value_data = event.entities.registry_value_data
        MERGE (p)-[rel:Write]->(r)
        SET rel.timestamp = event.timestamp,
            rel.evidence_source = event.event_type,
            rel.confidence = 'High'
        """
        self._batch_execute(reg_query, [d for d in processed_data if d["event_type"] == "registry_set_value"],
                            param_name="events")

        # --- 5) 网络连接 (进程 → IP) ---
        net_conn_query = """
        UNWIND $events AS event WITH event
        MERGE (p:Process {id: event.proc_id})
        MERGE (ip:IP {id: event.entities.dst_ip})
        ON CREATE SET ip.ip = event.entities.dst_ip
        MERGE (p)-[r:Connect]->(ip)
        SET r.timestamp = event.timestamp,
            r.dst_port = event.entities.dst_port,
            r.evidence_source = event.event_type,
            r.confidence = 'High',
            r.protocol = event.entities.protocol
        """
        self._batch_execute(net_conn_query, [d for d in processed_data if
                                              d["event_type"] == "network_connection" and d["entities"].get("dst_ip")],
                            param_name="events")

        # --- 6) 进程注入 ---
        inject_query = """
        UNWIND $events AS event WITH event
        MERGE (src:Process {id: event.proc_id})
        MERGE (target:Process {id: event.target_proc_id})
        MERGE (src)-[r:Inject]->(target)
        SET r.timestamp = event.timestamp,
            r.is_memory_injection = true,
            r.evidence_source = event.event_type,
            r.confidence = 'High'
        """
        inject_data = []
        for d in processed_data:
            if d["event_type"] == "process_injection" and d["entities"].get("target_pid"):
                d["target_proc_id"] = self._generate_process_id(d["host_ip"], d["entities"].get("target_pid"), "unknown")
                inject_data.append(d)
        self._batch_execute(inject_query, inject_data, param_name="events")

        # --- [新增] 7) 进程 ↔ 用户关联 (EXECUTED_BY / RUN_AS) ---
        user_proc_query = """
        UNWIND $events AS event WITH event
        WHERE event.username IS NOT NULL AND event.proc_id IS NOT NULL
        MERGE (u:User {id: event.user_id})
        ON CREATE SET u.username = event.username
        MERGE (p:Process {id: event.proc_id})
        MERGE (p)-[r:RUN_AS]->(u)
        SET r.timestamp = event.timestamp,
            r.evidence_source = event.event_type,
            r.host = event.host_ip
        """
        user_proc_data = [d for d in processed_data if d.get("username") and d.get("proc_id")]
        self._batch_execute(user_proc_query, user_proc_data, param_name="events")

    # =========================================================================
    # 网络流量写入 - [增强] 增加进程 ↔ 网络因果边
    # =========================================================================
    def ingest_network_traffic(self, data_list):
        if not data_list: return
        processed_data = []
        for item in data_list:
            entities = item.get("entities", {})
            host_ip = item.get("host_ip") or item.get("src_ip")
            proc_id = None
            pid = entities.get("pid")
            if pid and host_ip: proc_id = self._generate_process_id(host_ip, pid)
            processed_data.append({
                "src_ip": item.get("src_ip"), "dst_ip": item.get("dst_ip"),
                "src_port": item.get("src_port"), "dst_port": item.get("dst_port"),
                "timestamp": item.get("timestamp"), "event_type": item.get("event_type"),
                "domain": entities.get("domain"), "protocol": item.get("protocol"),
                "features": item.get("traffic_features", {}), "proc_id": proc_id, "entities": entities
            })

        # 流量流 (IP → IP)
        flow_query = """
        UNWIND $events AS event WITH event
        WHERE event.src_ip IS NOT NULL AND event.dst_ip IS NOT NULL
        MERGE (src:IP {id: event.src_ip})
        ON CREATE SET src.ip = event.src_ip,
            src.type = CASE WHEN event.src_ip STARTS WITH '192.168.' OR event.src_ip STARTS WITH '10.' THEN 'Internal' ELSE 'External' END
        MERGE (dst:IP {id: event.dst_ip})
        ON CREATE SET dst.ip = event.dst_ip,
            dst.type = CASE WHEN event.dst_ip STARTS WITH '192.168.' OR event.dst_ip STARTS WITH '10.' THEN 'Internal' ELSE 'External' END
        MERGE (src)-[r:Traffic_Flow]->(dst)
        SET r.timestamp = event.timestamp,
            r.protocol = event.protocol,
            r.src_port = event.src_port,
            r.dst_port = event.dst_port,
            r.event_type = event.event_type,
            r.evidence_source = event.event_type,
            r.confidence = 'High'
        FOREACH (ignoreMe IN CASE WHEN event.proc_id IS NOT NULL THEN [1] ELSE [] END |
            MERGE (p:Process {id: event.proc_id})
            MERGE (p)-[conn:Connect]->(dst)
            SET conn.timestamp = event.timestamp,
                conn.dst_port = event.dst_port,
                conn.evidence_source = event.event_type,
                conn.confidence = 'High'
        )
        """
        self._batch_execute(flow_query, processed_data, param_name="events")

        # DNS 解析
        dns_query = """
        UNWIND $events AS event WITH event WHERE event.domain IS NOT NULL
        MERGE (src:IP {id: event.src_ip})
        MERGE (d:Domain {id: event.domain})
        ON CREATE SET d.name = event.domain
        FOREACH (ignoreMe IN CASE WHEN event.proc_id IS NOT NULL THEN [1] ELSE [] END |
            MERGE (p:Process {id: event.proc_id})
            MERGE (p)-[r:Resolve]->(d)
            SET r.timestamp = event.timestamp,
                r.query_type = event.entities.query_type,
                r.is_suspicious = event.features.is_covert_channel,
                r.evidence_source = event.event_type,
                r.confidence = CASE WHEN event.features.is_covert_channel = true THEN 'High' ELSE 'Medium' END
        )
        FOREACH (ignoreMe IN CASE WHEN event.proc_id IS NULL THEN [1] ELSE [] END |
            MERGE (src)-[r:Resolve]->(d)
            SET r.timestamp = event.timestamp,
                r.query_type = event.entities.query_type,
                r.is_suspicious = event.features.is_covert_channel,
                r.evidence_source = event.event_type
        )
        """
        self._batch_execute(dns_query, processed_data, param_name="events")

    # =========================================================================
    # 主机日志写入 - [增强] 用户登录会话 + 横向移动链路
    # =========================================================================
    def ingest_host_log(self, data_list):
        if not data_list: return
        processed_data = []
        for item in data_list:
            ds = item.get("data_source", "host_log")
            if item.get("event_type") in ["user_logon", "user_logoff", "user_logon_failed"]:
                entities = item.get("entities", {})
                host_ip = item.get("host_ip")
                username = entities.get("user")
                processed_data.append({
                    "host_ip": host_ip, "timestamp": item.get("timestamp"),
                    "event_type": item.get("event_type"),
                    "user": username,
                    "user_id": self._generate_user_id(host_ip, username) if host_ip and username else None,
                    "src_ip": entities.get("src_ip"),
                    "session_id": entities.get("session_id"),
                    "session_node_id": self._generate_session_id(host_ip, entities.get("session_id"))
                        if host_ip and entities.get("session_id") else None,
                    "logon_type": entities.get("logon_type") or entities.get("logon_type_name"),
                    "logon_process": entities.get("logon_process"),
                    "raw_id": item.get("raw_id")
                })

        # --- [增强] 登录事件：创建会话节点并链接 User→Session→Host ---
        logon_query = """
        UNWIND $events AS event WITH event
        WHERE event.user IS NOT NULL AND event.event_type = 'user_logon'
        MERGE (u:User {id: event.user_id})
        ON CREATE SET u.username = event.user
        MERGE (host:IP {id: event.host_ip})
        ON CREATE SET host.ip = event.host_ip

        // 创建登录会话节点（如果提供 session_id）
        FOREACH (ignoreMe IN CASE WHEN event.session_node_id IS NOT NULL THEN [1] ELSE [] END |
            MERGE (s:Session {id: event.session_node_id})
            ON CREATE SET s.session_id = event.session_id,
                s.host = event.host_ip,
                s.logon_type = event.logon_type,
                s.logon_process = event.logon_process,
                s.timestamp_start = event.timestamp
            MERGE (u)-[:STARTS_SESSION]->(s)
            MERGE (s)-[:LOGGED_INTO]->(host)
            SET s.timestamp_start = event.timestamp
        )

        // 直接 User → Host 登录关系（向后兼容）
        MERGE (u)-[r:Logon]->(host)
        SET r.timestamp = event.timestamp,
            r.session_id = event.session_id,
            r.logon_type = event.logon_type,
            r.raw_id = event.raw_id,
            r.evidence_source = event.event_type,
            r.confidence = 'High'

        // [新增] 如果登录来自远程 IP，建立横向移动链路 SourceIP→User
        FOREACH (ignoreMe IN CASE WHEN event.src_ip IS NOT NULL THEN [1] ELSE [] END |
            MERGE (src:IP {id: event.src_ip})
            ON CREATE SET src.ip = event.src_ip
            MERGE (src)-[rel:Logon_Source]->(host)
            SET rel.timestamp = event.timestamp,
                rel.user = event.user,
                rel.evidence_source = event.event_type,
                rel.confidence = 'High'
            // 源 IP → 用户凭据关系（横向移动关键链路）
            MERGE (src)-[:USED_CREDENTIAL]->(u)
            SET rel.timestamp = event.timestamp
        )
        """
        self._batch_execute(logon_query, processed_data, param_name="events")

        # 登出事件
        logoff_query = """
        UNWIND $events AS event WITH event
        WHERE event.user IS NOT NULL AND event.event_type = 'user_logoff'
        MATCH (u:User {id: event.user_id})-[r:Logon]->(host:IP {id: event.host_ip})
        WHERE (event.session_id IS NULL) OR (r.session_id = event.session_id)
        SET r.end_time = event.timestamp

        // 更新会话结束时间
        FOREACH (ignoreMe IN CASE WHEN event.session_node_id IS NOT NULL THEN [1] ELSE [] END |
            OPTIONAL MATCH (s:Session {id: event.session_node_id})
            SET s.timestamp_end = event.timestamp
        )
        """
        self._batch_execute(logoff_query, processed_data, param_name="events")

        # --- [新增] 登录失败事件 → 暴力破解链路 ---
        failed_logon_query = """
        UNWIND $events AS event WITH event
        WHERE event.user IS NOT NULL AND event.event_type = 'user_logon_failed'
        MERGE (u:User {id: event.user_id})
        ON CREATE SET u.username = event.user
        MERGE (host:IP {id: event.host_ip})
        ON CREATE SET host.ip = event.host_ip
        MERGE (u)-[r:FAILED_LOGON]->(host)
        SET r.timestamp = event.timestamp,
            r.evidence_source = event.event_type,
            r.confidence = 'Medium'
        FOREACH (ignoreMe IN CASE WHEN event.src_ip IS NOT NULL THEN [1] ELSE [] END |
            MERGE (src:IP {id: event.src_ip})
            MERGE (src)-[:FAILED_LOGON_SOURCE]->(host)
            SET r.timestamp = event.timestamp
        )
        """
        self._batch_execute(failed_logon_query, processed_data, param_name="events")

    # =========================================================================
    # [增强] 攻击事件写入 - 强化 related_events 回连 + 证据属性
    # =========================================================================
    def ingest_attack_events(self, attack_data_list):
        if not attack_data_list:
            return

        # 1) 写入 AttackEvent 节点并连接相关实体
        ingest_query = """
        UNWIND $batch AS data
        MERGE (t:Technique {id: data.technique.id})
        ON CREATE SET
            t.name = data.technique.name,
            t.tactic_id = data.tactic.id,
            t.tactic_name = data.tactic.name
        MERGE (ae:AttackEvent {id: data.attack_id})
        ON CREATE SET
            ae.attack_id = data.attack_id,
            ae.confidence = data.confidence,
            ae.timestamp_start = data.timestamp_start,
            ae.timestamp_end = data.timestamp_end,
            ae.stage_order = data.stage_order,
            ae.victim_ip = data.victim_ip,
            ae.attacker_ip = data.attacker_ip,
            ae.description = data.description,
            ae.rule_id = data.rule_id
        MERGE (ae)-[:IS_TYPE]->(t)

        WITH ae, data.related_events AS evidence_ids, data
        UNWIND evidence_ids AS eid

        // 尝试匹配各类实体节点建立 TRIGGERED 关系
        OPTIONAL MATCH (exact_p:Process {id: eid})
        FOREACH (_ IN CASE WHEN exact_p IS NOT NULL THEN [1] ELSE [] END |
            MERGE (exact_p)-[r:TRIGGERED]->(ae)
            SET r.evidence_source = data.data_source,
                r.confidence = data.confidence,
                r.timestamp = data.timestamp_start
        )

        WITH ae, eid, data
        OPTIONAL MATCH (fuzzy_p:Process)
        WHERE eid ENDS WITH 'unknown' AND fuzzy_p.id STARTS WITH split(eid, '_unknown')[0]
        FOREACH (_ IN CASE WHEN fuzzy_p IS NOT NULL THEN [1] ELSE [] END |
            MERGE (fuzzy_p)-[r:TRIGGERED]->(ae)
            SET r.evidence_source = data.data_source,
                r.confidence = data.confidence,
                r.timestamp = data.timestamp_start
        )

        WITH ae, eid, data
        OPTIONAL MATCH (d:Domain {id: eid})
        FOREACH (_ IN CASE WHEN d IS NOT NULL THEN [1] ELSE [] END |
            MERGE (d)-[r:TRIGGERED]->(ae)
            SET r.evidence_source = data.data_source, r.confidence = data.confidence
        )
        WITH ae, eid, data
        OPTIONAL MATCH (f:File {id: eid})
        FOREACH (_ IN CASE WHEN f IS NOT NULL THEN [1] ELSE [] END |
            MERGE (f)-[r:TRIGGERED]->(ae)
            SET r.evidence_source = data.data_source, r.confidence = data.confidence
        )
        WITH ae, eid, data
        OPTIONAL MATCH (r:Registry {id: eid})
        FOREACH (_ IN CASE WHEN r IS NOT NULL THEN [1] ELSE [] END |
            MERGE (r)-[r_rel:TRIGGERED]->(ae)
            SET r_rel.evidence_source = data.data_source, r_rel.confidence = data.confidence
        )
        WITH ae, eid, data
        OPTIONAL MATCH (i:IP {id: eid})
        FOREACH (_ IN CASE WHEN i IS NOT NULL THEN [1] ELSE [] END |
            MERGE (i)-[r_rel:TRIGGERED]->(ae)
            SET r_rel.evidence_source = data.data_source, r_rel.confidence = data.confidence
        )
        WITH ae, eid, data
        OPTIONAL MATCH (u:User {id: eid})
        FOREACH (_ IN CASE WHEN u IS NOT NULL THEN [1] ELSE [] END |
            MERGE (u)-[r_rel:TRIGGERED]->(ae)
            SET r_rel.evidence_source = data.data_source, r_rel.confidence = data.confidence
        )
        """
        self._batch_execute(ingest_query, attack_data_list, param_name="batch")

        # 2) [增强] 时序链 - 带证据属性和时间间隔
        chain_query = """
        MATCH (a:AttackEvent)
        WITH a.victim_ip as victim, a
        ORDER BY a.timestamp_start ASC, a.id ASC
        WITH victim, collect(a) as events
        WHERE size(events) > 1
        UNWIND range(0, size(events)-2) as i
        WITH events[i] as a1, events[i+1] as a2
        WHERE duration.inSeconds(datetime(a1.timestamp_end), datetime(a2.timestamp_start)).seconds < $window
        MERGE (a1)-[r:NEXT_STAGE]->(a2)
        SET r.type = 'temporal',
            r.confidence = 'Low',
            r.evidence_source = 'temporal_correlation',
            r.time_interval = duration.inSeconds(datetime(a1.timestamp_end), datetime(a2.timestamp_start)).seconds,
            r.description = 'Temporal correlation within same host'
        """
        self._run_massive_update(chain_query, window=10000)
        logging.info(f"已更新 {len(attack_data_list)} 条事件的单机时序链")

        # 3) [新增] 根据共享实体连接攻击事件 - 证据驱动链接
        entity_link_query = """
        MATCH (e)-[:TRIGGERED]->(a1:AttackEvent)
        MATCH (e)-[:TRIGGERED]->(a2:AttackEvent)
        WHERE a1.id <> a2.id
          AND datetime(a1.timestamp_start) <= datetime(a2.timestamp_start)
          AND duration.inSeconds(datetime(a1.timestamp_start), datetime(a2.timestamp_start)).seconds < $window
        MERGE (a1)-[r:NEXT_STAGE]->(a2)
        SET r.type = 'shared_entity',
            r.confidence = 'Medium',
            r.evidence_source = 'shared_triggering_entity',
            r.evidence_entity = e.id,
            r.time_interval = duration.inSeconds(datetime(a1.timestamp_start), datetime(a2.timestamp_start)).seconds,
            r.description = 'Connected via shared entity: ' + e.id
        """
        self._run_massive_update(entity_link_query, window=10000)

    # =========================================================================
    # [增强] 跨主机因果链构建 - 横向移动链路 + 证据属性
    # =========================================================================
    def build_causal_chains(self, time_window_seconds=36000, max_hops=10):
        logging.info("开始执行跨主机因果关联分析...")

        # --- 条件A: 横向移动 (A.victim == B.attacker) ---
        causal_query = """
        MATCH (a1:AttackEvent)
        MATCH (a2:AttackEvent)
        WHERE a1.id <> a2.id
          AND datetime(a1.timestamp_start) <= datetime(a2.timestamp_start)
          AND duration.inSeconds(datetime(a1.timestamp_start), datetime(a2.timestamp_start)).seconds < $window
        AND (
            // 横向移动: 攻击者从 a1.victim 移动到 a2
            (a1.victim_ip = a2.attacker_ip)
            OR
            // 实体路径关联
            EXISTS {
                MATCH (e1)-[:TRIGGERED]->(a1)
                MATCH (e2)-[:TRIGGERED]->(a2)
                MATCH path = shortestPath(
                    (e1)-[:Spawn|Write|Read|Inject|Connect|Resolve|Load|Traffic_Flow|Logon|Logon_Source|
                           USED_CREDENTIAL|RUN_AS|STARTS_SESSION|LOGGED_INTO|FAILED_LOGON|
                           FAILED_LOGON_SOURCE*1..10]-(e2)
                )
                WHERE any(r IN relationships(path) WHERE type(r) IN ['Connect', 'Traffic_Flow', 'Logon_Source',
                       'USED_CREDENTIAL', 'FAILED_LOGON_SOURCE'])
            }
        )
        MERGE (a1)-[r:NEXT_STAGE]->(a2)
        SET r.type = 'causal',
            r.confidence = 'High',
            r.description = CASE
                WHEN a1.victim_ip = a2.attacker_ip THEN 'Lateral Movement: ' + a1.victim_ip + ' -> ' + a2.victim_ip
                ELSE 'Cross-Host Causal via entity path'
            END,
            r.time_interval = duration.inSeconds(datetime(a1.timestamp_start), datetime(a2.timestamp_start)).seconds,
            r.evidence_source = 'causal_analysis'
        """
        self._run_massive_update(causal_query, window=time_window_seconds)

        # --- [新增] 横向移动路径: User→Session→Process 链路记录 ---
        lateral_path_query = """
        MATCH (src_host:IP)-[:Logon_Source]->(target_host:IP)
        MATCH (src_host)-[:USED_CREDENTIAL]->(u:User)
        MATCH (u)-[:Logon]->(target_host)
        OPTIONAL MATCH (u)-[:STARTS_SESSION]->(s:Session)-[:LOGGED_INTO]->(target_host)
        OPTIONAL MATCH (p:Process)-[:RUN_AS]->(u)
        WHERE p.host = target_host.ip
        WITH src_host, target_host, u, s, p
        MERGE (src_host)-[r:LATERAL_MOVEMENT]->(target_host)
        SET r.user = u.username,
            r.session_id = s.session_id,
            r.process = p.name,
            r.process_id = p.id,
            r.logon_time = s.timestamp_start,
            r.type = 'lateral_movement',
            r.confidence = 'High',
            r.evidence_source = 'logon_analysis'
        // 关联到攻击事件
        WITH src_host, target_host, u, p
        MATCH (ae:AttackEvent)
        WHERE (ae.victim_ip = target_host.ip OR ae.attacker_ip = target_host.ip)
          AND (ae.stage_order >= 7 AND ae.stage_order <= 8) // Lateral Movement stages
        MERGE (ae)-[:LATERAL_TO]->(target_host)
        """
        self._run_massive_update(lateral_path_query)
        logging.info("因果推断分析更新完成")