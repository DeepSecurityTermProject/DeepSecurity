import yaml
import uuid
import os
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
# 配置简单的日志，方便调试
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

#----------------------------------------------------------------------
#实现ATT&CK与实体节点间的映射关系
#----------------------------------------------------------------------

class EventAggregator:
    def __init__(self, default_window_seconds=60):
        """
        初始化聚合器
        :param default_window_seconds: 默认的时间窗口大小（秒）
        """
        self.window = default_window_seconds
        # 缓存结构: {(host_ip, event_type): deque([time1, time2, ...])}
        self.buffer = defaultdict(deque)

    def check_threshold(self, event, threshold_count):
        """
        检查是否在时间窗口内达到了次数阈值
        :param event: 当前处理的事件字典
        :param threshold_count: 触发告警所需的最小次数
        :return: Boolean (True 表示达到阈值，应该报警)
        """
        # 1. 构造唯一键 (区分不同主机的同类事件)
        host_ip = event.get('host_ip') or event.get('src_ip')
        event_type = event.get('event_type')

        if not host_ip or not event_type:
            return False

        key = (host_ip, event_type)

        # 2. 解析时间 (假设输入是 ISO8601 字符串)
        try:
            # 注意：需根据实际数据格式调整 strptime
            # 这里简化处理，假设数据带 'Z'
            ts_str = event.get('timestamp').replace('Z', '')
            current_time = datetime.fromisoformat(ts_str)
        except Exception:
            # 如果时间解析失败，使用当前系统时间兜底
            current_time = datetime.utcnow()

        # 3. 滑动窗口逻辑
        # 3.1 记入当前事件
        self.buffer[key].append(current_time)

        # 3.2 移除过期事件 (即：当前时间 - 最早记录时间 > 窗口大小)
        while self.buffer[key]:
            earliest_time = self.buffer[key][0]
            if (current_time - earliest_time).total_seconds() > self.window:
                self.buffer[key].popleft()
            else:
                break  # 队列是有序的，如果头部没过期，后面的肯定也没过期

        # 4. 判断阈值
        # 只有当数量 刚好等于 阈值时触发（避免第6次、第7次重复报警）
        # 或者根据需求设为 >= 并定期清理
        if len(self.buffer[key]) == threshold_count:
            return True

        return False

class ATTACKMapper:
    def __init__(self, rules_file='attack_rules.yaml'):
        """
        初始化映射器
        :param rules_file: YAML规则文件的路径
        """
        self.rules = self._load_rules(rules_file)
        # [新增] 初始化聚合器，默认窗口60秒
        self.aggregator = EventAggregator(default_window_seconds=60)

    def _load_rules(self, file_path):
        """
        从YAML文件加载规则，包含错误处理
        """
        # 1. 检查文件是否存在
        if not os.path.exists(file_path):
            logging.error(f"规则文件未找到: {file_path}")
            return []

        # 2. 读取并解析YAML
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # safe_load 比 load 更安全，防止代码注入
                rules = yaml.safe_load(f)

                if not rules:
                    logging.warning("规则文件为空")
                    return []

                logging.info(f"成功加载 {len(rules)} 条ATT&CK映射规则")
                return rules

        except yaml.YAMLError as e:
            logging.error(f"YAML格式解析错误: {e}")
            return []
        except Exception as e:
            logging.error(f"读取规则文件时发生未知错误: {e}")
            return []

    def analyze_event(self, event_data):
        """
        核心函数：接收单条归一化后的数据，返回ATT&CK映射结果
        """
        # --- [新增] 白名单过滤逻辑 ---
        entities = event_data.get('entities', {})
        cmdline = entities.get('command_line') or entities.get('cmdline') or ""

        # 1. 忽略探针自身的进程 (防止递归检测)
        if "client_agent.py" in cmdline or "behavior_monitor" in cmdline:
            return []

        # 2. 忽略分析引擎自身的流量 (连接 Neo4j 或 SQL Server 的流量)
        dst_port = event_data.get('dst_port')
        if dst_port in [7687, 1433, 5000]:  # Neo4j, SQL, Flask
            return []

        if not self.rules:
            logging.warning("规则库为空，无法执行分析")
            return []

        matched_attacks = []

        # 1. 提取基础信息
        data_source = event_data.get("data_source")
        event_type = event_data.get("event_type")

        # 合并特征方便查找
        features = {}
        if "behavior_features" in event_data:
            features.update(event_data["behavior_features"])
        if "traffic_features" in event_data:
            features.update(event_data["traffic_features"])

        # 2. 遍历规则库进行匹配
        for rule in self.rules:
            # 2.1 检查数据源是否匹配
            if rule.get('data_source') != data_source:
                continue

            # 2.2 检查事件类型是否匹配
            trigger = rule.get('trigger', {})
            if trigger.get('event_type') != event_type:
                continue

            # 2.3 检查阈值与聚合 (针对暴力破解等)
            rule_threshold = trigger.get('threshold', 1)
            is_triggered = False

            if rule_threshold > 1:
                # 调用聚合器检查
                if self.aggregator.check_threshold(event_data, rule_threshold):
                    is_triggered = True
            else:
                # 2.4 检查特征条件 (Features)
                feature_match = True

                # 检查 behavior_features
                # [新增] 检查 entities (Process Name, File Path, Registry Key)
                if feature_match and 'entities' in trigger:
                    event_entities = event_data.get('entities', {})
                    for key, val in trigger['entities'].items():
                        event_val = event_entities.get(key)

                        # 支持列表匹配 (rule defined list of suspicious processes)
                        if isinstance(val, list):
                            if event_val not in val:
                                feature_match = False
                                break
                        # 支持字符串包含匹配 (e.g. registry key contains "Run")
                        elif isinstance(val, str) and isinstance(event_val, str):
                            if val not in event_val:  # 简单的包含匹配
                                feature_match = False
                                break
                        # 精确匹配
                        elif event_val != val:
                            feature_match = False
                            break

                if feature_match:
                    is_triggered = True

            # ================= [修复的核心代码块] =================
            if is_triggered:
                logging.info(f"[ALERT] Rule Triggered! RuleID={rule.get('rule_id')} EventType={event_type}")

                mapping = rule.get('attack_mapping', {})

                # [增强] 生成与该事件相关的多个实体ID，用于建立 TRIGGERED 关系
                related_ids = self._generate_all_entity_ids(event_data)

                attack_result = {
                    "attack_id": str(uuid.uuid4()),  # 攻击事件唯一ID (Neo4j: AttackEvent节点ID)
                    "rule_id": rule.get("rule_id"),  # 补充：便于追溯是哪条规则触发的
                    "data_source": data_source,      # [新增] 记录数据源用于证据追溯
                    "tactic": {
                        "id": mapping.get('tactic_id'),
                        "name": mapping.get('tactic_name')
                    },
                    "technique": {
                        "id": mapping.get('technique_id'),
                        "name": mapping.get('technique_name')
                    },
                    # [增强] 存放所有相关的实体ID列表（多个实体类型）
                    "related_events": related_ids,
                    "confidence": "High",  # 默认高置信度，可根据规则复杂程度调整
                    "timestamp_start": event_data.get("timestamp"),
                    "timestamp_end": event_data.get("timestamp"),  # 如果是聚合事件，这里可以延后
                    "victim_ip": event_data.get("host_ip") or event_data.get("src_ip"),
                    "attacker_ip": self._extract_attacker_ip(event_data),
                    # 计算攻击阶段顺序 (1-11)
                    "stage_order": self._determine_stage(mapping.get('tactic_name')),
                    "description": rule.get("description", "No description provided")
                }
                matched_attacks.append(attack_result)
            # ====================================================

        return matched_attacks

    def _extract_attacker_ip(self, event):
        # 如果是外传类规则 (Exfiltration / C2)，目标IP通常是攻击者
        if event.get('event_type') in ['data_exfiltration', 'dns_tunnel_suspected', 'icmp_tunnel_suspected']:
            return event.get('dst_ip')

        # 如果是入站攻击 (Exploit / Scan / Login)，源IP是攻击者
        if 'src_ip' in event.get('entities', {}):
            return event['entities']['src_ip']

        return event.get('src_ip')

    # =========================================================================
    # [增强] 生成该事件所有相关的实体节点 ID 列表
    # =========================================================================
    def _generate_all_entity_ids(self, event):
        """
        生成该事件所有相关的实体节点 ID，确保 AttackEvent 能回连到
        Process、User、IP、Domain、File、Registry、Session 等多种实体类型。
        返回一个 ID 列表。
        """
        ids = []

        data_source = event.get('data_source')
        entities = event.get('entities', {})
        host_ip = event.get('host_ip')

        # 1. 进程相关 ID (Process Node)
        pid = entities.get('pid')
        if pid and host_ip:
            # 尝试生成带时间戳的进程ID
            timestamp_suffix = event.get('timestamp') if event.get('event_type') == 'process_create' else 'unknown'
            proc_id = f"{host_ip}_{pid}_{timestamp_suffix}"
            ids.append(proc_id)

            # 父进程 ID
            parent_pid = entities.get('parent_pid')
            if parent_pid:
                parent_id = f"{host_ip}_{parent_pid}_unknown"
                ids.append(parent_id)

        # 2. 用户相关 ID (User Node)
        username = entities.get('user') or entities.get('username')
        if username and host_ip:
            user_id = f"{host_ip}_{username}"
            ids.append(user_id)

        # 3. IP 地址相关 (IP Node)
        src_ip = event.get('src_ip') or entities.get('src_ip')
        if src_ip:
            ids.append(src_ip)

        dst_ip = event.get('dst_ip') or entities.get('dst_ip')
        if dst_ip:
            ids.append(dst_ip)

        # 4. Domain (DNS查询)
        domain = entities.get('domain')
        if domain:
            ids.append(domain)

        # 5. 文件路径 (File Node)
        file_path = entities.get('file_path')
        if file_path and host_ip:
            file_id = f"{host_ip}_{file_path}"
            ids.append(file_id)

        # 6. 进程名作为 fallback (File Node 或 Process)
        process_name = entities.get('process_name')
        if process_name and host_ip and not pid:
            # 如果没有 PID 但知道进程名，用名称作为辅助标识
            ids.append(f"{host_ip}_proc_{process_name}")

        # 7. 注册表 (Registry Node)
        registry_key = entities.get('registry_key')
        if registry_key:
            ids.append(registry_key)

        # 8. 会话 ID (Session Node)
        session_id = entities.get('session_id')
        if session_id and host_ip:
            session_node_id = f"{host_ip}_session_{session_id}"
            ids.append(session_node_id)

        # 9. 去重并返回
        return list(set(ids))

    def _generate_event_id(self, event):
        """
        [向后兼容] 生成与图数据库实体节点一致的 ID，用于建立 TRIGGERED 关系。
        现在返回唯一主实体 ID（兼容旧代码）。
        """
        # 直接取第一个实体 ID
        all_ids = self._generate_all_entity_ids(event)
        if all_ids:
            return all_ids[0]

        # 5. 兜底：防止返回 None 导致报错
        return f"Unlinked_Event_{event.get('timestamp')}"

    def _determine_stage(self, tactic_name):
        stages = {
            "Reconnaissance": 1, "Resource Development": 1,
            "Initial Access": 2, "Execution": 3, "Persistence": 3,
            "Privilege Escalation": 4, "Defense Evasion": 4,
            "Credential Access": 5, "Discovery": 6, "Lateral Movement": 7,
            "Collection": 8, "Command and Control": 9, "Exfiltration": 10, "Impact": 11
        }
        return stages.get(tactic_name, 0)


# ==========================================
# 4. 测试运行 (Main)
# ==========================================
if __name__ == "__main__":
    # 实例化 Mapper，它会自动读取当前目录下的 attack_rules.yaml
    mapper = ATTACKMapper("attack_rules.yaml")

    # 模拟输入数据：隐蔽信道
    traffic_event =         {
            "data_source": "host_behavior",
            "timestamp": "2023-10-27T10:06:00Z",
            "host_ip": "192.168.1.100",
            "event_type": "registry_set_value",
            "entities": {
                "process_name": "malware.exe",
                "pid": 5555,
                "registry_key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil",
                "registry_value_name": "Evil",
                "registry_value_data": "C:\\Temp\\malware.exe"
            },
            "behavior_features": {}
        }

    # 执行分析
    results = mapper.analyze_event(traffic_event)

    # 打印结果
    import json

    print(json.dumps(results, indent=4, ensure_ascii=False))