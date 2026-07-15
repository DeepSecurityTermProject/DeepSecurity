#!/bin/bash
# ============================================================
# setup-soc.sh — SOC 安全监测节点初始化
# 对应主机: soc-node (192.168.10.10 / 192.168.200.50)
# 执行方式: sudo bash setup-soc.sh
# ============================================================
set -e

# 非交互模式，防止 debconf 弹窗挂死
export DEBIAN_FRONTEND=noninteractive

echo "=========================================="
echo " DeepSecurity Lab — soc-node 初始化"
echo " 角色: 安全监测/SOC 节点"
echo " IP: 192.168.10.10 (Management)"
echo "     192.168.200.50 (Internal)"
echo "=========================================="

# -------- 系统更新 --------
echo "[1/8] 系统更新..."
apt-get update -qq && apt-get upgrade -y -qq

# -------- 安装 Java (Elasticsearch 依赖) --------
echo "[2/8] 安装 Java..."
apt-get install -y -qq openjdk-17-jre-headless

# -------- 安装 Elasticsearch --------
echo "[3/8] 安装 Elasticsearch..."
if ! dpkg -l | grep -q elasticsearch; then
  curl -L -s https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.0-amd64.deb -o /tmp/es.deb
  dpkg -i /tmp/es.deb 2>/dev/null || apt-get install -y -f -qq
fi

cat > /etc/elasticsearch/elasticsearch.yml << 'EOF'
cluster.name: ds-lab
node.name: soc-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
EOF

systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

# -------- 安装 Logstash --------
echo "[4/8] 安装 Logstash..."
if ! dpkg -l | grep -q logstash; then
  curl -L -s https://artifacts.elastic.co/downloads/logstash/logstash-8.11.0-amd64.deb -o /tmp/logstash.deb
  dpkg -i /tmp/logstash.deb 2>/dev/null || apt-get install -y -f -qq
fi

# Logstash pipeline: 接收 Beats + Syslog，输出到 Elasticsearch
cat > /etc/logstash/conf.d/ds-pipeline.conf << 'EOF'
input {
  beats {
    port => 5044
  }
  syslog {
    port => 514
  }
}

filter {
  # 添加时间戳
  date {
    match => ["timestamp", "ISO8601"]
    remove_field => ["timestamp"]
  }

  # 按 host_role 字段打标签
  if [fields][host_role] == "dmz_web" {
    mutate { add_tag => ["dmz", "low_security"] }
  }
  if [fields][host_role] == "db_internal" {
    mutate { add_tag => ["internal", "high_security"] }
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "ds-lab-%{+YYYY.MM.dd}"
  }
  # 调试用：同时输出到控制台
  stdout {
    codec => rubydebug
  }
}
EOF

systemctl enable logstash
systemctl start logstash

# -------- 安装 Neo4j --------
echo "[5/8] 安装 Neo4j..."
apt-get install -y -qq wget gnupg
# 使用现代 gpg --dearmor 方式替代废弃的 apt-key
wget -q -O - https://debian.neo4j.com/neotechnology.gpg.key | gpg --dearmor -o /usr/share/keyrings/neo4j.gpg 2>/dev/null || true
echo "deb [signed-by=/usr/share/keyrings/neo4j.gpg] https://debian.neo4j.com stable latest" | tee /etc/apt/sources.list.d/neo4j.list
apt-get update -qq 2>/dev/null || true
apt-get install -y -qq neo4j 2>/dev/null || {
  # 如果官方源失败，使用社区版直接下载
  echo "Neo4j 官方源不可用，跳过。请手动安装。"
}

if command -v neo4j &> /dev/null; then
  neo4j-admin dbms set-initial-password '<NEO4J_PASSWORD>' 2>/dev/null || true
  systemctl enable neo4j
  systemctl start neo4j
fi

# -------- 安装 Python 3 & pip --------
echo "[6/8] 安装 Python 环境..."
apt-get install -y -qq python3 python3-pip python3-venv

# 安装 DeepSecurity 项目依赖
if [ -f /vagrant/../../../requirements.txt ]; then
  pip3 install -r /vagrant/../../../requirements.txt 2>/dev/null || true
fi

# -------- 安装 Wazuh Manager (可选) --------
echo "[7/8] 安装 Wazuh Manager (可选)..."
# Wazuh 提供完整的 HIDS 能力，可根据需要安装
# curl -s https://packages.wazuh.com/4.x/wazuh-install.sh | bash
# 默认跳过，如需启用请取消注释
echo "  跳过 Wazuh 安装（默认）。如需启用，取消脚本中的注释。"

# -------- 配置 iptables --------
echo "[8/8] 配置 iptables..."

# 预安装 iptables-persistent（必须在封锁网络前完成，否则无法下载）
apt-get install -y -qq iptables-persistent 2>/dev/null || true

iptables -F
iptables -X

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 入站：日志接收（来自 DMZ + Internal）
iptables -A INPUT -s 192.168.100.0/24 -p tcp --dport 5044 -j ACCEPT
iptables -A INPUT -s 192.168.200.0/24 -p tcp --dport 5044 -j ACCEPT
iptables -A INPUT -s 192.168.100.0/24 -p udp --dport 514 -j ACCEPT
iptables -A INPUT -s 192.168.200.0/24 -p udp --dport 514 -j ACCEPT
iptables -A INPUT -s 192.168.100.0/24 -p tcp --dport 1514 -j ACCEPT
iptables -A INPUT -s 192.168.200.0/24 -p tcp --dport 1514 -j ACCEPT

# 入站：Elasticsearch（Internal 网段）
iptables -A INPUT -s 192.168.200.0/24 -p tcp --dport 9200 -j ACCEPT

# 入站：Flask API（Internal 网段）
iptables -A INPUT -s 192.168.200.0/24 -p tcp --dport 5000 -j ACCEPT

# 入站：Neo4j（Internal 网段）
iptables -A INPUT -s 192.168.200.0/24 -p tcp --dport 7687 -j ACCEPT

# 出站：SSH 巡检到 DMZ + Internal
iptables -A OUTPUT -d 192.168.100.0/24 -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -d 192.168.200.0/24 -p tcp --dport 22 -j ACCEPT

# 入站：SSH（Vagrant NAT 管理通道 — VirtualBox 默认 10.0.2.0/24）
iptables -A INPUT -s 10.0.2.0/24 -p tcp --dport 22 -j ACCEPT

# 出站：WinRM 到 Internal Windows
iptables -A OUTPUT -d 192.168.200.0/24 -p tcp --dport 5985 -j ACCEPT

# 出站：DNS / NTP
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

netfilter-persistent save

echo ""
echo "=========================================="
echo " soc-node 初始化完成！"
echo " 服务: Elasticsearch (:9200), Logstash (:5044), Neo4j (:7687)"
echo " 管理 IP: 192.168.10.10 (Management)"
echo " 巡检 IP: 192.168.200.50 (Internal)"
echo ""
echo " 验证: curl http://localhost:9200/_cat/indices"
echo "=========================================="
