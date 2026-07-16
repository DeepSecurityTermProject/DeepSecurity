#!/bin/bash
# ============================================================
# setup-db-internal.sh — 内网数据库服务器初始化
# 对应主机: db-internal (192.168.200.20)
# 执行方式: sudo bash setup-db-internal.sh
# ============================================================
set -e

# 非交互模式，防止 debconf 弹窗挂死
export DEBIAN_FRONTEND=noninteractive

echo "=========================================="
echo " DeepSecurity Lab — db-internal 初始化"
echo " 角色: 内网数据库服务器"
echo " IP: 192.168.200.20"
echo "=========================================="

# -------- 系统更新 --------
echo "[1/6] 系统更新..."
apt-get update -qq && apt-get upgrade -y -qq

# -------- 安装 MySQL 8.0 --------
echo "[2/6] 安装 MySQL 8.0..."
apt-get install -y -qq mysql-server
systemctl enable mysql
systemctl start mysql

# 创建数据库和用户（使用占位符密码，实际部署请替换）
mysql -u root << 'SQL'
CREATE DATABASE IF NOT EXISTS SecurityTraceDB;
CREATE USER IF NOT EXISTS '<DB_USERNAME>'@'192.168.200.40' IDENTIFIED BY '<DB_PASSWORD>';
CREATE USER IF NOT EXISTS '<DB_USERNAME>'@'192.168.200.%' IDENTIFIED BY '<DB_PASSWORD>';
GRANT ALL PRIVILEGES ON SecurityTraceDB.* TO '<DB_USERNAME>'@'192.168.200.40';
GRANT ALL PRIVILEGES ON SecurityTraceDB.* TO '<DB_USERNAME>'@'192.168.200.%';
FLUSH PRIVILEGES;
SQL

# 启用 MySQL 日志
cat >> /etc/mysql/mysql.conf.d/mysqld.cnf << 'EOF'

# === DeepSecurity Lab: 日志配置 ===
general_log_file       = /var/log/mysql/general.log
general_log            = 1
slow_query_log_file    = /var/log/mysql/slow.log
slow_query_log         = 1
long_query_time        = 2
log_error              = /var/log/mysql/error.log
EOF

systemctl restart mysql

# -------- 安装 auditd --------
echo "[3/6] 安装 auditd..."
apt-get install -y -qq auditd
systemctl enable auditd
systemctl start auditd

cat >> /etc/audit/rules.d/ds-monitor.rules << 'EOF'
# 监控数据库文件
-w /var/lib/mysql/ -p wa -k db_data
-w /etc/mysql/ -p wa -k mysql_config

# 监控敏感凭证文件
-w /etc/shadow -p wa -k identity

# execve 调用
-a always,exit -F arch=b64 -S execve -k exec_trace
EOF

systemctl restart auditd

# -------- 配置 rsyslog 转发 --------
echo "[4/6] 配置 rsyslog 转发..."
cat >> /etc/rsyslog.d/50-forward-to-soc.conf << 'EOF'
*.* @192.168.200.50:514
EOF
systemctl restart rsyslog

# -------- 安装 Filebeat --------
echo "[5/6] 安装 Filebeat..."
if ! dpkg -l | grep -q filebeat; then
  curl -L -s https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.0-amd64.deb -o /tmp/filebeat.deb
  dpkg -i /tmp/filebeat.deb 2>/dev/null || apt-get install -y -f -qq
fi

cat > /etc/filebeat/filebeat.yml << 'EOF'
filebeat.inputs:
  - type: filestream
    id: mysql-general
    enabled: true
    paths:
      - /var/log/mysql/general.log
    fields:
      log_type: mysql_general
      host_role: db_internal

  - type: filestream
    id: mysql-slow
    enabled: true
    paths:
      - /var/log/mysql/slow.log
    fields:
      log_type: mysql_slow
      host_role: db_internal

  - type: filestream
    id: mysql-error
    enabled: true
    paths:
      - /var/log/mysql/error.log
    fields:
      log_type: mysql_error
      host_role: db_internal

  - type: filestream
    id: auth-log
    enabled: true
    paths:
      - /var/log/auth.log
    fields:
      log_type: auth
      host_role: db_internal

  - type: filestream
    id: auditd-log
    enabled: true
    paths:
      - /var/log/audit/audit.log
    fields:
      log_type: auditd
      host_role: db_internal

output.logstash:
  hosts: ["192.168.200.50:5044"]
EOF

systemctl enable filebeat
systemctl start filebeat 2>/dev/null || true

# -------- iptables 防火墙 --------
echo "[6/6] 配置 iptables..."

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

# 入站：来自 web-dmz 的 MySQL（web-dmz 通过 ds-internal 接口 192.168.200.40 连接）
iptables -A INPUT -s 192.168.200.40 -p tcp --dport 3306 -j ACCEPT

# 入站：来自 Internal 网段的 SQL Server（如安装）
iptables -A INPUT -s 192.168.200.0/24 -p tcp --dport 1433 -j ACCEPT

# 入站：SSH（soc-node 和内网管理）
iptables -A INPUT -s 192.168.10.0/24 -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -s 192.168.200.0/24 -p tcp --dport 22 -j ACCEPT
# 入站：SSH（Vagrant NAT 管理通道 — VirtualBox 默认 10.0.2.0/24）
iptables -A INPUT -s 10.0.2.0/24 -p tcp --dport 22 -j ACCEPT

# 出站：DNS / NTP
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

# 出站：日志转发
iptables -A OUTPUT -d 192.168.200.50 -p tcp --dport 5044 -j ACCEPT
iptables -A OUTPUT -d 192.168.200.50 -p udp --dport 514 -j ACCEPT

# 出站：AD 域认证（如加入域）
iptables -A OUTPUT -d 192.168.200.10 -p tcp -m multiport --dports 88,389 -j ACCEPT

netfilter-persistent save

echo ""
echo "=========================================="
echo " db-internal 初始化完成！"
echo " 服务: MySQL (3306), Filebeat, auditd"
echo " 数据库: SecurityTraceDB"
echo "=========================================="
