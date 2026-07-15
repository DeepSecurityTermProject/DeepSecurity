#!/bin/bash
# ============================================================
# setup-web-dmz.sh — DMZ Web/API 服务器初始化
# 对应主机: web-dmz (192.168.100.10)
# 执行方式: sudo bash setup-web-dmz.sh
# ============================================================
set -e

# 非交互模式，防止 debconf 弹窗挂死
export DEBIAN_FRONTEND=noninteractive

echo "=========================================="
echo " DeepSecurity Lab — web-dmz 初始化"
echo " 角色: DMZ Web/API 服务器"
echo " IP: 192.168.100.10"
echo "=========================================="

# -------- 系统更新 --------
echo "[1/6] 系统更新..."
apt-get update -qq && apt-get upgrade -y -qq

# -------- 安装 Nginx --------
echo "[2/6] 安装 Nginx..."
apt-get install -y -qq nginx
systemctl enable nginx
systemctl start nginx

# 创建模拟 API 端点
cat > /var/www/html/api.json << 'EOF'
{"status": "ok", "service": "DeepSecurity DMZ API", "version": "1.0"}
EOF

# 修改默认首页
cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html><head><title>DeepSecurity Lab — DMZ Web</title></head>
<body>
<h1>DeepSecurity Lab — DMZ Web Server</h1>
<p>Host: web-dmz | IP: 192.168.100.10 | Zone: DMZ (低安全防御区)</p>
</body></html>
EOF

# -------- 安装 auditd --------
echo "[3/6] 安装 auditd（系统调用审计）..."
apt-get install -y -qq auditd
systemctl enable auditd
systemctl start auditd

# 添加关键审计规则
cat >> /etc/audit/rules.d/ds-monitor.rules << 'EOF'
# 监控关键文件访问
-w /etc/shadow -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /var/www/html/ -p wa -k web_content
-w /etc/nginx/ -p wa -k nginx_config

# 监控 execve 系统调用
-a always,exit -F arch=b64 -S execve -k exec_trace
EOF

systemctl restart auditd

# -------- 安装并配置 rsyslog 转发 --------
echo "[4/6] 配置 rsyslog 转发到 soc-node..."
apt-get install -y -qq rsyslog

cat >> /etc/rsyslog.d/50-forward-to-soc.conf << 'EOF'
# 转发所有日志到 SOC 节点
*.* @192.168.200.50:514
EOF

systemctl restart rsyslog

# -------- 安装 Filebeat（转发 Nginx 日志 + auditd 日志） --------
echo "[5/6] 安装 Filebeat..."
if ! dpkg -l | grep -q filebeat; then
  curl -L -s https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.0-amd64.deb -o /tmp/filebeat.deb
  dpkg -i /tmp/filebeat.deb 2>/dev/null || apt-get install -y -f -qq
fi

cat > /etc/filebeat/filebeat.yml << 'EOF'
filebeat.inputs:
  - type: filestream
    id: nginx-access
    enabled: true
    paths:
      - /var/log/nginx/access.log
    fields:
      log_type: nginx_access
      host_role: dmz_web

  - type: filestream
    id: nginx-error
    enabled: true
    paths:
      - /var/log/nginx/error.log
    fields:
      log_type: nginx_error
      host_role: dmz_web

  - type: filestream
    id: auth-log
    enabled: true
    paths:
      - /var/log/auth.log
    fields:
      log_type: auth
      host_role: dmz_web

  - type: filestream
    id: auditd-log
    enabled: true
    paths:
      - /var/log/audit/audit.log
    fields:
      log_type: auditd
      host_role: dmz_web

output.logstash:
  hosts: ["192.168.200.50:5044"]
EOF

systemctl enable filebeat
systemctl start filebeat 2>/dev/null || true

# -------- 配置 iptables 防火墙 --------
echo "[6/6] 配置 iptables 防火墙规则..."

# 预安装 iptables-persistent（必须在封锁网络前完成，否则无法下载）
apt-get install -y -qq iptables-persistent

# 清除已有规则
iptables -F
iptables -X

# 默认策略
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 已建立连接
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 入站：HTTP/HTTPS（任意源）
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# 入站：SSH（soc-node 管理 — 实际源 IP 为 ds-internal 接口 192.168.200.50）
iptables -A INPUT -s 192.168.200.0/24 -p tcp --dport 22 -j ACCEPT
# 入站：SSH（Vagrant NAT 管理通道 — VirtualBox 默认 10.0.2.0/24）
iptables -A INPUT -s 10.0.2.0/24 -p tcp --dport 22 -j ACCEPT

# 出站：到 db-internal 的 MySQL
iptables -A OUTPUT -d 192.168.200.20 -p tcp --dport 3306 -j ACCEPT

# 出站：DNS / NTP
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

# 出站：日志转发到 soc-node
iptables -A OUTPUT -d 192.168.200.50 -p tcp --dport 5044 -j ACCEPT
iptables -A OUTPUT -d 192.168.200.50 -p udp --dport 514 -j ACCEPT

# 持久化 iptables
netfilter-persistent save

echo ""
echo "=========================================="
echo " web-dmz 初始化完成！"
echo " 服务: Nginx (80/443), Filebeat, auditd"
echo " 日志转发: soc-node:5044 (Logstash), :514 (Syslog)"
echo "=========================================="
