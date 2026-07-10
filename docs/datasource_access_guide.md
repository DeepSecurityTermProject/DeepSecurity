# 数据源接入说明与验证命令

本文档说明 5 种数据源的输入格式、API 接入方式及端到端验证流程。

> **安全声明**：文中所有示例均使用内网测试地址（`192.168.x.x`、`10.x.x.x`）、预留占位符（`your-*`）和样例域名（`example.com`），不含任何真实密码、Token、主机名或公网资产。

---

## 目录

1. [Sysmon（Windows 端点监控）](#1-sysmon)
2. [Auditd（Linux 审计日志）](#2-auditd)
3. [Falco（Linux 运行时安全）](#3-falco)
4. [Zeek（网络流量监控）](#4-zeek)
5. [Suricata（IDS/IPS 告警）](#5-suricata)
6. [样例加载与批量验证](#6-样例加载)
7. [状态查询](#7-状态查询)
8. [入库查询](#8-入库查询)
9. [统一分析验证](#9-统一分析验证)

---

## 1. Sysmon

### 输入格式

Sysmon XML 事件，每条为 `<Event xmlns="...">...</Event>` 格式。支持的事件 ID：

| Event ID | 类型 | 说明 |
|----------|------|------|
| 1 | process_create | 进程创建 |
| 3 | network_connection | 网络连接 |
| 8 | process_injection | 进程注入 |
| 11 | file_create | 文件创建 |
| 13 | registry_set_value | 注册表写入 |
| 22 | dns_query | DNS 查询 |

### 日志导出方式

```powershell
# 从 Windows 事件查看器导出 Sysmon 日志
wevtutil epl Microsoft-Windows-Sysmon/Operational sysmon_export.evtx

# 转换为 XML（使用内置工具或 PowerShell）
Get-WinEvent -Path sysmon_export.evtx -Oldest | ForEach-Object {
    $_.ToXml()
} | Out-File sysmon_export.xml
```

### API 调用示例

```powershell
# JSON 方式上传
Invoke-RestMethod -Uri "http://localhost:5000/datasource/api/ingest/sysmon" `
  -Method POST -ContentType "application/json" `
  -Body '{"events": ["<Event xmlns=\"...\">...</Event>"], "host_name": "win-dc01"}'

# 文件上传方式
Invoke-RestMethod -Uri "http://localhost:5000/datasource/api/ingest/sysmon" `
  -Method POST `
  -Form @{file=Get-Item "sysmon_export.xml"; host_name="win-dc01"}
```

### 样例文件

`data/samples/sysmon_samples.json` — 包含 6 条 Sysmon 事件（Event ID 1/3/8/11/13/22）。

---

## 2. Auditd

### 输入格式

Linux Auditd 原始日志行，`key=value` 对格式：

```
type=SYSCALL msg=audit(1752085800.123:456): arch=c000003e syscall=59 success=yes exit=0 ... comm="curl" exe="/usr/bin/curl" key="command-exec"
```

支持的系统调用：`execve(59)`, `openat(257)`, `connect(42)`, `unlink(87)` 等，以及 `USER_AUTH` 等认证事件。

### 日志路径

```bash
# 默认 Auditd 日志路径
/var/log/audit/audit.log

# 查看最近的审计事件
sudo ausearch -i --start recent
```

### API 调用示例

```bash
# cURL 方式上传
curl -X POST http://localhost:5000/datasource/api/ingest/auditd \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      "type=SYSCALL msg=audit(1752085800.123:456): arch=c000003e syscall=59 success=yes exit=0 comm=\"curl\" exe=\"/usr/bin/curl\" key=\"command-exec\""
    ],
    "host_name": "linux-srv-01"
  }'

# 上传整个 audit.log 文件（先转为 JSON 行格式）
cat /var/log/audit/audit.log | jq -R -s 'split("\n") | map(select(length>0)) | {events: ., host_name: "linux-srv-01"}' | \
  curl -X POST http://localhost:5000/datasource/api/ingest/auditd \
  -H "Content-Type: application/json" -d @-
```

### 样例文件

`data/samples/auditd_samples.json` — 包含 6 条 Auditd 事件。

---

## 3. Falco

### 输入格式

Falco JSON 告警（每行一个 JSON 对象）：

```json
{"output":"14:30:00.123: Warning A shell was spawned in a container ...","priority":"Warning","rule":"A shell was spawned in a container","time":"2026-07-09T06:30:00.123456789Z","output_fields":{...}}
```

### 日志路径

```bash
# Falco 默认输出（取决于配置）
/var/log/falco/falco_events.json

# 或通过 falco 命令行直接输出
sudo falco -o json_output=true
```

### API 调用示例

```bash
curl -X POST http://localhost:5000/datasource/api/ingest/falco \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {"json": "{\"output\":\"...\",\"priority\":\"Warning\",\"rule\":\"A shell was spawned in a container\",\"time\":\"2026-07-09T06:30:00.123456789Z\",\"output_fields\":{\"proc.name\":\"bash\",\"proc.pid\":5678}}"}
    ],
    "host_name": "k8s-node-01"
  }'
```

### 样例文件

`data/samples/falco_samples.json` — 包含 5 条 Falco 告警事件。

---

## 4. Zeek

### 输入格式

Zeek TSV 日志（`.log` 文件），包含 `#fields` 头行：

```
#separator \x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	...
1752085800.123456	C8abc123def45678	192.168.10.50	49152	203.0.113.50	443	tcp	ssl	...
```

### 支持的日志类型

| 日志类型 | 文件 | 说明 |
|----------|------|------|
| conn | conn.log | TCP/UDP/ICMP 连接 |
| dns | dns.log | DNS 请求/响应 |
| http | http.log | HTTP 请求 |
| ssl | ssl.log | TLS 握手 |
| files | files.log | 文件传输 |

### 日志路径

```bash
# Zeek 默认日志路径
/usr/local/zeek/logs/current/conn.log
/usr/local/zeek/logs/current/dns.log
/usr/local/zeek/logs/current/http.log
```

### API 调用示例

```bash
# 文件上传方式
curl -X POST http://localhost:5000/datasource/api/ingest/zeek \
  -F "file=@/usr/local/zeek/logs/current/conn.log" \
  -F "host_name=zeek-sensor-01" \
  -F "log_type=conn"

# JSON 方式上传单行
curl -X POST http://localhost:5000/datasource/api/ingest/zeek \
  -H "Content-Type: application/json" \
  -d '{
    "lines": ["1752085800.123456\tC8abc123def45678\t192.168.10.50\t49152\t203.0.113.50\t443\ttcp\tssl\t..."],
    "host_name": "zeek-sensor-01",
    "log_type": "conn"
  }'
```

### 样例文件

`data/samples/zeek_conn.log` — 包含 6 条 Zeek conn 日志记录（含完整 `#fields` 头）。

---

## 5. Suricata

### 输入格式

Suricata `eve.json`（JSON Lines 格式，每行一个 JSON 对象）：

```json
{"timestamp":"2026-07-09T06:30:05.123456+0800","event_type":"alert","src_ip":"192.168.10.50","src_port":49162,"dest_ip":"185.220.101.34","dest_port":443,"proto":"TCP","alert":{"signature":"ET TROJAN Cobalt Strike Beacon","severity":1}}
```

### 日志路径

```bash
# Suricata 默认 eve.json 路径
/var/log/suricata/eve.json
```

### API 调用示例

```bash
# 文件上传
curl -X POST http://localhost:5000/datasource/api/ingest/suricata \
  -F "file=@/var/log/suricata/eve.json" \
  -F "host_name=suricata-sensor-01"

# JSON 方式上传
curl -X POST http://localhost:5000/datasource/api/ingest/suricata \
  -H "Content-Type: application/json" \
  -d '{
    "lines": ["{\"timestamp\":\"2026-07-09T06:30:05+0800\",\"event_type\":\"alert\",\"src_ip\":\"192.168.10.50\",\"dest_ip\":\"185.220.101.34\",\"dest_port\":443,\"proto\":\"TCP\",\"alert\":{\"signature\":\"ET TROJAN Cobalt Strike Beacon\",\"severity\":1}}"],
    "host_name": "suricata-sensor-01"
  }'
```

### 样例文件

`data/samples/suricata_samples.json` — 包含 6 条 Suricata eve.json 事件（alert/dns/http/tls/flow 类型）。

---

## 6. 样例加载

### 加载全部样例

```bash
curl -X POST http://localhost:5000/datasource/api/samples/load \
  -H "Content-Type: application/json" \
  -d '{}'
```

预期返回（全部成功时 `ok: true`）：

```json
{
  "ok": true,
  "results": {
    "sysmon": {"inserted": 6, "skipped": 0, "errors": 0},
    "auditd": {"inserted": 6, "skipped": 0, "errors": 0},
    "falco": {"inserted": 5, "skipped": 0, "errors": 0},
    "zeek": {"inserted": 6, "skipped": 0, "errors": 0},
    "suricata": {"inserted": 6, "skipped": 0, "errors": 0}
  }
}
```

### 加载单个数据源样例

```bash
# 仅加载 Sysmon 样例
curl -X POST http://localhost:5000/datasource/api/samples/load \
  -H "Content-Type: application/json" \
  -d '{"source": "sysmon"}'

# 仅加载 Zeek 样例
curl -X POST http://localhost:5000/datasource/api/samples/load \
  -H "Content-Type: application/json" \
  -d '{"source": "zeek"}'
```

### 验证命令

```bash
# 列出可用的样例文件
curl http://localhost:5000/datasource/api/samples/list

# 验证测试全部通过
python -B -m unittest discover tests -v
```

---

## 7. 状态查询

```bash
# 查询所有数据源状态
curl http://localhost:5000/datasource/api/status

# 查询单个数据源状态
curl http://localhost:5000/datasource/api/status/sysmon
curl http://localhost:5000/datasource/api/status/zeek
curl http://localhost:5000/datasource/api/status/suricata

# 数据源状态页面（浏览器访问）
# http://localhost:5000/datasource/
```

状态字段说明：

| 字段 | 说明 |
|------|------|
| status | unknown / healthy / warning / error |
| total_inserted | 累计成功入库事件数 |
| total_errors | 累计错误次数 |
| consecutive_errors | 连续错误次数（>=3 → error） |
| last_error | 最近一次错误信息 |
| last_error_time | 最近一次错误时间 |
| last_ingestion_time | 最近一次入库时间 |

---

## 8. 入库查询

### DataBridge 内存模式（SQL Server 不可用时自动降级）

```python
from utils.data_bridge import get_bridge

bridge = get_bridge()

# 查询主机行为（Sysmon + Auditd + Falco）
behaviors = bridge.query("HostBehaviors", limit=100)
print(f"HostBehaviors: {len(behaviors)} records")

# 查询网络流量（Zeek + Suricata）
traffic = bridge.query("NetworkTraffic", limit=100)
print(f"NetworkTraffic: {len(traffic)} records")

# 查询统一事件（去重）
events = bridge.get_all_events()
net_count = sum(1 for e in events if e.get("_category") == "network_traffic")
print(f"Total events: {len(events)}, NetworkTraffic: {net_count}")
```

### SQL Server 模式

```sql
-- 主机行为
SELECT COUNT(*) FROM dbo.HostBehaviors;

-- 网络流量
SELECT COUNT(*) FROM dbo.NetworkTraffic;

-- 按数据源分组统计
SELECT
    JSON_VALUE(result, '$.data_source') AS data_source,
    COUNT(*) AS cnt
FROM dbo.HostBehaviors
GROUP BY JSON_VALUE(result, '$.data_source');
```

---

## 9. 统一分析验证

### 启动分析

```bash
# 触发统一多源分析
curl -X POST http://localhost:5000/attack/api/analyze/unified \
  -H "Content-Type: application/json" \
  -d '{"time_start": "2026-07-09T06:00", "time_end": "2026-07-09T07:00"}'
```

预期结果中 `data_sources` 字段应显示各分类的事件数：

```
HostLogs(N), HostBehaviors(N), NetworkTraffic(N)
```

其中 `NetworkTraffic` 计数应 > 0（来自 Zeek 和 Suricata），且总数不重复。

### 端到端验证流程

```bash
# 1. 加载样例数据
curl -X POST http://localhost:5000/datasource/api/samples/load \
  -H "Content-Type: application/json" -d '{}'

# 2. 检查状态
curl http://localhost:5000/datasource/api/status | python -m json.tool

# 3. 运行统一分析
curl -X POST http://localhost:5000/attack/api/analyze/unified \
  -H "Content-Type: application/json" -d '{}'

# 4. 查看分析报告
curl http://localhost:5000/attack/api/reports

# 5. 运行单元测试确认
python -B -m unittest discover tests -v
```

### 预期测试结果

```
Ran 69 tests in ...s
OK
```

- 5 个数据源的样例加载测试均断言 `inserted >= 5`
- host_ip 语义测试确认主机名不进入 IP 字段
- 状态错误跟踪测试确认错误保留与恢复
- 无效输入测试确认完全无法解析时返回空结果
- 网络流量分类测试确认 Zeek/Suricata 归类为 network_traffic
