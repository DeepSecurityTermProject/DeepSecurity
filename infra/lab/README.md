# infra/lab — 企业内网靶场部署基础设施

本目录包含 Issue #1 的可复现部署方案。

## 文件说明

```
infra/lab/
├── README.md                 # 本文件
├── Vagrantfile               # Vagrant 一键部署（6 台 VM，推荐）
├── docker-compose.yml        # Docker Compose 快速演示
├── scripts/
│   ├── setup-web-dmz.sh      # DMZ Web 服务器初始化 (Linux)
│   ├── setup-db-internal.sh  # 内网数据库服务器初始化 (Linux)
│   ├── setup-soc.sh          # SOC 节点初始化 (Linux)
│   ├── setup-dc.ps1          # 域控制器初始化 (Windows PowerShell)
│   └── setup-workspace.ps1   # 工作站初始化 (Windows PowerShell)
├── mysql-conf.d/             # MySQL 自定义配置（Docker 方案使用）
└── logstash-conf.d/          # Logstash pipeline 配置（Docker 方案使用）
```

## 方案选择

| 场景 | 推荐方案 | 说明 |
|------|---------|------|
| 完整靶场体验 | **Vagrant** (`vagrant up`) | 6 台真实 VM，含 Windows 域控/Sysmon，最接近生产环境 |
| 手动精细控制 | **文档手动部署** (`docs/网络环境搭建指南.md` 方案 A) | 逐台创建 VM，适合学习和调试 |
| 快速验证（无 Windows 需求） | **Docker Compose** (`docker compose up -d`) | 容器化轻量方案，启动快，资源占用低 |

## 前置条件

### Vagrant 方案
- [VirtualBox](https://www.virtualbox.org/) 7.0+
- [Vagrant](https://www.vagrantup.com/) 2.3+
- 宿主机 ≥ 16 GB RAM, ≥ 100 GB 空闲磁盘
- 网络通畅（首次启动需下载 Box，约 5-10 GB）

### Docker 方案
- [Docker Engine](https://docs.docker.com/engine/install/) 24+
- [Docker Compose](https://docs.docker.com/compose/install/) v2+
- 宿主机 ≥ 8 GB RAM

## 快速开始

```powershell
# === Vagrant 方案 ===
cd infra\lab
vagrant up                    # 启动全部 VM（首次约 20-40 分钟）
vagrant status                # 查看所有 VM 状态
vagrant ssh soc-node          # SSH 进入 SOC 节点
vagrant halt                  # 关闭所有 VM

# === Docker 方案 ===
cd infra\lab
docker compose up -d          # 启动所有容器
docker compose ps             # 查看状态
docker exec -it ds-soc-node bash  # 进入 SOC 容器
docker compose down           # 停止并移除
```

## 初始化脚本用途

| 脚本 | 做什么 |
|------|--------|
| `setup-web-dmz.sh` | 安装 Nginx, auditd, rsyslog; 配置日志转发到 soc-node:5044; 应用 iptables 防火墙 |
| `setup-db-internal.sh` | 安装 MySQL 8.0; 配置 auditd + rsyslog; 应用 iptables 防火墙 |
| `setup-soc.sh` | 安装 Elasticsearch, Logstash, Neo4j, Python 3.10+; 配置日志接收 pipeline |
| `setup-dc.ps1` | 安装 AD DS + DNS 角色; 部署 Sysmon; 配置 Winlogbeat→Logstash; 设置 Windows 防火墙 |
| `setup-workspace.ps1` | 加入域; 安装 Sysmon + Winlogbeat; 开启 PowerShell 日志; 设置 Windows 防火墙 |

> 所有脚本中密码使用 `<PLACEHOLDER>` 占位符，实际部署前需替换。

## 注意事项

- 本环境为**完全隔离的靶场**，不与宿主机物理网络互通
- 所有 IP、账号、密码均为示例，不包含真实敏感信息
- 攻击机 (Kali) 仅可在靶场内部发起攻击，**禁止用于未授权的互联网攻击**
- Docker 方案中 Windows 相关节点使用 Linux 容器模拟，无法完整复现 Windows AD/Sysmon 行为
