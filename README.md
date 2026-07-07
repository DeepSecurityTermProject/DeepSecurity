# DeepSecurity / SecTrace

666基于大语言模型的攻击行为检测、捕获与溯源系统。项目围绕“检测 Detection -> 捕获 Capture -> 溯源 Attribution/Traceback”的安全分析链路，整合主机日志、主机行为、网络流量、MITRE ATT&CK 知识库、RAG 检索和 OpenAI 兼容 LLM 接口，用于课程实验、攻防场景演示和安全分析原型验证。

## 主要功能

- 攻击场景生成：内置 APT 全链条攻击、AI Agent 滥用攻击等模拟场景。
- 攻击检测：规则检测、RAG 知识库增强检测和可选 LLM 深度分析。
- 攻击捕获：多 Agent 协作抽取证据、构建攻击链、验证事件逻辑。
- 溯源归因：基于 TTP、IOC、攻击链和报告数据进行攻击画像分析。
- 数据可视化：Vue 3 + Naive UI 前端展示仪表盘、告警、日志、行为、流量、拓扑和攻击链。
- 多源数据接入：支持 SQL Server、Neo4j、Windows 日志、Sysmon/Falco 行为数据、PCAP/网络流量分析。

## 项目结构

```text
.
├── app_launcher.py              # 后端与前端开发服务启动器
├── config.py                    # 全局配置，敏感值从环境变量读取
├── requirements.txt             # Python 后端依赖
├── frontend/                    # Vue 3 + Vite 前端
├── xiaoxueqi/                   # Flask 应用工厂、蓝图路由和传统模板
├── utils/                       # 检测、捕获、归因、溯源、流量、日志、场景等业务模块
├── knowledge_base/              # ATT&CK、APT、RAG 知识库数据
├── data/                        # 运行时上传、抓包和临时数据目录，默认不提交
├── docs/                        # 实验报告、环境搭建、架构和项目文档
├── tests/                       # 基础验证测试
├── .env.example                 # 本地环境变量示例，不包含真实密钥
└── USER_MANUAL.md               # 详细使用说明
```

文档已整理到：

- `docs/architecture/`：架构分类说明。
- `docs/development/`：团队协作开发流程、分支规范、PR 规范和 Reviewer 检查清单。
- `docs/project/`：项目选题、数据库、接口、测试环境和客户端配置文档。
- `docs/` 根目录：实验报告、开源项目对比、演示录制和网络环境搭建指南。

## 环境要求

- Python 3.10 或更高版本
- Node.js 18 或更高版本
- SQL Server，按需启用
- Neo4j，按需启用
- Windows 日志采集、Sysmon、Falco、dumpcap 等采集工具，按模块需要安装

## 后端安装

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

项目不会自动读取 `.env` 文件。可以参考 `.env.example`，在系统环境变量、PowerShell 会话或启动脚本中设置需要的配置：

```powershell
$env:LLM_API_KEY = "your-local-api-key"
$env:DB_SERVER = "localhost,1433"
$env:DB_USERNAME = "sa"
$env:DB_PASSWORD = "your-local-password"
$env:NEO4J_URI = "bolt://localhost:7687"
$env:NEO4J_USER = "neo4j"
$env:NEO4J_PASSWORD = "your-local-password"
```

未配置 `LLM_API_KEY` 时，LLM 相关调用会跳过或返回“未配置”提示，规则检测和本地数据流程仍可继续使用。

## 前端安装

```powershell
cd frontend
npm install
npm run dev
```

前端默认运行在 `http://localhost:5173`，通过 `frontend/vite.config.ts` 将 API 代理到 Flask 后端 `http://localhost:5000`。

## 启动方式

回到项目根目录：

```powershell
python app_launcher.py
```

常用参数：

```powershell
python app_launcher.py --port 5000 --debug
python app_launcher.py --no-llm
python app_launcher.py --no-vite
```

默认入口：

- Vue 前端：`http://localhost:5173/`
- Flask 后端：`http://localhost:5000/`
- 仪表盘：`http://localhost:5173/dashboard`
- 场景管理：`http://localhost:5173/scenario`
- 攻击检测：`http://localhost:5173/detection`
- 溯源归因：`http://localhost:5173/attribution`

## 关键配置

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `SECRET_KEY` | Flask 本地开发密钥 | `dev-only-change-me` |
| `DB_DRIVER` | SQL Server ODBC 驱动 | `ODBC Driver 17 for SQL Server` |
| `DB_SERVER` | SQL Server 地址 | `localhost,1433` |
| `DB_DATABASE` | 业务数据库 | `SecurityTraceDB` |
| `DB_USERNAME` | SQL Server 用户名 | `sa` |
| `DB_PASSWORD` | SQL Server 密码 | 空 |
| `TRACE_SQL_HOST` | 溯源模块 SQL Server 地址 | `localhost,1433` |
| `TRACE_SQL_USER` | 溯源模块 SQL Server 用户名 | `sa` |
| `TRACE_SQL_PASS` | 溯源模块 SQL Server 密码 | 空 |
| `NEO4J_URI` | Neo4j Bolt 地址 | `bolt://localhost:7687` |
| `NEO4J_USER` | Neo4j 用户名 | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j 密码 | 空 |
| `LLM_API_KEY` | OpenAI 兼容 LLM API Key | 空 |
| `LLM_BASE_URL` | OpenAI 兼容 API 地址 | DashScope 兼容地址 |
| `LLM_MODEL` | 检测模型名称 | `qwen-flash` |
| `DUMPCAP_PATH` | dumpcap 可执行文件路径 | 空 |
| `LIVE_CAPTURE_DIR` | 在线抓包临时目录 | `data/live_captures` |

## 开发验证

```powershell
python -m unittest tests.test_config_security -v
python -m compileall config.py utils xiaoxueqi
```

敏感信息检查建议：提交前运行 secret scanner，或用 `rg` 按团队已知的密钥格式、默认密码和内网地址模式做一次全仓扫描。

## 安全说明

- 仓库不提交真实 API Key、数据库密码、Neo4j 密码或本地 `.env` 文件。
- `.env.example` 仅提供变量名和安全占位值。
- `frontend/node_modules/`、Python 缓存、构建产物、上传抓包和运行时数据均通过 `.gitignore` 排除。
- 如果历史提交中曾包含密钥，应在对应平台立即轮换密钥；本仓库当前为首个提交前清理。
