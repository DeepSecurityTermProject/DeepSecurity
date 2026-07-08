-- ============================================================
-- SecTrace 数据库一键建库脚本
-- 数据库: SecurityTraceDB
-- 执行: sqlcmd -S <SERVER_IP>,1433 -U <DB_USERNAME> -P <DB_PASSWORD> -d SecurityTraceDB -i create_database.sql
-- 或在 SSMS 中打开此文件直接执行
-- ============================================================

-- 1) HostLogs — 主机日志（Windows Event Log 归一化）
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'HostLogs')
CREATE TABLE dbo.HostLogs (
    id              INT IDENTITY PRIMARY KEY,
    result          NVARCHAR(MAX) NOT NULL,
    content         NVARCHAR(MAX) NULL,
    create_time     DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(),
    event_hash      VARCHAR(64)   NULL,
    host_name       NVARCHAR(510) NULL,
    event_time_utc  DATETIME2     NULL
);

-- 2) HostBehaviors — 主机行为（进程/文件/网络/注册表）
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'HostBehaviors')
CREATE TABLE dbo.HostBehaviors (
    id              INT IDENTITY PRIMARY KEY,
    result          NVARCHAR(MAX) NOT NULL,
    content         NVARCHAR(MAX) NULL,
    create_time     DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(),
    event_hash      VARCHAR(64)   NULL,
    host_name       NVARCHAR(510) NULL,
    event_time_utc  DATETIME2     NULL
);

-- 3) NetworkTraffic — 网络流量（PCAP 解析入库）
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'NetworkTraffic')
CREATE TABLE dbo.NetworkTraffic (
    id              INT IDENTITY PRIMARY KEY,
    result          NVARCHAR(MAX) NOT NULL,
    content         NVARCHAR(MAX) NULL,
    create_time     DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(),
    event_hash      VARCHAR(64)   NULL,
    host_name       NVARCHAR(510) NULL,
    event_time_utc  DATETIME2     NULL
);

-- 4) AttackReports — 攻击链分析报告
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'AttackReports')
CREATE TABLE dbo.AttackReports (
    id                  INT IDENTITY PRIMARY KEY,
    scenario_id         NVARCHAR(100) NOT NULL,
    victim_ip           NVARCHAR(100) NULL,
    attacker_ip         NVARCHAR(100) NULL,
    start_time          DATETIME      NULL,
    end_time            DATETIME      NULL,
    confidence          NVARCHAR(40)  NULL,
    attribution_type    NVARCHAR(100) NULL,
    attribution_name    NVARCHAR(200) NULL,
    report_json         NVARCHAR(MAX) NULL,
    created_at          DATETIME      NULL DEFAULT GETDATE()
);

-- 5) AnalysisReports — 多源 LLM 综合分析报告
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'AnalysisReports')
CREATE TABLE dbo.AnalysisReports (
    id                  INT IDENTITY PRIMARY KEY,
    report_id           VARCHAR(64)   NOT NULL,
    time_start          DATETIME2     NULL,
    time_end            DATETIME2     NULL,
    data_sources        NVARCHAR(512) NULL,
    total_events        INT           NULL DEFAULT 0,
    techniques_found    INT           NULL DEFAULT 0,
    attack_chain        NVARCHAR(MAX) NULL,
    llm_analysis        NVARCHAR(MAX) NULL,
    llm_model           NVARCHAR(128) NULL,
    confidence          NVARCHAR(64)  NULL,
    attribution         NVARCHAR(MAX) NULL,
    iocs                NVARCHAR(MAX) NULL,
    report_json         NVARCHAR(MAX) NULL,
    created_at          DATETIME2     NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT UQ_AnalysisReports_report_id UNIQUE (report_id)
);

-- 6) DetectionDetails — 检测明细
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'DetectionDetails')
CREATE TABLE dbo.DetectionDetails (
    id                  INT IDENTITY PRIMARY KEY,
    report_id           VARCHAR(64)   NOT NULL,
    data_source         NVARCHAR(128) NOT NULL,
    event_type          NVARCHAR(256) NULL,
    technique_id        NVARCHAR(64)  NULL,
    technique_name      NVARCHAR(512) NULL,
    tactic              NVARCHAR(128) NULL,
    severity            NVARCHAR(32)  NULL,
    confidence          FLOAT         NULL DEFAULT 0,
    source              NVARCHAR(64)  NULL,
    description         NVARCHAR(2048) NULL,
    raw_event_json      NVARCHAR(MAX) NULL,
    detected_at         DATETIME2     NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_DetectionDetails_Report FOREIGN KEY (report_id) REFERENCES dbo.AnalysisReports(report_id)
);

-- 7) TopologySnapshots — 网络拓扑快照
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'TopologySnapshots')
CREATE TABLE dbo.TopologySnapshots (
    id                  INT IDENTITY PRIMARY KEY,
    snapshot_id         VARCHAR(64)   NOT NULL,
    time_start          DATETIME2     NULL,
    time_end            DATETIME2     NULL,
    nodes_json          NVARCHAR(MAX) NULL,
    edges_json          NVARCHAR(MAX) NULL,
    zones_json          NVARCHAR(MAX) NULL,
    summary_json        NVARCHAR(MAX) NULL,
    created_at          DATETIME2     NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT UQ_TopologySnapshots_snapshot_id UNIQUE (snapshot_id)
);

-- 8) EvidenceCases — 证据包（一次分析对应一组证据链）
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'EvidenceCases')
CREATE TABLE dbo.EvidenceCases (
    case_id             VARCHAR(64)   NOT NULL PRIMARY KEY,
    verdict_id          VARCHAR(64)   NULL,
    chain_id            VARCHAR(64)   NULL,
    final_hash          VARCHAR(64)   NULL,
    report_json         NVARCHAR(MAX) NULL,
    iocs_json           NVARCHAR(MAX) NULL,
    techniques_json     NVARCHAR(MAX) NULL,
    created_at          DATETIME2     NULL DEFAULT SYSUTCDATETIME()
);

-- 9) EvidenceRecords — 证据索引（可定位到原始日志/行为/流量）
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'EvidenceRecords')
CREATE TABLE dbo.EvidenceRecords (
    id                  INT IDENTITY PRIMARY KEY,
    case_id             VARCHAR(64)   NOT NULL,
    evidence_id         VARCHAR(64)   NOT NULL,
    block_id            VARCHAR(64)   NULL,
    block_hash          VARCHAR(64)   NULL,
    previous_hash       VARCHAR(64)   NULL,
    source_table        NVARCHAR(64)  NOT NULL,
    source_record_id    INT           NOT NULL,
    event_hash          VARCHAR(64)   NOT NULL,
    collected_at        DATETIME2     NULL,
    analyzed_at         DATETIME2     NULL,
    evidence_type       NVARCHAR(64)  NULL,
    summary             NVARCHAR(512) NULL,
    CONSTRAINT FK_EvidenceRecords_Case FOREIGN KEY (case_id) REFERENCES dbo.EvidenceCases(case_id)
);

-- ============================================================
-- 索引
-- ============================================================
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_HostLogs_create_time')
    CREATE NONCLUSTERED INDEX IX_HostLogs_create_time ON dbo.HostLogs(create_time DESC);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_HostLogs_host_name')
    CREATE NONCLUSTERED INDEX IX_HostLogs_host_name ON dbo.HostLogs(host_name);

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_HostBehaviors_create_time')
    CREATE NONCLUSTERED INDEX IX_HostBehaviors_create_time ON dbo.HostBehaviors(create_time DESC);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_HostBehaviors_host_name')
    CREATE NONCLUSTERED INDEX IX_HostBehaviors_host_name ON dbo.HostBehaviors(host_name);

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_NetworkTraffic_create_time')
    CREATE NONCLUSTERED INDEX IX_NetworkTraffic_create_time ON dbo.NetworkTraffic(create_time DESC);

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_AttackReports_created_at')
    CREATE NONCLUSTERED INDEX IX_AttackReports_created_at ON dbo.AttackReports(created_at DESC);

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_AnalysisReports_created_at')
    CREATE NONCLUSTERED INDEX IX_AnalysisReports_created_at ON dbo.AnalysisReports(created_at DESC);

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_DetectionDetails_report_id')
    CREATE NONCLUSTERED INDEX IX_DetectionDetails_report_id ON dbo.DetectionDetails(report_id);

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_EvidenceCases_created_at')
    CREATE NONCLUSTERED INDEX IX_EvidenceCases_created_at ON dbo.EvidenceCases(created_at DESC);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_EvidenceRecords_case_id')
    CREATE NONCLUSTERED INDEX IX_EvidenceRecords_case_id ON dbo.EvidenceRecords(case_id, id);
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_EvidenceRecords_event_hash')
    CREATE NONCLUSTERED INDEX IX_EvidenceRecords_event_hash ON dbo.EvidenceRecords(event_hash);

PRINT 'SecTrace database initialized successfully. 9 tables + indexes created.';
