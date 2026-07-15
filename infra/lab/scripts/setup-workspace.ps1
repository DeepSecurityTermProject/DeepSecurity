<#
.SYNOPSIS
    setup-workspace.ps1 — Windows 开发者工作站初始化
.DESCRIPTION
    对应主机: win-workspace (192.168.200.30)
    执行方式: 以管理员身份运行 PowerShell
              Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
              .\setup-workspace.ps1
#>

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " DeepSecurity Lab — win-workspace 初始化" -ForegroundColor Cyan
Write-Host " 角色: 开发者工作站 / 终端" -ForegroundColor Cyan
Write-Host " IP: 192.168.200.30" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$ErrorActionPreference = "Continue"

# -------- 1. 设置静态 IP --------
Write-Host "[1/6] 配置静态 IP 192.168.200.30..." -ForegroundColor Yellow
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
$interfaceIndex = $adapter.ifIndex
New-NetIPAddress -InterfaceIndex $interfaceIndex -IPAddress 192.168.200.30 -PrefixLength 24 -DefaultGateway 192.168.200.1 -ErrorAction SilentlyContinue
Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ServerAddresses ("192.168.200.10", "8.8.8.8")

Rename-Computer -NewName "win-workspace" -Force -ErrorAction SilentlyContinue

# -------- 2. 加入域 --------
Write-Host "[2/6] 加入域 lab.local..." -ForegroundColor Yellow
$domainUser = "lab\setupadmin"
$domainPassword = ConvertTo-SecureString "<ADMIN_PASSWORD>" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($domainUser, $domainPassword)

Add-Computer -DomainName "lab.local" -Credential $credential -Force -ErrorAction SilentlyContinue
Write-Host "  已请求加入域 lab.local。重启后生效。" -ForegroundColor Green

# -------- 3. 开启高级审计策略 --------
Write-Host "[3/6] 配置高级审计策略..." -ForegroundColor Yellow
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable

# 启用 PowerShell 模块日志和脚本块日志
$psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
$psScriptBlockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

if (-not (Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force | Out-Null }
if (-not (Test-Path $psScriptBlockPath)) { New-Item -Path $psScriptBlockPath -Force | Out-Null }

Set-ItemProperty -Path $psLogPath -Name "EnableModuleLogging" -Value 1 -Type DWord
Set-ItemProperty -Path $psScriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# -------- 4. 安装 Sysmon --------
Write-Host "[4/6] 安装 Sysmon..." -ForegroundColor Yellow
$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZip = "C:\Windows\Temp\Sysmon.zip"
$sysmonDir = "C:\Windows\Temp\Sysmon"

Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip -ErrorAction SilentlyContinue
Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force -ErrorAction SilentlyContinue

$sysmonConfig = @'
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <ProcessCreate onmatch="exclude"/>
    <FileCreateTime onmatch="exclude"/>
    <NetworkConnect onmatch="include"/>
    <ProcessTerminate onmatch="exclude"/>
    <DriverLoad onmatch="exclude"/>
    <ImageLoad onmatch="exclude"/>
    <CreateRemoteThread onmatch="exclude"/>
    <RawAccessRead onmatch="exclude"/>
    <ProcessAccess onmatch="exclude"/>
    <FileCreate onmatch="include"/>
    <RegistryEvent onmatch="include"/>
    <PipeEvent onmatch="include"/>
    <WmiEvent onmatch="include"/>
  </EventFiltering>
</Sysmon>
'@
$sysmonConfig | Out-File -FilePath "$sysmonDir\config.xml" -Encoding UTF8

& "$sysmonDir\Sysmon64.exe" -accepteula -i "$sysmonDir\config.xml" 2>$null

# -------- 5. 安装 Winlogbeat --------
Write-Host "[5/6] 安装 Winlogbeat..." -ForegroundColor Yellow
$wbUrl = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.11.0-windows-x86_64.zip"
$wbZip = "C:\Windows\Temp\winlogbeat.zip"
$wbDir = "C:\Program Files\Winlogbeat"

if (-not (Test-Path $wbDir)) {
    Invoke-WebRequest -Uri $wbUrl -OutFile $wbZip -ErrorAction SilentlyContinue
    Expand-Archive -Path $wbZip -DestinationPath "C:\Program Files" -Force -ErrorAction SilentlyContinue
    Rename-Item -Path "C:\Program Files\winlogbeat-8.11.0-windows-x86_64" -NewName "Winlogbeat" -ErrorAction SilentlyContinue
}

$winlogbeatConfig = @'
winlogbeat.event_logs:
  - name: Security
    fields:
      log_type: windows_security
      host_role: win_workspace
  - name: Microsoft-Windows-Sysmon/Operational
    fields:
      log_type: sysmon
      host_role: win_workspace
  - name: Microsoft-Windows-PowerShell/Operational
    fields:
      log_type: powershell
      host_role: win_workspace

output.logstash:
  hosts: ["192.168.200.50:5044"]
'@
$winlogbeatConfig | Out-File -FilePath "$wbDir\winlogbeat.yml" -Encoding ASCII

& "$wbDir\install-service-winlogbeat.ps1" -ErrorAction SilentlyContinue
Start-Service winlogbeat -ErrorAction SilentlyContinue

# -------- 6. 配置 Windows 防火墙 --------
Write-Host "[6/6] 配置 Windows 防火墙..." -ForegroundColor Yellow

Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# 入站：soc-node WinRM 管理（实际源 IP 为 ds-internal 接口 192.168.200.50）
New-NetFirewallRule -Name "WinRM_Mgmt" -Direction Inbound -RemoteAddress 192.168.200.50 -LocalPort 5985 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue

# 入站：WinRM（Vagrant NAT 管理通道 — VirtualBox 默认 10.0.2.0/24）
New-NetFirewallRule -Name "Vagrant_WinRM" -Direction Inbound -RemoteAddress 10.0.2.0/24 -LocalPort 5985 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue

# 出站：域认证
New-NetFirewallRule -Name "AD_Auth" -Direction Outbound -RemoteAddress 192.168.200.10 -RemotePort 88,389 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue

# 出站：日志转发
New-NetFirewallRule -Name "Logstash_Out" -Direction Outbound -RemoteAddress 192.168.200.50 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue

# 出站：DNS
New-NetFirewallRule -Name "DNS_Out" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " win-workspace 初始化完成！" -ForegroundColor Green
Write-Host " 域: lab.local (待重启生效)" -ForegroundColor Green
Write-Host " 服务: Sysmon, Winlogbeat, 高级审计策略" -ForegroundColor Green
Write-Host " 日志转发: soc-node:5044 (Logstash)" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
