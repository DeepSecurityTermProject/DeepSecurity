<#
.SYNOPSIS
    setup-dc.ps1 — Windows 域控制器初始化
.DESCRIPTION
    对应主机: dc-ad (192.168.200.10)
    执行方式: 以管理员身份运行 PowerShell
              Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
              .\setup-dc.ps1
#>

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " DeepSecurity Lab — dc-ad 初始化" -ForegroundColor Cyan
Write-Host " 角色: 域控制器 / 身份服务" -ForegroundColor Cyan
Write-Host " IP: 192.168.200.10" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$ErrorActionPreference = "Stop"

# -------- 1. 设置静态 IP --------
Write-Host "[1/7] 配置静态 IP 192.168.200.10..." -ForegroundColor Yellow
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
$interfaceIndex = $adapter.ifIndex
New-NetIPAddress -InterfaceIndex $interfaceIndex -IPAddress 192.168.200.10 -PrefixLength 24 -DefaultGateway 192.168.200.1 -ErrorAction SilentlyContinue
Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ServerAddresses ("192.168.200.10", "8.8.8.8")

Rename-Computer -NewName "dc-ad" -Force -ErrorAction SilentlyContinue

# -------- 2. 安装 AD DS + DNS 角色 --------
Write-Host "[2/7] 安装 AD DS 和 DNS 服务器角色..." -ForegroundColor Yellow
Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools

# 提升为域控制器（使用占位符密码）
Write-Host "[3/7] 提升为域控制器 — lab.local..." -ForegroundColor Yellow
$securePassword = ConvertTo-SecureString "<DSRM_PASSWORD>" -AsPlainText -Force
Install-ADDSForest `
    -DomainName "lab.local" `
    -DomainNetbiosName "LAB" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns:$true `
    -SafeModeAdministratorPassword $securePassword `
    -Force:$true `
    -NoRebootOnCompletion:$true

# -------- 3. 创建测试域用户 --------
Write-Host "[4/7] 创建域用户..." -ForegroundColor Yellow
# 注意: 域控重启后 AD 才完全可用，以下命令在重启后执行
$scriptBlock = {
    New-ADUser -Name "devuser" -SamAccountName "devuser" `
        -UserPrincipalName "devuser@lab.local" `
        -AccountPassword (ConvertTo-SecureString "<USER_PASSWORD>" -AsPlainText -Force) `
        -Enabled $true -PasswordNeverExpires $true `
        -ErrorAction SilentlyContinue

    New-ADUser -Name "setupadmin" -SamAccountName "setupadmin" `
        -UserPrincipalName "setupadmin@lab.local" `
        -AccountPassword (ConvertTo-SecureString "<ADMIN_PASSWORD>" -AsPlainText -Force) `
        -Enabled $true -PasswordNeverExpires $true `
        -ErrorAction SilentlyContinue

    Add-ADGroupMember -Identity "Domain Admins" -Members "setupadmin" -ErrorAction SilentlyContinue
    Add-ADGroupMember -Identity "Domain Users" -Members "devuser" -ErrorAction SilentlyContinue
}

# 将用户创建脚本注册为开机任务（域控提升后自动执行）
$scriptPath = "C:\vagrant\scripts\create-ad-users.ps1"
$scriptBlock.ToString() | Out-File -FilePath $scriptPath -Encoding UTF8

# -------- 4. 安装 Sysmon --------
Write-Host "[5/7] 安装 Sysmon..." -ForegroundColor Yellow
$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZip = "C:\Windows\Temp\Sysmon.zip"
$sysmonDir = "C:\Windows\Temp\Sysmon"

Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip -ErrorAction SilentlyContinue
Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force -ErrorAction SilentlyContinue

# Sysmon 配置文件（使用 SwiftOnSecurity 社区配置为基础）
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
Write-Host "[6/7] 安装 Winlogbeat..." -ForegroundColor Yellow
$wbUrl = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.11.0-windows-x86_64.zip"
$wbZip = "C:\Windows\Temp\winlogbeat.zip"
$wbDir = "C:\Program Files\Winlogbeat"

if (-not (Test-Path $wbDir)) {
    Invoke-WebRequest -Uri $wbUrl -OutFile $wbZip -ErrorAction SilentlyContinue
    Expand-Archive -Path $wbZip -DestinationPath "C:\Program Files" -Force -ErrorAction SilentlyContinue
    Rename-Item -Path "C:\Program Files\winlogbeat-8.11.0-windows-x86_64" -NewName "Winlogbeat" -ErrorAction SilentlyContinue
}

# Winlogbeat 配置
$winlogbeatConfig = @'
winlogbeat.event_logs:
  - name: Security
    fields:
      log_type: windows_security
      host_role: dc_ad
  - name: System
    fields:
      log_type: windows_system
      host_role: dc_ad
  - name: Microsoft-Windows-Sysmon/Operational
    fields:
      log_type: sysmon
      host_role: dc_ad
  - name: Directory Service
    fields:
      log_type: ad_ds
      host_role: dc_ad
  - name: Microsoft-Windows-PowerShell/Operational
    fields:
      log_type: powershell
      host_role: dc_ad

output.logstash:
  hosts: ["192.168.200.50:5044"]
'@
$winlogbeatConfig | Out-File -FilePath "$wbDir\winlogbeat.yml" -Encoding ASCII

& "$wbDir\install-service-winlogbeat.ps1" -ErrorAction SilentlyContinue
Start-Service winlogbeat -ErrorAction SilentlyContinue

# -------- 7. 配置 Windows 高级防火墙 --------
Write-Host "[7/7] 配置 Windows 防火墙..." -ForegroundColor Yellow

# 默认策略
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block

# 入站：AD DS 服务
New-NetFirewallRule -Name "AD_Kerberos" -Direction Inbound -RemoteAddress 192.168.200.0/24 -LocalPort 88 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -Name "AD_LDAP" -Direction Inbound -RemoteAddress 192.168.200.0/24 -LocalPort 389 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -Name "AD_SMB" -Direction Inbound -RemoteAddress 192.168.200.0/24 -LocalPort 445 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -Name "AD_RPC" -Direction Inbound -RemoteAddress 192.168.200.0/24 -LocalPort 135 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue

# 入站：RDP（soc-node — 实际源 IP 为 ds-internal 接口 192.168.200.50）
New-NetFirewallRule -Name "RDP_Mgmt" -Direction Inbound -RemoteAddress 192.168.200.50 -LocalPort 3389 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue

# 入站：WinRM（soc-node — 实际源 IP 为 ds-internal 接口 192.168.200.50）
New-NetFirewallRule -Name "WinRM_Mgmt" -Direction Inbound -RemoteAddress 192.168.200.50 -LocalPort 5985 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue

# 入站：WinRM / RDP（Vagrant NAT 管理通道 — VirtualBox 默认 10.0.2.0/24）
New-NetFirewallRule -Name "Vagrant_WinRM" -Direction Inbound -RemoteAddress 10.0.2.0/24 -LocalPort 5985 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -Name "Vagrant_RDP" -Direction Inbound -RemoteAddress 10.0.2.0/24 -LocalPort 3389 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue

# 出站：日志转发
New-NetFirewallRule -Name "Logstash_Out" -Direction Outbound -RemoteAddress 192.168.200.50 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue

# 出站：DNS
New-NetFirewallRule -Name "DNS_Out" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " dc-ad 初始化完成！" -ForegroundColor Green
Write-Host " 域: lab.local (NETBIOS: LAB)" -ForegroundColor Green
Write-Host " 角色: AD DS, DNS, Sysmon, Winlogbeat" -ForegroundColor Green
Write-Host " 日志转发: soc-node:5044 (Logstash)" -ForegroundColor Green
Write-Host " 注意: 域控提升后需要重启才能生效！" -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor Green
