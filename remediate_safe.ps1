$ErrorActionPreference='Stop'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$backup = "C:\vibecode\temp6\remediation_backup_$stamp"
New-Item -ItemType Directory -Path $backup -Force | Out-Null
$log = New-Object System.Collections.Generic.List[string]
function Say($m){ Write-Host $m; $log.Add($m) }

Say "[1/5] Backup current values -> $backup"
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "$backup\system.reg" /y | Out-Null
reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "$backup\winlogon.reg" /y | Out-Null
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "$backup\dnsclient.reg" /y 2>$null | Out-Null
(Get-SmbServerConfiguration | Select-Object RequireSecuritySignature) | ConvertTo-Json | Set-Content "$backup\smb_before.json" -Encoding UTF8

Say "[2/5] UAC: EnableLUA=1"
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1 -Type DWord
Say ("      EnableLUA = " + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA).EnableLUA)

Say "[3/5] Auto logon off: AutoAdminLogon=0"
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value '0'
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue
Say ("      AutoAdminLogon = " + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon).AutoAdminLogon)

Say "[4/5] SMB signing required"
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force | Out-Null
Say ("      RequireSecuritySignature = " + (Get-SmbServerConfiguration).RequireSecuritySignature)

Say "[5/5] LLMNR disabled: EnableMulticast=0"
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null }
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 0 -Type DWord
Say ("      EnableMulticast = " + (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast).EnableMulticast)

$log | Set-Content "$backup\apply_log.txt" -Encoding UTF8
Say "DONE. To revert use the .reg files and smb_before.json in $backup"