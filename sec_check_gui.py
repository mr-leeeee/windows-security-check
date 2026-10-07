"""Windows 보안 점검 GUI (규칙 기반, Windows/CIS 베이스라인 참고).

PowerShell로 로컬 보안 설정을 읽기 전용 수집한 뒤 각 항목을 양호/위험/주의/낮음/확인불가로
평가한다. 각 항목은 '왜 위험한가(평가)'와 '단계별 해결 방법'을 함께 제공하고, 전체에 대한
'종합 평가'를 생성한다. 표준 라이브러리만 사용하므로 PyInstaller로 단일 .exe를 만들어
다른 Windows PC(Python 불필요)에서 실행할 수 있다.

실행:   python sec_check_gui.py
테스트: python -m unittest test_sec_check -v
빌드:   pyinstaller --onefile --windowed --uac-admin --name WindowsSecurityCheck sec_check_gui.py
"""

from __future__ import annotations

import datetime as dt
import html
import json
import subprocess
import threading
import tkinter as tk
from dataclasses import dataclass, field
from tkinter import filedialog, messagebox, ttk

CREATE_NO_WINDOW = 0x08000000

PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$o = [ordered]@{}
$o.host = $env:COMPUTERNAME
$o.isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$os = Get-CimInstance Win32_OperatingSystem
if ($os) { $o.osCaption = $os.Caption; $o.osBuild = $os.BuildNumber }

$mp = Get-MpComputerStatus
if ($mp) { $o.defender = [ordered]@{ rtp = [bool]$mp.RealTimeProtectionEnabled; av = [bool]$mp.AntivirusEnabled; sigAge = $mp.AntivirusSignatureAge } }
$pref = Get-MpPreference
if ($pref) { $o.defenderExclusions = @(@($pref.ExclusionPath) + @($pref.ExclusionExtension) + @($pref.ExclusionProcess) | Where-Object { $_ -and $_ -notmatch 'Must be an administrator' }) }

$fw = Get-NetFirewallProfile
if ($fw) { $o.firewall = @($fw | ForEach-Object { [ordered]@{ name = $_.Name; enabled = [bool]$_.Enabled } }) }

$s = Get-SmbServerConfiguration
if ($s) { $o.smb1 = [bool]$s.EnableSMB1Protocol; $o.smbSigning = [bool]$s.RequireSecuritySignature }

$o.rdpDeny = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
$o.uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA).EnableLUA
$o.autologon = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon).AutoAdminLogon
$o.llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast).EnableMulticast

if ($o.isAdmin) {
  $bl = Get-BitLockerVolume
  if ($bl) { $o.bitlockerSupported = $true; $o.bitlocker = @($bl | ForEach-Object { [ordered]@{ mount = $_.MountPoint; protection = "$($_.ProtectionStatus)" } }) }
  else { $o.bitlockerSupported = $false; $o.bitlocker = @() }
} else { $o.bitlockerSupported = $null; $o.bitlocker = @() }

$lu = Get-LocalUser
if ($lu) { $o.users = @($lu | ForEach-Object { [ordered]@{ name = $_.Name; enabled = [bool]$_.Enabled; passwordRequired = [bool]$_.PasswordRequired; sid = $_.SID.Value } }) }

$hf = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hf) { $o.lastHotfixId = $hf.HotFixID; $o.lastHotfix = $hf.InstalledOn.ToString('yyyy-MM-dd') }

$o.pendingReboot = [bool](Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
$o.listenPorts = @(Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique)
$o | ConvertTo-Json -Depth 6
"""

ORDER_KEY = {"높음": 0, "중간": 1, "낮음": 2, "양호": 3, "정보": 4, "확인불가": 5}
ROW_COLOR = {"높음": "#ffd6d6", "중간": "#ffe9cc", "낮음": "#fff9cc", "양호": "#daf5df", "정보": "#eef2f7", "확인불가": "#ececec"}
SENSITIVE_PORTS = {21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB",
                   1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5985: "WinRM", 6379: "Redis", 27017: "MongoDB"}


@dataclass
class Result:
    title: str
    status: str          # 양호 / 위험 / 주의 / 낮음 / 정보 / 확인불가
    severity: str        # 높음 / 중간 / 낮음 / 정보
    detail: str
    fix: str = ""
    category: str = ""
    why: str = ""                       # 평가: 왜 위험/중요한가
    steps: tuple[str, ...] = field(default_factory=tuple)  # 단계별 해결 방법


def _ok(title: str, detail: str, category: str) -> Result:
    return Result(title, "양호", "정보", detail, category=category)


def _bad(status: str, severity: str, title: str, detail: str, category: str,
         why: str = "", steps: tuple[str, ...] = (), fix: str = "") -> Result:
    return Result(title, status, severity, detail, fix, category, why, steps)


# --------------------------------------------------------------------------- checks
def check_uac(d: dict) -> Result:
    v = d.get("uac")
    if v is None:
        return _bad("확인불가", "정보", "사용자 계정 컨트롤(UAC)", "UAC 값을 읽지 못했습니다.", "계정", "", ("관리자 권한으로 프로그램을 다시 실행하세요.",))
    if v == 1:
        return _ok("사용자 계정 컨트롤(UAC)", "UAC가 켜져 있습니다.", "계정")
    return _bad(
        "위험", "높음", "사용자 계정 컨트롤(UAC)",
        f"UAC가 꺼져 있습니다 (EnableLUA={v}). 권한 상승이 동의 없이 조용히 실행됩니다.", "계정",
        why="UAC가 꺼져 있으면 악성코드가 '관리자 권한을 허용하시겠습니까?' 확인 없이 관리자 권한을 획득해 시스템 전체를 장악할 수 있습니다.",
        steps=(
            "Win+R → 'UserAccountControlSettings.exe' 실행 (또는 시작 메뉴에서 'UAC' 검색)",
            "슬라이더를 '기본값(Default)' 이상으로 올리고 확인",
            "재부팅하면 적용됩니다",
            "명령으로 하려면 관리자 PowerShell에서: Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1",
        ), fix="UAC 슬라이더를 기본값 이상으로, 또는 EnableLUA=1")


def check_autologon(d: dict) -> Result:
    v = d.get("autologon")
    if v is None:
        return _bad("확인불가", "정보", "자동 로그온", "값을 읽지 못했습니다.", "계정", "", ("관리자 권한으로 프로그램을 다시 실행하세요.",))
    if str(v) != "1":
        return _ok("자동 로그온", "자동 로그온이 꺼져 있습니다.", "계정")
    return _bad(
        "위험", "높음", "자동 로그온",
        "자동 로그온(AutoAdminLogon=1)이 켜져 있습니다. 부팅 시 로그인 없이 진입되고 자격증명이 레지스트리에 남을 수 있습니다.", "계정",
        why="부팅 시 암호 없이 자동 로그인되면, 노트북을 분실하거나 물리적으로 접근한 사람이 곧바로 바탕화면에 들어옵니다. 또한 Winlogon 레지스트리에 자격증명이 평문에 가깝게 남을 수 있습니다.",
        steps=(
            "Win+R → 'netplwiz' 실행",
            "'사용자가 사용자 이름과 암호를 입력해야 합니다' 체크박스를 체크하고 확인",
            "명령으로 하려면: Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value '0'  후  Remove-ItemProperty '...\\Winlogon' -Name DefaultPassword",
            "재부팅해 로그인 화면이 뜨는지 확인",
        ), fix="AutoAdminLogon=0 및 DefaultPassword 제거")


def check_password_required(d: dict) -> Result:
    users = [u for u in (d.get("users") or []) if u.get("enabled")]
    if not users:
        return _bad("확인불가", "정보", "암호 요구 계정", "활성 계정 정보를 읽지 못했습니다.", "계정", "", ("관리자 권한으로 프로그램을 다시 실행하세요.",))
    nopw = [u["name"] for u in users if u.get("passwordRequired") is False]
    if not nopw:
        return _ok("암호 요구 계정", "활성 계정 모두 암호를 요구합니다.", "계정")
    return _bad(
        "위험", "높음", "암호 요구 계정",
        f"암호를 요구하지 않는 활성 계정: {', '.join(nopw)}", "계정",
        why="암호 없는 계정은 물리적 접근자나 원격 공격자가 인증 없이 로그인할 수 있습니다. 특히 자동 로그온과 겹치면 곧바로 관리자 세션까지 이어질 수 있습니다.",
        steps=(
            f"해당 계정에 암호 설정: 관리자 PowerShell에서  net user {nopw[0]} *  실행 후 새 암호 2회 입력",
            "또는 설정 > 계정 > 로그인 옵션에서 암호 추가",
            "최소 12자 이상 + 대·소문자·숫자·기호 조합 권장",
        ), fix="해당 계정에 강한 암호 설정")


def _sid_user(d: dict, suffix: str) -> dict | None:
    for u in d.get("users") or []:
        if str(u.get("sid") or "").endswith(suffix):
            return u
    return None


def check_guest(d: dict) -> Result:
    g = _sid_user(d, "-501")
    if not g or not g.get("enabled"):
        return _ok("Guest 계정", "Guest 계정이 비활성입니다.", "계정")
    return _bad(
        "위험", "높음", "Guest 계정", "Guest 계정이 활성화되어 있습니다.", "계정",
        why="Guest 계정은 인증 없이 시스템에 접근할 수 있어 불필요한 공격 표면이 되고, 파일·공유에 무단 접근 경로가 됩니다.",
        steps=(
            "관리자 PowerShell에서: net user guest /active:no",
            "또는 lusrmgr.msc → 사용자 → Guest 우클릭 → 속성 → '계정 사용 안 함'",
        ), fix="Guest 계정 비활성화")


def check_builtin_admin(d: dict) -> Result:
    a = _sid_user(d, "-500")
    if not a or not a.get("enabled"):
        return _ok("내장 Administrator", "내장 Administrator가 비활성입니다.", "계정")
    return _bad(
        "주의", "중간", "내장 Administrator", "내장 Administrator 계정이 활성입니다.", "계정",
        why="이름이 알려진 내장 관리자 계정은 무차별 대입 공격의 1순위 표적입니다. 개별 관리자 계정을 쓰는 편이 안전합니다.",
        steps=(
            "관리자 PowerShell에서: net user Administrator /active:no",
            "개별 관리자 계정(예: 본인 계정)을 관리자 그룹에 유지해 사용",
        ), fix="내장 Administrator 비활성화")


def check_bitlocker(d: dict) -> Result:
    if d.get("isAdmin") is not True:
        return _bad("확인불가", "정보", "디스크 암호화(BitLocker)", "관리자 권한이 없어 확인하지 못했습니다.", "암호화", "", ("관리자 권한으로 프로그램을 다시 실행하세요.",))
    if d.get("bitlockerSupported") is False:
        return _bad("확인불가", "정보", "디스크 암호화(BitLocker)", "BitLocker를 사용할 수 없습니다(Home 등).", "암호화", "Windows Home 에디션은 BitLocker가 없습니다. Pro 이상에서 사용 가능합니다.", ("Windows Pro/Enterprise로 업그레이드하거나 VeraCrypt 같은 대안을 검토하세요.",))
    vols = d.get("bitlocker") or []
    if not vols:
        return _bad("확인불가", "정보", "디스크 암호화(BitLocker)", "볼륨 정보를 읽지 못했습니다.", "암호화", "", ("관리자 권한으로 프로그램을 다시 실행하세요.",))
    off = [v.get("mount", "?") for v in vols if v.get("protection") != "On"]
    if not off:
        return _ok("디스크 암호화(BitLocker)", "모든 볼륨이 암호화되어 있습니다.", "암호화")
    return _bad(
        "주의", "중간", "디스크 암호화(BitLocker)",
        f"암호화되지 않은 볼륨: {', '.join(off)}. 디스크 도난 시 데이터가 노출됩니다.", "암호화",
        why="디스크가 암호화되지 않으면 노트북을 도난당하거나 디스크를 분리했을 때, 로그인 암호와 무관하게 파일 전체를 읽을 수 있습니다.",
        steps=(
            "TPM 존재 확인: 관리자 PowerShell에서 Get-Tpm (TPM 있으면 자동 잠금 해제 가능)",
            "복구키 백업 수단 확보(USB 저장 / Azure AD / 인쇄) — 반드시 PC 외부에 보관",
            "암호화 시작: Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector",
            "진행 확인: Get-BitLockerVolume  (ProtectionStatus=On 이면 완료)",
            "복구키 확인: (Get-BitLockerVolume -MountPoint C:).KeyProtector",
        ), fix="BitLocker로 볼륨 암호화 (복구키 백업 필수)")


def check_smb1(d: dict) -> Result:
    v = d.get("smb1")
    if v is None:
        return _bad("확인불가", "정보", "SMB1 프로토콜", "SMB 설정을 읽지 못했습니다.", "네트워크", "", ("관리자 권한으로 프로그램을 다시 실행하세요.",))
    if v is False:
        return _ok("SMB1 프로토콜", "SMB1이 꺼져 있습니다.", "네트워크")
    return _bad(
        "위험", "높음", "SMB1 프로토콜", "SMB1이 켜져 있습니다. 랜섬웨어·웜 공격 표면이 됩니다.", "네트워크",
        why="SMB1은 EternalBlue/WannaCry 등 심각한 취약점이 반복적으로 발견된 구식 프로토콜로, 켜져 있으면 랜섬웨어·웜에 감염되고 네트워크로 확산될 위험이 큽니다.",
        steps=(
            "관리자 PowerShell에서: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
            "요청 시 재부팅",
            "확인: Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol  (False 이면 해제됨)",
        ), fix="SMB1 기능 제거")


def check_smb_signing(d: dict) -> Result:
    v = d.get("smbSigning")
    if v is None:
        return _bad("확인불가", "정보", "SMB 서명", "SMB 설정을 읽지 못했습니다.", "네트워크", "", ("관리자 권한으로 프로그램을 다시 실행하세요.",))
    if v is True:
        return _ok("SMB 서명", "SMB 보안 서명이 요구됩니다.", "네트워크")
    return _bad(
        "주의", "중간", "SMB 서명", "SMB 보안 서명이 요구되지 않습니다. NTLM 릴레이에 노출될 수 있습니다.", "네트워크",
        why="SMB 서명이 없으면 공격자가 중간에서 인증(NTLM)을 가로채 다른 서버로 릴레이해 관리자 권한을 탈취할 수 있습니다.",
        steps=(
            "서버 측: Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
            "클라이언트 측(선택): Set-SmbClientConfiguration -RequireSecuritySignature $true -Force",
            "확인: Get-SmbServerConfiguration | Select RequireSecuritySignature",
        ), fix="SMB 보안 서명 요구")


def check_rdp(d: dict) -> Result:
    v = d.get("rdpDeny")
    if v is None:
        return _bad("확인불가", "정보", "원격 데스크톱(RDP)", "값을 읽지 못했습니다.", "네트워크", "", ("관리자 권한으로 프로그램을 다시 실행하세요.",))
    if v == 1:
        return _ok("원격 데스크톱(RDP)", "RDP 연결이 차단되어 있습니다.", "네트워크")
    return _bad(
        "주의", "중간", "원격 데스크톱(RDP)", "RDP가 허용되어 있습니다. 자격증명 공격 표면이 됩니다.", "네트워크",
        why="RDP가 열려 있으면 인터넷에서 무차별 대입·취약점 공격의 표적이 됩니다. BlueKeep 같은 원격 코드 실행 취약점의 통로이기도 합니다.",
        steps=(
            "불필요하면 끄기: 설정 > 시스템 > 원격 데스크톱 → 끔",
            "명령: Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1",
            "꼭 필요하면: NLA(네트워크 수준 인증) 필수 + 계정 잠금 정책 + 방화벽에서 허용 IP만 제한",
        ), fix="RDP 비활성화(필요 시 NLA·방화벽 제한)")


def check_firewall(d: dict) -> Result:
    fw = d.get("firewall") or []
    if not fw:
        return _bad("확인불가", "정보", "방화벽", "방화벽 상태를 읽지 못했습니다.", "네트워크", "", ("관리자 권한으로 프로그램을 다시 실행하세요.",))
    off = [x.get("name", "?") for x in fw if not x.get("enabled")]
    if not off:
        return _ok("방화벽", "모든 프로필에서 방화벽이 켜져 있습니다.", "네트워크")
    return _bad(
        "위험", "높음", "방화벽", f"꺼진 방화벽 프로필: {', '.join(off)}", "네트워크",
        why="방화벽이 꺼진 프로필에서는 외부에서 들어오는 연결이 필터링되지 않아, 열려 있는 서비스가 그대로 공격에 노출됩니다.",
        steps=(
            "모든 프로필 켜기: Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
            "확인: Get-NetFirewallProfile | Select Name,Enabled",
        ), fix="모든 프로필 방화벽 활성화")


def check_llmnr(d: dict) -> Result:
    v = d.get("llmnr")
    if v is None:
        return _ok("LLMNR", "LLMNR이 꺼져 있습니다.", "네트워크")
    if str(v) == "0":
        return _ok("LLMNR", "LLMNR이 꺼져 있습니다.", "네트워크")
    return _bad(
        "낮음", "낮음", "LLMNR", "LLMNR이 활성(기본값)입니다. 로컬 네트워크에서 이름 스푸핑에 악용될 수 있습니다.", "네트워크",
        why="LLMNR은 같은 네트워크의 공격자(Responder 등)가 응답을 위조해 사용자의 NTLM 해시를 탈취하는 데 악용됩니다. 회사/공용 네트워크에서 특히 위험합니다.",
        steps=(
            "gpedit.msc → 컴퓨터 구성 > 관리 템플릿 > 네트워크 > DNS 클라이언트",
            "'멀티캐스트 이름 확인 끄기' 정책을 '사용'으로 설정",
            "명령으로 하려면: New-Item 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force; Set-ItemProperty '...\\DNSClient' -Name EnableMulticast -Value 0",
        ), fix="LLMNR 비활성(EnableMulticast=0)")


def check_defender_rtp(d: dict) -> Result:
    dd = d.get("defender") or {}
    if not dd:
        return _bad("확인불가", "정보", "백신 실시간 보호", "Defender 상태를 읽지 못했습니다.", "악성코드", "", ("타사 백신을 사용 중이면 정상일 수 있습니다.",))
    if dd.get("rtp"):
        return _ok("백신 실시간 보호", "Defender 실시간 보호가 켜져 있습니다.", "악성코드")
    return _bad(
        "위험", "높음", "백신 실시간 보호", "실시간 보호가 꺼져 있습니다.", "악성코드",
        why="실시간 보호가 꺼지면 악성코드가 실행되고 파일을 암호화하는 순간에도 차단되지 않습니다.",
        steps=(
            "Windows 보안 > 바이러스 및 위협 방지 > 실시간 보호 켜기",
            "명령: Set-MpPreference -DisableRealtimeMonitoring $false",
            "타사 백신을 쓰는 경우 중복 방지를 위해 하나만 활성화",
        ), fix="Defender 실시간 보호 활성화")


def check_signature_age(d: dict) -> Result:
    age = (d.get("defender") or {}).get("sigAge")
    if not isinstance(age, int) or isinstance(age, bool):
        return _bad("확인불가", "정보", "백신 시그니처", "시그니처 나이를 읽지 못했습니다.", "업데이트", "", ("타사 백신 사용 중이면 해당 백신의 업데이트 상태를 확인하세요.",))
    if age <= 7:
        return _ok("백신 시그니처", f"시그니처가 최신입니다 ({age}일).", "업데이트")
    return _bad(
        "주의", "중간", "백신 시그니처", f"시그니처가 오래되었습니다 ({age}일).", "업데이트",
        why="시그니처(정의)가 오래되면 최근에 등장한 악성코드를 인식하지 못해 탐지율이 떨어집니다.",
        steps=(
            "정의 업데이트: Update-MpSignature",
            "또는 설정 > Windows Update > 업데이트 확인",
            "확인: Get-MpComputerStatus | Select AntivirusSignatureAge",
        ), fix="백신 시그니처 업데이트")


def check_exclusions(d: dict) -> Result:
    if d.get("isAdmin") is not True:
        return _bad("확인불가", "정보", "백신 예외 경로", "관리자 권한이 없어 확인하지 못했습니다.", "악성코드", "", ("관리자 권한으로 프로그램을 다시 실행하세요.",))
    ex = [e for e in (d.get("defenderExclusions") or []) if e]
    if not ex:
        return _ok("백신 예외 경로", "Defender 예외가 없습니다.", "악성코드")
    return _bad(
        "주의", "중간", "백신 예외 경로", f"Defender 예외가 설정되어 있습니다: {', '.join(map(str, ex))}", "악성코드",
        why="공격자는 Defender 제외 경로에 악성코드를 숨겨 탐지를 우회하는 경우가 많습니다. 정당한 예외라도 최소화해야 합니다.",
        steps=(
            "Windows 보안 > 바이러스 및 위협 방지 > 설정 관리 > 제외 항목",
            "불필요한 경로/확장자/프로세스 제외 제거",
            "명령: Remove-MpPreference -ExclusionPath 'C:\\경로'  (또는 -ExclusionExtension / -ExclusionProcess)",
        ), fix="불필요한 Defender 예외 제거")


def check_patch(d: dict) -> Result:
    hot = d.get("lastHotfix")
    age_days = None
    if hot:
        try:
            age_days = (dt.date.today() - dt.datetime.strptime(hot, "%Y-%m-%d").date()).days
        except ValueError:
            age_days = None
    if age_days is None:
        return _bad("확인불가", "정보", "최근 보안 패치", "설치 이력을 읽지 못했습니다.", "업데이트", "", ("설정 > Windows Update에서 직접 확인하세요.",))
    if age_days <= 35:
        return _ok("최근 보안 패치", f"최근 패치({d.get('lastHotfixId')})가 {hot}에 설치되었습니다.", "업데이트")
    return _bad(
        "주의", "중간", "최근 보안 패치", f"최근 패치가 {hot}({age_days}일 전)입니다.", "업데이트",
        why="패치가 오래 미뤄지면 이미 공개된 취약점(CVE)에 그대로 노출됩니다. 공격 도구가 공개되어 있는 경우가 많습니다.",
        steps=(
            "설정 > Windows Update > 업데이트 확인 → 설치",
            "재부팅해 마무리",
            "확인: Get-HotFix | Sort InstalledOn -Descending | Select -First 1",
        ), fix="Windows Update 실행 후 재부팅")


def check_pending_reboot(d: dict) -> Result:
    if d.get("pendingReboot"):
        return _bad("정보", "정보", "재부팅 대기", "재부팅 대기 중인 업데이트가 있습니다.", "업데이트",
                    why="재부팅 전까지는 일부 보안 패치가 완전히 적용되지 않습니다.",
                    steps=("데이터를 저장하고 재부팅하세요.",), fix="가능한 시점에 재부팅")
    return _ok("재부팅 대기", "재부팅 대기 항목이 없습니다.", "업데이트")


def check_ports(d: dict) -> Result:
    ports = sorted(set(d.get("listenPorts") or []))
    sensitive = sorted(p for p in ports if p in SENSITIVE_PORTS)
    detail = f"{len(ports)}개 포트 리슨: {ports}"
    if sensitive:
        names = ", ".join(f"{p}({SENSITIVE_PORTS[p]})" for p in sensitive)
        detail += f"  |  주의 대상 서비스 포트: {names}"
    return Result("리스닝 TCP 포트", "정보", "정보", detail, "", "네트워크")


CHECKS = [
    check_uac, check_autologon, check_password_required, check_guest, check_builtin_admin,
    check_bitlocker, check_smb1, check_smb_signing, check_rdp, check_firewall, check_llmnr,
    check_defender_rtp, check_signature_age, check_exclusions, check_patch, check_pending_reboot,
    check_ports,
]


def run_checks(data: dict) -> list[Result]:
    return [fn(data) for fn in CHECKS]


def baseline(results: list[Result]) -> tuple[int, str, dict]:
    counts = {s: sum(1 for x in results if x.status == s) for s in ("위험", "주의", "낮음", "양호", "정보", "확인불가")}
    judged = [x for x in results if x.status in ("양호", "위험", "주의", "낮음")]
    passed = sum(1 for x in judged if x.status == "양호")
    rate = round(100 * passed / len(judged)) if judged else 100
    grade = "A" if rate >= 90 else "B" if rate >= 75 else "C" if rate >= 60 else "D" if rate >= 40 else "F"
    return rate, grade, counts


def assess(results: list[Result]) -> str:
    """전체에 대한 사람이 읽는 종합 평가 문단."""
    issues = sorted((x for x in results if x.status in ("위험", "주의", "낮음")),
                    key=lambda r: ORDER_KEY.get(r.severity, 9))
    rate, grade, c = baseline(results)
    if not issues:
        return (f"종합 평가: 베이스라인 통과율 {rate}%(등급 {grade}). 확인된 위험/주의 항목이 없습니다. "
                f"양호 {c['양호']}건, 확인불가 {c['확인불가']}건.")
    head = f"종합 평가: 베이스라인 통과율 {rate}%(등급 {grade}). 개선이 필요한 항목 {len(issues)}건"
    if c["위험"]:
        head += f" (위험 {c['위험']}건 포함)"
    head += ". "
    order = "우선 조치 순서: " + " → ".join(f"{i+1}) {x.title}" for i, x in enumerate(issues[:4]))
    if len(issues) > 4:
        order += f" 외 {len(issues) - 4}건"
    tips = []
    if any(x.title.startswith("암호") or x.title == "자동 로그온" or x.title == "UAC" for x in issues):
        tips.append("계정·권한 항목은 즉시 조치를 권장합니다.")
    if any(x.title == "최근 보안 패치" for x in issues):
        tips.append("패치 후에는 반드시 재부팅하세요.")
    return head + order + (". " + " ".join(tips) if tips else ".")


# --------------------------------------------------------------------------- collect
def collect(on_proc=None, timeout: float = 120.0) -> dict:
    proc = subprocess.Popen(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_SCRIPT],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
        creationflags=CREATE_NO_WINDOW,
    )
    if on_proc:
        on_proc(proc)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise RuntimeError("수집 시간이 초과되었습니다(120초). PowerShell 응답 없음.")
    if proc.returncode != 0 or not out.strip():
        raise RuntimeError((err or "").strip()[:400] or "PowerShell 수집 실패(취소 또는 오류)")
    return json.loads(out)


# --------------------------------------------------------------------------- GUI
class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Windows 보안 점검")
        self.geometry("1120x780")
        self.minsize(900, 600)
        self.configure(bg="#f5f6f8")
        self.results: list[Result] = []
        self.data: dict = {}
        self._proc: subprocess.Popen | None = None
        self._by_item: dict[str, Result] = {}
        self._build()

    def _build(self) -> None:
        top = tk.Frame(self, bg="#f5f6f8", padx=14, pady=12)
        top.pack(fill="x")
        tk.Label(top, text="Windows 보안 점검", font=("Malgun Gothic", 17, "bold"), bg="#f5f6f8").pack(side="left")
        self.cancel_btn = tk.Button(top, text="취소", command=self.cancel, state="disabled", font=("Malgun Gothic", 10),
                                    bg="#e6e9ef", relief="flat", padx=12, pady=4)
        self.cancel_btn.pack(side="right", padx=8)
        self.btn = tk.Button(top, text="점검 시작", command=self.start, font=("Malgun Gothic", 11, "bold"),
                             bg="#2f6fed", fg="white", activebackground="#1f4fb8", relief="flat", padx=18, pady=4)
        self.btn.pack(side="right")
        self.export_btn = tk.Button(top, text="HTML 보고서 저장", command=self.export_html, state="disabled",
                                    font=("Malgun Gothic", 10), bg="#e6e9ef", relief="flat", padx=12, pady=4)
        self.export_btn.pack(side="right", padx=8)

        self.banner = tk.Label(self, text="", anchor="w", bg="#fff4e5", fg="#8a5a00", font=("Malgun Gothic", 10), padx=10)
        self.status = tk.Label(self, text="준비됨", anchor="w", bg="#f5f6f8", fg="#444", font=("Malgun Gothic", 10))
        self.status.pack(fill="x", padx=14)
        self.bar = ttk.Progressbar(self, mode="indeterminate")
        self.bar.pack(fill="x", padx=14, pady=6)
        self.summary = tk.Label(self, text="", anchor="w", bg="#f5f6f8", font=("Malgun Gothic", 12, "bold"))
        self.summary.pack(fill="x", padx=14, pady=(0, 6))

        cols = ("severity", "status", "category", "title", "detail")
        headings = {"severity": "심각도", "status": "상태", "category": "분류", "title": "항목", "detail": "상세"}
        widths = {"severity": 60, "status": 70, "category": 70, "title": 200, "detail": 740}
        frame = tk.Frame(self, bg="#f5f6f8")
        frame.pack(fill="both", expand=True, padx=14)
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", height=12)
        for c in cols:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=widths[c], anchor="w", stretch=(c == "detail"))
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        for sev, color in ROW_COLOR.items():
            self.tree.tag_configure(sev, background=color)
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)

        tk.Label(self, text="선택한 항목의 평가 · 해결 방법", anchor="w", bg="#f5f6f8",
                 font=("Malgun Gothic", 10, "bold")).pack(fill="x", padx=14, pady=(8, 2))
        self.detail = tk.Text(self, height=9, wrap="word", font=("Malgun Gothic", 10), bg="#ffffff",
                              relief="flat", borderwidth=1, padx=8, pady=6)
        self.detail.pack(fill="both", padx=14, pady=(0, 12))
        self.detail.configure(state="disabled")

    def start(self) -> None:
        self.btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.export_btn.configure(state="disabled")
        self.banner.pack_forget()
        self.tree.delete(*self.tree.get_children())
        self._by_item.clear()
        self.summary.configure(text="")
        self._set_detail("")
        self.status.configure(text="수집 중...")
        self.bar.start(12)
        threading.Thread(target=self._work, daemon=True).start()

    def cancel(self) -> None:
        self.status.configure(text="취소 중...")
        if self._proc is not None:
            try:
                self._proc.kill()
            except Exception:  # noqa: BLE001 - best effort
                pass

    def _work(self) -> None:
        try:
            data = collect(on_proc=lambda p: setattr(self, "_proc", p))
            results = run_checks(data)
        except Exception as exc:  # noqa: BLE001 - surface any failure
            self.after(0, self._fail, str(exc))
            return
        self.after(0, self._render, data, results)

    def _fail(self, msg: str) -> None:
        self.bar.stop()
        self.btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled")
        self.status.configure(text="오류")
        messagebox.showerror("점검 실패", msg)

    def _set_detail(self, text: str) -> None:
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        if text:
            self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def _show_detail(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        x = self._by_item.get(sel[0])
        if not x:
            return
        lines = [f"■ {x.title}  [{x.severity}/{x.status}]  ({x.category})", "", f"· 현황: {x.detail}"]
        if x.why:
            lines += ["", f"· 평가(왜 중요한가): {x.why}"]
        if x.steps:
            lines += ["", "· 해결 방법:"]
            lines += [f"   {i+1}) {s}" for i, s in enumerate(x.steps)]
        elif x.status == "양호":
            lines += ["", "· 조치 불필요 (양호)"]
        self._set_detail("\n".join(lines))

    def _work_done(self) -> None:
        self.bar.stop()
        self.btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled")

    def _render(self, data: dict, results: list[Result]) -> None:
        self._work_done()
        self.export_btn.configure(state="normal")
        self.data, self.results = data, results
        for x in sorted(results, key=lambda r: (ORDER_KEY.get(r.severity, 9), ORDER_KEY.get(r.status, 9))):
            iid = self.tree.insert("", "end", values=(x.severity, x.status, x.category, x.title, x.detail), tags=(x.severity,))
            self._by_item[iid] = x
        rate, grade, c = baseline(results)
        self.summary.configure(
            text=f"베이스라인 통과율 {rate}% (등급 {grade})   ·   위험 {c['위험']} · 주의 {c['주의']} · 낮음 {c['낮음']} · 양호 {c['양호']} · 확인불가 {c['확인불가']}"
        )
        self.status.configure(text=f"{data.get('host', '?')} · {data.get('osCaption', '')} (빌드 {data.get('osBuild', '?')})")
        if data.get("isAdmin") is not True:
            self.banner.configure(text="⚠ 관리자 권한이 아닙니다. BitLocker/Defender 제외 항목은 '확인불가'로 표시됩니다.")
            self.banner.pack(fill="x", padx=14, pady=(2, 0))
        self._set_detail(assess(results))

    def export_html(self) -> None:
        if not self.results:
            return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")],
                                            initialfile="security_report.html")
        if not path:
            return
        rate, grade, c = baseline(self.results)
        ordered = sorted(self.results, key=lambda r: (ORDER_KEY.get(r.severity, 9), ORDER_KEY.get(r.status, 9)))
        rows = "\n".join(
            f"<tr style='background:{ROW_COLOR.get(x.severity, '#fff')}'>"
            f"<td>{html.escape(x.severity)}</td><td>{html.escape(x.status)}</td><td>{html.escape(x.category)}</td>"
            f"<td>{html.escape(x.title)}</td><td>{html.escape(x.detail)}</td></tr>"
            for x in ordered
        )
        blocks = []
        for x in ordered:
            if x.status == "양호":
                continue
            parts = [f"<h3>{html.escape(x.title)} <small>[{html.escape(x.severity)}/{html.escape(x.status)}]</small></h3>",
                     f"<p><b>현황:</b> {html.escape(x.detail)}</p>"]
            if x.why:
                parts.append(f"<p><b>평가:</b> {html.escape(x.why)}</p>")
            if x.steps:
                items = "".join(f"<li>{html.escape(s)}</li>" for s in x.steps)
                parts.append(f"<p><b>해결 방법:</b></p><ol>{items}</ol>")
            blocks.append("".join(parts))
        details = "\n".join(blocks) or "<p>개선이 필요한 항목이 없습니다.</p>"
        doc = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>Windows 보안 점검 보고서</title>
<style>
 body{{font-family:'Malgun Gothic',sans-serif;margin:24px;color:#222;line-height:1.5}}
 h1{{font-size:20px}} h3{{font-size:15px;margin:16px 0 4px;border-left:4px solid #2f6fed;padding-left:8px}}
 .meta{{color:#666;margin-bottom:8px}} .assess{{background:#f0f4ff;border:1px solid #cdd9f5;padding:10px 12px;border-radius:6px;margin:10px 0}}
 table{{border-collapse:collapse;width:100%;font-size:13px;margin-top:10px}}
 th,td{{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}}
 th{{background:#2f6fed;color:#fff}} small{{color:#666;font-weight:normal}}
</style></head><body>
<h1>Windows 보안 점검 보고서</h1>
<div class="meta">호스트: {html.escape(str(self.data.get('host','?')))} · {html.escape(str(self.data.get('osCaption', '')))}
 (빌드 {html.escape(str(self.data.get('osBuild', '?')))}) · 생성 {dt.datetime.now():%Y-%m-%d %H:%M}</div>
<div class="meta">베이스라인 통과율 <b>{rate}%</b> (등급 {grade}) · 위험 {c['위험']} · 주의 {c['주의']} · 낮음 {c['낮음']} · 양호 {c['양호']} · 확인불가 {c['확인불가']}</div>
<div class="assess">{html.escape(assess(self.results))}</div>
<table><thead><tr><th>심각도</th><th>상태</th><th>분류</th><th>항목</th><th>상세</th></tr></thead>
<tbody>{rows}</tbody></table>
<h2>상세 평가 및 해결 방법</h2>
{details}</body></html>"""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(doc)
        messagebox.showinfo("저장 완료", f"보고서를 저장했습니다:\n{path}")


def main() -> None:
    App().mainloop()


if __name__ == "__main__":
    main()