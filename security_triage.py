"""laya 보안 트리아져: Windows 로컬 설정을 읽기 전용으로 수집한 뒤, laya로 위험도/조치/분류를 판정한다.

laya는 스캐너가 아니라 텍스트 분류기이므로, 실제 점검은 PowerShell(읽기 전용)로 하고
laya는 "이 발견사항이 얼마나 위험하고, 조치가 필요한가"를 판단하는 System 1 레이어로만 쓴다.

사용법:
    python security_triage.py
    python security_triage.py --raw      # laya 판정 없이 수집된 사실만 출력
"""

from __future__ import annotations

import argparse
import json
import subprocess
from typing import Any

import laya

PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$o = [ordered]@{}
$mp = Get-MpComputerStatus
if ($mp) { $o.defender = [ordered]@{ rtp = [bool]$mp.RealTimeProtectionEnabled; av = [bool]$mp.AntivirusEnabled; sigAge = $mp.AntivirusSignatureAge } }
$fw = Get-NetFirewallProfile
if ($fw) { $o.firewall = @($fw | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) }
$s = Get-SmbServerConfiguration
if ($s) { $o.smb1 = [bool]$s.EnableSMB1Protocol; $o.smb2 = [bool]$s.EnableSMB2Protocol; $o.smbSigning = [bool]$s.RequireSecuritySignature }
$o.rdpDeny = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
$o.uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA).EnableLUA
$o.autologon = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon).AutoAdminLogon
$o.llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast).EnableMulticast
$bl = Get-BitLockerVolume
if ($bl) { $o.bitlocker = @($bl | ForEach-Object { "$($_.MountPoint)=$($_.ProtectionStatus)" }) }
$lu = Get-LocalUser
if ($lu) { $o.users = @($lu | ForEach-Object { [ordered]@{ name = $_.Name; enabled = [bool]$_.Enabled; passwordRequired = [bool]$_.PasswordRequired } }) }
$hf = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hf) { $o.lastHotfix = [string]$hf.InstalledOn; $o.lastHotfixId = $hf.HotFixID }
$pref = Get-MpPreference
if ($pref) { $o.defenderExclusions = @($pref.ExclusionPath) }
$o.listenPorts = @(Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique)
$o | ConvertTo-Json -Depth 5
"""

QUESTIONS: dict[str, dict[str, Any]] = {
    "severity": {
        "type": "score",
        "instructions": "How serious is this fact for the security of a personal Windows computer?",
        "criteria": [
            "info: expected or healthy, no risk",
            "low: minor hardening gap",
            "medium: a real weakness worth fixing",
            "high: a serious weakness that exposes the machine",
        ],
    },
    "action": {
        "type": "noul",
        "instructions": "Should the owner fix or change this soon?",
    },
    "category": {
        "type": "choice",
        "instructions": "Which security area does this fact belong to?",
        "criteria": {
            "accounts": "user accounts, passwords, logon, UAC",
            "network": "firewall, SMB, RDP, listening ports, LLMNR",
            "encryption": "disk encryption, secure boot",
            "updates": "patches, signatures, antivirus status",
            "other": "none of the above",
        },
    },
}


def collect() -> dict[str, Any]:
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_SCRIPT],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"PowerShell 수집 실패: {proc.stderr.strip()[:500]}")
    return json.loads(proc.stdout)


def to_findings(data: dict[str, Any]) -> list[str]:
    f: list[str] = []
    d = data.get("defender") or {}
    f.append(
        f"Windows Defender real-time protection is {'on' if d.get('rtp') else 'OFF'}; "
        f"antivirus engine is {'on' if d.get('av') else 'OFF'}."
    )
    f.append(f"Windows Defender signature age is {d.get('sigAge')} day(s).")
    ex = [e for e in (data.get("defenderExclusions") or []) if e]
    f.append(
        ("Windows Defender exclusions are configured: " + ", ".join(map(str, ex)))
        if ex
        else "No Windows Defender exclusions are configured."
    )
    f.append(f"Firewall profile state: {', '.join(data.get('firewall') or ['unknown'])}.")
    f.append(f"SMB1 protocol is {'enabled' if data.get('smb1') else 'disabled'}.")
    f.append(
        f"SMB security signature is {'required' if data.get('smbSigning') else 'NOT required'}."
    )
    f.append(
        "Remote Desktop connections are "
        + ("denied (disabled)." if data.get("rdpDeny") == 1 else "ALLOWED.")
    )
    f.append(
        f"User Account Control (EnableLUA) is set to {data.get('uac')} "
        f"({'enabled' if data.get('uac') == 1 else 'disabled'})."
    )
    f.append(
        "Automatic logon (AutoAdminLogon) is "
        + ("ENABLED." if data.get("autologon") == "1" else "disabled.")
    )
    f.append(
        "LLMNR multicast name resolution is "
        + ("not disabled (default on)." if data.get("llmnr") in (None, "1", 1, "") else "disabled.")
    )
    for v in data.get("bitlocker") or ["unavailable"]:
        f.append(f"BitLocker volume {v}.")
    for u in data.get("users") or []:
        if u.get("enabled"):
            f.append(
                f"Local account '{u.get('name')}' is enabled; "
                f"password required is {bool(u.get('passwordRequired'))}."
            )
    f.append(
        f"Last OS hotfix {data.get('lastHotfixId')} was installed on {data.get('lastHotfix')}."
    )
    ports = data.get("listenPorts") or []
    f.append(f"The machine listens on {len(ports)} TCP port(s): {sorted(set(ports))}.")
    return f


def triage(findings: list[str]) -> list[dict[str, Any]]:
    router = laya.Router(device="cpu", preload=False)
    requests = [{"state": text, "questions": QUESTIONS} for text in findings]
    results = router.predict_batch(requests, batch_size=8)
    rows: list[dict[str, Any]] = []
    for text, res in zip(findings, results):
        a = res["answers"]
        rows.append(
            {
                "finding": text,
                "severity": float(a["severity"]["score"]),
                "severity_legend": a["severity"]["legend"],
                "severity_conf": float(a["severity"]["confidence"]),
                "p_action": float(a["action"]["noul"]),
                "category": a["category"]["choice"],
            }
        )
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="laya 기반 Windows 보안 트리아지")
    ap.add_argument("--raw", action="store_true", help="수집된 사실만 JSON으로 출력")
    args = ap.parse_args()

    data = collect()
    findings = to_findings(data)
    if args.raw:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return

    rows = triage(findings)
    rows.sort(key=lambda r: (r["severity"], r["p_action"]), reverse=True)

    print(f"\n{'#':<3} {'sev':<5} {'P(act)':>7}  {'category':<11} finding")
    print("-" * 100)
    for i, r in enumerate(rows, 1):
        level = str(max(0, min(3, round(r["severity"]))))
        print(
            f"{i:<3} {r['severity']:.2f}  {r['p_action']:>6.2f}  {r['category']:<10} {r['finding']}"
        )
        print(f"      ↳ {r['severity_legend'][level]}")

    actionable = sorted(
        [r for r in rows if r["p_action"] >= 0.5], key=lambda x: -x["severity"]
    )
    print(f"\n조치 필요(P(act)>=0.5): {len(rows)}건 중 {len(actionable)}건")
    for r in actionable:
        print(f"  - [{r['severity']:.2f}] {r['category']:<10} {r['finding']}")


if __name__ == "__main__":
    main()