# Windows Security Check (WindowsSecurityCheck)

로컬 Windows PC의 보안 설정을 **읽기 전용**으로 점검하고, 항목별 **평가(왜 중요한가)**와
**단계별 해결 방법**, 그리고 **종합 평가**를 제공하는 단일 실행 GUI 도구입니다.

- Python + Tkinter(표준 라이브러리)로 작성 → PyInstaller 단일 `.exe`
- 점검 외에는 아무것도 하지 않음. **쓰기/전송 없음**(진단은 레지스트리·WMI 조회만)
- 관리자 권한으로 실행하면 BitLocker / Defender 예외까지 점검
- 결과를 **HTML 보고서**로 저장(종합 평가 + 항목별 평가/해결 방법 포함)

---

## 왜 만들었나

기존에는 laya(Ollama)로 심각도를 판정했지만, laya는 보안 스캐너가 아니어서
**오탐/오판**(예: UAC 꺼짐을 "낮음", RDP 차단을 "위험")이 잦았습니다.
그래서 **규칙 기반(Windows/CIS 참고)**으로 전면 재작성했고, 점수도 발명 지표 대신
**베이스라인 통과율(%)**로 계산합니다.

---

## 점검 항목 (17개)

| 분류 | 항목 | 심각도 |
|---|---|---|
| 계정 | 사용자 계정 컨트롤(UAC) | 높음 |
| 계정 | 자동 로그온 | 높음 |
| 계정 | 암호 없는 계정 | 높음 |
| 계정 | Guest 계정 활성 | 높음 |
| 계정 | 내장 Administrator 활성 | 중간 |
| 암호화 | 디스크 암호화(BitLocker) | 중간 |
| 네트워크 | SMB1 프로토콜 | 높음 |
| 네트워크 | SMB 서명 | 중간 |
| 네트워크 | 원격 데스크톱(RDP) | 중간 |
| 네트워크 | 방화벽(도메인/개인/공용) | 높음 |
| 네트워크 | LLMNR | 낮음 |
| 악성코드 | Defender 실시간 보호 | 높음 |
| 악성코드 | Defender 예외 경로 | 중간 |
| 업데이트 | 백신 시그니처 나이 | 중간 |
| 업데이트 | 최근 보안 패치 | 중간 |
| 업데이트 | 재부팅 대기 | 정보 |
| 네트워크 | 리스닝 TCP 포트 | 정보 |

---

## 채점 방식

- 규칙: `기준`이면 **양호**, 아니면 심각도 높음/중간/낮음(`위험`/`주의`/`낮음`).
- 점수(베이스라인 통과율) = `{양호} / {양호 + 위험 + 주의 + 낮음} × 100`
  - `정보`, `확인불가`는 통과율 계산에서 제외
- 등급: `≥90 A · ≥75 B · ≥60 C · ≥40 D · 그 외 F`
- **종합 평가**: 통과율 + 개선 필요 항목 수 + 우선 조치 순서를 한 문단으로 생성

> `확인불가`는 관리자 권한 부족 등으로 판정할 수 없는 항목입니다. 정확한 판정을 위해
> 관리자 권한으로 실행하세요(UAC 프롬프트가 뜹니다).

---

## 사용법

### 1) exe 실행 (권장)
`WindowsSecurityCheck.exe` 더블클릭 → UAC "예" → **점검 시작** → 표에서 항목 클릭 시
아래 상세 패널에 **평가 · 해결 방법** 표시 → 필요 시 **HTML 보고서 저장**.

### 2) 소스 실행
```powershell
python sec_check_gui.py
```

### 2) 빌드 (exe)
```powershell
pip install pyinstaller
pyinstaller --onefile --windowed --uac-admin --name WindowsSecurityCheck `
  --distpath dist --workpath build --specpath . --noconfirm sec_check_gui.py
```

---

## HTML 보고서

저장하면 다음이 포함됩니다.

- 헤더: 호스트 / OS / 빌드 / 생성 시각
- 요약: 통과율 + 등급 + 상태별 개수
- 종합 평가
- 결과 표(심각도순)
- **상세 평가 및 해결 방법**: 양호가 아닌 항목마다 `현황 / 평가 / 해결 방법(번호 목록)`

---

## 안전 · 프라이버시

- 점검은 **조회만** 합니다(레지스트리 읽기, `Get-*` Cmdlet).
- 데이터를 **외부로 전송하지 않습니다.**
- 자동 적용(조치)은 포함하지 않습니다. 점검·안내·실행은 사용자가 직접 합니다.
  참고로 안전 조치 실행 스크립트 `remediate_safe.ps1`(백업 포함, 영문 메시지)를 제공합니다.

### 되돌리기
`remediate_safe.ps1`는 실행 전 `remediation_backup_<timestamp>\`에
`system.reg`, `winlogon.reg`, `dnsclient.reg`, `smb_before.json`, `apply_log.txt`를
저장합니다. 문제가 생기면 `.reg` 파일을 더블클릭해 병합하면 원래대로 되돌릴 수 있습니다.

---

## 파일 구성

| 파일 | 설명 |
|---|---|
| `sec_check_gui.py` | 메인 프로그램(GUI + 점검 규칙 + HTML 보고서) |
| `test_sec_check.py` | 단위 테스트 24개 (`python -m unittest test_sec_check -v`) |
| `remediate_safe.ps1` | 안전 조치 실행 스크립트(백업 포함, 영문) |
| `WindowsSecurityCheck.spec` | PyInstaller 빌드 스펙 |
| `sec_check_gui.py` 빌드 | exe는 Release 또는 로컬 빌드 |

### 부록(레거시 실험)
초기 탐색 과정의 파일입니다. 본 프로그램과 무관하며 참고용입니다.

| 파일 | 설명 |
|---|---|
| `security_triage.py` | laya로 심각도를 판정하던 초기 트리아지(오판으로 폐기) |
| `laya_demo.py` | laya 사용 데모 |
| `hindsight_demo.py` | hindsight(laya 메모리) 데모 |

---

## 요구사항

- **exe**: Windows 10/11, 별도 설치 없음
- **소스**: Python 3.11+, Tkinter(표준), (선택) PyInstaller

---

## 라이선스

MIT License — `LICENSE` 참고.