"""laya 사용 예제 — System 1 결정 모델.

완전 로컬/오프라인 동작. API 키, 크레딧, GPU 불필요.
최초 1회만 Hugging Face에서 체크포인트(~808MB)를 내려받고 이후엔 캐시를 씁니다.

실행:
    python laya_demo.py
"""

from __future__ import annotations

from laya import Router

# 라우터가 요청 언어를 보고 english / multilingual 체크포인트를 자동 선택합니다.
router = Router()

STATE_KO = (
    "3월에 결제가 두 번 청구됐습니다. 중복 금액을 오늘 환불해 주세요. "
    "안 그러면 요금제를 해지하겠습니다."
)

QUESTIONS = {
    "department": {
        "type": "choice",
        "instructions": "어느 부서가 처리해야 하나?",
        "criteria": {
            "billing": "청구/결제/환불",
            "technical": "버그/장애/시스템 오류",
            "other": "기타",
        },
    },
    "urgency": {
        "type": "score",
        "instructions": "긴급도는?",
        "criteria": ["안 급함", "곧", "막힘"],
    },
    "churn_risk": {
        "type": "noul",
        "instructions": "해지/이탈 위협이 있는가?",
    },
}

STATE_EN = (
    "The dashboard throws a 500 whenever I open the billing report. "
    "Please fix it, our finance team is blocked."
)


def main() -> None:
    for label, state in (("KO", STATE_KO), ("EN", STATE_EN)):
        result = router.predict(state, QUESTIONS)
        answers = result["answers"]
        print(f"[{label}] routed -> {result['routing']['model']}")
        print(f"  department : {answers['department']['choice']}")
        print(
            f"  urgency    : {answers['urgency']['score']} "
            f"(conf {answers['urgency']['confidence']:.3f})"
        )
        print(f"  churn_risk : {answers['churn_risk']['noul']:.3f}")
        print()


if __name__ == "__main__":
    main()