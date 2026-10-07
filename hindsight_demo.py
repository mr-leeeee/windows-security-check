"""hindsight 사용 예제 — 에이전트 장기 메모리 (Ollama 로컬 LLM).

전부 로컬에서 동작합니다. API 키/크레딧 불필요.
- LLM   : Ollama (qwen2.5:3b)  -> 사실추출 / reflect
- 임베딩 : 로컬 sentence-transformers
- DB    : 내장 pg0 (PostgreSQL 임베디드)

전제: Ollama가 실행 중이고 `ollama pull qwen2.5:3b` 완료.
(qwen3 계열은 thinking 생성 때문에 저전력 CPU에서 reflect가 매우 느림)

환경변수는 반드시 `import hindsight` 보다 먼저 설정해야 합니다.
(hindsight가 import 시점에 설정을 캐시하기 때문)

실행:
    python hindsight_demo.py
"""

from __future__ import annotations

import os

# --- 설정 (import 전에 반드시) ---------------------------------------------
os.environ["HINDSIGHT_API_LLM_PROVIDER"] = "ollama"
os.environ["HINDSIGHT_API_LLM_MODEL"] = os.environ.get("HINDSIGHT_MODEL", "qwen2.5:3b")
os.environ["HINDSIGHT_API_LLM_API_KEY"] = "ollama"
os.environ["HINDSIGHT_API_LLM_BASE_URL"] = "http://127.0.0.1:11434"
os.environ["HINDSIGHT_API_EMBEDDINGS_PROVIDER"] = "local"

# 저전력 CPU(N100) 튜닝:
#  - LLM/작업 타임아웃 확대 (기본값은 빠른 GPU를 가정)
#  - 동시 LLM 호출 수 제한 (CPU 4코어 과부하 방지)
os.environ["HINDSIGHT_API_LLM_TIMEOUT"] = "600"
os.environ["HINDSIGHT_API_LLM_MAX_CONCURRENT"] = "1"
os.environ["HINDSIGHT_API_RETAIN_WALL_TIMEOUT"] = "900"
os.environ["HINDSIGHT_API_CONSOLIDATION_WALL_TIMEOUT"] = "900"
os.environ["HINDSIGHT_API_REFLECT_WALL_TIMEOUT"] = "900"

from hindsight import HindsightClient, HindsightServer  # noqa: E402

BANK = "demo-bank"


def main() -> None:
    server = HindsightServer(
        llm_provider="ollama",
        llm_model=os.environ["HINDSIGHT_API_LLM_MODEL"],
        llm_api_key=os.environ["HINDSIGHT_API_LLM_API_KEY"],
        llm_base_url=os.environ["HINDSIGHT_API_LLM_BASE_URL"],
    )
    try:
        server.start(timeout=300)
        print(f"server up: {server.url}")
        client = HindsightClient(base_url=server.url, timeout=900)

        client.retain(
            bank_id=BANK,
            content="Alice works at Google as a software engineer on the search team.",
            context="profile",
        )
        client.retain(
            bank_id=BANK,
            content="Bob is the CTO and prefers concise bullet-point updates.",
            context="profile",
        )
        print("retained 2 memories")

        recalled = client.recall(bank_id=BANK, query="Where does Alice work?")
        print("\n[recall] Where does Alice work?")
        for item in recalled.results:
            print(f"  - ({item.type}) {item.text}")

        reflected = client.reflect(bank_id=BANK, query="Tell me about Alice and Bob")
        print("\n[reflect] Tell me about Alice and Bob")
        print(f"  {reflected.text if hasattr(reflected, 'text') else reflected}")
    finally:
        server.stop()


if __name__ == "__main__":
    main()