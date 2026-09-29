# PR — 석현 SPA Discovery/Verification PR 선별 반영 (`feat/utility-environment`)

## 배경

석현의 `feat/spa-discovery-verification` PR(→ `integration/v0.2`, PR #19)을 현재
`feat/utility-environment` 브랜치에 반영 요청받았다.

확인 결과 그의 브랜치는 **내 최신 커밋 위에 쌓여 있고** 내 변경(`--cookie` 세션,
submit-게이트, BAC denial-게이트, 대시보드 입력점당 1개 표시)을 **모두 보존**한다.
그러나 그대로 얹으면 **14개 테스트가 실패**한다. 이 실패는 병합 탓이 아니라 **석현
브랜치 자체의 상태**다(선별 반영 전, 내 작업트리가 그의 tip과 **파일 단위로 동일**함을
확인). 실패에 **안전(safety) 회귀**가 포함돼 있어, 통째로 반영하지 않고 **테스트를
깨뜨리지 않는 안전한 부분만 선별 반영**했다.

- 반영 커밋: `925723f`
- 검증: 반영 시점 867 테스트 통과(현재는 랜덤 예측기 추가로 891), format/lint/type 통과

---

## ✅ 반영한 부분

| 석현 PR 섹션 | 반영 파일 | 이유 |
| --- | --- | --- |
| **5. LLM Verification 성능 최적화** (전체) | `verification/llm_proposal.py` | 자체 완결·독립적이고 **탐지 판단 알고리즘을 바꾸지 않는** 실행시간 최적화. `max_tokens 2048→512`, `retry 3→2`, LLM 프롬프트에 넣는 baseline 값만 축약(원본 `MutationSubject`·실제 HTTP 요청은 불변) |
| **4. Focused Verification** 중 proposer 부분 | `verification/llm_proposal.py` | 제안 수 상한(SQLi ≤4 / Reflected XSS ≤3), **중복 LLM payload 제거**가 `llm_proposal.py` 안에서 완결. LLM 제안이 deterministic Payload Validator를 통과해야만 실제 요청에 쓰이는 게이팅은 **기존 구조 그대로 유지** |
| **9. 실행 프로필 분리** 중 스크립트 | `run_progress_demo.ps1`, `run_progress_external.ps1` | `analyze --dynamic` 데모 실행용 독립 스크립트. 코드 의존성 없음(무해) |

> 참고: 섹션 4의 "local LLM proposer 지원"과 "최종 Ranking Top-K를 그대로 Focused
> Verification 대상으로 사용"은 **이미 이 브랜치에 있는 기능**이라(각각 local-ai proposer
> 병합, `VerificationSelection`/`rank_analysis`) 석현 PR에서 새로 가져온 것이 아니다.

---

## ❌ 반영하지 않은 부분 (석현이 원본 브랜치에서 수정 후 재반영 권장)

| 석현 PR 섹션 | 관련 파일 | 반영 안 한 이유 |
| --- | --- | --- |
| **1. Dynamic Discovery 확장** (SPA interaction, fetch/XHR 수집, rendered navigation) | `discovery/dynamic_browser.py`, `dynamic_crawler.py`, `rendered_dom.py` | Chromium 동적 e2e 테스트 실패(`test_final_output_consistency`, `test_final_cli_combined_probe`, `test_simple_cli_real_chromium_policy`) |
| **2. POST JSON / JSON_BODY 지원** | `domain/models.py`(`json_body`를 `RequestTemplate` **fingerprint**에 추가), `discovery/html_extractor.py`, `network_canonicalization.py`, `observation/*` | `RequestTemplate`의 정체성(fingerprint)을 바꿔 **모든 템플릿 fingerprint 불일치**를 유발하고, POST-JSON 정규화 **id가 비결정적**이 된다(`test_post_json_eligibility_and_budgets_are_bounded` 등 유닛 실패) |
| **3. ASP.NET state param 필터** (`__VIEWSTATE`/`__EVENTVALIDATION` 제외) | `discovery/html_extractor.py`, `observation/planner.py` | 2번의 discovery/`json_body` 변경과 fingerprint로 **결합**돼 단독 분리가 불가(html_extractor를 그의 것으로 두면 fingerprint 커플링으로 실패) |
| **6. Dynamic Crawler 안정성** (worker 예외 전달, SPA authority, redirect scope) | `discovery/dynamic_crawler.py`, `dynamic_browser.py` | 동적 변경 묶음 + authority 유닛 테스트 실패(`test_rejects_external_userinfo_fragment_and_cross_origin_grants`) |
| **7. URL fragment 제거 / `INVALID_AUTHORITY` 수정** | `cli.py` | 🔴 이 authority 처리 변경이 **비-loopback 대상 거부를 무력화**한다: `test_cli_rejects_non_loopback_record`가 **exit 2(거부) → 0(수용)**. loopback 강제는 핵심 안전 규칙이라 그대로 가져올 수 없음 |
| **8. CLI / 로그 개선** (후보별 검증시간 표시, `tqdm` 진행바) | `cli.py` | 동적 e2e 실패에 얽혀 있고, `tqdm`를 `pyproject.toml`에 **선언하지 않아** 깨끗한 환경에선 import 실패 |

---

## 왜 통째로 반영하지 않았나 — 실패 근거

14개 실패 중 **환경(Chromium)이 아닌 결정적 실패**가 핵심이다:

| 실패 테스트 | 증상 | 성격 |
| --- | --- | --- |
| `test_cli_rejects_non_loopback_record` | 비-loopback 거부 exit **2 → 0** | 🔴 안전 회귀 |
| `test_url_input_writes_...` | probe 요청 수 **2 → 4** | 요청 배가 |
| `test_post_json_eligibility_...` | POST-JSON 정규화 id 비결정성 | 결정성 회귀 |
| `test_combined_handoff_preserves_...` | 핸드오프 컨텍스트 불일치 | 계약 위반 |

이 실패들은 **석현 브랜치 자체의 상태**이며(그대로 얹은 작업트리가 그의 tip과 동일),
안전 규칙(loopback 강제)·도메인 fingerprint를 바꾸는 커플링이라 통째 반영은 위험하다.

---

## 이 브랜치가 현재 가진 파이프라인

석현이 제시한 "현재" 전체 파이프라인(Static + Dynamic SPA Discovery → JSON POST →
LLM 제안 → …)은 **아직 이 브랜치의 상태가 아니다**. 이 브랜치는 다음을 유지한다:

```text
Static Discovery (+ submit 게이트, --cookie 세션/BAC)
→ InputPoint → Lightweight Probe → Scoring & Ranking → Top-K
→ Focused Verification (deterministic + local-LLM proposer, 이번에 상한·중복제거·성능 최적화)
→ Deterministic Validation → HTTP Re-Probe → Confidence Update → Report
```

SPA Dynamic Discovery / JSON_BODY 확장은 위 "반영하지 않은 부분"이 원본 브랜치에서
수정된 뒤 별도로 합류시키는 것을 권장한다.

---

## 후속 권장

1. 석현이 원본 브랜치에서 위 회귀를 수정 — 특히 **(7) 비-loopback 거부 안전 회귀**,
   **(2) POST-JSON fingerprint/결정성**, **(8) `tqdm` 의존성 선언**.
2. 수정 후에는 SPA Dynamic Discovery + JSON_BODY 기능 전체를 다시 반영할 수 있다.
3. `integration/v0.2`에는 이미 석현 PR이 머지돼 있으므로, 위 안전 회귀는 그쪽에서도
   우선 확인이 필요하다.
