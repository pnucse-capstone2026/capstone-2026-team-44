# 검증 기반 신뢰도 갱신 · BAC · 리포트 개선 (팀 공유용)

> 브랜치: **`feat/confidence-update`**
> v0.2 파이프라인의 **마지막 단계**를 완성한 작업입니다. 보안/ML 배경이 없어도 읽을 수 있게 개념부터 설명합니다.

---

## 0. 30초 요약

지금까지 파이프라인은 "크롤링 → 입력점 찾기 → 특징 수집 → **취약할 확률로 순위 매기기(Top-K)**"까지였습니다. 순위는 매겼지만, **그게 정말 취약한지 한 번 더 확인하는 단계가 없었습니다.**

이 브랜치가 그 마지막 단계를 만듭니다.

1. 상위 후보에 **같은 유형의 변형 페이로드**를 다시 보내 보고,
2. 돌아온 응답의 **특징을 처음(baseline)과 비교**해서,
3. **재현되면 신뢰도 유지, 새로 취약 신호가 보이면 상승, 안전하게 막혔으면 하락** —
4. 이렇게 갱신한 **최종 신뢰도**를 리포트의 대표 점수로 씁니다.

여기에 더해 **접근제어 취약점(BAC)** 을 관측·순위·검증하는 경로를 붙였고, 리포트를 **웹 대시보드 하나**로 정리했으며, **방어 지침을 케이스별로 세분화**했습니다.

| | 이전 | 이후(이 브랜치) |
|---|---|---|
| 파이프라인 끝 | Top-K 랭킹에서 종료 | **검증으로 신뢰도 갱신**까지 |
| 대표 점수 | 검증 이전 확률 | **검증 이후 신뢰도** |
| 취약 유형 | SQLi, XSS | + **Broken Access Control** |
| 방어 지침 | 유형당 한 줄 | **유형·케이스별 구조화 지침** |
| 리포트 | 여러 산출물 | **단일 웹 대시보드** |

---

## 1. 이 작업이 어디에 위치하나

```
크롤링 → 입력점 추출 → 특징 수집 → 보정 확률로 Top-K 랭킹 → [★ 검증으로 신뢰도 갱신 ★] → 대시보드
```

★ 부분이 이번 작업입니다. 코드는 `src/vulnspider/verification/`에 있고, 접근제어(BAC) 관측은 `src/vulnspider/access/`에 있습니다.

---

## 2. 꼭 기억할 개념 — "우선순위"와 "신뢰도"는 다르다

- **우선순위(prior)**: "이 후보를 먼저 봐야 할까?"를 정하는 값. 검증 **이전**의 보정된 확률입니다. **Top-K 선택은 이 값으로** 합니다.
- **신뢰도(confidence)**: "실제로 취약할 가능성이 얼마나 되나?"를 검증 **이후**에 갱신한 값. **표시 순서와 대표 점수는 이 값으로** 합니다.

즉 **무엇을 볼지는 prior가 정하고, 얼마나 믿을지는 검증이 정합니다.** 리포트는 Top-K를 prior로 뽑되(선택 순위 `selection_rank` 보존), 화면 표시는 최종 신뢰도로 재정렬합니다. (도메인 규칙 6/7 — prior는 순위 점수 `RankScore`가 아니라 보정 확률입니다.)

---

## 3. 검증 파이프라인 — 5단계 자세히

| 단계 | 모듈 | 설명 |
|---|---|---|
| ① **제안(propose)** | `proposal.py` | 같은 유형의 변형 페이로드를 만듭니다. 제공자 중립 인터페이스(`PayloadProposer`)이며, 기본 구현은 규칙 기반 `DeterministicMutationProposer`(SQL 메타문자 / HTML sentinel / 경계값). |
| ② **검증(validate)** | `validator.py` | **반드시** 거치는 결정적 게이트. **승인된 값만 전송**하고, 거부되면 아예 실행하지 않습니다. 거부 사유는 고정된 분류로 남깁니다. |
| ③ **재전송(re-probe)** | `planner.py` | 검증된 값 **하나만** baseline 요청에 주입해 다시 보냅니다(한 번에 한 가지만 바꾸는 규칙). v0.1의 전송/추출기를 그대로 재사용합니다. |
| ④ **차이(delta)** | `delta.py` | 새로 수집한 Feature Vector를 baseline과 비교합니다. |
| ⑤ **신뢰도(confidence)** | `confidence.py` | 차이를 규칙 + 보정 계수로 해석해 신뢰도를 갱신합니다. |

전체를 엮는 것은 `focused.py`의 `verify_analysis`입니다.

> **중요:** 최종 판단을 LLM이 하는 게 아닙니다. LLM(또는 결정적 기본기)은 페이로드를 **제안**만 하고, 그 페이로드가 실제로 실행되려면 결정적 validator를 통과해야 하며, 신뢰도는 **규칙과 코퍼스 보정 계수**가 정합니다.

---

## 4. 어떤 신호를, 어떻게 해석하나

핵심은 **"단순 에러"와 "진짜 취약 신호"를 구분**하는 것입니다. 그 구분은 응답 길이·상태코드가 아니라 **판별 특징(discriminating feature)** 으로 합니다.

- SQLi → `sql_error_pattern`(DB 오류 노출)
- XSS → 위험 문자가 인코딩 없이 원본 그대로 반사되는지

네 가지 대표 시나리오:

| 상황 | 신호 | 결과 |
|---|---|---|
| 같은 취약이 변형 페이로드에서도 재현 | `SUPPORT_REPRODUCED` | 신뢰도 **유지/소폭 상승** |
| baseline에선 약했는데 변형에서 새 취약 신호 | `SUPPORT_NEW` | 신뢰도 **상승** |
| 위험 문자가 안전하게 인코딩됨 | `WEAKEN` | 신뢰도 **하락** |
| 전송 실패 또는 페이로드가 5xx 유발(baseline은 정상) | `INCONCLUSIVE` | **판단 보류**(유지) |
| 별다른 차이 없음 | `UNCHANGED` | 유지 |

**보정 계수(LLR) 예시** — 코퍼스에서 학습:

```
logit(최종신뢰도) = logit(prior) + LLR(유형, 신호)      (|LLR| ≤ 1.0)

SUPPORT_REPRODUCED  +1.0   (취약 20 / 안전 0 으로 완전 분리)
WEAKEN              -1.0   (취약 0 / 안전 20)
SQLI · UNCHANGED    -0.407 (블라인드 SQLi가 UNCHANGED로 떨어지는 경향 반영)
```

캡(1.0)을 둬서 점수가 급격히 튀지 않고 부드럽게 움직입니다.

---

## 5. 코퍼스 보정 (ADR-033 · Phase 2/4)

- 손으로 고른 상수 대신 **라벨된 코퍼스로 (유형, 신호)별 LLR을 학습**했습니다.
- 코퍼스: **146 샘플 / 14개 loopback 앱**(DVWA 스타일 합성 fixtures). 학습 모델은 `data/corpus/verification-model.json`에 커밋되어 있습니다.
- **out-of-fold Brier 0.136 → 0.102** (검증 단계가 확률 보정을 개선).
- 근거 없는 신호(`NOT_EXECUTED`/`INCONCLUSIVE`)는 0으로 고정하고, 특정 유형에서 관측되지 않은 신호는 기본 LLR로 폴백합니다(작은 표본의 스무딩 왜곡 방지).
- 재현 명령: `tools/build_verification_corpus.py`, `corpus verify-fit --report`.

---

## 6. 단일 대시보드 + 리포트 개선 (ADR-034)

- `-u` 실행이 기본으로 **웹 대시보드 하나**(`vulnspider-report.html`)를 만듭니다(`--no-html`로 생략). 헤드라인 점수 = 검증 이후 신뢰도. JSON도 동일 값(`final_confidence`/`verification_outcome`/`prior_probability`)을 담아 HTML과 어긋나지 않습니다.
- **INCONCLUSIVE 게이트 강화**: 전송 실패 또는 페이로드가 유발한 5xx만 해당. 단순 길이 차이는 `UNCHANGED`로 남깁니다(과다 INCONCLUSIVE 억제).
- **유형별 선택 건수**는 이제 **건수가 많은 유형부터** 정렬됩니다.
- **방어 지침을 케이스별로 세분화**(`reporting/guidance.py`):
  - SQLi: **에러 기반**(DB 오류 노출) vs **추론 기반**(응답 차이만, 블라인드)
  - XSS: 문맥별 출력 인코딩(HTML 본문 / 속성 / 자바스크립트 / URL)
  - BAC: **IDOR(식별자 치환)** vs **인증 우회(자격증명 제거)**
  - 각 지침은 *요지 → 핵심 대응 → 추가 방어 → 확인 포인트* 구조. 기존에 지침이 아예 없던 BAC도 추가.
- **"선택된 후보 확률 비교" 차트**: 전체 폭 + 다열 배치 + 상위 8개만 표시(나머지는 `더보기`로 접기) → k가 커도 세로 스크롤이 짧습니다.

---

## 7. Broken Access Control(BAC) 파이프라인 (ADR-035)

접근제어 취약점은 "인증이 필요한 리소스에 인증 없이/남의 식별자로 접근되는가"입니다.

- **관측** (`access/planner.py`·`executor.py`): 두 가지 검사를 **GET 전용·비파괴**로 수행
  - `CREDENTIAL_STRIP`: 쿠키·Authorization 헤더를 제거하고 재요청
  - `IDENTIFIER_SUBSTITUTION`: 숫자 id를 다른 값으로 바꿔 재요청
- **랭킹**: BAC 후보를 SQLi/XSS와 **같은 보정 확률 척도**로 통합 랭킹(`build_decision_candidates`).
- **대시보드**: BAC 후보를 endpoint·검사 종류·원본/변형 응답(상태·본문 크기)으로 렌더.
- **검증** (`verification/access_verify.py`): `IDENTIFIER_SUBSTITUTION` 후보를 다른 id(+2/+5/−1)로 재확인 → 재현되면 유지, 아니면 약화.
- **opt-in**: 추가 요청이 생기므로 **`--access-control`(기본 off)** 로만 켭니다. 플래그가 없으면 기존 요청 예산 그대로.

> **정밀화 노트:** 데모에서 공개 조회 페이지(숫자 id를 쓰는 product/article 등)가 IDOR로 오탐되던 문제가 있었습니다. SQLi 파라미터 seed를 비숫자로 바꿔 **BAC 후보를 13개 → 2개(진짜 IDOR만)** 로 좁혔습니다.

---

## 8. 사용법 상세

### 8.1 빠른 시작 — 로컬 데모로 확인

```bash
# 1) 로컬 데모 타겟 (별도 터미널)
python demo_target_server.py            # http://127.0.0.1:8899
#    입력점 32개 · 주입 취약 20개 · BAC/IDOR 2개 · 라우트 15개

# 2) k=20 정적 스캔 + 검증 + BAC + 대시보드
PYTHONPATH=src python -m vulnspider -u http://127.0.0.1:8899/ \
  --static-only -k 20 \
  --access-control \
  --verify --verification-model data/corpus/verification-model.json \
  --html-output vulnspider-report.html \
  --crawl-output vulnspider-crawl.json \
  --verify-output vulnspider-verification.json \
  -o vulnspider-analysis.json
```

**k=20 결과 (데모 기준):**

- 콘솔: `scan complete (mode=static-only, selected=20)` + 산출물 4개 경로
- 채점된 후보 **66개** 중 상위 **20개** 선택
- 유형 분포: **SQL Injection 9 · Reflected XSS 9 · Broken Access Control 2**
- 대시보드: 확률 구간 도넛·유형별 건수·파이프라인 축소·후보 비교(더보기), 각 후보 카드에 순위 근거·실행된 요청·검증 결과·**케이스별 방어 지침**

### 8.2 명령어 구조와 옵션 — 무엇이 필수인가

**필수는 `-u/--url` 하나뿐**입니다. 나머지는 전부 기본값이 있거나 opt-in이라, 넣지 않으면 그 기능이 그냥 실행되지 않습니다.

| 옵션 | 의미 | 필수 여부 |
|---|---|---|
| `-u / --url URL` | 스캔할 루트 URL | **✅ 필수** |
| `--static-only` | 정적(HTML 파싱)만 사용. **빼면 동적**(브라우저 렌더) 발견 | 동적 원하면 **제거** |
| `-k / --top-k N` | 관측·검증할 상위 후보 수 (기본 **10**, 최대 20) | 선택 |
| `--access-control` | BAC(접근제어) 관측 — **추가 GET 요청**이 생기는 opt-in | 선택 |
| `--verify` | focused verification(변형 페이로드 재전송) 실행 | 선택 |
| `--verification-model PATH` | 검증 신뢰도 **보정 모델** | `--verify`와 함께 권장 |
| `--dynamic-allow-navigation URL` | 동적 크롤이 이동할 **same-origin** URL 하나 허용(반복 가능) | 동적에서만 |
| `--dynamic-allow-resource CAT=URL` | `script`/`style`/`fetch_xhr` 리소스 로드 허용 | 동적·SPA에서만 |
| `--html-output` / `-o` / `--crawl-output` / `--verify-output` | 산출물 경로 | 선택(기본 `vulnspider-*.{html,json}`) |

**동작별 최소 명령:**

```bash
# 동적 최소 (나머지 전부 기본값 — -k 10, 검증 없이 확률 랭킹만)
PYTHONPATH=src python -m vulnspider -u <URL>

# 정적 최소
PYTHONPATH=src python -m vulnspider -u <URL> --static-only
```

### 8.3 정적 vs 동적 — 동적은 어떻게 켜나

- **정적**(`--static-only`): HTML을 파싱해 링크·폼에서 입력점을 찾습니다. 빠르고 의존성이 적습니다.
- **동적**(`--static-only`를 **뺌**): **Playwright 브라우저로 페이지를 실제 렌더**해 자바스크립트로 생성되는 링크·폼·XHR까지 관측합니다. SPA에 필요합니다.
  - simple `-u` 모드는 `--static-only`가 없으면 **자동으로 동적**으로 전환됩니다(내부적으로 `dynamic = not --static-only`).
  - 동적은 기본이 매우 보수적이라 첫 페이지 렌더 후 **명시적으로 허가한 URL로만** 이동/리소스 로드를 합니다 → `--dynamic-allow-navigation`, `--dynamic-allow-resource`로 하나씩 허용.
  - `--static-only`와 `--dynamic-allow-*`는 **동시에 쓸 수 없습니다**(서로 모순).

```bash
# 동적 예시 (SPA) — --static-only 를 뺀 것 + 동적 그랜트가 핵심
PYTHONPATH=src python -m vulnspider -u https://app.example/ -k 20 \
  --access-control \
  --verify --verification-model data/corpus/verification-model.json \
  --dynamic-allow-navigation https://app.example/dashboard \
  --dynamic-allow-resource fetch_xhr=https://app.example/api/items \
  --html-output report.html
```

### 8.4 실제 사이트(외부 URL)에 적용하려면

이 도구는 **"authorized loopback/localhost 테스트 대상"용 프로토타입**입니다(`--help`·ADR-004에 명시, 모든 성능 수치도 합성 loopback fixtures 기준). 실제 외부 사이트에 쓰기 전 아래를 반드시 확인하세요.

1. **권한이 전제입니다.** 대상이 **본인 소유**이거나 **서면으로 침투테스트를 허가받은** 자산이어야 합니다. 무단 스캔은 법적 문제가 됩니다. 도구가 host를 loopback으로 강제 차단하지는 않지만, 그것이 외부 스캔을 정당화하지는 않습니다.
2. **동적은 Playwright(브라우저) 설치**가 필요합니다.
3. 크롤러는 **same-origin scope 제한**이 있어 외부 도메인 링크·리다이렉트를 자동 차단합니다(안전장치). 동적도 허가한 URL만 따라갑니다.
4. 실제 앱은 대개 **로그인 뒤 콘텐츠**가 많은데, 현재 도구는 **인증 크롤 미지원**이라 공개 페이지 위주로만 관측됩니다.
5. **요청 예산/rate-limit 제어가 아직 없으므로**, 운영 시스템에는 부하·차단 위험이 있습니다(§11 참고).

> **권장:** 학습·시연 목적이면 DVWA 같은 취약 실습 앱을 로컬(`http://127.0.0.1`)에 띄워 돌리세요. 실제 자산은 **권한·범위를 서면으로 확정한 뒤에만** 적용하세요.

---

## 9. 테스트 / E2E 검증

- **유닛 720 · 통합 59 통과**, format/lint/type 전부 통과.
- **E2E 매트릭스 15개 시나리오**로 다양한 옵션을 점검:
  - 정적/동적, verify on/off, access on/off, k 경계값(1·20·21·0·−1), HTML on/off, native/legacy, model·conformal, 에러 케이스(없는 모델 파일·닫힌 포트·인자 누락)
  - **파이프라인 미처리 예외/크래시 0건**, 모든 경계·에러 케이스가 명확한 종료 코드로 graceful 처리
  - 동적 모드는 정적 데모에서 `DYNAMIC_INCOMPLETE`로 안전하게 거부(의도된 안전장치)

---

## 10. 안전성 / 거버넌스

- **validator 승인 전에는 페이로드를 실행하지 않습니다** — 거부된 값에는 실행 흔적이 남지 않고, 이를 테스트로 증명합니다.
- **read-only · loopback/localhost 한정 · 한 번에 한 가지만**(ADR-004). BAC 프로브도 **GET 전용·비파괴**.
- **LLM이 최종 판단하지 않습니다** — 페이로드 제안만 하고, 실행 여부는 결정적 validator가, 신뢰도는 규칙/보정 계수가 정합니다.
- **실제 LLM proposer는 본체 파이프라인과 아직 코드 통합되지 않았습니다.** `src/vulnspider/verification/`에서는 결정적 기본기가 `no-model` provider로 동작합니다. 석현의 실제 proposer는 **로컬 파인튜닝 모델** `payload_verifier_v2/`(3B GGUF `vulnspider-3b_v3`, ChatML 템플릿·Qwen 계열 기반 추정, `llama_cpp` 로컬 추론 — **클라우드 API가 아님**)이며, `main`을 제외한 브랜치들(`integration/v0.2`·`feat/local_ai_verifier`·이 브랜치)에 **독립 실행 도구로 존재**해 `vulnspider-*.json`을 입력으로 받습니다. 다만 `src` 본체가 이 모듈을 호출하지는 않으므로(참조 0건), 이를 `PayloadProposer` 뒤로 끼워 넣는 코드 통합이 후속 과제입니다.
- **네트워크 접근/페이로드 실행이 바뀌는 변경은 2인 리뷰 대상**입니다.

---

## 11. 정직한 한계와 다음 작업

- **실제 LLM proposer는 독립 도구로 존재하나 본체 파이프라인과 코드 통합 미완** — 석현의 `payload_verifier_v2/`(로컬 파인튜닝 모델)가 `main` 제외 브랜치들에 있지만 `src/vulnspider/`가 이를 호출하지 않습니다(참조 0). 현재는 결정적 규칙 기반 제안이 그 자리를 대신하며, 코드 통합이 다음 작업입니다.
- **코퍼스가 6개 신호 중 3개만 실측** — `SUPPORT_NEW`/`INCONCLUSIVE`/`NOT_EXECUTED`는 관측 표본이 없어 기본값으로 둡니다. 코퍼스 확장이 선행돼야 더 정직해집니다.
- **BAC 한계** — opt-in(요청 예산), 순차 id 과탐 여지(데모는 seed 정밀화로 완화), `CREDENTIAL_STRIP` 전용 검증은 미구현.
- **요청 예산/rate-limit/baseline 재사용 미적용**(현재 보류).
- **실제 DVWA는 인증 크롤이 필요**해 현재 도구 범위 밖 — 지금 수치는 합성 loopback fixtures 기준으로, 실제 웹 앱 성능이 아닙니다.

---

## 12. 용어집

| 용어 | 뜻 |
|---|---|
| **prior / 우선순위** | 검증 이전의 보정 확률. Top-K 선택 기준 |
| **confidence / 신뢰도** | 검증 이후 갱신된 값. 표시·대표 점수 기준 |
| **focused verification** | 상위 후보에만 변형 페이로드를 재전송해 확인하는 단계 |
| **validator** | 페이로드 전송 전 반드시 통과해야 하는 결정적 게이트 |
| **LLR (로그우도비)** | (유형, 신호)별로 신뢰도를 얼마나 움직일지 정하는 학습 계수 |
| **BAC / IDOR** | 접근제어 취약점 / 식별자만 바꿔 남의 리소스에 접근 |
| **out-of-fold Brier** | 학습에 안 쓴 데이터로 잰 확률 예측 오차(낮을수록 좋음) |

---

*근거: `docs/DECISION_LOG.md` ADR-032/033/034/035 · `src/vulnspider/verification/`·`access/`·`reporting/` · 커밋 `a806382`…`29c90d1`.*
