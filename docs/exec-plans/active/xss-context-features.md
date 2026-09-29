# Feature 확장 — Reflection 문맥과 인코딩 탐지

## Goal

XSS 후보에서 **현재 feature로는 원리적으로 구분 불가능한 오탐**을 제거한다.

`feat/scoring`의 측정이 남긴 지배적 오차원이 여기다. 코퍼스에서 marker가 반사된
XSS 후보 34개 중 실제 취약은 14개뿐인데, **어떤 scoring/selection 알고리즘도
나머지 20개를 걸러낼 수 없다.** 이유는 알고리즘이 아니라 feature다: probe
marker가 영숫자(`VULNSPIDER_` + 16진수)라서, 출력을 이스케이프하는 안전한 앱과
그대로 출력하는 취약한 앱이 **똑같이 `marker_reflected = 1.0`** 을 만든다.

```text
xss_raw      <h2>Results for VULNSPIDER_ABC123<script></h2>          취약
xss_escaped  <p>No matches for VULNSPIDER_ABC123&lt;script&gt;</p>   안전
```

목표 수치는 `docs/EVALUATION_PROTOCOL.md` §8-C와
`docs/DECISION_LAYER_OVERVIEW.md` §8.6의 오라클 상한이다.

```text
                Brier     Rec@1   Rec@3   MAP@5
현재            0.1134    0.405   0.869   0.871
오라클 상한      0.0628    0.440   0.964   1.000
```

## Non-Goals

- 크롤러 인증. 실제 앱 진입은 별도 브랜치다.
- 실제 애플리케이션(DVWA 등) 코퍼스 수집. feature schema가 먼저 고정돼야 한다.
- 결정 계층 변경. `scoring/calibration.py`, `decision/`, `evaluation/`은 새
  feature를 자동으로 흡수한다. 손댈 필요가 없다.
- `response_time_diff_ratio`. 단일 요청 timing은 노이즈가 커서 득보다 실이 클
  가능성이 높다(`FEATURE_SCHEMA.md` §4도 높은 가중치를 금지한다).
- 의존성 추가. 표준 라이브러리만 유지한다.

## Context Read

- `docs/FEATURE_SCHEMA.md` §5(정의), §8(추가 규칙), §9(보정 모델에서의 취급)
- `docs/EVALUATION_PROTOCOL.md` §8-B/§8-C(측정 결과), §7.2(후속 ablation)
- `docs/DECISION_LOG.md` ADR-004(one-at-a-time probe), ADR-021~027
- `src/vulnspider/observation/planner.py` — marker 생성
- `src/vulnspider/features/extraction.py` — feature 추출
- `tools/corpus_target_site.py` — 라벨 애플리케이션

## Current State

`features/extraction.py`가 추출하는 feature는 4개뿐이다.

```text
status_code_changed
response_length_diff_ratio
marker_reflected
sql_error_pattern
```

`FEATURE_SCHEMA.md` §5는 `safe_html_encoding_detected`,
`dangerous_reflection_context`, `reflection_count_norm`을 정의만 해두고
구현하지 않았다. §3의 정적 feature(`numeric_value`, `id_like_name`)도 마찬가지다.

marker는 `deterministic_probe_marker()`가 만들고 형식은
`VULNSPIDER_` + 16진수 16자리다. **위험 문자가 하나도 없다.**

## Proposed Changes

### 1. Probe sentinel — 이것이 선행 조건이다 (ADR 필요)

`safe_html_encoding_detected`는 **feature 추출만으로 구현할 수 없다.** 인코딩
여부를 관측하려면 인코딩될 수 있는 문자를 먼저 보내야 한다.

marker를 두 부분으로 나눈다.

```text
VULNSPIDER_<16진수16>            식별 토큰 (현행 유지, 항상 영숫자)
VULNSPIDER_<16진수16>Z<'">Z      sentinel 부착 형태
```

**두 토큰을 함께 보내는 것이 핵심 설계다.** sentinel만 보내면 WAF나 입력 필터가
그것을 잘라냈을 때 반사 자체가 사라져 후보가 "안전"해 보인다. **오탐을 줄이려다
새로운 미탐을 만드는 셈이다.** 두 토큰이 있으면 세 상태를 구분할 수 있다.

```text
식별 토큰 없음                  -> marker_reflected = 0        (반사 안 됨)
식별 토큰 있음 + sentinel 없음   -> safe_html_encoding 미관측    (필터링됨)
식별 토큰 있음 + sentinel 인코딩 -> safe_html_encoding = 1.0     (안전)
식별 토큰 있음 + sentinel 원본   -> safe_html_encoding = 0.0     (위험)
```

두 번째 줄이 도메인 규칙 8("미관측은 관측된 0이 아니다")의 적용이다. 필터링을
안전으로 해석하면 WAF가 있는 모든 앱이 안전해 보인다.

**안전 검토 대상이다.** 전송 내용이 바뀐다. 다만 sentinel은 파괴적이지 않고
스크립트가 아니다 — `<`, `>`, `"`, `'` 네 문자뿐이며 실행 가능한 payload가
아니다. ADR-004(one-at-a-time probe)는 유지된다.

### 2. `safe_html_encoding_detected`

sentinel의 위험 문자가 **일관되게** entity로 변환됐는지 본다.

```text
1.0  네 문자가 모두 entity(&lt; &gt; &quot; &#x27; 등)로 변환
0.0  하나라도 원본 그대로
미관측  sentinel이 응답에 없음(필터링) 또는 본문 디코딩 실패
```

부분 인코딩(일부만 변환)은 `0.0`으로 본다. 하나라도 원본이면 그 문자로 탈출할
여지가 있기 때문이다. 판단 근거를 `details`에 문자별로 남긴다.

### 3. `dangerous_reflection_context`

marker 주변 문맥을 분류한다. `FEATURE_SCHEMA.md` §5의 수치화를 따른다.

```text
0.0  text-safe / unknown
0.5  attribute-like
1.0  script-like
```

**불확실하면 추측하지 않고 미관측으로 둔다.** §5가 이미 그렇게 지시한다.
문맥 파싱은 정규식이 아니라 `html.parser`(표준 라이브러리)로 구현한다.

주의: HTML-escape가 `<script>` 블록 안에서는 방어가 되지 않는다. 이 경우
`safe_html_encoding_detected = 1.0`이면서 `dangerous_reflection_context = 1.0`이
동시에 성립할 수 있고, 그것이 맞는 관측이다. 두 feature를 독립적으로 유지하고
scorer가 결합을 학습하게 둔다.

### 4. `reflection_count_norm`

```text
min(marker 등장 횟수 / 3, 1.0)
```

싸고 정의가 이미 확정돼 있다.

### 5. 정적 feature — `numeric_value`, `id_like_name`

`InputPoint.baseline_value`와 `name`에서 계산한다. 네트워크가 필요 없다.

이 둘이 있어야 `EVALUATION_PROTOCOL.md` §5의 **Baseline C가 정의대로**
구현된다. 현재는 "numeric parameter 우선" 절반이 빠진 채 reflection만 쓰고 있다.

### 6. 코퍼스 타겟 확장

`tools/corpus_target_site.py`가 현재 만드는 `xss_escaped`는 `html.escape()`를
일괄 적용해 분리가 지나치게 깔끔하다. 오라클 상한이 낙관적인 이유다. 실제 앱에
가깝게 어려운 사례를 추가한다.

```text
xss_partial_escape   < 만 막고 " 는 통과        -> 속성 탈출 가능, 취약
xss_attribute        속성 값에 반사, escape 됨   -> 안전
xss_script_context   <script> 안에 반사, HTML escape -> 여전히 취약
xss_filtered         위험 문자를 아예 제거       -> 안전하지만 sentinel 소실
```

마지막 사례가 1번의 3상태 처리를 실제로 검증한다.

### 7. Prior 가중치

`HEURISTIC_TERMS`에 새 feature의 prior를 추가한다. `FEATURE_SCHEMA.md` §7의
초안 가중치를 그대로 쓴다.

```text
safe_html_encoding_detected   -30   (penalty)
dangerous_reflection_context  +15
reflection_count_norm         +10
numeric_value                 +15   (SQLi)
```

## Interfaces / Data Changes

- `features/extraction.py`: feature 4개 -> 9개. 기존 4개의 계산은 불변.
- `observation/planner.py`: marker 형식 변경. `marker_strategy` 버전을 올리고
  기존 전략도 유지해 재현성을 지킨다.
- `FEATURE_SCHEMA_VERSION`을 올린다. 기존 코퍼스는 이전 버전으로 남고 새
  코퍼스와 섞이지 않는다.
- `scoring/engine.py`의 `XSS_TERMS`/`SQLI_TERMS`와
  `calibration.HEURISTIC_TERMS`에 항목 추가. **가중합 계산 방식은 불변.**
- `decision/`, `evaluation/`, `corpus/`는 **변경 없음.** feature 개수에
  무관하게 동작한다.

## Safety / Scope Impact

- **전송 내용이 바뀐다.** marker에 `<`, `>`, `"`, `'`가 포함된다. 파괴적이지
  않고 스크립트가 아니며 상태를 바꾸지 않는다. 2인 리뷰 대상.
- 요청 수는 늘지 않는다. 같은 baseline/probe 쌍에서 feature만 더 뽑는다.
- 대상은 여전히 loopback/localhost로 한정된다.
- ADR-004(one-at-a-time) 유지.

## Test Plan

- unit: sentinel 인코딩 판정 — 전체 인코딩 / 부분 인코딩 / 원본 / 소실
- unit: 3상태 구분 — 반사 안 됨 / 필터링됨(미관측) / 인코딩됨 / 원본
- unit: 문맥 분류 — text / attribute / script / 불확실(미관측)
- unit: script 문맥 + HTML escape 조합이 둘 다 관측되는지
- unit: `reflection_count_norm` 상한 clipping
- unit: `numeric_value`, `id_like_name` 순수 함수 검증
- unit: marker 전략 버전이 다르면 재현이 갈리는지
- integration: 확장된 타겟 사이트 4종에 대해 파이프라인 end-to-end
- regression: 기존 4개 feature 값이 바뀌지 않는지 (기존 코퍼스와 비교)

## Acceptance Criteria

- [ ] sentinel 이중 마커로 "필터링됨"을 미관측으로 구분
- [ ] `safe_html_encoding_detected` 구현, 부분 인코딩은 0.0
- [ ] `dangerous_reflection_context` 구현, 불확실하면 미관측
- [ ] `reflection_count_norm`, `numeric_value`, `id_like_name` 구현
- [ ] Baseline C가 §5 정의대로 동작
- [ ] 코퍼스 타겟에 부분 인코딩·속성·script 문맥·필터링 사례 추가
- [ ] 코퍼스 재수집 후 `tools/evaluate_ranking.py` 재측정
- [ ] `FEATURE_SCHEMA.md` §8의 13개 항목을 새 feature마다 기록
- [ ] ADR 기록 (marker sentinel, feature schema 버전 상승)
- [ ] 의존성 0개 유지, 기존 테스트 통과

## 측정 방법

feature를 하나 추가할 때마다 아래를 돌려 효과를 확인한다. 결정 계층과 평가
도구가 이미 있으므로 피드백 루프가 짧다.

```text
PYTHONPATH=src python tools/build_corpus.py --applications 14
PYTHONPATH=src python tools/evaluate_ranking.py
PYTHONPATH=src python tools/evaluate_heldout.py --top-k 5
```

비교 기준:

```text
현재      Brier 0.1134  Rec@3 0.869  MAP@5 0.871   XSS held-out 1/8
오라클    Brier 0.0628  Rec@3 0.964  MAP@5 1.000
```

**오라클에 미달하는 것이 정상이다.** 오라클은 완벽한 탐지를 가정하고, 확장된
타겟 사이트는 일부러 더 어렵게 만든다. 실제 목표는 "오라클 근접"이 아니라
**"XSS held-out recall이 1/8에서 유의미하게 오르는 것"**이다.

## Open Questions

- sentinel 문자 집합을 `<>"'` 로 할지 백틱과 백슬래시까지 넣을지. 넓힐수록
  탐지력은 오르지만 필터링 확률도 오른다. 좁게 시작하고 필요하면 넓힌다.
- 부분 인코딩을 `0.0`(위험)으로 볼지 `0.5`(중간)로 볼지. 초안은 `0.0`이다 —
  하나라도 원본이면 탈출 여지가 있기 때문. 실제 앱에서 재검토.
- `FEATURE_SCHEMA_VERSION` 상승 시 기존 `data/corpus/`를 유지할지 교체할지.
  비교를 위해 둘 다 남기는 쪽을 제안한다.
