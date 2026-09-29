# Dynamic 수집 이후의 전처리 수정 (팀 공유용)

> `feat/preprocess_han` 브랜치에서 **내가 고친 두 가지 버그**를 정리한 문서다.
> (브랜치의 Native Dynamic Discovery 구현 자체는 다른 분 작업이고, 이 문서는
> 그 위에 올라간 마지막 두 커밋 `1ebbc05`, `f81271c`를 다룬다.)
> PR #6으로 `main`에 머지 완료.

---

## 0. 30초 요약

Dynamic 크롤러가 붙으면서 **Static 시절에 우연히 성립하던 가정 두 개**가 깨졌고,
그걸 고쳤다.

| | 문제 | 고침 |
|---|---|---|
| **① CLI** | `analyze ... --dynamic`이 실행조차 안 되고 exit code 2로 죽음 | top-level 파서에 `allow_abbrev=False` |
| **② 전처리** | InputPoint 하나가 `FeatureVector` 여러 개 → 같은 후보가 중복 생성 | **InputPoint당 FeatureVector 1개**로 합성 (ADR-020) |

②가 본체다. 한 문장으로:

> **하나의 입력점을 여러 request context로 관측했으면, 그 관측들을 먼저 하나의
> feature 벡터로 합친 다음에 후보를 만든다.** 합성 규칙은 "존재 기반(existential)" —
> 어느 run에서든 신호가 보였으면 그 값을 채택한다.

---

## 1. 배경 — 왜 하필 지금 터졌나

### 1.1 용어 (읽기 전에 이것만)

| 용어 | 뜻 |
|---|---|
| **Endpoint** | 경로 단위. 예: `/search` |
| **InputPoint** | 사용자 입력이 들어가는 지점. 예: `/search`의 `q` 파라미터 |
| **RequestContext** | 그 InputPoint를 실제로 때릴 수 있는 **구체적 요청 템플릿**. 예: `/search?q=one` |
| **probe run** | baseline 요청 1회 + probe 요청 1회 = 응답 쌍 하나 |
| **FeatureVector** | 관측된 feature 묶음. **소유 단위는 InputPoint** (`docs/DOMAIN_MODEL.md` §9) |
| **Candidate** | `(InputPoint, 취약점 유형)` 쌍. **랭킹의 원자 단위** (ADR-002) |

### 1.2 Static에서는 우연히 맞았던 가정

Native Static 단일 시드 크롤에서는 InputPoint 하나가 사실상 probe-ready context를
**하나만** 가졌다. 그래서 아래 두 가정이 우연히 성립했다.

```text
가정 1:  FeatureVector 1개  =  probe run 1개
가정 2:  candidate id 1개   =  ScoringResult 1개
```

### 1.3 Dynamic이 붙으면서 깨진 것

Native Dynamic 크롤러(+ Static/Dynamic merge)는 **같은 endpoint의 같은 파라미터를
서로 다른 값으로 여러 번** 관측한다.

```text
static이 발견:            /search?q=one
렌더링된 링크에서 발견:    /search?q=two

→ Endpoint, InputPoint fingerprint 는 동일 (경로/파라미터 이름 기준)
→ RequestTemplate 만 다름  →  probe-ready RequestContext 2개, 둘 다 READY
```

즉 **InputPoint 1개인데 probe run은 2개**가 된다. 가정 1이 깨진다.

---

## 2. 버그 ① — `analyze --dynamic`이 파싱 단계에서 죽는다

간단 스캔(`vulnspider -u URL`) 작업이 top-level 파서에
`--dynamic-allow-navigation`, `--dynamic-allow-resource`를 추가했다.

argparse는 **subparser가 돌기 전에 모든 argv 토큰을 top-level 파서 기준으로 먼저
분류**한다. 그래서 `analyze` 서브커맨드의 `--dynamic`이 위 두 옵션의
**모호한 축약(ambiguous abbreviation)** 으로 해석되어, discovery가 한 줄도 돌기 전에
exit code 2로 끝났다.

```python
# src/vulnspider/cli.py — build_parser()
parser = argparse.ArgumentParser(
    prog="vulnspider",
    description="VulnSpider prototype command line interface.",
    # Simple-mode --dynamic-allow-* options otherwise make the analyze
    # subcommand's --dynamic an ambiguous top-level abbreviation.
    allow_abbrev=False,
    ...
)
```

`--version`, `--url` 같은 **정확히 일치하는** 옵션은 영향 없고, 서브파서 옵션도
그대로다.

> 이걸 먼저 고친 이유: **Dynamic 경로를 실행할 수 없으면 버그 ②를 재현조차 할 수
> 없다.** 그래서 별개 버그지만 같은 작업에 묶었다.

---

## 3. 버그 ② — InputPoint 하나가 후보를 두 번 만든다 (본체)

### 3.1 재현

fake browser + fake static transport로 재현한 결과:

```text
input points:     1
READY contexts:   2
feature vectors:  2   ← 같은 input_point_id 를 가진 벡터가 2개
scoring results:  4   ← 그런데 candidate id 는 2개뿐 (SQLi, XSS)
```

### 3.2 실제로 무엇이 깨졌나

**(가) 근거의 출처가 사라진다.**
`select_top_k`가 중복 candidate를 **조용히** 접는다. 최댓값이 선택되므로 랭킹 결과
자체는 맞지만, 그 점수가 **어느 관측에서 나왔는지** 설명이 없어진다.

**(나) 같은 후보가 `selected`와 `unrankable`에 동시에 나온다.**
context 하나는 transport error로 실패하고 다른 하나는 성공하면, **같은 candidate id가
양쪽 목록에 모두** 등장한다. 리포트 상 모순이다.

**(다) 요약 숫자가 candidate가 아니라 관측을 센다.**
`summary.total_scoring_results / rankable_results / unrankable_results`가 후보 개수가
아니라 관측 개수라서 리포트가 오해를 부른다.

### 3.3 왜 이게 "버그"인가 — 문서가 이미 정하고 있었다

- `docs/DOMAIN_MODEL.md` §9: `FeatureVector` = **"하나의 InputPoint + 그것을 만든
  probe run들"**. 애초에 `probe_run_ids`가 tuple로 정의되어 있었다.
- ADR-002: 랭킹 원자 단위는 `InputPoint × VulnerabilityType`. **한 번의 분석에서 같은
  candidate id가 두 번 생기면 안 된다.**

즉 새 규칙을 만든 게 아니라, **이미 있던 규칙에 구현을 맞춘 것**이다.

### 3.4 고침 — 존재 기반(existential) 합성

후보를 만들기 **전에**, 같은 InputPoint의 probe run 결과들을 feature 단위로 합친다.

```text
for each feature name:
    entries  = 그 InputPoint의 모든 probe run 관측
    observed = [e for e in entries if e.observed]

    if not observed:
        observed=false, value=null
        details.reason = "no-observed-probe-run"
    else:
        value = max(e.value for e in observed)
        동점이면 probe_run_id 오름차순으로 결정
```

핵심 성질 4가지:

1. **미관측은 관측을 가리지 못한다.** 반대로 **모든 run이 미관측이면 feature는
   미관측으로 남는다** (도메인 규칙 8: "미관측 ≠ 관측된 0").
2. **run이 하나뿐이면 원본 벡터를 그대로 반환한다.** → Static 단일 context 결과는
   **벡터 id까지 기존과 동일**하다. 회귀 없음.
3. **probe 실행은 계속 context 단위로 한다.** context 하나만 골라 실행하면 판별력 있는
   관측(예: 정상 숫자 baseline vs 이미 깨진 baseline)을 임의로 버리게 된다.
   **관측은 하나도 안 버린다. 합치기만 한다.**
4. **서로 다른 extractor version이 같은 feature 이름을 만들면 합성하지 않고 실패한다.**

### 3.5 왜 `max`인가 (합성 규칙의 근거)

`RankScore`는 **취약 확률이 아니라 검증 우선순위**다(ADR-003, 도메인 규칙 6).
같은 InputPoint를 여러 request context로 관측했을 때 **그중 하나에서라도 신호가
보였다면 그 InputPoint를 먼저 검증해야 한다.**

게다가 기존 `select_top_k`가 이미 중복 candidate 중 최댓값을 고르고 있었으므로,
**랭킹 결과의 연속성이 유지된다** — 바뀐 건 결과가 아니라 회계(accounting)와 설명
가능성이다.

### 3.6 추적성 — `details`에 남기는 것

합성된 값은 **단일 요청 한 쌍의 재현이 아니다.** (feature A는 run 1에서, feature B는
run 2에서 올 수 있다.) 그래서 출처를 전부 남긴다.

| 키 | 내용 |
|---|---|
| `aggregation` | 합성 정책 버전 = `input-point-existential-v1` |
| `aggregated_probe_run_ids` | 합성에 참여한 probe run 전체 |
| `selected_probe_run_id` | **채택된 값을 만든 run** |
| `probe_run_values` | run별 값 (미관측이면 `null`) |
| `unobserved_probe_runs` | 미관측 run 수 |

---

## 4. 같이 고친 작은 것들

- **디코딩 실패 응답을 "관측된 0.0"으로 기록하던 문제.**
  `ResponseSnapshot.decoded_text is None`인데도 `marker_reflected` /
  `sql_error_pattern`이 "확인했고 0.0"으로 기록했다. **도메인 규칙 8 위반**이라
  미관측(`details.reason = "response-body-not-decoded"`)으로 바꿨다.
- **GET-only skip 경고가 거짓말하던 문제.**
  collector가 뭐든 상관없이 `"native static analysis..."`라고 찍었다. 실제
  collector kind를 넣도록 고쳤다.
- **HTML 리포트.** 벡터 하나에 관측이 여러 개 붙을 수 있으므로, 대표 probe run을
  임의의 마지막 것이 아니라 **`ProbePlan.id` 최소값으로 결정적으로** 고른다.
  `requests_executed`도 실제 실행된 요청 수로 넘긴다.

---

## 5. 팀에 영향 있는 변경 (이 절만은 꼭)

| 항목 | 내용 |
|---|---|
| 새 public 함수 | `vulnspider.features.combine_input_point_features()` |
| 새 상수 | `FEATURE_AGGREGATION_VERSION = "input-point-existential-v1"` |
| `AnalysisResult.feature_vectors` | **이제 InputPoint당 1개** |
| `ProbeObservation` | **여러 관측이 같은 `feature_vector_id`를 공유할 수 있다** |
| 리포팅 join 규칙 | "관측 1개 = 벡터 1개" 가정 금지. 벡터의 `probe_run_ids` **멤버십**으로 join |
| HTML 리포트 API | `build_html_report_context` / `render_html_report` / `write_html_report`에 optional `requests_executed` 추가 (기본값은 기존 동작과 동일) |
| `FeatureVector` 모델 | **안 바뀜.** `probe_run_ids`가 원래 tuple이라 다중 run을 담을 수 있었다 |
| 네트워크 동작 | **안 바뀜.** 요청 수/대상/메서드 동일, GET-only 유지, 새 payload 없음 |

> ⚠️ **가장 중요한 주의:** 합성된 feature 값은 **요청 한 쌍의 재현이 아니다.**
> 어느 run에서 왔는지는 항상 `selected_probe_run_id`로 설명할 수 있어야 한다.
> 리포트나 후속 분석에서 "이 벡터 = 이 요청" 이라고 가정하지 말 것.

---

## 6. 검증

- **신규 unit 테스트 23개** — `tests/unit/test_feature_aggregation.py` (14),
  `tests/unit/test_native_pipeline_cli.py` (9). 단일 run passthrough, 다중 run 합성,
  동점 tie-break, 전부 미관측, 일부 미관측, 다른 InputPoint/schema 혼합 시 거부,
  `selected` ∩ `unrankable` = ∅ 등.
- **전체 스위트 459개 통과** (unit 405 + integration 54, Playwright Chromium 포함).
  `check_format` / `check_lint` / `check_types` / `git diff --check` 모두 통과.
- **실제 loopback 타겟에 `vulnspider -u` 실행:**

  ```text
  JS로 삽입된 /search?q=rendered 를 dynamic 이 발견
    + static 의 q=one, q=two
  → READY context 4개
  → FeatureVector 2개  (InputPoint당 1개)  ✅
  → ScoringResult 4개  (= 2 InputPoint × 2 type)  ✅
  → 중복 candidate id 없음  ✅
  ```

- 재현 전/후 비교:

  | | 고치기 전 | 고친 후 |
  |---|---|---|
  | FeatureVector | 2 (같은 InputPoint) | **1** |
  | ScoringResult | 4 (candidate는 2개) | **2** |
  | `selected` ∩ `unrankable` | 발생 가능 | **∅** |

---

## 7. 남은 일

1. **Gate Review 미수령.** AGENTS.md의 Definition of Done을 아직 못 채워서 실행 계획이
   `docs/exec-plans/active/`에 남아 있다. (`completed/`로 옮기려면 리뷰 필요)
2. **BAC feature family가 추가되면** 존재 기반(max) 합성이 그대로 맞는지 재검토해야
   한다. "어느 하나에서라도 보였으면 우선순위 ↑"가 BAC에서도 성립하는지는 별도 판단.

**이번에 일부러 안 한 것 (non-goals):** 새 feature 추가(`numeric_value`,
`reflection_count_norm` 등), scorer 가중치 변경, Discovery/크롤러 로직 변경,
POST request context 실행 허용(GET-only 안전 제약 유지).

---

## 8. 참고

| 무엇 | 어디 |
|---|---|
| 결정 근거 | `docs/DECISION_LOG.md` **ADR-020** |
| 합성 규칙 명세 | `docs/FEATURE_SCHEMA.md` **§7-1 Multi-context InputPoint 합성** |
| 실행 계획 | `docs/exec-plans/active/dynamic-multi-context-feature-vectors.md` |
| 코드 | `src/vulnspider/features/extraction.py`, `src/vulnspider/pipeline.py`, `src/vulnspider/cli.py` |
| 커밋 | `1ebbc05` (CLI), `f81271c` (전처리) — PR #6 |
