# Dynamic-ready FeatureVector preprocessing

## Goal

Native Dynamic 및 Combined 수집 결과에서 하나의 `InputPoint`가 여러 개의
probe-ready `InputPointRequestContext`를 갖게 되었을 때에도
`FeatureVector`와 `VulnerabilityCandidate`가 도메인 규칙과 일치하도록
전처리를 수정한다.

- `FeatureVector`는 `docs/DOMAIN_MODEL.md` §9 정의대로 "하나의 InputPoint에
  귀속되는 feature 집합"이 되어야 하며 `probe_run_ids`는 그 InputPoint를
  관측한 모든 probe run을 담아야 한다.
- 랭킹 원자 단위는 `InputPoint x VulnerabilityType` (ADR-002)이므로 한 번의
  분석에서 같은 candidate id가 두 번 생성되면 안 된다.

## Non-Goals

- 새 feature 추가 (`numeric_value`, `reflection_count_norm` 등)는 하지 않는다.
- scorer 가중치 변경은 하지 않는다.
- Discovery/크롤러 쪽 로직은 바꾸지 않는다 (다른 owner 소유).
- POST request context 실행 허용은 하지 않는다. GET-only 안전 제약은 유지한다.

## Context Read

- AGENTS.md (도메인 규칙 2, 3, 8, 9)
- docs/DOMAIN_MODEL.md §9 `FeatureVector`, "FeatureVector identity"
- docs/FEATURE_SCHEMA.md §4-§7
- docs/DECISION_LOG.md ADR-002, ADR-008, ADR-010, ADR-011
- docs/TEAM_INTERFACES_V0_2.md §1, §2
- `src/vulnspider/discovery/{dynamic_crawler,rendered_dom,merge,combined}.py`
- `src/vulnspider/{features,scoring,selection,pipeline}.py`
- `src/vulnspider/reporting/{analysis_report,html_report,json_report}.py`

## Current State

Static 단일 시드 크롤에서는 하나의 `InputPoint`가 사실상 하나의
probe-ready context만 가졌기 때문에 다음 두 가정이 우연히 성립했다.

1. `FeatureVector` 하나 = probe run 하나
2. candidate id 하나 = `ScoringResult` 하나

Native Dynamic 크롤러(및 Static+Dynamic merge)는 같은 endpoint/파라미터를
서로 다른 값으로 여러 번 관측한다. 예: static이 `/search?q=one`,
dynamic 렌더링 링크가 `/search?q=two`를 발견하면

- `Endpoint`, `InputPoint` fingerprint는 동일 (경로/파라미터 이름 기준)
- `RequestTemplate`은 서로 다름 → `InputPointRequestContext` 2개, 둘 다 READY

가 되어 위 가정이 깨진다. 재현 결과(fake browser + fake transport):

```text
input points: 1
READY contexts: 2
feature vectors: 2   (같은 input_point_id)
scoring results: 4   (candidate id는 2개뿐)
```

확인된 영향:

- `select_top_k`가 중복 candidate를 조용히 접는다. 랭킹 결과 자체는 최댓값이
  선택되므로 맞지만, 근거가 어느 관측에서 왔는지 설명이 사라진다.
- 한 context는 관측에 실패하고(transport error) 다른 context는 성공하면 같은
  candidate id가 `selected`와 `unrankable`에 **동시에** 나타난다.
- `summary.total_scoring_results / rankable_results / unrankable_results`가
  candidate 단위가 아니라 관측 단위라서 리포트가 오해를 부른다.

추가로 발견한 것:

- `pipeline._analyze_contexts`의 GET-only skip 경고 문구가 collector와
  무관하게 "native static analysis"라고 말한다.
- `features.extraction._marker_reflected` / `_sql_error_pattern`이
  `decoded_text`가 없는 응답을 "관측했고 0.0"으로 기록한다. 도메인 규칙 8
  ("Missing feature is not observed zero") 위반이다.
- (별개 버그) 최상위 CLI 파서에 `--dynamic-allow-*`가 추가되면서
  `analyze ... --dynamic`이 argparse 축약 모호성으로 죽는다. Dynamic 경로를
  테스트할 수 없어 함께 고친다.

## Proposed Changes

1. `features/extraction.py`
   - `combine_input_point_features()` 추가. 같은 `InputPoint`의
     `FeatureVector`들을 하나로 합친다.
   - 합성 규칙(존재 기반 / existential):
     - feature별로 `observed=True`인 관측이 하나도 없으면 미관측으로 남긴다.
     - 하나 이상 있으면 값이 가장 큰 관측을 채택한다. 동점이면
       `probe_run_id` 오름차순으로 결정한다.
     - `details`에 채택된 run, 전체 run별 값, 미관측 run 수를 남긴다.
   - run이 하나뿐이면 입력 벡터를 그대로 반환한다(기존 동작 보존).
2. `pipeline.py`
   - `_analyze_contexts`가 실행 결과를 `input_point_id`로 묶고, InputPoint당
     한 개의 `FeatureVector`를 만든 뒤 `generate_candidates`를 호출한다.
   - `ProbeObservation.feature_vector_id`는 합성된 벡터를 가리킨다.
   - GET-only skip 경고에 실제 collector kind를 넣는다.
3. `reporting/analysis_report.py`
   - "관측 1개 = 벡터 1개" 검증을 "관측의 ResponsePair가 벡터의
     `probe_run_ids`에 있어야 하고, 벡터의 `probe_run_ids`는 그 벡터를
     소유한 관측들의 pair 집합과 정확히 일치해야 한다"로 바꾼다.
4. `reporting/html_report.py`, `cli.py`
   - `requests_executed`를 실제 실행된 probe run 수로 전달할 수 있도록
     선택적 인자를 추가한다. 벡터당 대표 probe run은 `probe_plan.id` 최소값으로
     결정적으로 고른다.
5. `cli.py`
   - 최상위 파서에 `allow_abbrev=False`를 지정해 `analyze --dynamic` 모호성을
     제거한다.
6. 문서
   - `docs/FEATURE_SCHEMA.md`에 multi-context 합성 규칙과 버전 기록.
   - `docs/DECISION_LOG.md`에 ADR-020 추가.

## Interfaces / Data Changes

- 새 public 함수 `vulnspider.features.combine_input_point_features`.
- 새 상수 `FEATURE_AGGREGATION_VERSION = "input-point-existential-v1"`.
- `FeatureVector` 모델 자체는 바뀌지 않는다. `probe_run_ids`가 원래 tuple로
  정의되어 있어 다중 run을 담을 수 있다.
- `AnalysisResult.feature_vectors`는 이제 InputPoint당 1개다.
- `build_html_report_context/render_html_report/write_html_report`에
  선택적 `requests_executed` 인자 추가(기본값은 기존 동작과 동일).

## Safety / Scope Impact

- 네트워크 요청 수/대상/메서드는 바뀌지 않는다. GET-only 제약 유지.
- 실행되는 probe 수는 이전과 동일하다(context 단위 실행 유지).
- 새 payload나 상태 변경 동작 없음.

## Test Plan

- unit (`tests/unit/test_candidate_scoring.py` 또는 신규):
  - 단일 run passthrough (동일 객체 반환)
  - 다중 run existential 합성, 동점 tie-break
  - 모든 run 미관측 → `observed=False`, value `None`
  - 일부 run 미관측 → 관측된 값 채택, details에 미관측 수 기록
  - 다른 InputPoint / 다른 schema version 혼합 시 거부
- unit (pipeline): 같은 InputPoint의 READY context 2개 → 벡터 1개,
  candidate 2개(type별 1개), `selected`/`unrankable` 교집합 없음
- unit (reporting): 합성 벡터를 가진 분석 결과로 analysis report 생성 성공
- 기존 전체 unit + integration 스위트 회귀

## Acceptance Criteria

- [x] 하나의 InputPoint는 한 번의 분석에서 하나의 `FeatureVector`만 만든다.
- [x] 같은 candidate id가 `selected`와 `unrankable`에 동시에 나오지 않는다.
- [x] 미관측 feature는 여전히 `observed=false`, `value=null`이다.
- [x] 채택된 feature 값의 출처 probe run이 details에 남는다.
- [x] Static 단일 context 결과는 기존과 동일한 벡터 id를 만든다.
- [x] `analyze --dynamic`이 다시 동작한다.
- [x] 전체 unit 스위트 통과.

## Progress Log

- 2026-08-10: 계획 작성. Dynamic/Combined 경로에서 multi-context InputPoint
  재현 완료 (fake browser + fake static transport). READY context 2개가
  FeatureVector 2개 / ScoringResult 4개(candidate id는 2개)를 만들고, 한
  context가 실패하면 같은 candidate가 `selected`와 `unrankable`에 동시에
  나타나는 것을 확인.
- 2026-08-10: 구현 완료. 같은 재현에서 FeatureVector 1개 / ScoringResult 2개,
  `selected` ∩ `unrankable` = ∅ 확인.
- 2026-08-10: 검증 완료.
  - `python -B -m unittest discover -s tests` → 459 tests OK
    (unit 405 + integration 54, Playwright Chromium 설치 후 브라우저 스위트
    포함)
  - `tools/check_format.py`, `tools/check_lint.py`, `tools/check_types.py`,
    `git diff --check` 모두 통과
  - 실제 loopback 타겟에 `vulnspider -u` 실행: JS로 삽입된
    `/search?q=rendered` 링크를 dynamic이 발견해 static의 `q=one`, `q=two`와
    합쳐져 READY context 4개 → FeatureVector 2개(InputPoint당 1개),
    ScoringResult 4개(=2 InputPoint x 2 type), 중복 candidate id 없음.
- 2026-08-10: 미해결 — Gate Review는 아직 받지 않았다. AGENTS.md의 Definition
  of Done을 채우기 전에는 `active/`에 둔다.

## Decision Log

- Decision: run 간 합성은 feature별 최댓값(존재 기반)으로 한다.
- Reason: `RankScore`는 검증 우선순위이지 취약 확률이 아니다(ADR-003, 도메인
  규칙 6). 같은 InputPoint를 서로 다른 context로 관측했을 때 어느 하나에서라도
  신호가 보였다면 그 InputPoint의 검증 우선순위는 올라가야 한다. 또한 기존
  `select_top_k`가 이미 중복 candidate 중 최댓값을 선택하고 있었으므로 랭킹
  결과의 연속성이 유지된다.
- Decision: 벡터를 합성하되 probe 실행은 context 단위로 유지한다.
- Reason: context 하나만 골라 실행하면 판별력 있는 관측을 임의로 버리게 된다.

## Open Questions

- 이후 BAC feature family가 추가되면 존재 기반 합성이 그대로 맞는지 재검토
  필요.
