# HTML Dashboard Report

## Goal

CLI JSON 출력과 동일한 검증된 데이터(SelectionOutcome, 실제 실행된
baseline/probe 요청·응답)를 사람이 브라우저에서 바로 검토할 수 있는 단일
정적 HTML 대시보드 파일로도 생성한다. `vulnspider analyze`에 `--html-output`
옵션을 추가해 JSON 리포트와 함께(또는 대신) 생성할 수 있게 한다.

## Non-Goals

- Focused/multi-payload verification을 새로 만들지 않는다. v0.1 Light Probe는
  InputPoint당 baseline 1회 + probe 1회만 보낸다
  (`docs/ARCHITECTURE.md` §2.2). 대시보드는 실제로 전송된 이 한 쌍만
  보여주고, 여러 개의 SQLi/XSS 확인용 payload를 보낸 것처럼 표시하지 않는다.
- `RankScore`/`selection_priority`를 vulnerability probability나
  confidence로 표현하지 않는다 (`AGENTS.md` 규칙 5-6, ADR-010).
- BAC/IDOR 후보를 만들지 않는다. scoring이 SQLI/REFLECTED_XSS만 생성하므로
  대시보드도 이 두 유형만 렌더링한다.
- 실시간 서버, 자동 새로고침, JS 기반 인터랙션 없음 — 완전히 정적인 단일
  HTML 파일.
- 새 서드파티 의존성 추가 없음 (`pyproject.toml`의 `dependencies = []` 유지,
  표준 라이브러리 `html.escape`만 사용).
- `reporting`이 점수를 재계산하지 않는다는 기존 규칙 유지
  (`docs/ARCHITECTURE.md` §6).

## Context Read

- `AGENTS.md`
- `PLANS.md`
- `CODE_REVIEW.md`
- `docs/ARCHITECTURE.md`
- `docs/DOMAIN_MODEL.md`
- `docs/FEATURE_SCHEMA.md`
- `docs/PROTOTYPE_V0_1.md`
- `docs/DECISION_LOG.md`
- `src/vulnspider/reporting/json_report.py`
- `src/vulnspider/pipeline.py`
- `src/vulnspider/cli.py`
- `src/vulnspider/observation/executor.py`, `planner.py`
- `src/vulnspider/domain/models.py`
- `src/vulnspider/scoring/engine.py`, `src/vulnspider/selection/top_k.py`
- `tests/unit/test_selection_reporting.py`
- `tests/integration/test_v01_smoke.py`
- 사용자가 첨부한 `report.html` (디자인 참고용 목업 — 이 repo의 어느
  브랜치(main/`prototype_han`/`prototype_seok`)에도 존재하지 않음을 확인함.
  참고만 하고 내용은 그대로 복사하지 않는다. 특히 "confidence %"와
  다건(多件) "Verification payload" 표는 그대로 재현하지 않는다: 전자는
  AGENTS.md 규칙 5-6 위반, 후자는 v0.1이 실제로 보내지 않는 payload를
  보낸 것처럼 보이는 허위 표시가 된다.)

## Current State

- `pipeline.analyze_legacy_records()`가 InputPoint마다 `ProbePlan`을 만들고
  `RequestExecutor.execute_plan()`으로 baseline/probe 요청을 실행하지만,
  feature 추출 이후 `ProbePlan`/`ResponseSnapshot`은 버려진다. `AnalysisResult`
  에는 `adapter_result`, `scoring_results`, `selection`, `warnings`만 남는다.
- `reporting/json_report.py`는 `SelectionOutcome`만으로 결정적 JSON을
  만든다. endpoint/param 표시용 `InputPoint`/`Endpoint` 조인이나 실제 probe
  payload는 포함하지 않는다.
- `cli.py`의 `analyze` 서브커맨드는 `--output`(JSON) 하나만 필수로 받는다.
- `AGENTS.md:41`, `docs/PROTOTYPE_V0_1.md:70`, `docs/ARCHITECTURE.md:338`이
  모두 "dashboard"를 v0.1 out-of-scope로 명시한다 (main/seok 브랜치도 동일).
- 180개 단위/통합 테스트가 현재 모두 통과 (`python -m unittest discover -s
  tests`).

## Proposed Changes

1. **Docs (스코프 변경 공식화)**
   - `docs/DECISION_LOG.md`: ADR-011 추가 (dashboard in-scope로 전환, 근거와
     제약 명시).
   - `AGENTS.md`, `docs/PROTOTYPE_V0_1.md`, `docs/ARCHITECTURE.md`: "dashboard"를
     out-of-scope 목록에서 제거하고 in-scope Output에 추가. "focused
     verification"은 계속 out-of-scope로 유지 (별개 항목).
2. **`pipeline.py`**
   - `ProbeObservation` frozen dataclass 추가: `feature_vector_id`,
     `input_point_id`, `probe_plan: ProbePlan`, `baseline_response:
     ResponseSnapshot`, `probe_response: ResponseSnapshot`.
   - 루프에서 `execution`을 소비할 때 하나씩 기록.
   - `AnalysisResult`에 `probe_observations: tuple[ProbeObservation, ...]`,
     `elapsed_seconds: float`(루프 전체를 `time.monotonic()`으로 측정) 필드
     추가.
3. **`reporting/html_report.py`** (신규)
   - `build_html_report_context(outcome, *, warnings=(), input_points={},
     endpoints={}, probe_runs={}, target="")`: 검증된 plain-data 컨텍스트
     (dict/dataclass) 생성. `outcome.validate()` 재검증 후 `ReportingError`
     재사용.
   - `probe_runs`는 `feature_vector_id -> (ProbePlan, baseline_response,
     probe_response)` 매핑으로 받는다 — `reporting`이 `pipeline`을 import하지
     않도록 pipeline 전용 타입 대신 domain 타입 3-튜플을 사용
     (의존성 방향 `reporting -> ... -> domain` 유지, `docs/ARCHITECTURE.md`
     §6).
   - `render_html_report(...)`: 표준 라이브러리만으로 HTML 문자열 생성.
     모든 문자열 보간은 `html.escape()`로 이스케이프 (endpoint/param/evidence
     reason/warning 등은 크롤링된 실제 응답에서 온 신뢰할 수 없는 데이터일 수
     있음 — 리포트 자체의 XSS를 방지).
   - `write_html_report(...)`: 파일로 저장.
   - 용어: `selection_priority`는 "priority" 라벨과 백분율 막대로 표시하되
     "confidence"/"probability"/"confirmed" 단어를 쓰지 않는다.
   - "Why it ranks" 섹션: 기존 JSON evidence를
     `[vuln_type] feature=value x weight -> contribution` 형태로 표시(JSON
     리포트와 동일 데이터, 새 계산 없음).
   - "Executed requests" 섹션: `probe_runs`에서 찾은 실제 baseline/probe 요청
     2건을 role/URL 또는 변경된 필드+주입 값/status/응답 길이/elapsed_ms로
     표시. 데이터가 없으면(예: 유닛 테스트가 outcome만 넘긴 경우) 섹션을
     생략.
   - 상단 요약 통계: endpoints/input points 수(`endpoints`,`input_points`
     매핑 크기), selected(top-K), 실행된 요청 수(`2 * len(probe_runs)`),
     `elapsed_seconds`. 값이 없으면 0 또는 생략.
   - unrankable/warnings 섹션 포함(JSON 리포트와 동일하게 숨기지 않음).
4. **`reporting/__init__.py`**: 새 공개 함수 export.
5. **`cli.py`**: `analyze`에 선택적 `--html-output PATH` 인자 추가. 지정 시
   `analysis.adapter_result.input_points`/`endpoints`를 id로 인덱싱하고
   `analysis.probe_observations`를 `feature_vector_id`로 인덱싱해
   `write_html_report`에 전달.

## Interfaces / Data Changes

```text
pipeline.AnalysisResult
  + probe_observations: tuple[ProbeObservation, ...]
  + elapsed_seconds: float

pipeline.ProbeObservation (new)
  feature_vector_id: str
  input_point_id: str
  probe_plan: ProbePlan
  baseline_response: ResponseSnapshot
  probe_response: ResponseSnapshot

reporting.html_report (new module)
  build_html_report_context(outcome, *, warnings=(), input_points={}, endpoints={}, probe_runs={}, target="") -> dict
  render_html_report(outcome, **same kwargs) -> str
  write_html_report(outcome, destination, **same kwargs) -> None

cli analyze
  + --html-output PATH (optional)
```

기존 `build_json_report`/`render_json_report`/`write_json_report`,
`AnalysisResult`의 기존 4개 필드, 기존 CLI 인자는 그대로 유지 — 이번
변경은 순수 추가(additive)이며 기존 시그니처를 깨지 않는다.

## Safety / Scope Impact

- 네트워크 동작 변경 없음: 새 요청을 보내지 않고, 이미 실행된
  baseline/probe 요청·응답을 리포트에 노출만 한다.
- 권한/스코프 가드(loopback-only 등) 변경 없음.
- 새로운 위험: 리포트 HTML에 크롤링된 응답 텍스트(예: evidence reason,
  endpoint path)를 보간하므로, 이스케이프 누락 시 리포트 자체가 XSS
  벡터가 될 수 있다. 모든 보간값에 `html.escape()`를 강제한다.

## Test Plan

- unit: `tests/unit/test_html_reporting.py`
  - 결정적 출력(동일 입력 → 동일 HTML 문자열).
  - endpoint/param/evidence reason에 `<script>` 등 위험 문자 포함 시
    이스케이프되는지.
  - "confidence"/"probability"/"confirmed" 단어가 출력에 없는지(기존 JSON
    테스트와 동일한 불변식).
  - `input_points`/`endpoints`/`probe_runs`를 비워도 예외 없이 렌더링되는지
    (graceful degradation).
  - 손상된 `SelectionOutcome`에 대해 `ReportingError`로 재검증 실패하는지
    (`test_selection_reporting.py`의 `test_reporting_boundary_*`와 동일
    패턴).
- integration: `test_v01_smoke.py`의 기존 CLI 스모크 테스트에 `--html-output`
  경로를 추가하고, 생성된 HTML에 실제 후보/증거/실행된 요청 정보가
  들어있는지 확인.
- negative: `--html-output` 없이 실행 시 기존 동작(온리 JSON) 회귀 없는지.

## Acceptance Criteria

- [x] `vulnspider analyze --input ... --top-k N --output result.json
      --html-output result.html` 실행 시 두 파일 모두 생성된다.
- [x] `--html-output` 생략 시 기존 동작과 100% 동일(회귀 없음).
- [x] HTML 리포트의 모든 수치·근거는 JSON 리포트와 동일한 `SelectionOutcome`
      에서 유도되며 별도로 재계산되지 않는다.
- [x] "confidence"/"probability"/"confirmed" 문구가 HTML에 없다.
- [x] "Executed requests" 섹션은 실제로 전송된 baseline/probe 요청만
      보여주며, 존재하지 않는 다건 payload를 만들어내지 않는다.
- [x] 모든 보간 텍스트가 이스케이프된다(수동 XSS 페이로드 픽스처로 확인).
- [x] `python -m unittest discover -s tests`, `check_format.py`,
      `check_lint.py`, `check_types.py` 모두 통과.
- [x] `docs/DECISION_LOG.md`, `AGENTS.md`, `docs/PROTOTYPE_V0_1.md`,
      `docs/ARCHITECTURE.md`가 새 스코프를 반영한다.

## Progress Log

- 2026-07-12: 사용자 요청 접수. AGENTS.md/PROTOTYPE_V0_1.md/ARCHITECTURE.md가
  dashboard를 out-of-scope로 명시하고 있음을 확인, 사용자에게 스코프 확장
  여부와 리포트 범위(최소/확장/전체 재현)를 확인함 → "정식 스코프 확장" +
  "전체 재현(파이프라인 확장)" 선택 받음. "전체 재현"은 실제로 v0.1이
  전송하는 baseline/probe 1쌍의 재현으로 해석하고(허구의 다건 payload 표는
  별도 out-of-scope인 focused verification이므로 제외), 이 계획 문서 작성.
- 2026-07-12: 구현 완료.
  - `docs/DECISION_LOG.md`에 ADR-011 추가; `AGENTS.md`,
    `docs/PROTOTYPE_V0_1.md`(§13 신설), `docs/ARCHITECTURE.md`에서
    dashboard를 out-of-scope 목록에서 제거하고 in-scope로 반영.
  - `pipeline.py`: `ProbeObservation` 추가, `AnalysisResult`에
    `probe_observations`/`elapsed_seconds` 필드 추가(순수 추가, 기존
    시그니처 불변). 기존 180개 테스트 회귀 없음 확인.
  - `reporting/html_report.py` 신규 구현. 초안 작성 중 발견/수정한 실제
    버그: (1) `ScoringResult`를 `vulnspider.selection`이 아니라
    `vulnspider.scoring`에서 import해야 했음, (2) 헤더에 `<span "ver">`
    같은 잘못된 HTML 속성, (3) 가장 중요한 문제 — 후보 카드 렌더링에서
    `f"""..."""`(삼중 큰따옴표) f-string의 `{}` 표현식 안에서 동일한
    큰따옴표로 dict 접근(`candidate["rank"]`)을 하거나 `{}` 안에 백슬래시가
    들어간 중첩 f-string을 쓰는 실수가 있었음 — 둘 다 `pyproject.toml`의
    `requires-python = ">=3.11"`에서는 실제 `SyntaxError`가 난다(3.12의
    PEP 701 전에는 f-string 표현식 안에서 바깥과 같은 인용부호 재사용과
    백슬래시가 금지됨). 값을 지역 변수로 미리 계산해 `{}` 안에는 변수명만
    넣는 방식으로 고쳐 해결. 자체 smoke 스크립트로 실행 후 발견.
  - 진실성 불변식(문구) 재확인 중, 각주/안내 문구에서 "confidence"를
    부정하는 문장("not a confirmed exploit or a vulnerability
    probability")조차 금지어 그 자체를 포함한다는 점을 발견 — 부정문이라도
    금지어를 아예 쓰지 않도록 문구를 다시 씀("not a verified exploit",
    "verification-priority signal, not a vulnerability verdict" 등).
  - 브라우저(Browser pane)로 실제 렌더링 확인: escaping이 DOM에서도
    올바르게 동작(공격 payload가 텍스트로만 보이고 실행되지 않음),
    accessibility tree로 레이아웃 구조 확인. 스크린샷 캡처 자체는 이
    세션의 Browser pane에서 반복적으로 timeout됐지만(콘솔 에러 없음,
    get_page_text/read_page는 정상 동작) 코드 문제로 보이지 않음.
  - `reporting/__init__.py`, `cli.py`(`--html-output` 선택 인자) 연결.
  - 신규 테스트: `tests/unit/test_html_reporting.py`(11개),
    `tests/integration/test_v01_smoke.py`에 HTML 종단 검증 + "플래그
    생략 시 회귀 없음" 테스트 추가.
  - 최종 검증: `python -m unittest discover -s tests` 192 passed;
    `check_format.py`/`check_lint.py`/`check_types.py` 모두 통과.
  - 커밋은 수행하지 않음(사용자가 명시적으로 요청할 때까지 보류).

## Decision Log

- Decision: dashboard를 v0.1 in-scope로 전환한다(ADR-011).
  Reason: 사용자가 CLI JSON과 별개로 검토용 웹 대시보드를 명시적으로
  요청했고, 정식 스코프 확장 프로세스(PLANS.md)를 따르기로 확인함.
- Decision: `selection_priority`는 "priority"로만 표기하고 confidence/
  probability 언어를 쓰지 않는다.
  Reason: AGENTS.md 규칙 5-6, ADR-010과 충돌 방지.
- Decision: "Verification payload" 절은 실제 실행된 baseline/probe 1쌍만
  보여준다.
  Reason: v0.1은 focused/multi-payload verification을 구현하지 않음
  (ARCHITECTURE.md §2.2). 존재하지 않는 payload를 표시하면 허위 증거가 된다.
- Decision: `reporting/html_report.py`는 `pipeline`을 import하지 않고
  `probe_runs`를 `(ProbePlan, ResponseSnapshot, ResponseSnapshot)` 3-튜플
  매핑으로 받는다.
  Reason: `docs/ARCHITECTURE.md` §6 의존성 방향(`reporting -> ... ->
  domain`)을 유지하기 위함.

## Open Questions

- 없음 (범위는 사용자 확인 완료). 후속 버전에서 실제 multi-payload focused
  verification을 추가하면 이 대시보드의 "Executed requests" 섹션을 확장할
  수 있다는 점만 메모.
