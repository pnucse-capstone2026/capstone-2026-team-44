# VulnSpider v0.2 - Native Static Discovery MVP

## Goal

사용자가 명시한 root URL에서 bounded Native Static Crawler를 실행해
same-origin HTML page, link, query, GET/POST form과 input control을 수집하고,
canonical domain model로 변환한 뒤 기존 Observation / Feature / Scoring /
Top-K / JSON 및 optional HTML reporting 경로에 연결한다.

최종 실행 흐름:

```text
URL input
  -> root URL / scope / budget validation
  -> bounded native static crawl
  -> HTML link, query, form, input extraction
  -> CanonicalDiscoveryResult
  -> existing observation / features / scoring / Top-K
  -> JSON report
  -> optional HTML report
```

기존 `vulnspider analyze --input <legacy-records.json>` 경로는 그대로
유지하고 URL 기반 입력을 additive하게 추가한다.

이 계획은 다음을 동시에 보장하는 foundation을 대상으로 한다.

- 기존 `Endpoint`, `InputPoint`, `RequestTemplate`,
  `InputPointRequestContext`의 v0.1 identity와 ownership 의미를 재사용한다.
- collector가 ordered/repeated parameter, raw query, form boundary, hidden
  input, source provenance를 손실 없이 전달한다.
- 정확한 요청을 만들 수 없는 surface도 버리지 않되 명시적으로
  non-probe-ready로 표시하고 실행 경계에서는 fail-closed한다.
- static/dynamic collector가 같은 surface에 대해 같은 child identity를
  만들고, 전체 출력과 직렬화 순서는 입력 순서와 무관하게 결정적이다.
- `LegacyCrawlerAdapter`는 v0.1 호환과 regression을 위한 별도 wrapper
  경로로만 연결하고 native provenance를 주장하지 않는다.
- BAC에는 정적 경로, 리소스, identifier 후보 힌트만 전달하며 access
  candidate, feature, score, global Top-K 정책은 만들지 않는다.

## Non-Goals

- 실제 HTTP 요청 또는 crawler transport
- Native Dynamic Crawler, Playwright, Selenium, JavaScript rendering
- SPA route 자동 탐색 또는 browser event 실행
- login 자동화, role/session switching
- form 자동 제출. GET/POST form은 발견하고 template만 생성한다.
- same-origin 밖의 crawl, public-site 자동 테스트, 대량 crawling
- robots.txt 또는 anti-bot 우회, CAPTCHA 우회
- BAC access-context 최종 모델, feature extraction, scoring, Top-K 비교
- SQLi / Reflected XSS feature 또는 scoring 변경
- LLM context, payload mutation, `PayloadValidator`, focused verification,
  confidence update
- 기존 report 의미 또는 dashboard 계산 로직 변경
- v0.1 pipeline 또는 legacy adapter의 대규모 리팩터링
- 기존 architecture 문서, ADR, Git workflow 문서 변경
- legacy runtime 또는 SQLite schema를 core contract에 포함하는 작업
- 인증 우회, brute force, exploit payload 확대
- 비범위 기능을 위한 placeholder framework

## Context Read

계획 작성 시 다음 문서, 코드, 테스트를 확인했다. 문서와 구현이 다른
경우 코드와 테스트를 현재 source of truth로 사용했다.

### Repository rules and architecture

- `AGENTS.md`
- `PLANS.md`
- `CODE_REVIEW.md`
- `README_START_HERE.md`
- `docs/PROTOTYPE_V0_2.md`
- `docs/TEAM_INTERFACES_V0_2.md`
- `docs/ARCHITECTURE.md`
- `docs/DOMAIN_MODEL.md`
- `docs/DECISION_LOG.md`
- `docs/LEGACY_AUDIT.md`

### Implemented code

- `src/vulnspider/domain/models.py`
- `src/vulnspider/domain/__init__.py`
- `src/vulnspider/discovery/legacy_adapter.py`
- `src/vulnspider/discovery/__init__.py`
- `src/vulnspider/observation/planner.py`
- `src/vulnspider/observation/executor.py`
- `src/vulnspider/pipeline.py`
- `src/vulnspider/cli.py`
- empty package shells under `src/vulnspider/scope/` and
  `src/vulnspider/surface/`

### Tests and fixtures

- `tests/unit/test_domain_models.py`
- `tests/unit/test_legacy_adapter.py`
- `tests/unit/test_probe_planner.py`
- `tests/integration/test_v01_smoke.py`
- `tests/fixtures/legacy_crawl_records.json`
- completed execution-plan examples under `docs/exec-plans/completed/`

Planning baseline:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_domain_models `
  tests.unit.test_legacy_adapter `
  tests.unit.test_probe_planner `
  tests.integration.test_v01_smoke
```

2026-07-26 기준 동일한 명령을 workspace Python으로 실행했으며 113개
테스트가 통과했다. 현재 shell의 `PATH`에는 `python`이 없으므로 실제 구현
세션에서는 repository 문서의 명령을 실행할 수 있는 Python 환경을 먼저
활성화하거나 명시적인 Python executable을 사용한다.

## Current State

### Repository structure and actual call flow

구현된 v0.1 호출 흐름은 다음과 같다.

```text
cli.main()
  -> _load_legacy_records()
  -> pipeline.analyze_legacy_records()
  -> LegacyCrawlerAdapter.convert()
  -> LegacyAdapterResult
       Endpoint[]
       InputPoint[]
       RequestTemplate[]
       InputPointRequestContext[]
       warning strings
  -> each InputPointRequestContext sorted by id
  -> ProbePlanner.plan()
  -> RequestExecutor.execute_plan()
  -> extract_minimal_features()
  -> generate_candidates()
  -> select_top_k()
  -> JSON and optional HTML reporting
```

`pipeline.py`는 adapter가 반환한 `InputPointRequestContext`를 순회하면서
`input_point_id`와 `request_template_id`를 lookup한다. 참조가 없으면
`PipelineError`를 내고, loopback URL만 허용한 뒤 planner를 호출한다.
planner는 context ownership을 다시 확인하고
`RequestContextCompleteness.COMPLETE`가 아니거나 structured
non-probe-ready reason이 있으면 요청을 만들지 않는다.

현재 `scope/`와 `surface/`는 `__init__.py`만 있는 package shell이다.
run-level discovery contract, native collector, scope/budget authority는
구현되어 있지 않다.

### Existing deterministic identity

`domain/models.py`는 Python built-in `hash()` 대신 canonical JSON과
SHA-256을 사용하는 `stable_fingerprint()`를 제공한다.

- `Endpoint`: method + normalized scheme + normalized host + canonical path
- `InputPoint`: endpoint fingerprint + location + normalized name + optional
  auth context + optional occurrence index
- `RequestTemplate`: endpoint ownership + method/URL + canonical
  headers/cookies + ordered query/form pairs + completeness + context key +
  provenance
- `InputPointRequestContext`: InputPoint id + RequestTemplate id + role

`RequestTemplate.query`와 `form`은 ordered pair tuple이다. mapping 입력은
정렬되지만 sequence 입력은 순서와 duplicate name을 보존한다. URL query는
adapter에서 `parse_qsl(..., keep_blank_values=True)`로 읽으며, URL 순서를
legacy JSON metadata보다 우선한다.

### Objects produced by LegacyCrawlerAdapter

`LegacyCrawlerAdapter.convert()`는 immutable result container인
`LegacyAdapterResult`를 반환한다.

| Output | Current construction |
| --- | --- |
| `Endpoint` | query는 `GET`, form은 resolved action과 normalized method로 생성 |
| `InputPoint` | query/form name별 생성, repeated query와 stable form duplicate는 occurrence-level로 생성 |
| `RequestTemplate` | raw URL, ordered query/form pairs, context key, provenance와 completeness 보존 |
| `InputPointRequestContext` | `from_objects()`로만 생성하여 association을 즉시 검증 |
| `warnings` | deterministic conversion 과정의 사람이 읽는 문자열 tuple |

현재 adapter의 중요한 보존 동작은 다음과 같다.

- 동일 query name의 occurrence index와 동일 값 repeated occurrence를
  구분한다.
- blank query value를 빈 문자열로 보존한다.
- URL query order를 authoritative source로 사용한다.
- stable form boundary가 있으면 duplicate same-name form control을 ordered
  occurrence로 보존한다.
- hidden input이 legacy record에 존재하면 버리지 않는다.
- missing method/action default와 provenance를 구분한다.
- form boundary 또는 hidden-input completeness를 알 수 없는 legacy form은
  `PARTIAL`/ambiguous와 structured reason을 남긴다.
- 반환 tuple은 fingerprint 또는 id 기준으로 정렬한다.

### LegacyAdapterResult limitations

`LegacyAdapterResult`는 canonical child object를 만들지만 v0.2
cross-owner contract 자체는 아니다.

- `contract_version`, `discovery_run_id`, collector policy/config identity가
  없다.
- validated `target_scope_id`, scope-decision reference, budget summary가
  없다.
- count/budget consistency를 검증하는 `CrawlStatistics`가 없다.
- provenance가 여러 child metadata와 warning string에 분산되어 있고
  run-level 참조 무결성 검증이 없다.
- probe readiness가 first-class record가 아니라 template completeness와
  metadata를 planner가 해석해서 결정한다.
- 전체 object graph에서 duplicate id, unresolved reference, endpoint
  fingerprint mismatch, statistics mismatch를 한 번에 검증하는 handoff
  boundary가 없다.
- warning이 structured code가 아니므로 consumer가 안전 결정을 위해
  파싱해서는 안 된다.
- BAC static hint 경계가 없다.
- `LegacyCrawlRecord`와 `LegacyAdapterResult`는 compatibility 내부
  object이며 core contract에 노출되면 안 된다.

## Proposed Changes

### Contract shape

새 모델은 `src/vulnspider/discovery/contracts.py`에 둔다. discovery
producer가 소유하는 run-level handoff이므로 기존 injection/observation
domain model을 복제하지 않는다.

```text
CanonicalDiscoveryResult
  contract_version
  discovery_run_id
  discovery_metadata: DiscoveryMetadata
  scope_metadata: ScopeMetadata
  crawl_statistics: CrawlStatistics
  endpoints: tuple[Endpoint, ...]
  input_points: tuple[InputPoint, ...]
  request_templates: tuple[RequestTemplate, ...]
  input_point_request_contexts: tuple[InputPointRequestContext, ...]
  probe_readiness: tuple[ProbeReadiness, ...]
  crawl_provenance: tuple[DiscoveryProvenance, ...]
  bac_static_hints: tuple[BACStaticHint, ...]
  warnings: tuple[DiscoveryWarning, ...]
```

`CanonicalDiscoveryResult`는 arbitrary direct construction을 trusted
contract로 인정하지 않는다. `create(...)` factory가 child object를
snapshot하고, canonical ordering과 전체 validation을 수행한 뒤에만
instance를 반환한다. 공개 `validate()`는 deserialization 또는 handoff
직전에 같은 규칙을 재검증한다.

### New model candidates

| Model | Minimum planned fields and boundary |
| --- | --- |
| `CollectorKind` | `NATIVE_STATIC`, `NATIVE_DYNAMIC`, `LEGACY_COMPATIBILITY`; legacy가 native provenance를 주장하지 못하게 하는 discriminator |
| `DiscoveryMetadata` | collector kind/version, immutable run key, normalized configuration fingerprint, start/end timestamp metadata |
| `ScopeMetadata` | `target_scope_id`, requested target URL, scope policy version, scope-decision refs, budget policy version; 실제 enforcement 규칙은 포함하지 않음 |
| `CrawlStatistics` | configured/consumed request budget, configured/reached depth, page/response/redirect/scope decision counts, emitted object counts |
| `DiscoveryProvenance` | subject kind/id, run id, collector observation key, source URL, parent URL, depth, collector kind, observed timestamp |
| `ProbeReadyStatus` | `READY` 또는 `NOT_READY` |
| `NonProbeReadyReasonCode` | missing/partial/ambiguous context, unsupported location, lossy method/action provenance, raw query unavailable/alignment failure 등 versioned machine code |
| `ProbeReadiness` | InputPoint id, optional request-context id, status, ordered reason codes |
| `DiscoveryWarning` | stable code, optional subject/provenance refs, display message, canonical JSON-like details |
| `BACStaticHint` | hint kind, source subject kind/id, provenance id, static evidence; role/session/access result/score 필드 없음 |
| `CanonicalDiscoveryResult` | 위 모든 canonical child와 run metadata를 소유하는 validated aggregate |

`ScopeMetadata`와 `CrawlStatistics`는 후속 Scope/Budget foundation이
구현 객체를 제공할 자리를 예약한다. 이번 foundation은 opaque policy/ref와
summary consistency만 정의하고 URL 허용 여부나 redirect enforcement
알고리즘은 정의하지 않는다.

`BACStaticHint`는 `InputPoint`에 강제로 귀속하지 않는다. endpoint,
request template, path/resource observation 등 review된 source subject를
참조할 수 있지만 하나의 InputPoint를 요구하지 않는다. static evidence에
weight, rank score, vulnerability verdict, role/session 관계를 넣지 않는다.

### Existing model reuse and minimal extension

다음 모델은 새로 만들지 않고 그대로 canonical child로 재사용한다.

- `Endpoint`
- `InputPoint`
- `RequestTemplate`
- `InputPointRequestContext`

identity 입력과 prefix도 v0.1 규칙을 유지한다. contract factory는 별도
parallel identity를 만들지 않는다.

`src/vulnspider/domain/models.py` 변경은 다음 최소 범위만 후보로 둔다.

- `InputPoint.metadata`, `RequestTemplate.metadata`,
  `RequestTemplate.headers`, `RequestTemplate.cookies`를 construction 시
  deep-frozen snapshot으로 만들어 frozen dataclass 내부의 mutable alias가
  contract validation 이후 바뀌지 않게 한다.
- 기존 fingerprint 입력, field 의미, id prefix, planner API는 바꾸지
  않는다.
- 해당 immutability 변경이 기존 v0.1 호출자와 type check에 영향을 주면
  contract-owned snapshot helper로 한정하고 기존 public model 의미는
  유지한다. 대규모 model refactor는 하지 않는다.

### Producer, consumer, owner

| Model / boundary | Producer | Consumer | Owner / required review |
| --- | --- | --- | --- |
| `CanonicalDiscoveryResult` and discovery-owned submodels | Native Static, later Native Dynamic, explicit legacy compatibility wrapper | Observation / Feature & Prioritization | 상현; 상현 + 수훈 contract review |
| `Endpoint` | native collector 또는 legacy adapter | contract validator, planner, reporting | existing shared domain; identity 변경 시 affected-owner review |
| `InputPoint` | native collector 또는 legacy adapter | contract validator, probe planning, SQLi/XSS candidate path | existing shared domain; v0.1 atomic-unit invariant 유지 |
| `RequestTemplate` | native collector 또는 legacy adapter | contract validator, probe planner | existing shared domain; request provenance 변경 시 상현 + 수훈 review |
| `InputPointRequestContext` | producer가 `from_objects()`로 생성 | contract validator, probe planner | existing shared domain; arbitrary id construction 금지 |
| `ProbeReadiness` | discovery producer의 contract factory | observation orchestration | 상현; consumer는 status를 승격하거나 reason을 제거하지 않음 |
| `BACStaticHint` | native discovery/preprocessing | future BAC preprocessing | 상현 boundary, exact access model은 팀 review 전 미정 |
| `ScopeMetadata` / `CrawlStatistics` | future Scope/Budget authority가 제공, discovery가 handoff에 포함 | contract validation, observation accounting | 상현; exact scope/budget record schema는 Open Decision |

### Stable identity rules

모든 persistent identity는 `stable_fingerprint()`와 canonical JSON
serialization의 SHA-256을 사용한다. Python built-in `hash()`와 collection
iteration order를 사용하지 않는다.

1. 기존 child identity는 현재 v0.1 fingerprint를 그대로 사용한다.
2. contract에 들어오는 기본 child id는 `ep_`, `inp_`, `rt_`, `ipctx_`
   prefix와 해당 canonical fingerprint의 앞 16자리 규칙을 만족해야 한다.
   기존 모델이 custom id construction을 허용하더라도 validated canonical
   contract는 content와 맞지 않는 custom id를 거부한다.
3. `discovery_run_id`는 최소한 contract version, `target_scope_id`,
   collector kind/version, normalized configuration fingerprint, immutable
   run key를 bind한다. timestamp나 object input order만으로 만들지 않는다.
4. `DiscoveryProvenance.id`는 run id, collector observation key, subject
   kind/id, source URL, parent URL, depth를 bind한다. 같은 surface의 여러
   source observation을 덮어쓰지 않는다.
5. `ProbeReadiness.id`가 필요하면 InputPoint id, optional context id,
   status, ordered reason code를 bind한다.
6. `BACStaticHint.id`는 hint policy version, hint kind, source subject,
   provenance id, canonical static evidence를 bind한다.
7. display message, wall-clock duration, list insertion order는 child
   semantic identity에 넣지 않는다.

`discovery_run_id`에 사용될 immutable run key의 발급 주체와 동일 설정의
재실행을 같은 run으로 볼지는 Open Decision으로 남긴다. 결정 전에는
producer-supplied key를 required field로 두고 임의 UUID나 현재 시각을
factory 내부에서 몰래 생성하지 않는다.

### Provenance and ownership rules

- 모든 `Endpoint`, `InputPoint`, `RequestTemplate`,
  `InputPointRequestContext`, `BACStaticHint`는 현재
  `discovery_run_id`에 속한 `DiscoveryProvenance`를 최소 하나 가진다.
- child가 여러 페이지, collector, 또는 context에서 발견되면 child
  identity는 deduplicate할 수 있지만 provenance occurrence는 모두
  보존한다.
- `InputPoint.endpoint_id`와 `RequestTemplate.endpoint_id`는 같은
  contract 안의 `Endpoint.id`를 resolve해야 한다.
- 두 객체의 `endpoint_fingerprint`는 resolved Endpoint의 fingerprint와
  일치해야 한다.
- `RequestTemplate.method`, URL scheme/host/path는 resolved Endpoint
  identity와 일치해야 한다.
- `InputPointRequestContext`는 실제 object를 사용한
  `validate_input_point_request_context()`를 통과해야 한다.
- consumer는 id, occurrence index, form membership, raw query,
  readiness를 다시 추론하지 않는다.
- native collector는 `discovered_by`와 provenance에 native collector를
  기록한다. compatibility wrapper는 항상 `LEGACY_COMPATIBILITY`를
  기록하며 `native_static`/`native_dynamic`을 사용할 수 없다.
- legacy `LegacyCrawlRecord`, `LegacyAdapterResult`, legacy DB row 또는
  legacy parser object는 contract field나 nested metadata에 들어갈 수
  없다. 필요한 정보만 canonical scalar/tuple/mapping으로 복사한다.

### Validation boundary

`CanonicalDiscoveryResult.create()`와 `validate()`는 다음 순서로 검증한다.

1. 지원되는 contract major version, collector discriminator, non-empty
   run/scope/policy identity를 확인한다.
2. 모든 collection을 expected type으로 제한하고 id/fingerprint 중복을
   검사한다.
3. `Endpoint.fingerprint`를 current domain rule로 재계산한다.
4. `InputPoint.fingerprint`, endpoint ownership, occurrence index를
   검증한다.
5. `RequestTemplate.fingerprint`, endpoint ownership, method/URL binding,
   ordered pair shape를 검증한다.
6. URL에 raw query가 있는 template은 decoded ordered pair가
   `RequestTemplate.query`와 정확히 align하는지 확인한다. raw token 자체는
   URL에 그대로 남긴다.
7. 모든 `InputPointRequestContext` reference를 resolve하고 existing
   association validator를 실행한다.
8. 모든 provenance/readiness/warning/hint reference가 현재 aggregate의
   subject를 resolve하는지 확인한다.
9. `READY`는 정확한 context id, 빈 reason 목록, `COMPLETE` template,
   trusted method/action provenance, supported QUERY/FORM location, raw-query
   alignment를 요구한다.
10. `NOT_READY`는 최소 한 개의 machine-readable reason을 요구한다.
    incomplete context는 유효한 discovery data일 수 있지만 `READY`로
    승격할 수 없다.
11. bindable InputPoint에 context가 없으면 context id가 없는
    `NOT_READY / REQUEST_CONTEXT_MISSING` record가 있어야 한다.
12. native form의 omitted method는 HTML default GET, omitted action은
    current document URL로 해석할 수 있다. source document가 명확하고
    provenance가 각각 `html_default_get`,
    `html_default_current_document`이면 assumption이 아니라 명시적 HTML
    semantics로 취급한다. relative action은 source URL로 resolve하고 raw와
    resolved 값을 모두 보존한다.
13. legacy metadata의 missing method/action은 HTML 원문 누락인지 collector
    손실인지 알 수 없으므로 기존 `unknown_assumed_*` provenance를 유지하고
    non-probe-ready로 판정한다.
14. hidden control은 반드시 preserved surface다. native collector가 같은
    form의 모든 successful control과 stable boundary를 보존했다면 hidden
    type만으로 non-probe-ready가 되지 않는다. legacy hidden completeness를
    증명할 수 없으면 form context 전체가 non-probe-ready다.
15. `CrawlStatistics`의 값은 음수가 아니어야 하고 consumed budget은
    configured budget을 넘지 않아야 하며 emitted object counts는 실제
    tuple 길이와 일치해야 한다.
16. forbidden legacy runtime type, mutable/unsupported metadata value,
    non-finite number를 거부한다.
17. canonical ordering을 확인하고 aggregate content digest와
    `discovery_run_id` 입력의 일관성을 확인한다.

ownership/fingerprint 불일치, unresolved reference, duplicate id는
non-probe-ready로 낮추지 않고 contract 전체를 거부한다. 이는 불완전하지만
정직한 discovery와 손상된 object graph를 구분하기 위한 경계다.

### Deterministic output ordering

factory는 입력 순서와 무관하게 아래 key로 정렬한 tuple만 저장한다.

| Collection | Canonical sort key |
| --- | --- |
| endpoints | `(fingerprint, id)` |
| input points | `(fingerprint, id)` |
| request templates | `(fingerprint, id)` |
| request contexts | `(input_point_id, request_template_id, role, id)` |
| probe readiness | `(input_point_id, request_context_id or "", status, reason_codes)` |
| provenance | `(subject_kind, subject_id, collector_observation_key, id)` |
| BAC static hints | `(hint_kind, source_subject_kind, source_subject_id, id)` |
| warnings | `(code, subject_id or "", provenance_id or "", details_fingerprint)` |

mapping은 key를 정렬하고 sequence 의미가 있는 query/form/provenance
occurrence는 원래 순서를 유지한다. set iteration과 input list position은
identity 또는 output order의 근거로 사용하지 않는다.

같은 semantic fixture의 record 순서를 뒤집거나 hash seed를 바꿔도
`to_dict()` 결과와 canonical JSON bytes가 같아야 한다. deserialized
contract가 위 순서가 아니면 validator는 silent reorder 없이 거부한다.
producer-side factory만 입력을 canonicalize한다.

### Probe-ready decision boundary

`ProbeReadiness`는 discovery producer가 계산해 전달하고 planner가 최종
실행 직전에 기존 검증을 다시 수행한다.

```text
valid object graph
  + supported QUERY or FORM InputPoint
  + validated InputPointRequestContext
  + COMPLETE RequestTemplate
  + exact method/action provenance
  + exact occurrence and baseline binding
  + aligned raw query when present
  + no structured blocking reason
    => READY

otherwise, if the discovery evidence itself is valid
    => NOT_READY + one or more reason codes

corrupt identity/reference/ownership
    => reject CanonicalDiscoveryResult
```

BAC static hints는 이 injection probe-readiness 판정에 참여하지 않는다.
향후 BAC access context와 실행 matrix가 승인될 때 별도 readiness contract를
정의한다.

### Legacy compatibility path

새 `src/vulnspider/discovery/legacy_compat.py`에 explicit wrapper를 둔다.

```text
legacy record mappings
  -> LegacyCrawlerAdapter.convert()
  -> LegacyAdapterResult
  -> wrap_legacy_adapter_result(...)
  -> CanonicalDiscoveryResult
       collector_kind = LEGACY_COMPATIBILITY
```

wrapper는 기존 adapter의 normalization을 복제하지 않는다. 기존 child
object identity와 ordered pairs를 그대로 사용하고, run/scope metadata,
structured provenance, readiness, statistics, warnings를 추가한다.

기존 `analyze_legacy_records()` 경로는 이번 foundation에서 바꾸지 않는다.
따라서 v0.1 CLI와 scoring/reporting regression은 기존 테스트로 계속
검증한다. 새 compatibility integration test는 wrapper 결과에서 다시 꺼낸
child id, pair order, context ownership이 `LegacyAdapterResult`와 같은지
비교한다.

legacy form은 기존 `PARTIAL`과 reason을 `NOT_READY`로 옮긴다. legacy query
context는 기존 adapter와 planner가 증명하는 범위에서만 `READY`가 될 수
있다. structured query metadata만 있고 raw URL context를 증명할 수 없는
경우의 readiness는 Open Decision 결과에 따라 명시적으로 versioning하며,
기존 v0.1 pipeline 동작을 몰래 바꾸지 않는다.

### Static HTML extraction and canonical preprocessing

새 parser는 network I/O를 하지 않는 pure boundary로 구현한다.

```text
extract_static_html(
    html: str,
    source_url: str,
    discovery metadata/provenance inputs
) -> StaticExtractionResult
```

Planned behavior:

- 표준 라이브러리 `html.parser.HTMLParser` 또는 repository dependency가
  없는 동등한 parser를 사용한다. 신규 third-party dependency는 추가하지
  않는다.
- anchor `href`를 document order로 수집하고 `urljoin()`으로 resolve한다.
- fragment는 crawl identity에서 제거한다. 원래 href와 source provenance는
  보존한다.
- `http`/`https` URL만 crawl candidate로 반환한다.
  `mailto:`, `javascript:`, `data:`와 malformed URL은 structured skip으로
  기록한다.
- source URL과 discovered link URL의 raw query string을 그대로 보존하고
  `parse_qsl(..., keep_blank_values=True)`의 ordered pairs를 canonical
  request context로 사용한다.
- repeated query name과 값이 같은 repeated occurrence도 occurrence index로
  분리한다.
- form boundary는 document-order form index가 아니라 source URL과
  deterministic form evidence로 만든 collector observation key를 사용한다.
  동일 문서 안에서 duplicate-identical form을 구분해야 하는 경우에만
  stable document occurrence를 명시적으로 identity에 포함한다.
- form method가 없으면 HTML default `GET`, action이 없으면 current document
  URL, relative action은 `urljoin(source_url, raw_action)`으로 resolve한다.
  raw attribute와 standards-derived provenance를 함께 저장한다.
- `input`, `textarea`, `select`의 named control을 보존한다. 최소 type은
  text, hidden, password, email, number이고 알 수 없는 input type도
  `type_hint`로 보존한다.
- `textarea`는 text content, `select`는 selected option 또는 첫 option의
  value/text를 deterministic baseline으로 사용한다. disabled 또는 name이
  없는 control은 request template에 포함하지 않고 structured skip을
  기록한다.
- GET form control은 ordered query pairs, POST form control은 ordered form
  pairs에 넣는다. form은 절대 제출하지 않는다.
- stable form boundary 안의 duplicate name은 occurrence-level
  `InputPoint`로 생성한다.
- malformed/unclosed form은 parser가 복구 가능한 evidence만 보존하고
  exact boundary 또는 successful controls를 증명할 수 없으면
  non-probe-ready reason을 남긴다.
- 같은 canonical surface는 child identity로 deduplicate하되 서로 다른
  provenance occurrence는 모두 남긴다.

### Same-origin scope and bounded crawl engine

새 crawler는 단순한 synchronous queue와 injectable transport를 사용한다.
HTML parser와 transport는 분리한다.

```text
StaticCrawler.crawl(root_url, CrawlPolicy, transport)
  -> CanonicalDiscoveryResult
```

`CrawlPolicy`의 MVP 필드:

- `max_pages`
- `max_requests`
- `max_depth`
- `max_elapsed_seconds`
- `max_redirects`
- `delay_seconds`
- `timeout_seconds`
- `max_response_bytes`

Safety rules:

1. root URL은 absolute `http`/`https`이며 normalized origin을 가져야 한다.
2. scope identity는 `(scheme, normalized hostname, effective port)`의 exact
   origin equality다. suffix, substring, DNS alias 추론을 사용하지 않는다.
3. production default는 user-supplied root와 same-origin이다.
4. tests는 `localhost`, loopback IP, test-owned loopback server만 사용한다.
5. discovered cross-origin URL은 queue에 넣거나 요청하지 않고
   `OFF_SCOPE_LINK` skip으로 기록한다.
6. redirect는 자동 follow하지 않는다. 각 `Location`을 resolve한 뒤 scope,
   redirect count, request/time budget을 다시 확인하고 다음 요청을
   명시적으로 수행한다.
7. off-scope redirect는 요청하지 않고 `OFF_SCOPE_REDIRECT`로 기록한다.
8. redirect loop는 visited redirect chain으로 중단한다.
9. request budget은 redirect hop을 포함해 transport send 직전에 reserve한다.
10. page budget은 parse 대상으로 받아들인 unique HTML page 수를 제한한다.
11. depth는 root `0`에서 시작하고 max depth를 넘는 link는 요청하지 않는다.
12. time budget은 queue iteration, delay, redirect 전에 monotonic clock으로
    확인한다.
13. timeout과 response-size limit은 transport boundary에서 적용한다.
14. `Content-Type`이 HTML이 아니면 body를 parser에 넘기지 않고 structured
    skip과 statistics만 기록한다.
15. queue는 `(depth, canonical_url)` key로 deterministic하게 처리한다.
    duplicate URL과 fragment variant는 요청 전에 deduplicate한다.
16. delay는 실제 request 사이에만 적용하며 injectable sleeper/clock으로
    unit test에서 기다리지 않는다.
17. cookie/session secret 저장은 하지 않는다. MVP crawler는 explicit auth
    automation을 지원하지 않는다.

### Pipeline and CLI integration

현재 `analyze` subcommand의 `--input`을 제거하거나 의미를 바꾸지 않는다.
가장 작은 additive CLI는 mutually exclusive input group이다.

```text
vulnspider analyze (--input LEGACY_JSON | --url ROOT_URL) \
  --top-k N \
  --output REPORT_JSON \
  [--html-output REPORT_HTML] \
  [bounded crawl policy options]
```

`--input`과 `--url`을 동시에 주거나 둘 다 생략하면 parsing 단계에서
거부한다. crawl policy option은 `--url`에서만 의미가 있으며 legacy 입력과
함께 사용하면 명확한 CLI error를 낸다.

Pipeline split:

```text
analyze_legacy_records()
  -> unchanged v0.1 compatibility behavior

analyze_discovery_result()
  -> validated CanonicalDiscoveryResult
  -> deterministic READY context iteration
  -> existing ProbePlanner / Executor / Features / Scoring / Top-K

analyze_url()
  -> StaticCrawler.crawl()
  -> analyze_discovery_result()
```

non-probe-ready surface와 crawl skip/warning은 report warning에 포함하지만
candidate나 finding을 fabricate하지 않는다. probe-ready context가 하나도
없어도 truthful empty selection과 crawl accounting을 JSON report로 쓸 수
있어야 한다. fatal root validation 또는 crawler startup failure는 report를
쓰지 않고 명확한 CLI error로 종료한다.

기존 output-path equality validation과 HTML renderer의 authoritative
`SelectionOutcome` 사용 규칙은 그대로 유지한다.

### Loopback end-to-end fixture

integration test는 test process가 ephemeral loopback HTTP server를 직접
시작하고 종료한다. fixture routes에는 다음을 포함한다.

- index HTML
- same-origin link와 duplicate/fragment variant
- 외부 origin 링크
- repeated/blank/percent-encoded query URL
- GET form, POST form, hidden input
- missing/relative action과 missing method
- same-origin redirect, off-scope redirect, redirect loop
- non-HTML response

E2E transport는 crawler의 실제 standard-library HTTP transport를 사용하되
probe 단계는 기존 injectable fake transport를 사용하거나 fixture server가
neutral marker 요청을 안전하게 응답하도록 한다. 어떤 경우에도 public
Internet로 요청하지 않았음을 server request log와 off-scope sentinel로
검증한다.

## Interfaces / Data Changes

Planned public discovery API:

```text
vulnspider.discovery
  CanonicalDiscoveryResult
  CollectorKind
  DiscoveryMetadata
  ScopeMetadata
  CrawlStatistics
  DiscoveryProvenance
  ProbeReadyStatus
  NonProbeReadyReasonCode
  ProbeReadiness
  DiscoveryWarning
  BACStaticHint
  wrap_legacy_adapter_result
  StaticExtractionResult
  extract_static_html
  CrawlPolicy
  StaticCrawler
  StaticCrawlerTransport
```

`CanonicalDiscoveryResult.create(...)`가 producer validation boundary다.
consumer는 complete validated result를 받거나 typed
`DiscoveryContractError`를 받는다. consumer용 helper는 canonical
`READY` context를 순서대로 yield할 수 있지만 context를 재구성하거나
`NOT_READY`를 승격하지 않는다.

Contract serialization은 primitive mapping/list/scalar만 반환하며 class
repr, enum repr, object memory address, set을 출력하지 않는다. JSON
artifact writer나 persistence schema는 이번 foundation 범위에 포함하지
않는다.

Additional pipeline/CLI API:

```text
pipeline.analyze_discovery_result(result, *, top_k, transport, ...)
pipeline.analyze_url(root_url, *, crawl_policy, crawler_transport,
                     probe_transport, top_k, ...)

cli analyze
  --input LEGACY_JSON | --url ROOT_URL
  existing --top-k / --output / --html-output
  bounded --max-pages / --max-requests / --max-depth /
          --max-elapsed-seconds / --max-redirects /
          --delay-seconds / --timeout-seconds
```

## Safety / Scope Impact

- Milestone 1과 2는 network I/O가 없는 pure contract/parser다.
- Milestone 3부터 user-supplied root URL에 대한 bounded network I/O가
  추가된다. 요청 전 exact same-origin, request/time/depth/page budget을
  검사하고 redirect는 transport가 자동으로 따라가지 못하게 한다.
- production crawler는 root URL과 same-origin만 허용한다. automated test는
  test-owned loopback server만 사용하며 public Internet를 사용하지 않는다.
- POST form은 canonical template만 만들고 crawler가 제출하지 않는다.
- corrupt ownership은 전체 contract error, incomplete request context는
  structured non-probe-ready로 처리한다.
- compatibility wrapper는 legacy suffix scope logic이나 redirect behavior를
  신뢰하지 않고 native provenance를 표시하지 않는다.
- BAC static hint는 실행/score/verdict가 아니며 local authorized fixture
  밖의 credential, account, role 조작 정보를 수집하지 않는다.
- cookie/session/credential을 crawl metadata, warning, report에 저장하지
  않는다.
- 새 third-party dependency는 추가하지 않는다.

## Test Plan

### Normal unit tests

`tests/unit/test_discovery_contract.py`:

- 최소 native static fixture가 validated result를 생성한다.
- 기존 four child model을 동일 object semantics와 id로 재사용한다.
- producer input permutation이 동일 tuple order와 canonical JSON을 만든다.
- static과 dynamic metadata를 사용해 같은 surface를 생성했을 때 child
  identity는 같고 run/provenance identity는 다르다.
- complete query/form context가 `READY`가 된다.
- native HTML default method/action 및 relative action resolution이 raw와
  resolved provenance를 보존한다.
- structured warnings, statistics, provenance count가 실제 child와
  일치한다.
- BAC static hint가 Endpoint/RequestTemplate provenance를 참조할 수 있고
  InputPoint를 요구하지 않는다.
- contract-owned mapping과 sequence가 caller mutation의 영향을 받지 않는다.

### Adversarial and negative tests

`tests/unit/test_discovery_contract_adversarial.py`:

| Required case | Expected assertion |
| --- | --- |
| same-name repeated query parameter | ordered pair와 occurrence `0`, `1`이 보존되고 id가 다름 |
| repeated occurrence with equal values | 값이 같아도 occurrence id/context/readiness가 collapse하지 않음 |
| blank query value | `""`를 `None` 또는 missing으로 바꾸지 않음 |
| percent-encoded raw query token | decoded pair와 raw token을 모두 보존하고 비대상 token을 재인코딩하지 않음 |
| hidden input | native complete form에서는 보존, lossy legacy form에서는 structured NOT_READY |
| omitted form method | native HTML default GET provenance를 검증하고 legacy unknown assumption과 구분 |
| omitted or relative form action | current-page default/relative resolution과 raw provenance를 검증 |
| duplicate form field | stable boundary+order가 있으면 occurrence-level, 없으면 ambiguous NOT_READY |
| InputPoint / RequestTemplate ownership mismatch | aggregate construction을 거부 |
| endpoint fingerprint mismatch | aggregate construction을 거부 |
| incomplete request context | valid result에 남지만 `NOT_READY`와 reason이 필수 |
| nondeterministic result ordering | forged unsorted result/deserialization을 거부; producer permutation은 동일 bytes |
| legacy internal object leak | `LegacyCrawlRecord`, `LegacyAdapterResult`, arbitrary legacy object가 nested field에 있으면 거부 |

추가 negative cases:

- duplicate child id with different content
- unresolved endpoint/template/context/provenance reference
- custom id that does not match canonical content
- `READY` with a non-empty reason list
- `NOT_READY` with no reason
- unsupported InputLocation marked `READY`
- negative statistics, budget over-consumption, emitted count mismatch
- unknown collector kind 또는 unsupported contract major version
- built-in `hash()` 사용 여부에 대한 source scan
- non-finite number, set, arbitrary mutable object in contract metadata
- BAC hint containing score, verdict, or unresolved source reference

### Static extraction tests

`tests/unit/test_static_extractor.py`:

- same-name/equal-value repeated query, blank query, raw percent-encoded query
- duplicate form field와 stable occurrence identity
- missing method, missing action, relative action
- text/hidden/password/email/number/textarea/select baseline extraction
- fragment URL normalization
- `mailto:`, `javascript:`, `data:`와 malformed link structured skip
- malformed/unclosed form의 fail-closed readiness
- 같은 canonical URL의 다른 query occurrence/context 보존
- input HTML과 source URL이 같을 때 byte-equivalent deterministic output
- parser가 transport/network module을 import하거나 호출하지 않음

### Static crawler tests

`tests/unit/test_static_crawler.py`는 scripted fake transport, fake monotonic
clock, fake sleeper를 사용한다.

- same-origin link만 요청
- cross-origin link는 send 전에 skip
- duplicate/fragment URL request deduplication
- same-origin redirect와 off-scope redirect
- redirect loop와 max redirect
- timeout과 oversized response
- non-HTML response skip
- page/request/depth/time budget exhaustion
- deterministic traversal order
- delay accounting
- malformed root/discovered URL
- POST form request가 transport로 전송되지 않음

### Pipeline and CLI tests

`tests/unit/test_native_pipeline_cli.py`:

- `--url` 정상 실행
- 기존 `--input` 정상 실행
- `--url`/`--input` 동시 지정과 모두 누락 거부
- URL 전용 policy option을 legacy input과 함께 사용하면 거부
- JSON output과 JSON+HTML output
- normalized 동일 output path 거부
- crawler fatal failure는 report를 만들지 않음
- valid empty/partial discovery는 거짓 candidate/finding 없이 truthful
  report와 warning을 생성
- native path가 기존 planner/features/scoring/reporting을 재사용

### Loopback integration

`tests/integration/test_native_static_discovery_e2e.py`:

- ephemeral loopback server의 root URL에서 실제 crawler transport 실행
- fixture의 links/forms/query/redirect/non-HTML surface를 canonical contract로
  확인
- off-scope sentinel에 request가 도달하지 않았음을 확인
- URL input부터 JSON 및 optional HTML report 생성까지 확인
- repeated/equal/blank/raw query와 hidden/form provenance 확인
- server request log로 max request, redirect, POST non-submission 확인
- server와 thread/socket을 test 종료 시 항상 정리

### Legacy Adapter regression

`tests/unit/test_legacy_adapter_contract.py` and existing adapter tests:

- wrapper 전후 Endpoint/InputPoint/RequestTemplate/context id와 ordered pair를
  비교한다.
- warning string은 deterministic structured warning code로 mapping하되 원본
  정보가 사라지지 않는지 확인한다.
- legacy form의 partial/ambiguous/hidden-loss reason이 `NOT_READY`가 되는지
  확인한다.
- legacy collector가 `NATIVE_STATIC` 또는 `NATIVE_DYNAMIC` provenance를
  만들 수 없음을 확인한다.
- wrapper 결과의 nested graph에 legacy runtime object가 없음을 확인한다.
- 기존 `tests/unit/test_legacy_adapter.py`를 수정 없이 통과시킨다.
- 기존 `tests/unit/test_probe_planner.py`와
  `tests/integration/test_v01_smoke.py`를 수정 없이 통과시켜 v0.1 CLI
  behavior가 변하지 않았음을 증명한다.

### Test commands

Focused commands:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest tests.unit.test_discovery_contract
python -B -m unittest tests.unit.test_discovery_contract_adversarial
python -B -m unittest tests.unit.test_legacy_adapter_contract
python -B -m unittest tests.unit.test_static_extractor
python -B -m unittest tests.unit.test_static_crawler
python -B -m unittest tests.unit.test_native_pipeline_cli
python -B -m unittest tests.integration.test_discovery_contract_compatibility
python -B -m unittest tests.integration.test_native_static_discovery_e2e
```

Regression and full gate:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_domain_models `
  tests.unit.test_legacy_adapter `
  tests.unit.test_probe_planner `
  tests.integration.test_v01_smoke
python -B -m unittest discover -s tests
python -B tools/check_format.py
python -B tools/check_lint.py
python -B tools/check_types.py
git diff --check
```

Determinism test는 같은 fixture를 여러 input permutation과 서로 다른
`PYTHONHASHSEED` subprocess에서 직렬화해 byte equality를 확인한다. 이
subprocess는 network를 사용하지 않는다.

## Canonical Contract Design Detail

이 절의 세부 Phase는 아래 authoritative MVP Milestone 중 Milestone 1의
contract 구현과 Milestone 4의 compatibility 연결에 사용한다. 전체 작업
순서와 focused commit 경계는 뒤의 `Implementation Sequence`가 우선한다.

### Phase 1 - Canonical result models and validation

Planned files:

- add `src/vulnspider/discovery/contracts.py`
- update `src/vulnspider/discovery/__init__.py`
- minimally update `src/vulnspider/domain/models.py` only if required for
  immutable snapshots
- update `src/vulnspider/domain/__init__.py` only for a reused public stable
  JSON helper, not for parallel model classes

Work:

1. Add enums, structured metadata/provenance/readiness/warning/hint records.
2. Add `DiscoveryContractError`.
3. Implement SHA-256 identity helpers using existing `stable_fingerprint()`.
4. Implement `CanonicalDiscoveryResult.create()`, `validate()`, canonical
   ordering, and primitive deterministic serialization.
5. Implement full reference, identity, ownership, readiness, statistics, and
   forbidden-type validation.
6. Keep all network and crawler logic outside this module.

Done When:

- Invalid object graphs cannot be minted through the public factory.
- Existing child identities and planner APIs are unchanged.
- Equivalent producer inputs create byte-equivalent ordered output.
- `READY` and `NOT_READY` are machine-readable and fail-closed.
- no new dependency, HTTP request, BAC score, or legacy import exists.

Phase command:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest tests.unit.test_domain_models tests.unit.test_discovery_contract
```

### Phase 2 - Contract fixtures and negative tests

Planned files:

- add `tests/fixtures/discovery_contract_fixtures.py`
- add `tests/unit/test_discovery_contract.py`
- add `tests/unit/test_discovery_contract_adversarial.py`
- update `tests/unit/test_domain_models.py` only for minimal immutability
  regression introduced in Phase 1

Work:

1. Build network-free native-static-shaped fixture factories from canonical
   objects, not legacy records.
2. Add every required adversarial case from this plan.
3. Add forged-object/deserialization tests for aggregate-level validation that
   normal factories intentionally prevent.
4. Add input permutation and hash-seed determinism tests.
5. Add source scan ensuring no built-in `hash()` is used in persistent identity.

Done When:

- All required adversarial cases have explicit expected status or exception.
- Negative tests fail for the intended contract rule, not incidental
  constructor errors.
- Fixture ordering changes do not change canonical output.
- Native fixtures do not instantiate any legacy class.

Phase command:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_discovery_contract `
  tests.unit.test_discovery_contract_adversarial
```

### Phase 3 - Legacy compatibility wrapper

Planned files:

- add `src/vulnspider/discovery/legacy_compat.py`
- update `src/vulnspider/discovery/__init__.py`
- add `tests/unit/test_legacy_adapter_contract.py`
- add `tests/integration/test_discovery_contract_compatibility.py`

Work:

1. Wrap `LegacyAdapterResult` without duplicating adapter normalization.
2. Copy only canonical child objects and JSON-like provenance/warning facts.
3. Emit `LEGACY_COMPATIBILITY` collector metadata and deterministic structured
   warning/readiness records.
4. Compare wrapper child identity, ordering, occurrence, raw query, and
   ownership with direct adapter output.
5. Keep `pipeline.analyze_legacy_records()` and the CLI unchanged.

Done When:

- Existing adapter output remains byte/identity compatible at its current
  boundary.
- Wrapped legacy forms remain non-probe-ready for documented lossy reasons.
- Legacy internal objects cannot escape into the core contract.
- Existing adapter, planner, and v0.1 smoke tests pass unchanged.

Phase command:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_legacy_adapter_contract `
  tests.unit.test_legacy_adapter `
  tests.unit.test_probe_planner `
  tests.integration.test_discovery_contract_compatibility `
  tests.integration.test_v01_smoke
```

### Phase 4 - Scope/Budget foundation interface

Planned files:

- update `src/vulnspider/discovery/contracts.py`
- update `tests/unit/test_discovery_contract.py`
- update `tests/unit/test_discovery_contract_adversarial.py`

Work:

1. Finalize the minimal opaque `ScopeMetadata` refs and version fields approved
   by the Scope/Budget owner.
2. Validate configured-versus-consumed budget/depth counters without
   implementing enforcement.
3. Require stable references for allowed/rejected scope decisions and future
   redirect decisions.
4. Add a consumer helper that yields only ordered `READY` injection contexts
   while retaining all rejected/non-ready accounting.
5. Document through types that future ScopeGuard supplies authority and
   discovery only carries its validated snapshot.

Done When:

- A future Scope/Budget implementation can populate the contract without
  changing child discovery identities.
- Missing scope authority, budget overrun, or count mismatch fails validation.
- No request is sent and no scope decision algorithm is implemented.
- BAC hint and injection readiness remain separate.

Phase command:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_discovery_contract `
  tests.unit.test_discovery_contract_adversarial
```

### Phase 5 - Independent Gate Review

Planned files:

- no planned production change; reviewer examines the complete diff
- update this execution plan's Progress Log and Decision Log with findings and
  final gate result

Review procedure:

1. A reviewer other than the implementation agent reads this plan,
   `AGENTS.md`, `CODE_REVIEW.md`, the changed files, and focused tests.
2. Reviewer reports `BLOCKER`, `MAJOR`, `MINOR`, `TEST GAPS`, and
   `VERDICT: APPROVE | REQUEST_CHANGES`.
3. Map `APPROVE` with no blocking findings to `PASS`; map `APPROVE` with only
   recorded non-blocking issues to `PASS WITH MINOR`; map any unresolved
   Critical/High or `REQUEST_CHANGES` to `BLOCK`.
4. Fix blocking findings and rerun focused, regression, full, static, and diff
   checks before another independent review.

Done When:

- No unresolved identity, ownership, provenance, readiness, ordering, scope,
  legacy leakage, or BAC-boundary blocker remains.
- All required adversarial cases are present and meaningful.
- Full verification commands pass.
- Independent outcome is `PASS` or `PASS WITH MINOR`.
- plan Progress Log records exact commands, counts, findings, and final result.

## Implementation Sequence

각 Milestone은 최대 2회의 다음 loop를 사용한다.

```text
inspect current code/tests
  -> minimum implementation
  -> narrow tests
  -> full regression
  -> independent Gate Review
  -> fix Critical/High only
  -> PASS or PASS WITH MINOR
  -> focused commit
```

naming 취향, optional helper, 미래 refactor/optimization은 재작업 loop나
BLOCK 사유로 사용하지 않는다.

### Milestone 0 - Safe branch and executable plan

Files:

- rename and update
  `docs/exec-plans/active/v0_2_native_static_discovery_mvp.md`

Work:

1. Confirm repository, branch, remote branch absence, `main..HEAD`, status,
   stash.
2. Rename branch to `feat/native-static-discovery-mvp`.
3. Preserve contract research and expand this plan through URL-to-report MVP.
4. Verify only this plan changed before the planning commit.

Done When:

- current branch is `feat/native-static-discovery-mvp`
- no production commit exists before the planning commit
- plan covers all five implementation milestones, tests, review, and commits
- stash remains untouched

Commit:

```text
docs(plan): define native static discovery MVP
```

### Milestone 1 - Canonical Discovery Contract

Files:

- add `src/vulnspider/discovery/contracts.py`
- update `src/vulnspider/discovery/__init__.py`
- minimally update `src/vulnspider/domain/models.py` and
  `src/vulnspider/domain/__init__.py` only if immutable snapshots need it
- add `tests/fixtures/discovery_contract_fixtures.py`
- add `tests/unit/test_discovery_contract.py`
- add `tests/unit/test_discovery_contract_adversarial.py`
- update this plan's Progress/Decision Log

Work:

1. Implement metadata, scope, statistics, provenance, structured warning/skip,
   probe readiness, BAC static hint, aggregate validation, ordering and export.
2. Reuse existing child models and `stable_fingerprint()`.
3. Add every required contract failure test.
4. Prohibit nested legacy runtime object and mutable alias leakage.

Narrow test:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_domain_models `
  tests.unit.test_discovery_contract `
  tests.unit.test_discovery_contract_adversarial
```

Done When:

- ownership/fingerprint/unresolved/duplicate/reference corruption is rejected
- READY-without-context and NOT_READY-without-reason are rejected
- input permutations produce deterministic ordered output
- existing child model semantics and v0.1 tests remain valid
- independent result is PASS or PASS WITH MINOR

Commit:

```text
feat(discovery): add canonical discovery contract
```

### Milestone 2 - Static HTML Extraction and Preprocessing

Files:

- add `src/vulnspider/discovery/static_extractor.py`
- update `src/vulnspider/discovery/__init__.py`
- add `tests/unit/test_static_extractor.py`
- update `tests/fixtures/discovery_contract_fixtures.py`
- update this plan's Progress/Decision Log

Work:

1. Parse HTML strings without network I/O.
2. Extract/resolve links, query pairs, GET/POST forms and named controls.
3. Construct existing Endpoint/InputPoint/RequestTemplate/Context objects and
   contract-owned provenance/readiness.
4. Preserve repeated/equal/blank/raw query occurrence and hidden controls.
5. Produce deterministic deduplication and structured skips.

Narrow test:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_static_extractor `
  tests.unit.test_discovery_contract `
  tests.unit.test_discovery_contract_adversarial
```

Done When:

- all required extraction adversarial cases pass without network
- relative/default form semantics and POST non-submission boundary are explicit
- equivalent HTML/source inputs produce equivalent canonical identities/order
- independent result is PASS or PASS WITH MINOR

Commit:

```text
feat(discovery): extract canonical inputs from static HTML
```

### Milestone 3 - Scope, Budget and Static Crawl Engine

Files:

- add `src/vulnspider/discovery/static_crawler.py`
- update `src/vulnspider/discovery/__init__.py`
- add `tests/unit/test_static_crawler.py`
- update contract/extractor files only for evidenced integration needs
- update this plan's Progress/Decision Log

Work:

1. Validate root URL and exact same-origin scope.
2. Implement injectable synchronous transport with automatic redirects
   disabled.
3. Enforce request/page/depth/time/redirect/response budgets before relevant
   work.
4. Implement deterministic queue, duplicate/fragment normalization, delay and
   timeout.
5. Parse only HTML, collect structured statistics/warnings/skips, never submit
   forms.

Narrow test:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_static_crawler `
  tests.unit.test_static_extractor `
  tests.unit.test_discovery_contract
```

Done When:

- cross-origin links/redirects never reach transport
- every budget and redirect limit has a boundary test
- deterministic traversal is independent of link discovery insertion quirks
- no external network is used by tests
- independent result is PASS or PASS WITH MINOR

Commit:

```text
feat(discovery): add bounded native static crawler
```

### Milestone 4 - Pipeline and CLI Integration

Files:

- add `src/vulnspider/discovery/legacy_compat.py` if aggregate wrapping is
  needed for a shared consumer
- update `src/vulnspider/discovery/__init__.py`
- update `src/vulnspider/pipeline.py`
- update `src/vulnspider/cli.py`
- add `tests/unit/test_legacy_adapter_contract.py` if wrapper is added
- add `tests/unit/test_native_pipeline_cli.py`
- add `tests/integration/test_discovery_contract_compatibility.py` if wrapper
  is added
- update this plan's Progress/Decision Log

Work:

1. Add `analyze_discovery_result()` and `analyze_url()` while keeping
   `analyze_legacy_records()` behavior.
2. Feed only validated ordered READY contexts to existing planner/executor.
3. Add mutually exclusive `--url`/`--input`, bounded crawl options, and
   conflict validation.
4. Reuse existing JSON/HTML reporting and output-path validation.
5. Keep partial/failure reporting truthful and avoid fabricated findings.

Narrow test:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_native_pipeline_cli `
  tests.unit.test_legacy_adapter `
  tests.unit.test_probe_planner `
  tests.integration.test_v01_smoke
```

Done When:

- URL and legacy input paths both work
- conflicts/missing input and crawler failures are clear errors
- JSON and optional HTML preserve current authoritative reporting semantics
- existing v0.1 smoke test passes unchanged
- independent result is PASS or PASS WITH MINOR

Commit:

```text
feat(pipeline): analyze native static discovery results
```

### Milestone 5 - Loopback End-to-End Acceptance

Files:

- add `tests/fixtures/native_static_site.py` or an integration-local equivalent
- add `tests/integration/test_native_static_discovery_e2e.py`
- update this plan's Progress/Decision Log with actual evidence

Work:

1. Start an ephemeral loopback-only HTTP fixture server.
2. Exercise real URL input, crawler transport, canonical result, existing
   analysis and JSON/HTML reports.
3. Assert off-scope request absence, redirect/budget enforcement, POST
   non-submission, repeated/raw context preservation and report truthfulness.
4. Ensure deterministic cleanup and no public network.

Narrow test:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest tests.integration.test_native_static_discovery_e2e -v
```

Done When:

- root URL to JSON/HTML report succeeds on the loopback fixture
- fixture covers every required route/surface
- request log proves the safety boundaries
- full regression and static checks pass
- final independent result is PASS or PASS WITH MINOR

Commit:

```text
test(discovery): add native crawler end-to-end harness
```

### Final verification and Gate Review

After Milestone 5, run:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest discover -s tests
python -B -m unittest tests.integration.test_v01_smoke -v
python -B -m unittest tests.integration.test_native_static_discovery_e2e -v
python -B tools/check_format.py
python -B tools/check_lint.py
python -B tools/check_types.py
git diff --check
```

Review the complete branch diff and actual behavior as an independent reviewer,
up to three iterations. Only the following are blocking:

- off-scope URL reached transport
- budget or redirect scope bypass
- repeated occurrence identity loss
- ownership/reference corruption
- nondeterministic identity/output
- legacy analyze regression
- report truthfulness regression
- POST form submission
- public network use in tests
- full test failure
- secret/cookie/session persistence

If a blocker remains after three iterations, do not create a final corrective
commit or push. Record reproduction and remaining defects. Otherwise update this
plan in the relevant focused commit, confirm a clean worktree, and report
without pushing.

## Expected Change Files

Expected implementation diff for this MVP:

```text
src/vulnspider/discovery/contracts.py                         new
src/vulnspider/discovery/static_extractor.py                  new
src/vulnspider/discovery/static_crawler.py                    new
src/vulnspider/discovery/legacy_compat.py                     new only if shared aggregate wrapper is required
src/vulnspider/discovery/__init__.py                          update
src/vulnspider/domain/models.py                               minimal update if snapshot immutability requires it
src/vulnspider/domain/__init__.py                             minimal export update if required
src/vulnspider/pipeline.py                                    additive native-result and URL path
src/vulnspider/cli.py                                         mutually exclusive --input/--url
tests/fixtures/discovery_contract_fixtures.py                 new
tests/fixtures/native_static_site.py                          new or integration-local equivalent
tests/unit/test_discovery_contract.py                         new
tests/unit/test_discovery_contract_adversarial.py             new
tests/unit/test_static_extractor.py                           new
tests/unit/test_static_crawler.py                             new
tests/unit/test_native_pipeline_cli.py                        new
tests/unit/test_legacy_adapter_contract.py                    new only if wrapper is added
tests/integration/test_discovery_contract_compatibility.py    new only if wrapper is added
tests/integration/test_native_static_discovery_e2e.py         new
tests/unit/test_domain_models.py                              minimal regression update if domain immutability changes
docs/exec-plans/active/v0_2_native_static_discovery_mvp.md    progress updates during implementation
```

Not expected in this MVP:

```text
src/vulnspider/observation/planner.py
src/vulnspider/observation/executor.py
src/vulnspider/features/
src/vulnspider/scoring/
src/vulnspider/selection/
src/vulnspider/reporting/
tests/unit/test_legacy_adapter.py
tests/unit/test_probe_planner.py
tests/integration/test_v01_smoke.py
architecture / ADR / Git workflow documents
```

If implementation evidence shows that one of these "not expected" files must
change, stop the phase, record the reason here, and obtain affected-owner review
before expanding scope.

## Acceptance Criteria

- [x] `CanonicalDiscoveryResult` is a versioned, validated aggregate with
      discovery, scope, statistics, provenance, readiness, warning, and BAC
      static-hint boundaries.
- [x] Native-shaped fixtures construct canonical child models directly and do
      not create legacy records first.
- [x] Existing `Endpoint`, `InputPoint`, `RequestTemplate`,
      `InputPointRequestContext` identity and ownership semantics are reused.
- [x] persistent identity uses canonical SHA-256 rules and never Python
      built-in `hash()`.
- [x] repeated parameter name, occurrence index, equal repeated values, blank
      values, ordered pairs, and raw percent-encoded query context are preserved.
- [x] hidden inputs and duplicate form fields are preserved with stable form
      boundary and completeness provenance.
- [x] omitted/relative native form method/action follow explicit HTML semantics;
      lossy legacy assumptions remain distinguishable and fail-closed.
- [x] unresolved references, ownership mismatch, endpoint fingerprint mismatch,
      duplicate canonical ids, and legacy object leakage reject the contract.
- [x] incomplete but honest discovery remains visible as `NOT_READY` with
      structured reason and cannot be executed as `READY`.
- [x] output tuples and primitive serialization are deterministic under input
      permutation and hash-seed changes.
- [x] BAC static hints are not forced under one InputPoint and contain no score,
      verdict, role/session access result, or global Top-K policy.
- [x] Legacy compatibility preserves current child ids/provenance and never
      claims native collector provenance.
- [x] CLI accepts exactly one of legacy `--input` or native `--url`.
- [x] root URL and every requested redirect/link use exact same-origin scope.
- [x] cross-origin links and redirects are recorded but never sent.
- [x] request/page/depth/time/redirect/response-size limits are enforced before
      the corresponding work.
- [x] only HTML response bodies are parsed.
- [x] anchors, query pairs, GET/POST forms, input/textarea/select and relative
      action are extracted without submitting forms.
- [x] native method/action omission follows HTML defaults with provenance.
- [x] deterministic queueing and URL deduplication prevent duplicate requests
      without losing distinct request contexts.
- [x] URL input reaches existing observation/features/scoring/Top-K and creates
      JSON plus optional HTML reports.
- [x] loopback E2E proves off-scope request absence, POST non-submission,
      redirect/budget behavior and report generation.
- [x] v0.1 adapter/planner/CLI regression tests pass unchanged.
- [x] focused tests, full suite, format, lint, type, and `git diff --check` pass.
- [x] independent Gate Review reaches `PASS` or `PASS WITH MINOR`.

## Progress Log

- 2026-07-26: Confirmed branch `feat/canonical-discovery-contract` and clean
  worktree before planning.
- 2026-07-26: Read required repository rules, v0.2 interfaces/architecture,
  domain/decision/legacy documents, implemented domain/adapter/planner/executor/
  pipeline/CLI code, related tests, fixtures, and completed plan examples.
- 2026-07-26: Confirmed the actual v0.1 flow is adapter-result driven and no
  run-level canonical discovery contract, native collector, or Scope/Budget
  implementation exists.
- 2026-07-26: Ran the four requested baseline test modules with workspace
  Python: 113 tests passed. No production code or existing test was changed.
- 2026-07-26: Created this execution plan only. Implementation phases are not
  started.
- 2026-07-26: Confirmed the original feature branch did not exist on origin and
  `main..HEAD` was empty, then renamed the branch to
  `feat/native-static-discovery-mvp`.
- 2026-07-26: Renamed this plan from the contract-only filename and expanded it
  to the bounded native static crawler, pipeline/CLI integration, loopback E2E,
  focused commit, and final Gate Review scope. Production code remains
  unchanged at Milestone 0.
- 2026-07-26: Implemented Milestone 1 canonical discovery metadata, scope and
  crawl summaries, provenance, readiness, structured warnings, BAC static
  hints, aggregate ownership/identity validation, deterministic ordering, and
  primitive serialization while reusing the existing four domain child models.
- 2026-07-26: Added normal and adversarial contract coverage, including
  post-construction scope-reference mutation, recomputed-ID attacks, negative
  provenance depth, and BAC score/confidence/ranking/finding-decision
  boundaries. The focused suite passed 71 tests and the full suite passed 227
  tests; format, lint, type, and `git diff --check` also passed.
- 2026-07-26: Independent Milestone 1 Gate Review reached `PASS` with no
  Critical, High, or Minor residual after the authorized two-iteration unblock
  review. Milestone 2 has not started.
- 2026-07-26: Implemented Milestone 2 as a pure standard-library HTML parser
  with deterministic navigable-link metadata and canonical endpoint, input,
  request-template, request-context, provenance, readiness, statistics, and
  structured-warning output. No transport, form submission, pipeline, CLI,
  legacy, observation, scoring, selection, or reporting code changed.
- 2026-07-26: Added normal and adversarial extractor tests for relative and
  fragment links, raw/repeated/blank query occurrences, GET/POST form defaults,
  successful controls, malformed boundaries/actions, sensitive warning
  redaction, canonical ordering, immutability, and cross-hash-seed identity.
- 2026-07-26: Independent Milestone 2 Gate Review iteration 1 found one High
  issue: occurrence counting used raw names while `InputPoint` canonicalizes
  names. Added a failing `A`/`a` and decoded-empty-name regression, aligned
  counting with canonical names, and received iteration 2 `PASS` with no
  Critical, High, or Minor residual.
- 2026-07-26: Final Milestone 2 verification passed 14 extractor tests and all
  241 repository tests. Format, lint, type-hint, `git diff --check`, secret
  pattern, determinism, and no-network checks passed.
- 2026-07-27: Confirmed the Milestone 3 baseline on
  `feat/native-static-discovery-mvp`: all 241 tests passed and the worktree was
  clean at `2df1d30`; the existing stash remained read-only.
- 2026-07-27: Implemented the bounded synchronous native static crawler with
  exact effective-origin scope, canonical `(depth, URL)` traversal, explicit
  redirects, GET-only transport, request/page/depth/elapsed/redirect/delay/
  timeout budgets, bounded response reads, HTML-only extraction, deterministic
  aggregate merging, and structured warning/skip accounting.
- 2026-07-27: Added fake-transport normal/adversarial coverage and a
  test-owned `127.0.0.1` loopback fixture covering local and cross-origin
  redirects, loops, repeated query input, non-HTML, 404, timeout, oversized
  response, duplicate/fragment URLs, GET/POST forms, and an off-scope sentinel.
  The sentinel received zero requests and every primary-server request was GET.
- 2026-07-27: During local boundary review, bounded transport timeout was capped
  to remaining elapsed budget, responses completing after that budget were not
  parsed, redirect statistics were tied to actual reserved requests, and HTTP
  error-body read failures were converted to typed transport warnings.
- 2026-07-27: Final Milestone 3 verification passed 17 focused crawler tests and
  all 258 repository tests. Format, lint, type-hint, `git diff --check`,
  cross-hash-seed determinism, body-read bounds, and loopback-only network
  checks passed. Independent Gate Review iteration 1 reached `PASS` with no
  Critical, High, or Minor findings.
- 2026-07-27: Implemented Milestone 4 with separate legacy-record and native-URL
  entries converging on one observation/features/scoring/Top-K loop. The native
  entry consumes `CanonicalDiscoveryResult` directly, forwards only structured
  `READY` contexts, and executes only GET templates; POST forms remain visible
  discovery surfaces and are reported as skipped without submission.
- 2026-07-27: Added seven native pipeline/CLI tests for URL and legacy source
  exclusivity, malformed URL and crawler-policy validation, JSON plus HTML
  output, empty and partial crawl results, crawler warnings, and GET-only
  observation. The unchanged v0.1 smoke suite passed all 7 tests.
- 2026-07-27: Milestone 4 Gate Review iteration 1 reached `PASS` with no
  Critical or High findings. The focused suite passed 7 tests and the full
  suite passed all 265 tests; format, lint, type-hint, and `git diff --check`
  passed.
- 2026-07-27: Added the Milestone 5 real-transport CLI E2E with an ephemeral
  primary loopback site and a distinct-port loopback origin sentinel. The
  fixture covers duplicate and fragment links, repeated/blank/percent-encoded
  query contexts, GET/POST/default/relative forms, hidden input, textarea,
  select, local/external redirects, non-HTML, 404, and depth enforcement.
- 2026-07-27: The E2E completed with 12 bounded crawler GETs and 18 observation
  GETs. The external-origin sentinel and POST handler each received zero
  requests; duplicate canonical `/search?q=hello` was fetched once, the
  depth-two link was not fetched, and JSON/HTML represented the same selected
  candidate IDs, feature-vector IDs, evidence, and existing scores.
- 2026-07-27: Final Milestone 5 verification passed the focused E2E, all 266
  repository tests, and all 7 unchanged v0.1 smoke tests. Format, lint,
  type-hint, `git diff --check`, branch-diff review, and changed-file secret
  pattern checks passed.
- 2026-07-27: Independent final Gate Review reached `PASS` with no Critical,
  High, or Minor findings. All 25 acceptance criteria are complete; dynamic
  crawling, login/session automation, and JavaScript/SPA rendering remain
  explicitly deferred. Moved this plan from `active/` to `completed/`.

## Decision Log

- Decision: Use one real urllib CLI E2E with server-side request logs and a
  distinct-port loopback sentinel rather than any public target.
  Reason: this exercises the production crawler and observation transports
  while proving same-origin, GET-only, redirect, form, and credential
  boundaries without external network access.
- Decision: Verify blank and percent-encoded contexts in the crawler/request
  log while verifying the selected canonical candidate and evidence in both
  reports.
  Reason: multiple request contexts can share one InputPoint candidate ID, and
  Top-K intentionally deduplicates that candidate without erasing the
  discovery or execution contexts.
- Decision: Native analysis consumes `CanonicalDiscoveryResult.ready_contexts()`
  directly and applies an additional GET-only execution filter while retaining
  skipped POST contexts as warnings.
  Reason: canonical readiness is the discovery handoff boundary, while the
  static URL integration safety policy forbids automatic form submission and
  all POST execution.
- Decision: Keep crawler-policy CLI options URL-specific, allow zero depth and
  zero redirects as explicit bounded policies, and require positive page,
  request, and timeout budgets.
  Reason: root-only and no-redirect crawling are finite valid configurations,
  while zero pages, requests, or timeout cannot perform meaningful bounded
  discovery.
- Decision: Expose `CrawlPolicy`, GET-only crawler request/response transport
  types, `StaticCrawler.crawl()`, immutable `StaticCrawlResult`, and URL
  canonicalization from `vulnspider.discovery`.
  Reason: transport injection makes scope and budget boundaries testable while
  keeping Milestone 3 independent from the frozen probe executor and Milestone
  4 pipeline/CLI integration.
- Decision: Define origin as normalized `(scheme, hostname, effective port)`,
  remove default ports and fragments, preserve raw path/query bytes and ordered
  occurrences, and queue by `(depth, canonical_url)`.
  Reason: this gives exact same-origin enforcement and deterministic duplicate
  handling without lossy query decoding or suffix-based scope expansion.
- Decision: Disable urllib automatic redirects and read at most
  `max_response_bytes + 1`; reserve every initial or redirect-hop request before
  transport and revalidate redirect destinations before following them.
  Reason: off-scope redirects and oversized bodies must be blocked at the
  transport boundary rather than detected after an unsafe request or unbounded
  allocation.
- Decision: Count only unique HTML documents passed to `extract_static_html()`
  against `max_pages`; redirects, non-HTML, HTTP errors, timeouts, and oversized
  responses consume request/skip accounting but not the HTML page budget.
  Reason: this matches the execution plan's parser-page budget while retaining
  truthful transport statistics.
- Decision: Merge each per-document canonical result under one crawler
  metadata/scope identity and combine same-identity InputPoint baseline
  evidence before calling `CanonicalDiscoveryResult.create()`.
  Reason: cross-page provenance must be retained without duplicate child IDs or
  context validation failures when one canonical input is observed repeatedly.
- Decision: Implement the latest task-named public module as
  `vulnspider.discovery.html_extractor` with `extract_static_html()` returning
  immutable `StaticExtractionResult` and `NavigableLink` records.
  Reason: the milestone task explicitly names this API, and it keeps extraction
  separate from the future Milestone 3 crawl engine.
- Decision: Use `html.parser.HTMLParser` and URL utilities from the standard
  library, with no parser-owned transport or third-party dependency.
  Reason: Milestone 2 accepts HTML text and source context only; fetching,
  redirects, scope enforcement, budgets, and form submission are out of scope.
- Decision: Preserve raw query tokens and request pair order while canonicalizing
  names only for `InputPoint` identity and repeated-occurrence counting.
  Reason: request reconstruction needs lossless raw evidence, while ownership
  validation requires the same `strip().lower()` identity rule as the domain.
- Decision: Preserve safely recoverable malformed forms as partial,
  non-probe-ready contexts; skip unusable links/actions/controls with structured
  warnings whose URL evidence is fingerprinted rather than echoed.
  Reason: malformed input must not abort document extraction or fabricate a
  probe-ready request, and diagnostic payloads must not leak sensitive values.
- Decision: Aggregate validation re-runs each discovery-owned child's semantic
  validator before checking stable identity, ownership, and references.
  Reason: recomputing an ID must not legitimize mutated scope references,
  negative depth, duplicate readiness reasons, mutable evidence, or forbidden
  BAC decision semantics.
- Decision: Treat scope-decision references as sorted, unique, non-empty opaque
  tokens and deep-check warning/BAC evidence as immutable canonical JSON.
  Reason: the MVP reserves future ScopeGuard authority without accepting forged
  mutable handoff state or inventing an unapproved scope-decision registry.
- Decision: Reject BAC static-evidence keys that encode scoring, confidence,
  ranking priority, finding decisions, scorer maxima, or global Top-K
  selection, including normalized hyphen/underscore aliases.
  Reason: Milestone 1 owns static discovery hints only; BAC decision and ranking
  policy remain explicitly unapproved.
- Decision: Place run-level contract models under `vulnspider.discovery`, not
  in a parallel replacement for the existing domain package.
  Reason: 상현 owns the producer boundary, while existing child models are
  already canonical and consumed by planner/scoring/reporting.
- Decision: Reuse the four existing discovery child models and validate them as
  one aggregate.
  Reason: parallel Endpoint/InputPoint/RequestTemplate types would split
  identity and force downstream reconstruction.
- Decision: Treat corrupt identity/ownership as a contract error, and incomplete
  but internally honest context as structured `NOT_READY`.
  Reason: reference corruption cannot be made safe with a warning, while
  partial discovery remains useful for inventory and later collection.
- Decision: Preserve native HTML defaults as explicit standards-derived
  provenance, but keep legacy missing metadata as lossy assumptions.
  Reason: native source HTML can prove omission semantics; a legacy flattened
  record cannot prove whether metadata was omitted by HTML or collector loss.
- Decision: Keep BAC static hints independent from injection InputPoint
  readiness and ranking.
  Reason: ADR-014 defines BAC as a relationship-oriented family and its final
  access context is not approved.
- Decision: Keep `analyze_legacy_records()` behavior unchanged and add separate
  `analyze_discovery_result()` / `analyze_url()` paths.
  Reason: the adapter path is frozen v0.1 regression behavior while this MVP
  must make native discovery the additive primary URL path.
- Decision: Make producer factory canonicalize order and make handoff
  validation reject forged noncanonical order.
  Reason: producers may discover concurrently, but consumers must receive one
  deterministic representation and must not silently repair untrusted input.
- Decision: Use a synchronous deterministic crawler with explicit redirect
  handling and injectable transport/clock/sleeper.
  Reason: the MVP needs auditable budget and scope boundaries without async or
  browser complexity.
- Decision: Scope is exact normalized origin equality and redirect auto-follow
  is disabled.
  Reason: suffix matching and transport-controlled redirects can escape the
  authorized root scope.
- Decision: Use only the standard library for HTML parsing and HTTP transport.
  Reason: the repository has no production dependencies and the MVP does not
  need a new parser/browser dependency.
- Decision: Use `canonical-discovery/1.0`, deterministic semantic run identity,
  minimal versioned Scope/Crawl summary fields, and deterministic primitive
  serialization for the MVP.
  Reason: these choices satisfy the immediate producer/consumer boundary while
  leaving persisted JSON ingestion and dynamic collection for later work.

## Open Questions

No blocking Open Decision remains for this MVP. The following are explicitly
deferred and must not be solved by expanding this implementation:

- dynamic/browser collector provenance merge policy
- persisted canonical JSON ingestion/version migration
- non-loopback automated test targets
- authenticated session/cookie input
- BAC access-context model, scorer maximum, and cross-family Top-K
- public-site robots/anti-bot behavior
