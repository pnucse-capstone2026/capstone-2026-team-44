# Gate 1C — Risk-tiered Selective POST Replay

## 목적

VulnSpider는 GET-only crawler가 아니다. SPA/API 애플리케이션의 POST
surface도 폭넓게 발견하되, 다음 원칙을 적용한다.

> Discovery는 넓게, Active Execution은 위험도에 따라 제한한다.

최종 POST disposition은 다음과 같다.

- `SAFE_FOR_PROBE`: bounded Light Probe가 가능하다.
- `STRUCTURAL_ONLY`: 발견은 유지하지만 Active Replay는 하지 않는다.
- `BLOCKED_SENSITIVE`: 민감정보 저장과 Active Replay를 모두 금지한다.

Gate 1C는 POST를 모두 structural-only로 되돌리거나 현재 POST 발견 능력을
제거하는 작업이 아니다. Gate 1C-A는 후속 selective replay가 사용할 수 있도록
persistent discovery structure와 ephemeral replay material의 경계를 만든다.

## Context Read

- `AGENTS.md`
- `README_START_HERE.md`
- `PLANS.md`
- `CODE_REVIEW.md`
- `docs/ARCHITECTURE.md`
- `docs/DOMAIN_MODEL.md`
- `docs/GIT_WORKFLOW.md`
- Gate 1C-0 audit 결과와 현재 branch의 POST replay 구현

## 현재 문제

- 관찰된 POST가 reconstruction 가능하면 사실상 모두 `READY`가 된다.
- raw JSON member/query value가 persistent candidate와 canonical object에 남는다.
- structural candidate identity가 raw value에 종속된다.
- 별도 POST replay safety classifier가 없다.
- browser observation budget과 분리된 active POST replay budget이 없다.

## Gate 계획

1. **Gate 1C-A — Canonical identity + secret-safe representation**
   - structural identity를 raw value에서 분리한다.
   - persistent discovery structure와 ephemeral replay material을 분리한다.
   - POST endpoint와 JSON member 발견 능력 및 현재 실행 handoff는 보존한다.
2. **Gate 1C-B — POST Replay Policy classifier**
   - `SAFE_FOR_PROBE`, `STRUCTURAL_ONLY`, `BLOCKED_SENSITIVE`를 판정한다.
3. **Gate 1C-C — READY / NOT_READY handoff**
   - classifier 결과를 기존 readiness/context 계약에 연결한다.
4. **Gate 1C-D — Bounded POST Light Probe**
   - 독립적인 replay budget과 bounded execution을 적용한다.
5. **Gate 1C-E — Golden POST E2E**
   - 실제 browser observation, selective replay, state-change 및 secret leakage
     경계를 end-to-end로 검증한다.

Gate 1C-A에서는 classifier나 최종 readiness 정책을 구현 완료된 사실로 기록하지
않는다.

## Interfaces / Data Changes

- `BlockedPostJsonCandidate`는 method/origin/path/resource/member/query-name
  structure만 소유한다.
- `EphemeralRequestMaterial`은 정확한 replay URL/query/JSON body를 소유하되
  canonical identity, equality, repr 및 artifact serialization에서 제외한다.
- `NetworkDiscoveryCollection`과 worker pickle은 structural owner ID에 연결된
  explicit transient sidecar를 운반한다.
- `RequestTemplate`은 persistent structural fields와 실행 전용 accessors를
  분리한다. 기존 canonical `to_dict()` schema는 바꾸지 않는다.

## Safety / Scope Impact

- 새로운 host, method, browser authority 또는 transport 권한을 추가하지 않는다.
- 기존 exact-origin, loopback, blocked-before-transport POST 관찰 경계를 유지한다.
- 현재 replay 경로를 유지하지만 classifier와 별도 active POST budget은 후속
  Gate 전까지 추가하지 않는다.
- credential/security-token 이름을 좁게 확장하며 일반 `id`/`key` 이름은
  차단하지 않는다.

## Test Plan

- 제품 변경 전 structural ID/value leakage/CSRF-XSRF RED를 확보한다.
- POST canonicalization, domain identity, sensitive policy, planner execution,
  worker handoff와 crawl report leakage만 표적으로 검증한다.
- rendered DOM, same-origin navigation, GET/HEAD fetch/XHR를 독립 대조군으로
  검증한다.
- 전체 891-test suite는 이 Gate 요청에 따라 실행하지 않는다.

## Acceptance Criteria

- [x] 동일 structure/different values 및 JSON key ordering이 같은 candidate ID다.
- [x] InputPoint identity가 raw value와 무관하게 deterministic하다.
- [x] candidate repr/pickle 및 canonical/crawl artifact에 raw sentinel이 없다.
- [x] explicit transient material만 worker IPC에서 정확한 replay value를 운반한다.
- [x] POST Endpoint/InputPoint 발견과 현재 execution handoff가 유지된다.
- [x] CSRF/XSRF 이름은 차단되고 일반 `id`/`key`는 과잉 차단되지 않는다.
- [x] 표적 POST/worker/SPA 테스트와 diff/static 검증 결과를 기록한다.

## 현재 협업 충돌 영역

Gate 1C 기간에는 다음 파일을 coordination 대상으로 취급한다.

- `src/vulnspider/discovery/dynamic_browser.py`
- `src/vulnspider/discovery/dynamic_crawler.py`
- `src/vulnspider/discovery/network_canonicalization.py`
- `src/vulnspider/discovery/html_extractor.py`
- `src/vulnspider/discovery/contracts.py`
- `src/vulnspider/discovery/merge.py`
- `src/vulnspider/sensitive.py`
- `src/vulnspider/observation/planner.py`
- `src/vulnspider/pipeline.py`
- `src/vulnspider/reporting/crawl_report.py`

이 영역을 동시에 변경하는 작업은 먼저 현재 diff와 Gate 소유권을 확인한다.

## 명시적 Non-goals

- nested JSON replay
- GraphQL mutation
- multipart replay
- authenticated POST automation 확대
- external target support
- 새로운 vulnerability type
- JSON focused verification 확대

## Gate 1C-A 불변식

- Structural POST candidate identity는 raw member value와 JSON key ordering에
  의존하지 않는다.
- 기존 InputPoint의 구조적 deterministic identity 계약을 유지한다.
- raw JSON value와 token/password/CSRF-like sentinel은 persistent candidate,
  canonical discovery serialization, crawl artifact, discovery snapshot 및 일반
  report에 남지 않는다.
- replay에 필요한 baseline material은 명시적인 ephemeral execution material로
  분리하며 structural identity나 일반 artifact serialization에 포함하지 않는다.
- POST Endpoint/JSON member discovery와 POST-independent SPA/GET/HEAD 동작을
  유지한다.

## 진행 기록

- 2026-08-31: Gate 1C-0 설계 감사에서 최종 정책을 risk-tiered selective POST
  replay로 확정했다.
- 2026-08-31: Gate 1C-A 분리 경계는 value-free
  `BlockedPostJsonCandidate`/persistent `RequestTemplate`과, 일반 repr 및 artifact
  serialization에서 제외되는 명시적 `EphemeralRequestMaterial` sidecar로 정했다.
  sidecar는 현재 POST 실행 handoff를 유지하기 위해 live discovery result와 worker
  IPC pickle에서만 전달한다.
- 2026-08-31: 제품 수정 전 Gate 테스트 7개를 실행해 11개 assertion/subtest
  failure를 재현했다. 구조가 같고 값만 다른 candidate ID, candidate repr 및
  canonical artifact의 raw sentinel, CSRF/XSRF 이름 인식이 RED였다. JSON key
  ordering과 기존 InputPoint 구조 ID는 이미 PASS였다.
- 2026-08-31: 구조 candidate에서 member/query value를 제거하고, canonical JSON
  body는 member별 `null` structural binding으로 저장하며 InputPoint baseline은
  `None`으로 유지했다. planner만 execution sidecar의 정확한 query/JSON 값을
  사용한다. merge는 동일 structural template에 sidecar가 있는 경우 이를
  실행 경로로 보존한다.
- 2026-08-31: targeted Gate/POST/sensitive/domain/worker/planner/SPA 대조군 37개가
  PASS했다. 별도 SPA 대조군 8개도 PASS했고 format/lint 및 in-memory dependency
  stub을 사용한 type-hint 검증이 PASS했다. 저장소 기본 type checker의 최초
  실행은 base PR #19 환경의 undeclared `tqdm` 의존성 때문에 import 전에
  중단됐다. 전체 test suite는 실행하지 않았다.
- 2026-08-31: persistent candidate pickle, canonical `to_dict()`, discovery
  snapshot 및 crawl report에는 sentinel이 없음을 확인했다. worker IPC pickle은
  의도적으로 explicit transient sidecar를 운반하며, 일반 artifact serialization과
  repr에서는 해당 값을 숨긴다.
- 2026-08-31: 첫 independent Gate Review에서 sidecar URL이 structural owner에
  결속되지 않아 외부 URL로 바뀔 수 있는 High finding을 발견했다. POST 전용,
  scheme/authority/path, fragment 부재, URL/query pair, structural query/JSON name
  일치를 도메인 경계에서 검증하고 5개 fail-closed 회귀를 추가했다. 재리뷰는
  18개 표적 테스트와 이전 bypass 재현 차단을 확인하고 `PASS`를 판정했다.
- 2026-08-31: Gate 1C-B 제품 코드 전 classifier matrix를 추가하고, policy
  module 부재로 1개 import error를 재현했다. 빈 JSON object가 두 weak semantic
  signal만으로 SAFE가 되는 추가 RED도 재현했다.
- 2026-08-31: value-free `PostReplayPolicyFeatures`, 전용 disposition/reason
  model과 pure classifier를 추가했다. classifier/sensitive, Gate 1C-A
  identity/artifact/sidecar/planner/pipeline/worker, submit-gate, BAC live-cookie와
  artifact-redaction 표적 회귀 36개가 PASS했다. format/lint와 새 policy module의
  공개 type-hint 검증도 PASS했다. 저장소 전체 type-hint 검사는 기존 `cli.py`의
  undeclared `tqdm` import에서 module 검사 전에 중단됐다. 전체 unittest suite는
  실행하지 않았다.
- 2026-08-31: independent review 중 percent-encoded path, camelCase
  action/credential name, literal mutation, Gate 1C-A가 camel boundary를 제거한
  `cartAdd` → `cartadd` state semantic 우회를 발견했다. 각 case를 RED로 재현한 뒤
  UTF-8 percent-decoded path tokenization, camel boundary 보존, precomputed
  credential-material flag, direct mutation token과 concatenated context/action
  판정을 추가했다. 재리뷰에서는 GraphQL non-goal이 action/member positive
  evidence로 SAFE가 되는 gap과 concatenated context substring 과잉 판정을
  발견했다. explicit/path GraphQL fail-closed reason을 추가하고 concatenated
  판정을 exact context/action compound로 좁혔다. 수정 후 위 36개 표적 회귀가
  PASS했다.
- 2026-08-31: fresh independent Gate Review는 최종 snapshot에서 BLOCKER/MAJOR
  없음과 `APPROVE`를 판정했다. production feature builder가 raw observation에서
  GraphQL/credential/action flags를 생성하는 wiring 회귀는 Gate 1C-C의
  non-blocking test gap으로 남겼다.
- 2026-08-31: Gate 1C-C 제품 수정 전 handoff matrix 7개를 추가해 10 failure와
  5 error를 재현했다. policy가 observation에서 호출되지 않고, disposition/reason이
  candidate/readiness에 없으며, structural/sensitive POST가 삭제되거나 기존 READY
  sidecar를 유지하는 RED였다.
- 2026-08-31: dynamic POST projection에서 classifier를 호출하고 value-free
  candidate에 판정을 결속했다. canonical builder는 SAFE와 complete sidecar가 함께
  있을 때만 READY로 bind하며, 나머지는 structural template/context를 보존한 채
  policy reason이 있는 NOT_READY로 bind한다. 동일 structural owner의 중복 관측은
  가장 제한적인 disposition을 택하고 non-safe sidecar를 폐기한다.
- 2026-08-31: 첫 independent Gate 1C-C review는 alias path의 GraphQL mutation이
  production feature projection에서 explicit GraphQL flag를 잃어 SAFE가 되는 우회와,
  READY template에서 sidecar만 제거하면 planner가 persistent `null` binding을
  baseline으로 사용하는 우회를 BLOCKER로 재현했다. top-level GraphQL document를
  raw value 없이 boolean으로 projection하고, planner와 canonical READY validation
  모두 SAFE disposition + ephemeral material을 요구하도록 보강했다. 두 bypass
  재현과 관련 contract 회귀를 포함한 132개 표적 테스트 및 pipeline 대조군 1개가
  PASS했다.
- 2026-08-31: fresh re-review는 GraphQL ignored token인 leading BOM/comma 조합이
  alias-path mutation 판정을 우회하는 추가 BLOCKER를 발견했다. GraphQL boolean
  projection이 whitespace/comment뿐 아니라 BOM/comma prefix도 제거하도록 수정하고
  unprefixed, BOM-only, comma-only, BOM+comma+comment 혼합 회귀를 추가했다. 최종
  independent re-review는 네 변형 모두 STRUCTURAL_ONLY, sidecar-free, NOT_READY,
  planner-rejected이고 stripped-sidecar bypass도 닫힌 상태임을 확인해
  `APPROVE — 0 blockers, 0 majors`를 판정했다.
- 2026-08-31: Gate 1C-D-1 제품 수정 전 exact baseline/single-member/exclusion/
  value-isolation/budget/determinism matrix 8개를 추가했다. 기존 exact baseline,
  one-at-a-time, owner/material과 non-safe exclusion 6개는 PASS했고, 8-member SAFE
  fixture가 8 plans/16 requests를 생성해 cap 4 기대를 위반하는 2 failure를
  재현했다. 후속 adversarial owner test는 forged sidecar의 URL/query 불일치가
  planner에서 거부되지 않는 추가 RED 1개를 재현했다.
- 2026-08-31: 기존 `ProbePlanner`에 per-invocation
  `PostProbePlanningBudget(max_plans=4)`를 결속했다. selective JSON POST는 exact
  sidecar owner, URL/query alignment, structural member set, sensitive member 부재,
  single-target diff를 preflight한 뒤 RequestInstance 생성 전에 budget을 예약한다.
  cap 뒤 context는 deterministic reason으로 skip하며 GET/form/BAC planner는 이
  budget을 소비하지 않는다.
- 2026-08-31: independent Gate Review는 함수형 `plan_probe_request()`가 POST에서
  매 호출 implicit budget을 새로 만들던 cap 우회, JSON POST template을 QUERY
  InputPoint로 rebind해 persistent `null` baseline과 budget을 우회하는 location
  confusion, 동시 reservation check/increment race, public counter assignment로 cap을
  reset하는 네 finding을 재현했다. 각 우회를 별도 RED로 고정한 뒤 functional POST는
  explicit shared budget을 요구하고, JSON template policy는 target location과 무관하게
  적용하며 non-JSON target을 거부했다. budget은 frozen cap/private counter/read-only
  property와 lock-protected reservation을 사용한다.
- 2026-08-31: 최종 코드 snapshot에서 새 Gate tests와 planner/pairing/readiness/
  classifier/ephemeral 회귀 122개, submit-gate/BAC live-cookie/simple SPA/GET 대조군
  39개, combined handoff 1개로 총 162개가 PASS했다. combined test는 기존
  undeclared `tqdm` import 때문에 최초 collection이 중단되어 테스트 프로세스 안의
  in-memory stub으로 재실행했다. format/lint와 `git diff --check`가 PASS했고 전체
  suite와 real-target E2E는 요청대로 실행하지 않았다.
- 2026-08-31: final fresh independent re-review는 앞서 발견한 functional budget,
  QUERY rebinding/persistent-null, concurrent reservation, public reset과 mutable-hash
  우회가 모두 닫혔음을 확인했다. exact baseline/single-member/method-origin-path-
  query-member invariants, deterministic cap/order, GET/pairing/provenance와 artifact
  secret 경계를 다시 검토하고 `APPROVE — 0 blockers, 0 majors, 0 minors`를
  판정했다.
- 2026-08-31: Gate 1C-D-2 제품 수정 전 type-aware scalar tests를 추가해 19개 중
  6 failure를 재현했다. integer/float가 string marker로 바뀌고 boolean/null이
  plan과 budget을 소비하며 max finite float도 string이 되는 RED였다.
- 2026-08-31: 기존 planner 안의 JSON scalar mutation seam만 확장했다. string은
  기존 marker를 유지하고 integer는 `n + 1`, finite float는 adjacent finite
  number를 사용한다. boolean/null/non-finite는 RequestInstance/budget 전에
  fail-closed하며 numeric reflection feature는 missing으로 남긴다.
- 2026-08-31: 첫 독립 D-2 review는 112개 좁은 회귀와 numeric edge를 확인하고
  `PASS — APPROVE`를 판정했다. 후속 self-audit에서 observed JSON string이 full
  sentinel marker와 같은 경우 encoded/raw collision 비교 때문에 no-op plan이
  거부되는 edge를 추가 RED로 재현했다. 기존 deterministic marker primitive가
  identifier/full candidate collision을 모두 nonce fallback하도록 수정했다.
- 2026-08-31: 최종 snapshot의 D-2 core 21개와 POST readiness, GET planner,
  pairing/provenance, submit-gate, BAC live-cookie, simple SPA 회귀를 합친 109개가
  PASS했다. format/lint, in-memory `tqdm` stub type-hint와 `git diff --check`도
  PASS했다. 전체 suite와 real-target E2E는 요청대로 실행하지 않았다.
- 2026-08-31: fresh final re-review는 string identifier/full-sentinel collision,
  decoded JSON scalar 분기, unsupported type의 pre-budget fail-closed, exact sidecar/
  single-member/member-order, cap 4와 numeric missing-reflection/pairing provenance를
  재검토했다. 별도 67개 표적 테스트와 `git diff --check`가 PASS했고
  `PASS — 0 blockers, 0 majors, 0 minors`를 판정했다.
- 2026-08-31: Gate 1C-E 제품 수정 전 real Chromium Golden test를 추가해 fixture
  route/recording seam 부재를 RED로 확인했다. D-2 이후 SAFE POST가 READY/executable이
  된 현재 계약과 충돌하던 두 기존 integration assertion도 RED로 재현했다.
- 2026-08-31: 기존 loopback HTTP/Playwright seam만 확장해 SAFE search, state-changing
  cart, sensitive login, GraphQL mutation을 한 SPA에서 관측했다. 제품 코드는 변경하지
  않았고 `/api/search`만 2 plans/4 POST requests로 analysis까지 전달되며 나머지는
  discovery-only/0 transport임을 고정했다. 최종 D/C/B/A, GET/HEAD, submit-gate,
  BAC/redaction, pairing/provenance, simple SPA/results-pack을 포함한 149개 표적 테스트와
  format/lint/`git diff --check`가 PASS했다. 전체 suite와 external target은 실행하지
  않았다.
- 2026-09-01: Phase 2-0 환경 조사에서 저장소는 Python `>=3.11`만 명시하고 CI
  workflow나 exact-version pin은 두지 않음을 확인했다. 이 workspace의 전용
  `.venv-vulnspider` Python 3.12.13을 canonical test interpreter로 확정했다. 전역
  `python` 3.14.6과 unavailable `py` launcher는 이 Gate에 사용하지 않았다.
- 2026-09-01: CLI가 실제 progress bar와 progress write에 사용하는 `tqdm`을
  unconditional import하면서 root `pyproject.toml` runtime dependencies에는 선언하지
  않은 dependency declaration defect를 stub-free CLI import와 CLI test collection
  RED로 재현했다. root dependency에 `tqdm>=4.66,<5`만 추가하고 canonical venv에
  `.[dynamic]`을 설치했다. Playwright는 기존 `dynamic` extra와 lazy preflight 경계가
  일치하므로 제품/manifest 결함이 아니며, 같은 interpreter의 Playwright 1.62.0과
  matching Chromium headless launch를 확인했다.
- 2026-09-01: 수정 후 stub-free CLI import와 `pip check`, CLI 11개,
  observation/Gate 1C 76개, dynamic-browser 32개, real Chromium Golden 1개로 총
  120개 표적 테스트가 PASS했다. format/lint/type-hint/`git diff --check`도 PASS했고
  전체 suite는 Phase 2-0 범위에 따라 실행하지 않았다.
- 2026-09-01: fresh independent review가 dynamic install guide의 direct Playwright
  설치 명령은 새 core dependency를 누락한다는 minor를 발견했다. root와 docs guide를
  모두 canonical `python -m pip install -e ".[dynamic]"` 명령으로 통일했다. 최종
  independent re-review는 `PASS — 0 blockers, 0 majors, 0 minors`를 판정했다.

## Phase 2-0 canonical test harness

- Canonical interpreter:
  `C:\School\spiderman\.venv-vulnspider\Scripts\python.exe` (Python 3.12.13).
- VulnSpider dependency source of truth: root `pyproject.toml`. 별도
  `payload_verifier_v2` manifest와 read-only legacy `setup.py`는 root package의
  dependency source가 아니다.
- Test runner: standard-library `unittest`; repository-wide command는
  `python -B -m unittest discover -s tests`이고 이번 Gate에서는 실행하지 않는다.
- Source checkout 실행은 `$env:PYTHONPATH = "src"`를 명시한다.
- Dynamic browser dependency는 `pip install -e ".[dynamic]"`으로 설치하며 제품은
  dynamic opt-in 전까지 Playwright를 import하지 않는다.
- Phase 2-0 acceptance는 stub-free CLI import, observation/Gate 1C targeted tests,
  strict browser preflight 및 real Chromium Golden test로 검증한다.

## Gate 1C-A 후속 경계

- Gate 1C-B 전에는 POST replay classifier나 최종 disposition을 구현하지 않는다.
- Gate 1C-C는 sidecar가 없는 persisted/reloaded template을
  `RECONSTRUCTION_INCOMPLETE` NOT_READY로 확정했다.
- Gate 1C-D에서 현재 active POST 횟수를 별도 budget으로 제한하고 sidecar
  lifetime을 더 좁힐 수 있는지 재검토한다.

## Gate 1C-B classifier contract

Gate 1C-B는 `discovery/post_replay_policy.py`의 순수 policy component로
구현한다. 이 component는 현재 discovery readiness나 active transport를
변경하지 않는다.

입력은 다음 value-free structural feature로 제한한다.

- method와 query-free path
- normalized JSON member/query/header/cookie names
- fetch/XHR resource provenance와 optional UI action intent
- exact authorized loopback origin 여부
- normalized content type/charset
- top-level object/scalar shape와 reconstruction completeness
- credential value/header/cookie presence flag
- explicit GraphQL semantics flag

결과는 `PostReplayDisposition`과 deterministic primary
`PostReplayReasonCode`의 pair다. 민감 field/header/cookie가 가장 먼저
`BLOCKED_SENSITIVE`를 결정한다. method/origin/provenance/JSON shape/reconstruction
실패와 state-changing 또는 ambiguous semantics는 `STRUCTURAL_ONLY`다.
`SAFE_FOR_PROBE`는 모든 structural prerequisite를 만족하고, 주입 가능한
top-level member가 있으며, path/action/member 중 서로 다른 최소 두 signal
source에서 positive read-only evidence가 있을 때만 승인한다.

Gate 1C-B의 classifier result는 아직 `ProbeReadiness`, planner, pipeline 또는
POST execution budget에 연결하지 않는다. 해당 wiring은 Gate 1C-C/D 범위다.

## Gate 1C-B acceptance criteria

- [x] `/api/search` + `keyword`, `/api/filter` + `category,page`가
  `SAFE_FOR_PROBE`다.
- [x] update/cart/checkout, nested JSON, ambiguous endpoint와 빈 JSON object가
  `STRUCTURAL_ONLY`다.
- [x] password/token/authorization/session/CSRF/XSRF semantics가
  `BLOCKED_SENSITIVE`다.
- [x] `product_id`, `category`, `page`, `key`, `license_key`는 secret로
  과잉 차단되지 않는다.
- [x] 동일 member/shape의 scalar value 변화는 feature, disposition과 reason을
  바꾸지 않는다.
- [x] classifier는 기존 readiness와 active replay handoff를 변경하지 않는다.
- [x] GraphQL path/explicit semantics는 non-goal로 `STRUCTURAL_ONLY`다.

## Gate 1C-C readiness handoff contract

Gate 1C-C는 별도 readiness 계층을 만들지 않는다. 기존 경계를 다음 순서로
연결한다.

1. `_safe_blocked_post_json_candidate()`가 transient request body/header/query
   projection으로 `PostReplayPolicyFeatures`를 만들고 classifier를 호출한다.
   `query` member의 GraphQL document는 raw text 대신 explicit boolean만 투영한다.
2. `BlockedPostJsonCandidate.replay_policy`가 value-free structural observation과
   disposition/reason을 결속한다. `EphemeralRequestMaterial`은
   `SAFE_FOR_PROBE`에서만 collection sidecar에 들어간다.
3. `canonicalize_network_discovery()`가 candidate policy와 optional sidecar를
   기존 `CanonicalDiscoveryBuilder.add_structural_json_body_surface()`에 넘긴다.
4. builder의 기존 `_bind()`가 `ProbeReadiness`를 만든다.
   `CanonicalDiscoveryResult.ready_contexts()`가 READY만 반환하고,
   `analyze_discovery_result()`가 그 결과만 planner/executor에 넘긴다.

Disposition mapping은 다음과 같다.

| POST policy | Reconstruction | Readiness | Persistent structure | Planner handoff |
| --- | --- | --- | --- | --- |
| `SAFE_FOR_PROBE` | complete sidecar + owner match | `READY` | 유지 | 허용 |
| `SAFE_FOR_PROBE` | sidecar 누락/불완전 | `NOT_READY` + `POST_POLICY_STRUCTURAL_ONLY` (`RECONSTRUCTION_INCOMPLETE`) | 유지 | 금지 |
| `STRUCTURAL_ONLY` | 무관 | `NOT_READY` + `POST_POLICY_STRUCTURAL_ONLY` | 유지 | 금지 |
| `BLOCKED_SENSITIVE` | 무관 | `NOT_READY` + `POST_POLICY_BLOCKED_SENSITIVE` | value-free로 유지 | 금지 |
| assessment failure | 무관 | `NOT_READY` + `POST_POLICY_ASSESSMENT_FAILED` | value-free로 유지 | 금지 |

Discovery preservation invariant는 "발견했지만 실행하지 않는다"다. non-safe POST도
Endpoint, JSON InputPoint, structural `RequestTemplate`,
`InputPointRequestContext`, provenance와 readiness record를 유지한다. raw JSON/query
value는 persistent artifact에 넣지 않으며, credential 자체가 member name으로
관측되면 stable redacted placeholder로 대체한다. policy metadata에는 enum
disposition/reason만 기록한다.

Planner 우회 방지는 세 겹이다. collection은 non-safe owner에 sidecar 결속을
거부하고, canonical builder는 non-safe sidecar를 제거하며, template metadata의
`non_probe_ready_reasons`와 UNKNOWN completeness가 direct planner 호출도
fail-closed시킨다. 동일 구조의 SAFE/blocked 중복 관측은 관측 순서와 무관하게
`BLOCKED_SENSITIVE`가 이기며 기존 sidecar를 제거한다. owner mismatch는 기존
`EphemeralRequestMaterial` structural binding 검증에서 거부한다.

## Gate 1C-C acceptance criteria

- [x] search/filter safe JSON POST는 complete sidecar가 있을 때 READY이고 planner가
  exact transient baseline을 사용한다.
- [x] update/cart/ambiguous/nested/GraphQL POST는 structural discovery를 유지한
  NOT_READY다.
- [x] password/token/session/CSRF/JWT/header credential은 value-free structural
  discovery를 유지한 `BLOCKED_SENSITIVE`이며 sidecar가 없다.
- [x] classifier exception과 missing sidecar는 deterministic reason으로
  fail-closed한다.
- [x] structural owner mismatch와 duplicate-observation downgrade bypass를
  차단한다.
- [x] GET/HEAD authority, simple SPA discovery, submit gate와 BAC live-cookie/
  artifact-redaction 표적 회귀를 유지한다.
- [x] POST request budget, nested replay, multipart, GraphQL replay와 focused
  verification은 Gate 1C-D 이후 non-goal로 남긴다.

## Gate 1C-D-1 current POST planner seam

현재 selective JSON POST는 별도 planner architecture를 만들지 않고 기존
injection observation 경로를 그대로 사용한다.

```text
CanonicalDiscoveryResult.ready_contexts()
  -> pipeline._analyze_contexts()의 context-id 정렬
  -> 하나의 공유 ProbePlanner 인스턴스
  -> ProbePlanner.plan()
       readiness/policy/material preflight
       exact EphemeralRequestMaterial baseline
       target JSON member 하나만 marker로 교체
       per-planner POST budget 예약
       ProbePlan(baseline_request, probe_request)
  -> RequestExecutor.execute_plan()
       baseline 1회 + probe 1회
  -> plan/role/request-id가 결속된 ResponseSnapshot/ResponsePair
  -> extract_minimal_features()
  -> InputPoint별 feature aggregation/scoring
```

GET/query와 HTML form은 기존 marker, plan identity, execution, pairing 경로를
유지한다. Gate 1C-D-1의 새 budget과 material preflight는
`POST + JSON/JSON_BODY` selective replay에만 적용된다. BAC는 별도 GET-only
access planner/executor이며 이 budget을 소비하지 않는다.

현재 pairing contract에서는 같은 JSON body의 서로 다른 InputPoint라도 각
`ProbePlan`이 자신의 baseline/probe response ownership을 가져야 한다. 따라서
동일 baseline request bytes와 request ID가 여러 plan에 나타날 수 있지만,
`(probe_plan_id, request_role, request_id)` provenance는 서로 다르다. 이번 Gate는
baseline cache/dedup을 추가하지 않고 plan마다 baseline 1회를 유지한다.

## Gate 1C-D-1 bounded planning contract

Selective JSON POST plan은 다음 조건을 모두 만족할 때만 생성한다.

- method가 POST이고 target이 top-level `JSON/JSON_BODY` InputPoint다.
- template metadata disposition이 `SAFE_FOR_PROBE`다.
- context completeness가 `COMPLETE`이고 기존 non-ready reason이 없다.
- `EphemeralRequestMaterial`이 존재한다.
- sidecar scheme/authority/path와 fragment 부재가 structural URL owner에 맞는다.
- sidecar URL query와 query material이 정확히 정렬된다.
- sidecar query/JSON member names가 persistent structural names와 일치한다.
- JSON member name 중 credential/sensitive name이 없다.
- baseline은 sidecar의 exact execution URL/query/JSON scalar values를 사용한다.
- probe는 target member 하나만 기존 deterministic Light Probe marker의 canonical
  JSON string으로 교체한다.
- method, URL, query, form, JSON member order/set과 다른 member value는 유지한다.

Budget은 `PostProbePlanningBudget`이 `ProbePlanner` invocation마다 소유한다.
default cap은 **4 plans**이며 plan 하나는 기존 pairing 계약대로 baseline/probe
두 요청을 소유하므로 최대 **8 selective POST transport requests**다. context는
기존 deterministic context-id 정렬 순서로 planner에 들어가며, cap 이후 context는
동일한 `POST_PROBE_PLAN_BUDGET_EXHAUSTED` reason으로 skip된다. 예약은 모든
preflight와 mutation tuple 생성 후, baseline/probe `RequestInstance` 생성 전에
수행한다. public 함수형 `plan_probe_request()`는 selective POST에서 implicit
budget을 만들지 않고 caller가 하나의 shared budget을 명시해야 한다. cap과 private
counter는 외부 assignment로 reset할 수 없고 reservation/count read는 같은 lock으로
보호한다.

Cap 4의 근거는 graduation prototype의 현재 positive fixture가 보통 search/filter
1~2 scalar member이고 이를 그대로 수용하면서, discovery가 허용하는 최대 64 JSON
member가 128 active requests로 증폭되는 것을 8 requests로 제한하기 위해서다.
global scheduler나 endpoint별 adaptive policy를 새로 만들지 않는 가장 작은
deterministic bound이기도 하다.

Type-aware mutation은 Gate 1C-D-2로 남긴다. D-1에서는 string/integer/number/
boolean baseline scalar를 모두 exact sidecar value로 보존하지만, probe value는
기존 GET Light Probe의 deterministic reflection marker를 canonical JSON string으로
사용한다. nested object/array, GraphQL, multipart는 계속 plan을 만들지 않는다.

## Gate 1C-D-1 acceptance criteria

- [x] exact sidecar baseline이 persistent `null` binding 대신 사용된다.
- [x] plan 하나가 top-level target scalar member 하나만 변경한다.
- [x] second scalar plan은 다른 InputPoint의 value를 섞지 않는다.
- [x] method/origin/path/query/member set과 unrelated value가 유지된다.
- [x] missing/mismatched/forged sidecar는 RequestInstance 생성 전에 거부된다.
- [x] STRUCTURAL_ONLY/BLOCKED_SENSITIVE/GraphQL/nested JSON은 plan/execution 0이다.
- [x] planner invocation당 selective POST plan이 4를 넘지 않는다.
- [x] 함수형 planner entrypoint도 explicit shared budget 없이는 POST plan을 만들지
  않는다.
- [x] JSON POST template의 QUERY rebinding과 concurrent/public counter reset budget
  우회를 차단한다.
- [x] 같은 discovery input의 plan count/order/identity가 deterministic하다.
- [x] baseline dedup 없이 기존 ProbePlan/ResponsePair provenance를 유지한다.
- [x] GET, submit-gate, BAC live-cookie와 simple SPA 표적 회귀를 유지한다.

## Gate 1C-D-2 type-aware POST mutation contract

Gate 1C-D-2는 D-1의 planner, preflight, budget, execution과 pairing 경로를
그대로 사용하고 target top-level JSON scalar의 mutation value만 type-aware하게
선택한다. `SAFE_FOR_PROBE` + `READY` + owner-bound complete
`EphemeralRequestMaterial` 조건과 plan cap 4/transport request cap 8은 바꾸지
않는다.

Mutation matrix는 다음과 같다.

| Observed JSON type | Active probe | Probe/feature contract |
| --- | --- | --- |
| string | 기존 deterministic sentinel reflection marker의 canonical JSON string | 기존 marker strategy와 reflection feature를 그대로 사용한다. |
| integer | observed integer `n`의 `n + 1` | JSON integer type을 유지하고 정수에서 가능한 최소 non-zero 변화량 1만 적용한다. 문자열 marker를 전송하지 않으므로 reflection feature는 미관찰이다. |
| finite number/float | `math.nextafter(n, +inf)`; non-finite가 되면 `math.nextafter(n, -inf)` | 같은 binary float에서 표현 가능한 가장 가까운 유한 값을 사용한다. JSON number/float semantics를 유지하고 reflection feature는 미관찰이다. |
| boolean | plan 0 | `false -> true`가 권한/상태 의미를 바꿀 수 있어 active mutation 근거가 없다. |
| null | plan 0 | 대체 값의 안전한 type/semantic contract가 없다. |
| non-finite float | plan 0 | 표준 JSON transport value로 안전하게 재직렬화할 수 없다. |
| object/array | plan 0 | 기존 nested JSON non-goal을 유지한다. |

숫자 probe의 `ProbePlan.probe_marker`는 `None`이고 strategy는
`numeric-adjacent-v1`이다. 따라서 실제 request에 존재하지 않는 문자열을
reflection marker로 귀속하지 않는다. 기존 status/length differential 및 새 SQL
error feature는 그대로 관찰하지만 marker reflection/count/HTML encoding feature는
missing으로 남긴다. 별도 payload family나 mutation framework는 추가하지 않는다.

모든 허용 type에서 baseline은 sidecar의 exact observed canonical JSON scalar
tuple이다. probe는 같은 tuple index의 target value 하나만 바꾸며 method, execution
URL, authority/path/query, headers/cookies/form, JSON member set/order와 다른 member
value를 그대로 유지한다. boolean/null/non-finite 거부는 budget reservation과
`RequestInstance` 생성 전에 일어나므로 cap을 소비하지 않는다.

## Gate 1C-D-2 acceptance criteria

- [x] string scalar는 기존 non-destructive marker semantics를 재사용한다.
- [x] observed string이 identifier/full sentinel marker와 충돌해도 deterministic
  nonce fallback으로 non-noop string probe를 만든다.
- [x] integer는 type을 유지하며 deterministic `n + 1`만 사용한다.
- [x] finite float는 가장 가까운 유한 float로만 바뀌고 number semantics를
  유지한다.
- [x] boolean/null/non-finite float는 plan과 budget을 소비하지 않는다.
- [x] exact ephemeral baseline, single-member diff와 member set/order를 유지한다.
- [x] persistent `null` baseline과 owner mismatch는 계속 거부한다.
- [x] STRUCTURAL_ONLY/BLOCKED_SENSITIVE/nested/GraphQL/multipart는 plan 0이다.
- [x] plan cap 4/transport cap 8과 deterministic plan order/count를 유지한다.
- [x] numeric probe의 reflection features는 fabricated zero가 아닌 missing이다.
- [x] GET marker, ProbePlan/ResponsePair provenance, submit-gate, BAC live-cookie와
  simple SPA 회귀를 유지한다.

## Gate 1C-E Golden POST E2E contract

Gate 1C-E는 새 replay architecture를 추가하지 않고 기존 real Chromium
`DynamicLoopbackSite` seam에 네 POST observation을 함께 발생시키는 golden SPA를
추가한다. 브라우저 observation 단계는 모든 POST transport를 계속 차단하고 구조만
수집하며, 이후 기존 `analyze_url` planner/executor가 `SAFE_FOR_PROBE`인
`/api/search`만 active transport로 전달한다.

Golden fixture matrix는 다음과 같다.

| Observed request | Persistent discovery | Readiness / active replay |
| --- | --- | --- |
| `POST /api/search` string `keyword`, integer `page` | endpoint, top-level scalar InputPoint, value-free template/context | `SAFE_FOR_PROBE`, `READY`; exact sidecar baseline으로 2 plans / 4 requests |
| `POST /cart/add` | endpoint와 두 scalar InputPoint 유지, observed value 없음 | `STRUCTURAL_ONLY`, `NOT_READY`; 0 plans / 0 requests |
| `POST /login` username/password | value-free endpoint/InputPoint/template 유지, credential value 없음 | `BLOCKED_SENSITIVE`, `NOT_READY`; 0 plans / 0 requests |
| GraphQL mutation POST | endpoint와 top-level structure 유지, operation/query value 없음 | `STRUCTURAL_ONLY`, `NOT_READY`; 0 plans / 0 requests |

SAFE 실행은 plan마다 baseline/probe를 한 쌍씩 소유하므로 observed search body가
정확히 두 번, string single-member probe가 한 번, integer `1 -> 2` probe가 한 번
전송된다. 따라서 fixture의 실제 active POST는 `/api/search` 4회뿐이며 D-1의
4-plan/8-request 상한과 D-2 type-aware contract를 더 강화하지도 완화하지도 않는다.
각 `ResponsePair`는 exact plan id, baseline/probe request id와 role을 보존하고 두
FeatureVector 및 네 scoring result까지 기존 analysis pipeline으로 전달된다.

## Gate 1C-E acceptance criteria

- [x] real Chromium fetch observation에서 SAFE/state-changing/sensitive/GraphQL
  endpoint와 top-level InputPoint가 모두 보존된다.
- [x] `/api/search`만 `SAFE_FOR_PROBE` + `READY` handoff를 거쳐 keyword/page 두
  single-member plan과 정확히 4개의 POST request를 만든다.
- [x] string marker와 integer `1 -> 2`가 원래 JSON type, member set/order와 다른
  member 값을 보존한다.
- [x] cart/login/GraphQL은 `NOT_READY`, plan 0, active transport 0이다.
- [x] discovery/crawl/analysis artifact에는 search, cart, login, GraphQL의 raw
  observed value가 없다. exact search body는 live owner-bound sidecar에만 있다.
- [x] ProbePlan/ResponsePair request id, role, plan provenance와 analysis handoff가
  유지된다.
- [x] D/C/B/A, GET/HEAD, submit-gate, BAC cookie/redaction, simple SPA와 PR #21
  results-pack 표적 회귀를 유지한다.

## Decision Log

- Decision: structural candidate와 exact replay value는 structural owner ID로
  연결한 explicit sidecar로 분리한다.
- Reason: 최소한의 변경으로 deterministic identity와 artifact secret boundary를
  만들면서 현재 READY/planner handoff를 유지할 수 있다.
- Decision: persistent JSON binding은 member별 `null`, InputPoint baseline은
  `None`으로 표현한다.
- Reason: member 발견 구조와 기존 context ownership을 보존하면서 observed raw
  value를 canonical artifact에서 제거한다.
- Decision: Gate 1C-B POST disposition은 GET value-elision enum을 재사용하지
  않고 별도 `PostReplayDisposition`으로 표현한다.
- Reason: 기존 enum은 이미 허용된 GET의 value 보존 여부를 뜻하며, POST active
  replay 권한과 민감 차단을 함께 표현하지 못한다.
- Decision: SAFE positive evidence는 keyword 개수가 아니라 path/action/member의
  서로 다른 signal source 두 개 이상을 요구한다.
- Reason: 단일 약한 keyword로 SAFE를 승인하지 않으면서 search/filter JSON API의
  실용적 positive coverage를 유지한다.
- Decision: Gate 1C-C READY는 `SAFE_FOR_PROBE`와 owner-bound complete sidecar를
  모두 요구한다. disposition 또는 reconstruction 중 하나라도 불충분하면
  NOT_READY다.
- Reason: classifier 의미만으로 transient request reconstruction을 추정하거나,
  sidecar 존재만으로 policy를 우회하지 못하게 한다.
- Decision: non-safe POST도 structural template/context를 만들고 policy reason을
  기존 readiness/template metadata에 기록한다.
- Reason: 관측 coverage와 active replay 권한을 분리하며 direct planner 호출도
  fail-closed시킨다.
- Decision: Gate 1C-D-1 selective JSON POST cap은 per-`ProbePlanner` 4 plans로
  고정하고, cap reservation을 RequestInstance construction 전에 수행한다.
- Reason: common 1~2 member search/filter coverage는 유지하면서 최대 active POST를
  8 requests로 제한하고, 기존 pipeline의 단일 planner instance와 deterministic
  context ordering을 그대로 재사용할 수 있다.
- Decision: baseline cache를 추가하지 않고 각 ProbePlan이 exact baseline request와
  response provenance를 계속 소유한다.
- Reason: 같은 request bytes라도 observation ownership은 plan/role/request tuple이며,
  request 수 최적화가 이 reviewed pairing contract보다 우선할 수 없다.
- Decision: D-1의 number/boolean target도 기존 reflection marker JSON string을
  사용하고 type-aware bounded values는 D-2로 분리한다.
- Reason: 이번 Gate의 핵심은 exact baseline, single-member isolation과 budget이며,
  새로운 payload family/type semantics를 동시에 도입하지 않는다.
- Decision: D-2 integer는 `n + 1`, finite float는 가장 가까운 representable finite
  value를 사용하고 boolean/null/non-finite는 active target에서 제외한다.
- Reason: integer/float의 원래 JSON type을 유지하면서 가능한 가장 작은 deterministic
  변형만 허용하고, 권한/상태 의미를 바꿀 근거가 없는 scalar는 fail-closed하기
  위해서다.
- Decision: numeric probe에는 문자열 `probe_marker`를 귀속하지 않고 reflection
  feature를 missing으로 남긴다.
- Reason: 실제 request에 없는 identifier를 reflection evidence로 해석하거나 짧은
  숫자 문자열의 우연한 응답 등장을 positive reflection으로 오판하지 않기 위해서다.

## Open Questions

- sidecar lifetime을 planning 직후 더 단축할 수 있는지는 Gate 1C-D-2/E에서
  검토한다.
