# Decision Log

이 문서는 에이전트와 팀원이 반복해서 같은 설계를 재논의하지 않도록 결정 사항을 기록한다.

---

## ADR-001 — InputPoint as atomic observation unit

**Status:** Accepted

**Decision:** FeatureVector는 Endpoint 전체가 아니라 InputPoint에 귀속한다.

**Reason:** 동일 endpoint의 여러 parameter가 서로 다른 응답 신호를 만들 수 있으며, endpoint 단위 feature는 attribution을 오염시킨다.

---

## ADR-002 — Candidate = InputPoint x VulnerabilityType

**Status:** Accepted

**Decision:** 동일 InputPoint에 SQLi/XSS Candidate가 독립적으로 존재할 수 있다.

**Reason:** 취약점 유형별 feature와 score 의미가 다르다.

---

## ADR-003 — Separate RankScore from VerificationConfidence

**Status:** Accepted

**Decision:** RankScore는 후보 우선순위 전용이며 취약 확률로 해석하지 않는다.

**Reason:** 높은 우선순위가 높은 최종 확신도를 의미하지 않는다.

---

## ADR-004 — One-at-a-time Probe

**Status:** Accepted

**Decision:** 기본 Probe는 target InputPoint 하나만 변경한다.

**Reason:** response change attribution 확보.

---

## ADR-005 — Legacy crawler via adapter

**Status:** Historical — Accepted for v0.1; Superseded for the v0.2 primary
path by ADR-012 and ADR-013

**Decision:** 기존 WHSPIDER를 즉시 폐기하거나 본체를 대규모 수정하지 않는다. 먼저 audit 후 adapter로 연결한다.

**Reason:** 검증된 crawling logic은 활용하되 page-centric schema와 old LLM/RAG coupling은 새 시스템으로 전파하지 않는다.

---

## ADR-006 — LLM excluded from v0.1

**Status:** Accepted

**Decision:** 첫 프로토타입에는 LLM payload mutation을 넣지 않는다.

**Reason:** ranking 연구 가설을 독립적으로 검증하고 재현성을 확보한다.

---

## ADR-007 — BAC deferred and separately modeled

**Status:** Accepted

**Decision:** BAC는 v0.1에서 제외하고 향후 AccessCandidate 관계 모델로 다룬다.

**Reason:** SQLi/XSS의 단일 InputPoint injection 모델과 권한 관계 문제는 구조적으로 다르다.

---

## ADR-008 — Type-specific Top-K

**Status:** Superseded by ADR-010

**Decision:** v0.1 기본 selection은 vulnerability type별 Top-K다.

**Reason:** SQLi score와 XSS score가 동일 calibration이라고 가정하지 않는다.

---

## ADR-009 — Docs as system of record

**Status:** Accepted

**Decision:** `AGENTS.md`는 짧은 지도이며 세부 설계는 `docs/`에 둔다.

**Reason:** 거대한 단일 instruction file의 context 낭비와 stale rule 문제를 피한다.

---

## ADR-010 — Cross-type Top-K uses explicit selection priority

**Status:** Accepted

**Decision:** SQLi와 Reflected XSS 결과를 하나의 global Top-K로 선택할 때
raw RankScore를 직접 비교하지 않는다. 각 결과의 exact scorer maximum으로
raw score를 나눈 `selection_priority`를 사용하고 candidate id로 동률을
결정한다. raw RankScore는 그대로 보존한다. 이 결정은 ADR-008의
type-specific-only 기본 selection을 05D CLI에 대해 대체한다.

**Reason:** 현재 SQLi 범위는 0–75, Reflected XSS 범위는 0–45이므로 raw
값의 global 비교는 유형별 scale bias를 만든다. `selection_priority`는
확률이나 Confidence가 아니라 selection 전용 비교 key다.

---

## ADR-011 — HTML dashboard report added to v0.1 scope

**Status:** Accepted

**Decision:** v0.1은 기존 JSON 리포트에 더해, 동일한 검증된
`SelectionOutcome`과 실제로 실행된 baseline/probe 요청·응답으로부터
정적 HTML 대시보드 리포트를 생성할 수 있다 (`vulnspider analyze
--html-output`). 이는 `AGENTS.md`, `docs/PROTOTYPE_V0_1.md`,
`docs/ARCHITECTURE.md`가 명시하던 "dashboard is out of scope"를
대체한다.

**Reason:** 사용자가 CLI JSON 출력과 별도로 사람이 브라우저에서 바로
검토할 수 있는 대시보드 리포트를 명시적으로 요청했다. `PLANS.md`의
스코프 확장 절차(문서 갱신 + ADR + exec-plan)를 따라 의도적으로 범위를
넓힌다.

**Constraints (다른 ADR/규칙과의 충돌 방지):**

- `reporting`은 점수를 재계산하지 않는다(§ARCHITECTURE.md 6). HTML
  리포트는 JSON 리포트와 동일한 `SelectionOutcome`/`ScoreEvidence`만
  사용한다.
- `RankScore`/`selection_priority`는 여전히 vulnerability probability나
  confidence가 아니다(규칙 5-6, ADR-010). HTML 리포트는 "priority"/"rank
  score" 용어만 사용하고 "confidence"/"probability"/"confirmed"를 쓰지
  않는다.
- Focused/multi-payload verification은 계속 out-of-scope다
  (ARCHITECTURE.md §2.2). HTML 리포트의 "Executed requests" 절은 v0.1이
  실제로 보낸 baseline 1건 + probe 1건만 표시하며, 존재하지 않는 다건
  확인용 payload를 만들어 보여주지 않는다.
- BAC/IDOR 후보는 여전히 생성하지 않는다(ADR-007). 대시보드는 scoring이
  실제로 만드는 SQLI/REFLECTED_XSS만 렌더링한다.

**Alternatives considered:** 스코프를 바꾸지 않고 문서와 어긋난 채로
코드만 추가(reject — CODE_REVIEW.md 1번 체크리스트와 충돌); 별도
저장소(vulnspider 목업)에서만 진행(reject — 사용자가 이 저장소에 명시적
요청).

**Consequences:** `AGENTS.md`, `docs/PROTOTYPE_V0_1.md`,
`docs/ARCHITECTURE.md`의 out-of-scope 목록에서 "dashboard"를 제거하고
in-scope Output에 추가해야 한다. `pipeline.AnalysisResult`가
`ProbePlan`/`ResponseSnapshot`을 리포팅을 위해 보존하도록 확장된다
(순수 추가, 기존 필드/시그니처는 유지).

---

## ADR-012 — Native crawler is the v0.2 primary discovery path

**Status:** Accepted

**Date:** 2026-07-26

**Decision:** v0.2의 주 실행 경로는 target URL에서 시작하는 native static
crawler를 사용한다. static crawler가 canonical domain model을 직접
생성하며, 이후 dynamic/browser crawler prototype도 동일 contract에
연결한다.

**Reason:** legacy record 입력은 실시간 scope, redirect, request budget,
hidden input, raw query provenance를 완전하게 보장할 수 없다. v0.2의
discovery 책임과 안전 경계를 명시적인 producer가 소유해야 한다.

**Consequences:** static crawler를 먼저 구현하고 contract와 안전 제한을
검증한 뒤 dynamic crawler를 추가한다. 이 결정은 crawler가 구현됐다는
뜻이 아니며 현재 상태는 **Planned for v0.2**다.

---

## ADR-013 — LegacyCrawlerAdapter is compatibility-only in v0.2

**Status:** Accepted

**Date:** 2026-07-26

**Decision:** `LegacyCrawlerAdapter`는 삭제하지 않지만 v0.2 primary
discovery path에서는 사용하지 않는다. legacy 입력 변환과 regression
비교에만 유지한다.

**Reason:** v0.1 재현성과 과거 데이터 호환은 보존해야 하지만, legacy
schema의 불완전한 provenance를 native discovery contract의 기준으로
삼을 수 없다.

**Consequences:** ADR-005는 v0.1의 Historical 결정으로 남는다. native
crawler 기능을 adapter 내부에 추가하지 않으며 호환 경로 변경은 stable
identity와 provenance를 보존하거나 명시적으로 versioning한다.

---

## ADR-014 — BAC is a separate observation and scoring family

**Status:** Accepted

**Date:** 2026-07-26

**Decision:** BAC를 v0.2 범위에 포함하되 SQLi/XSS payload family에
끼워 넣지 않는다. 역할, 세션, 객체, 접근 관계를 표현하는 별도 observation,
feature, scoring family로 설계한다.

**Reason:** BAC는 단일 InputPoint mutation보다 두 개 이상의 권한
context와 객체 관계가 핵심이며 attribution과 안전 제한이 다르다.

**Consequences:** BAC 후보 모델과 bounded fixture 정책은 구현 전에
contract review가 필요하다. 자동 계정 생성, 권한 변경, destructive
verification은 허용하지 않는다.

---

## ADR-015 — LLM payloads require deterministic validator approval

**Status:** Accepted

**Date:** 2026-07-26

**Decision:** GPT/Gemini를 포함한 모든 LLM 출력은 실행 제안일 뿐이다.
모델이 만든 payload는 deterministic `PayloadValidator`가 target binding,
scope, family, encoding, mutation limit, safety policy를 승인하기 전에는
어떤 transport에도 전달하지 않는다.

**Reason:** provider 응답은 비결정적이고 신뢰할 수 없는 입력이다. 안전과
실행 가능성을 prompt 준수에 의존할 수 없다.

**Consequences:** validator rejection도 실험 결과로 기록한다. LLM은 최종
취약점 판단자가 아니며 focused verification만 구조화된 실행 evidence를
생성할 수 있다.

---

## ADR-016 — RankScore and VerificationConfidence remain independent

**Status:** Accepted

**Date:** 2026-07-26

**Decision:** ADR-003을 v0.2에서도 유지한다. `RankScore`와
`selection_priority`는 검증 순서를 위한 값이고,
`VerificationConfidence`는 focused verification의
`VerificationEvidence`에 deterministic rule을 적용한 별도 값이다.

**Reason:** 높은 ranking 신호를 검증 성공으로 해석하면 평가 leakage와
거짓 확신이 생긴다.

**Consequences:** confidence 계산은 ranking score를 단순 가산하지 않는다.
Confidence rule은 팀 전체가 리뷰하고 구현 owner는 석현이다.

---

## ADR-017 — v0.2 uses canonical cross-owner contracts

**Status:** Accepted

**Date:** 2026-07-26

**Decision:** owner 경계를 넘는 데이터는 versioned canonical contract로
전달한다. 초기 **Proposed Contract**는 `CanonicalDiscoveryResult`,
`RankedCandidateContext`, `VerificationResult`다.

**Reason:** consumer가 upstream 객체, ID, score, evidence, provenance를
재구성하면 attribution과 재현성이 깨진다.

**Consequences:** producer가 construction과 validation을 소유하고,
consumer는 forbidden reconstruction 규칙을 지킨다. contract 변경은
영향받는 producer와 consumer 리뷰가 필요하다.

---

## ADR-018 — Protected base branch and PR-only collaboration

**Status:** Accepted

**Date:** 2026-07-26

**Decision:** 과도기 base는 `prototype/v0.1`이며 main 승격 후에는 `main`을
공식 base로 사용한다. base branch 직접 commit을 금지하고 short-lived
branch와 PR을 사용한다.

**Reason:** 세 owner가 병렬 작업할 때 직접 commit과 암묵적 contract
변경은 통합 위험과 책임 불명을 키운다.

**Consequences:** 기본 merge 방식은 squash다. 기존 commit 보존이 중요한
integration PR은 review 후 merge commit을 사용할 수 있다. contract
변경은 영향 owner 리뷰가 필요하고 network scope 또는 payload 실행
변경은 2인 리뷰를 권장한다.

---

## ADR-019 — Simple CLI defaults to bounded Dynamic discovery

**Status:** Accepted

**Date:** 2026-08-04

**Decision:** `vulnspider -u URL` is a thin adapter over the existing combined
Static + Dynamic + merge + Light Probe pipeline. It uses the reviewed Dynamic
budget defaults except for a simple-adapter maximum link depth of two, allows
only exact same-origin GET URLs extracted from rendered anchors for
crawler-initiated navigation, and allows same-origin GET script/style resources
needed to render those anchors. The advanced
`vulnspider analyze` interface and its exact-grant defaults remain unchanged.

**Reason:** The public one-line command should discover JavaScript-rendered GET
surfaces without requiring users to predict those URLs, while page code must
not gain general navigation or active-transport authority.

**Consequences:** Naturally emitted same-origin GET/HEAD fetch/XHR use the existing
bounded simple-mode authority; WebSocket, EventSource, POST, form
submission, popup, child-frame documents, cross-origin, and different-port
traffic remain blocked unless an existing explicit advanced grant category
permits it. JSON publication uses same-directory temporary output plus atomic
replacement, and failed or degraded simple scans do not publish a new result.

---

## ADR-020 - Interface Contract v1 joins two canonical artifacts

**Status:** Accepted

**Date:** 2026-08-09

**Decision:** The current Probe-to-Feature boundary keeps the existing
`InputPoint`, `ProbePlan`, `ResponsePair`, and role-owned `ResponseSnapshot`
objects without a wrapper. Downstream Mutation integration consumes only
`vulnspider-crawl.json` and `vulnspider-analysis.json` through a validating,
in-memory `NormalizedCandidate` adapter. The adapter output is derived handoff
data, not a third canonical artifact.

**Reason:** Existing producers already own stable identity, provenance,
feature, scoring, and selection validation. A small join boundary makes those
guarantees consumable without duplicating the domain graph or introducing a
`context_registry.json` that could drift from its sources.

**Consequences:** Unresolved or contradictory IDs fail explicitly. Raw
credentials and unavailable evidence cannot be fabricated into mutation
context. BAC category/type values are reserved for a later reviewed producer;
this decision does not implement BAC behavior. Canonical discovery emits a
deterministic content-bound `discovery_snapshot_id`, and analysis records the
same snapshot reference. Non-decision elapsed-time telemetry is normalized out
of that binding. The handoff recalculates the binding and validates
serialized FeatureVectors, scoring evidence, and selection through the existing
scorers and Top-K implementation rather than trusting duplicated report values.

---

## ADR-021 - Canonicalize only already-allowed observed GET APIs

**Status:** Accepted

**Date:** 2026-08-14

**Decision:** Keep `PassiveNetworkObservation` as bounded audit-only evidence.
At the Guard decision seam, separately project only naturally emitted,
primary-page, exact-origin GET fetch/XHR requests that the existing Authority has
already allowed. Canonicalization consumes that internal candidate without
issuing, replaying, retrying, or reconstructing a request. Credential-free query
pairs produce ordinary Endpoint, QUERY InputPoint, RequestTemplate, and READY
request-context records through the existing canonical builder. A sensitive
query name/value or credential-bearing request header discards all values before
candidate retention and produces at most Endpoint plus ordered query-name
InputPoints with NOT_READY status and no template/context.

**Reason:** The Guard owns the original request and authoritative allow/scope
decision. Audit projections intentionally omit raw URLs and values, so rebuilding
from them would create false precision. Reusing existing canonical identities and
merge paths preserves deterministic DOM/network deduplication and lets the
unchanged ProbePlanner consume only validated READY contexts.

**Consequences:** HEAD, non-GET, blocked, off-scope, malformed, userinfo-bearing,
and oversized requests never become canonical. Raw authorization/cookie values,
JWTs, and sensitive query values are never retained by the candidate, audit, or
canonical artifacts. Canonical network objects participate in the existing
`discovery_snapshot_id`; audit-only occurrence changes do not. Safe READY
contexts may cause the existing analysis phase to send its normal attributed
baseline/probe pair, but canonicalization itself causes no transport.

---

## ADR-022 - Retain blocked POST JSON as structural-only discovery

**Status:** Accepted

**Date:** 2026-08-15

**Decision:** At the existing Guard scope/resource/method decision seam, inspect
only naturally attempted primary-page, exact-origin POST fetch/XHR requests with
`application/json` and an optional UTF-8 charset. The Guard still blocks the
request before transport. A bounded transient parser accepts only a top-level
object, rejects malformed/array/duplicate/oversized input, applies the shared
credential-material policy to the complete parsed tree, then discards every
value. A safe attempt retains only canonical source/endpoint URLs, resource
kind, and sorted top-level names. The existing builder emits a POST Endpoint and
JSON_BODY InputPoints with network provenance, no RequestTemplate/context, and
NOT_READY ownership.

**Reason:** A page's natural POST attempt reveals attack-surface structure even
when state-changing transport is prohibited. Capturing at the Guard preserves
authoritative primary-page and exact-origin evidence; reading passive audit
would require unsafe reconstruction. A value-free candidate supports canonical
identity and deterministic merge without creating replay authority or retaining
body/header secrets.

**Consequences:** POST remains non-executable in both browser transport and the
READY-GET-only analysis pipeline. Candidate/field/body bounds and sanitized
reason counts are deterministic. Sensitive material elides the whole candidate.
Malformed, non-object, duplicate-key, non-JSON, off-origin, non-primary, and
other-method attempts create no canonical surface. Safe structural objects
participate in the existing discovery snapshot and crawl/analysis binding.

---

## ADR-020 — One FeatureVector per InputPoint across its probe-ready contexts

**Status:** Accepted

**Date:** 2026-08-10

**Decision:** When one `InputPoint` owns several probe-ready
`InputPointRequestContext` objects, every executed probe run still runs, but
their per-run `FeatureVector` objects are combined into exactly one
`FeatureVector` for that `InputPoint` before candidate generation. Each feature
is combined existentially: the largest observed value wins, ties resolve by
ascending probe-run id, and a feature stays unobserved when no run observed it.
`probe_run_ids` lists every contributing `ResponsePair`, and `details` records
the aggregation version, the participating runs, the run that supplied the
retained value, each run's value, and the unobserved-run count. Aggregation
policy version: `input-point-existential-v1`.

**Context:** `docs/DOMAIN_MODEL.md` §9 already defines a `FeatureVector` as one
`InputPoint` plus the probe runs that produced it, and ADR-002 keeps
`InputPoint x VulnerabilityType` as the ranking atom. Native Static single-seed
crawls happened to bind one context per `InputPoint`, so a per-run vector was
indistinguishable from a per-InputPoint vector. Native Dynamic and Combined
discovery observe the same endpoint parameter through several request
templates, so per-run vectors produced several `ScoringResult` objects sharing
one candidate id. `select_top_k` then collapsed them silently, the same
candidate could appear in both `selected` and `unrankable`, and the reported
summary counted observations instead of candidates.

**Alternatives:** Probe only one deterministically chosen context per
`InputPoint`. Rejected because it discards the observation that discriminates
between contexts, for example a numeric baseline versus an already-broken one.
Fixing only the selection accounting was also rejected because it leaves the
ranking atom split across several feature vectors.

**Consequences:** `AnalysisResult.feature_vectors` holds one vector per
observed `InputPoint`, and several `ProbeObservation` records can reference the
same `feature_vector_id`. Reporting joins by `probe_run_ids` membership instead
of assuming one run per vector. A combined feature value can come from a
different probe run than its sibling feature, so a combined vector is not the
replay of one request pair; `selected_probe_run_id` keeps that explainable.
Single-context analyses are unchanged and keep their previous vector ids.
## ADR-021 — BAC joins the combined Top-K and selection produces the mutation handoff

**Status:** Accepted

**Date:** 2026-08-11

**Decision:** SQLi/Reflected XSS injection 후보와 BAC `AccessCandidate`를 하나의
combined Top-K로 합칠 때 ADR-010의 `selection_priority`(raw_rank_score / exact
scorer maximum)를 그대로 사용한다. BAC의 exact scorer maximum은
`ACCESS_MAX_RANK_SCORE`(=75.0, `access-control-weighted-v1`)이고 candidate id로
동률을 결정한다. Scorer는 기존 것을 재사용한다(`scoring.engine`의 SQLi/XSS,
`access.scoring`의 BAC). `selection.combined.select_combined_top_k()`는 이미
검증된 두 category 선택 결과만 병합하며 어떤 점수도 재계산하지 않는다.
`selection` 모듈은 이 combined Top-K를 mutation 모듈(LLM-assisted Payload
Mutation, owner 석현)로 넘기기 위한 handoff `RankedCandidateContext`
(ADR-017, `docs/TEAM_INTERFACES_V0_2.md` §2)를 `selection.handoff`에서 생성한다.

**Reason:** 검증 우선순위를 세 family에 걸쳐 하나의 순서로 제시하고 mutation
모듈에 단일 handoff로 전달하기 위함이다. `docs/TEAM_INTERFACES_V0_2.md` §2가
열어둔 "BAC가 SQLi/XSS global Top-K에 참여하는지" open decision을 이 ADR로
확정한다. 이는 ADR-010을 BAC family(ADR-014)까지 확장한다.

**Consequences:**

- `selection_priority`는 여전히 selection 전용 비교 key이며 확률이나
  Confidence가 아니다(ADR-010, ADR-016). 세 family의 raw scale이 다르므로 raw
  score를 직접 비교하지 않는다.
- handoff는 selection이 authoritative하게 소유한 필드만 채운다. scope/verification
  envelope(`target_scope_id`, `allowed_verification_policy`)는 selection이 소유하지
  않으므로 fabricate하지 않고 각 owner가 downstream에서 부여한다
  (`docs/TEAM_INTERFACES_V0_2.md` §2 forbidden reconstruction 준수).
- BAC observation pipeline(planner/executor)은 이 결정 범위 밖이며
  discovery/observation owner가 소유한다. `feat/selection-top-k`는 재사용한 BAC
  scorer·features·within-family selector만 가져온다.
- `docs/TEAM_INTERFACES_V0_2.md` §2 "BAC ranking and global selection boundary"와
  "Open contract decisions"의 해당 항목은 이 ADR을 참조하도록 갱신한다.

---

## ADR-022 — Calibrated probability replaces raw/max as the comparison key

**Status:** Accepted

**Date:** 2026-08-11

**Decision:** 후보 비교의 기준을 `raw_rank_score / exact_scorer_maximum`에서
보정된 확률 `P(vulnerable | observed evidence)`로 옮긴다. 확률은
`scoring/calibration.py`의 베이지안 로지스틱 회귀가 생성한다. 기존 휴리스틱
가중치(`SQLI_TERMS`, `XSS_TERMS`, `ACCESS_TERMS`)는 폐기하지 않고 logit
공간으로 rescale하여 Gaussian prior의 평균으로 사용한다.

이 결정은 ADR-003과 ADR-016의 "RankScore를 취약 확률로 해석하지 않는다"를
**decision layer 한정으로** 대체한다. `RankScore`, `selection_priority`,
`select_top_k()`, `select_combined_top_k()`의 의미와 동작은 바뀌지 않는다.

**Reason:** ADR-010과 ADR-021은 SQLi(0..75), Reflected XSS(0..45),
BAC(0..75)를 각자의 최댓값으로 나눠 비교했다. 이 몫이 왜 family 간에
비교 가능한지에 대한 근거는 없으며 ADR-010 본문도 "확률이 아니라 selection
전용 key"라고만 명시했다. 예산 배분은 서로 다른 family의 기대 효용을 실제로
더해야 하므로, 임의 스케일이 아닌 공통 단위가 필요하다. 확률은 그 단위다.

**Alternatives considered:** 가중치 Grid Search(reject — 탐색 대상이 가중치일
뿐이고 feature가 적어 이득이 없다); Learning-to-Rank(reject — 현재 feature
수와 코퍼스 규모에서 과적합하며, 비교군으로만 남긴다); 현행 유지(reject —
family 간 비교를 정당화할 수 없다).

**Consequences:**

- 학습 데이터가 없으면 `CalibratedScorer.from_prior()`의 `logit_mean`은
  `logit(base_rate) + RankScore / prior_scale`로 휴리스틱 순서를 정확히
  재현한다. 코퍼스 확보 전에도 안전하게 채택할 수 있다.
- `probability`는 `logit_mean`의 단조 함수가 아니다. weight posterior를
  적분하므로, 코퍼스가 정밀하게 고정한 가중치에 기댄 점수는 damping을 덜
  받고 거의 관측되지 않은 가중치에 기댄 점수는 base rate 쪽으로 당겨진다.
  휴리스틱 순서가 필요한 소비자는 `logit_mean`을 읽는다.
- ADR-016의 취지는 유지된다. 이 확률은 **검증 전 우선순위 확률**이고
  `VerificationConfidence`는 focused verification 이후의 별개 값이다. 둘을
  합산하거나 서로 대체하지 않는다.
- missing feature는 logit 합에서 제외된다. 관측된 `0.0`과 미관측이 점수상
  구분되지 않는다는 한계는 `CalibrationEvidence.observed`와
  `observed_feature_count`로 노출하고 `FEATURE_SCHEMA.md` §9에 기록한다.

---

## ADR-023 — Budget-constrained sequential selection is the decision layer

**Status:** Superseded by ADR-029

**Update (2026-08-14):** ADR-028이 기본을 확률 Top-K로 되돌렸고, ADR-029가 여기서
서술한 예산 selector·cost/severity·VoI 계층을 코드에서 제거했다. 본문은 역사
기록으로 보존한다.

**Date:** 2026-08-11

**Decision:** 고정 Top-K 대신 요청 예산 `B`를 입력으로 받는 결정 계층을
`vulnspider.decision`에 둔다. 세 부분으로 구성한다.

1. 명시적 cost/severity 정책(`decision/cost.py`).
2. 예산 제약 하 submodular 최대화(`decision/greedy.py`). 효용은
   `U(S) = Σ_families Σ_j discount^(j-1) · P · severity`이며, 같은
   `redundancy_key`(동일 서버 코드 경로) 내에서 수확 체감을 적용한다.
   density greedy와 "가장 좋은 단일 후보" 중 나은 쪽을 취해
   `½(1 − 1/e)` 근사를 보장한다. `discount = 1.0`이면 modular가 되고 같은
   절차가 `½` 근사다.
3. Value of Information 기반 순차 probe 선택(`decision/voi.py`).
   `EIG / cost`가 가장 큰 probe부터 실행하고 결과로 posterior를 갱신한다.

**Reason:** 졸업과제의 주장은 "적은 요청으로 검증 가치가 높은 후보를 먼저
검증한다"이고 `EVALUATION_PROTOCOL.md` §6의 주 지표도 request budget 대비
누적 발견이다. 그런데 알고리즘은 budget을 입력으로 받지 않았고 cost 모델도
없었다. 또한 파이프라인이 one-shot이라 첫 probe 결과가 다음 probe를 바꾸지
못해 "선택검증"이 선택에서 멈춰 있었다. 근사 보장이 있는 목적함수 최대화로
바꾸면 "왜 이 순서인가"에 정리로 답할 수 있으며, 이는 rule-based 순위가 줄
수 없는 것이다.

**Alternatives considered:** modular 효용 + 정확한 knapsack DP(reject — 같은
코드 경로의 중복성을 모델링하지 못해 템플릿 라우트 하나가 예산을 독점한다);
MDP/강화학습(reject — 필요한 데이터 규모가 졸업과제 범위를 넘는다);
Thompson Sampling(defer — 온라인 탐색-활용은 후속 작업으로 남긴다).

**Consequences:**

- `decision`은 `selection`의 검증된 출력만 소비하고 어떤 점수도 재계산하지
  않는다(ADR-017, ADR-021). `RankedCandidateContext`가 유일한 진입점이다.
- `decision/policy.py`는 I/O를 하지 않는다. probe 결과는 주입된
  `ProbeOutcomeSource`로 들어오며 transport는 인터페이스 뒤에 남는다.
- cost와 severity 기본값은 측정값이 아니라 문서화된 정책이다. 평가 harness가
  실측 요청 수로 대체해야 한다.
- 예산은 오늘의 고정 Top-K 대비 요청 수를 늘리지 않는다. 안전 경계는 변하지
  않는다.

---

## ADR-024 — Conformal risk control determines the selected set size

**Status:** Accepted (amended by ADR-029)

**Update (2026-08-14):** 핵심(conformal이 선택 집합 크기를 정한다)은 유효하나, 이제
`analyze --conformal`로만 켜지는 **선택적 컷**이다. 마지막 consequence의
`budget_covers_conformal_set`은 예산 계층과 함께 제거됐다(ADR-029).

**Date:** 2026-08-11

**Decision:** 선택 집합의 크기를 사람이 고르는 `k` 대신 conformal risk
control로 정한다. 보정 그룹에서 `R̂_n(λ) ≤ α − (1 − α)/n`을 만족하는 가장 큰
확률 임계값 `λ̂`을 선택하고, 그 임계값 이상인 후보를 모두 취한다. 보장은
`E[1 − Recall] ≤ α`다. 손실은 `1 − Recall`이고 positive가 없는 그룹의 손실은
0으로 정의한다. 그룹은 application 단위이며 이는 `EVALUATION_PROTOCOL.md`
§4의 leakage 방지 단위와 같다.

**Reason:** `k`는 지금까지 근거 없는 하이퍼파라미터였고 얼마나 많은 실제
positive가 잘려나가는지와 연결되어 있지 않았다. 과제 제목의 "선택검증"에
대응하려면 "몇 개를 뽑는가"가 알고리즘 안에서 답해져야 한다.

**Consequences:**

- 보장은 `α ≥ 1/(n+1)`일 때만 달성 가능하다. recall 90% 보장에는 보정
  application이 최소 9개 필요하다. 미달이면
  `ConformalThreshold.guarantee_attainable`이 `False`가 되고 임계값은 0.0으로
  떨어져 전부 선택한다. 보장되지 않은 수치를 보장된 것처럼 반환하지 않는다.
- exchangeability 가정은 웹 애플리케이션 간에 약하다. leave-one-app-out 보정과
  실측 위반율 보고를 필수로 하며, 명목 대비 실제 coverage 차이 자체를 결과로
  기록한다. `EVALUATION_PROTOCOL.md` §10에 명시한다.
- 예산이 보장 집합을 감당하지 못할 수 있다.
  `DecisionOutcome.budget_covers_conformal_set`이 이를 보고하며, 이 경우
  보장은 성립하지 않는다.

---

## ADR-025 — Decision layer reaches the CLI through new commands and a corpus

**Status:** Superseded in part by ADR-029

**Update (2026-08-14):** 코퍼스·ground-truth 결정은 유효하다. 다만 "frozen v0.1
표면을 건드리지 않고 새 `decide` 명령만 추가한다"는 방식은 뒤집혔다 — ADR-029가
`decide`를 제거하고 `analyze`/`-u`가 알고리즘을 직접 수행하도록 통합했다.

**Date:** 2026-08-11

**Decision:** 결정 계층을 CLI에서 도달 가능하게 만들되, frozen v0.1 명령 표면은
건드리지 않는다. `analyze`, `-u/--url` simple mode, 그리고 그 플래그들은 그대로
두고 **새 subcommand만 추가**한다.

```text
vulnspider decide            --url ... --budget N [--model M] [--conformal C] -o R
vulnspider corpus collect    --url ... --application-id A --ground-truth G -o C
vulnspider corpus fit        --corpus C -o M [--report Q]
vulnspider corpus calibrate  --corpus C --target-recall R -o T
```

새 패키지 `vulnspider.corpus`가 라벨 코퍼스를 소유한다. Ground truth key는
`docs/EVALUATION_PROTOCOL.md` §3의 6-튜플이며, 코퍼스는 authoritative
`Endpoint`/`InputPoint`에서 키를 만든다. 리포트나 표시 문자열에서 복원하지
않는다.

코퍼스 수집원은 `tools/corpus_target_site.py`가 생성하는 loopback 전용 라벨
애플리케이션이다. `AGENTS.md`의 안전 규칙이 허용하는 유일한 데이터 출처이며,
정답을 아는 이유는 동작을 이 파일에서 직접 작성했기 때문이다 — DVWA/WebGoat가
라벨 코퍼스로 쓰이는 것과 같은 근거다.

**Reason:** 결정 계층이 프로그램적으로만 도달 가능하면 실제로 쓸 수 없고,
Layer 1의 가중치와 Layer 3의 보장은 라벨 데이터 없이는 의미가 없다. 두 결핍은
같은 작업으로 해소된다.

**Alternatives considered:** `analyze`에 `--budget`/`--target-recall` 플래그
추가(reject — frozen 표면 변경이며 `analyze`의 계약이 "Top-K 리포트"라는 의미가
흐려진다); 인터넷 스캔으로 코퍼스 수집(reject — 안전 규칙 위반);
DVWA/WebGoat 컨테이너 자동 구동(defer — Docker 의존성과 사용자 환경 개입이
필요하므로 별도 결정 사항).

**Consequences:**

- 미라벨 후보는 negative가 아니라 **skip**이다. 없는 키는
  `GroundTruthStore.label_for()`가 `None`을 반환하고 수집기가 보고한다. 미라벨을
  안전으로 취급하면 precision이 조작되며, 이는 feature schema가 이미 금지한
  "missing은 관측된 0이 아니다"와 같은 오류다.
- Conformal 보정은 **leave-one-application-out out-of-fold 확률**로 수행한다.
  모델이 이미 라벨을 본 확률로 보정하면 보장이 낙관적으로 부풀려진다.
- `decide`는 Top-K가 아니라 전체 후보를 랭킹한 뒤 예산으로 자른다. 몇 개를
  검증할지는 결정 계층이 계산하는 값이지 입력받는 값이 아니므로 `--top-k`를
  받지 않는다.
- `redundancy_key`는 endpoint fingerprint다. 이는 ADR-023 시점의 한계
  (input point 참조를 기본값으로 사용)를 해소한다.
- 코퍼스 파일은 정규 순서로 기록한다. discovery 순회 순서가 실행마다
  달라지므로, 정렬하지 않으면 동일 `--seed`가 줄 순서만 다른 파일을 만들어
  §8의 재현성 요구를 무력화한다.
- 생성된 코퍼스 산출물(`data/corpus/`)은 저장소에 포함한다. 심사에서 수치의
  출처를 확인할 수 있어야 하고, 크기는 약 129KB로 부담되지 않는다.

---

## ADR-026 — Value of Information stays dormant until probing has a real choice

**Status:** Superseded by ADR-029

**Update (2026-08-14):** dormant 유지 대신 ADR-029가 `decision/voi.py`를 삭제했다.
근거는 동일하다 — 배선해도 아무것도 바꾸지 않으므로, 없는 기여가 있는 것처럼 보일
위험만 남는 코드였다. 되살리려면 이 본문의 경로 A/B가 먼저 필요하다.

**Date:** 2026-08-11

**Decision:** `decision/voi.py`는 유지하되 CLI에 배선하지 않는다.
`--exploration-budget` 플래그를 추가하지 않으며, `run_decision_layer()`의
`probe_options`/`observe` 인자는 현재 호출자가 채우지 않는다. 경로 A 또는 B
(아래)가 구현되기 전까지 **순차적(적응적) probing은 구현되지 않은 것으로
서술한다.**

**Reason:** 측정 결과 현재 파이프라인에는 VoI가 결정할 것이 없다. 네 가지가
독립적으로 이를 막는다.

1. **probe 1회가 feature를 전부 가져온다.** `extract_minimal_features()`는
   baseline/probe 쌍 하나에서 4개 feature를 모두 추출한다. "다음에 어떤
   feature를 측정할까"라는 결정 자체가 존재하지 않는다.
2. **미관측 feature가 없다.** 현재 코퍼스 146개 candidate 전부 feature가
   완전히 관측됐다(0/146 결측). 재probe로 밝힐 미지의 값이 없다.
3. **결정 계층이 실행될 때는 probe가 이미 끝나 있다.** `decide`는
   `analyze_url()`을 호출하고 그것은 ready context를 전부 probe한다. VoI는
   probe 예산을 배분하도록 설계됐는데 배분할 probe 예산이 남지 않는다. 남은
   것은 verification 예산이고 그것은 ADR-023의 greedy가 이미 쓴다.
4. **모델에서 candidate가 서로 독립이다.** `run_decision_layer()`는 관측된
   candidate의 posterior만 갱신한다. A를 probe해도 B가 변하지 않으므로 적응적
   순서가 임의 순서보다 나을 **수학적 근거가 없다.** 정적 feature가 추출되지
   않아 probe 이전 prior가 전부 동일하므로 첫 선택도 임의다.

따라서 지금 배선하면 실행되지 않거나, 실행돼도 증명 가능하게 아무것도 바꾸지
않는 코드 경로가 생긴다. 존재하지 않는 순차적 기여가 있는 것처럼 보이게 만드는
편이 배선하지 않는 것보다 나쁘다.

**Alternatives (VoI를 실제로 의미 있게 만드는 경로):**

- **경로 A — candidate 간 상관 모델링.** 같은 endpoint/코드 경로의 candidate가
  서로 정보를 주도록 Layer 1에 endpoint별 random effect를 넣는다. 그러면
  템플릿 라우트 100개 중 5개만 probe해도 나머지를 추론할 수 있고 "어느 5개를
  고를까"가 VoI의 실제 질문이 된다. 이미 있는 `redundancy_key`를 재사용한다.
  `analyze_url()`의 "전부 probe" 동작을 예산 제한으로 바꿔야 한다.
- **경로 B — probe family 복수화.** `ProbeFamily`의 `TYPE_PERTURBATION`,
  `GENERIC_PERTURBATION`은 정의만 있고 planner는 `REFLECTION_MARKER`만
  구현한다. 구현하면 비용과 우도가 다른 probe가 여러 개 생겨 "다음에 무엇을
  실행할까"가 실제 질문이 된다.

둘 다 배선이 아니라 모델링/관측 전략 작업이며 각각 별도 ADR이 필요하다.

**Consequences:**

- `decision/voi.py`와 그 테스트는 유지한다. 구현은 정확하며(전수 열거 대조
  완료) 경로 A와 B 모두 이 기계장치를 필요로 한다.
- `probe_options_from_rates()`가 유일한 Layer 1-Layer 2b 연결점이므로 함께
  휴면한다. `fit_naive_bayes_llr()`의 다른 용도(ablation)는 영향받지 않는다.
- VoI는 scoring도 selection도 아닌 **관측 계층** 결정이다. `feat/scoring`의
  완료 조건에 포함하지 않는다.

---

## ADR-027 — Top-K is the primary control and the request budget is optional

**Status:** Superseded by ADR-029

**Update (2026-08-14):** "Top-K가 주 파라미터"는 유효하며 이제 **유일한** 제어다.
`--budget`과 제약별 근사 보장 체제(`1−1/e` 등), `binding_constraint`는 예산 계층과
함께 제거됐다(ADR-029). 본문의 held-out 표는 결함 코퍼스 기준이라 더 이상 재현되지
않는다(ADR-030).

**Date:** 2026-08-12

**Decision:** `decide`의 주 파라미터는 `--top-k`이며 필수다. `--budget`은
선택적 보조 제약이고 기본값은 없음(무제한)이다. 두 제약과 conformal 임계값은
**독립적인 정지 조건**으로 함께 동작하며, 먼저 걸리는 것에서 멈추고 어느 것이
걸렸는지 `binding_constraint`로 보고한다. 이 결정은 ADR-023이 예산만 입력으로
받던 것을 대체한다.

**Reason:** ADR-023은 고정 K를 예산으로 **대체**했는데 이는 과했다.

- `AGENTS.md`의 미션이 "ranking what should be verified first"이고 랭킹의
  표준 출력은 Top-K다.
- 핵심 지표 4개가 전부 `@K`로 정의된다(§6). 제품이 Top-K를 못 내면 출력과
  평가 언어가 어긋난다.
- handoff 계약(`MutationHandoff.top_k_requested`)이 이미 K를 싣고 있다.
- **결정적 근거:** 예산의 의미는 `DEFAULT_FAMILY_COSTS`에 의존하는데 ADR-023
  스스로 그것을 "정책이지 측정값이 아니다"라고 명시했다. 즉 "예산 20"은
  검증되지 않은 비용 모델 위에서만 의미를 갖는다. K는 그런 의존성이 없다.

예산도 버리지 않는다. candidate마다 검증 비용이 다르므로 Top-10이 30 요청일
수도 60 요청일 수도 있고, §6이 request budget 곡선을 주 그래프로 지정한다.

**Consequences — 근사 보장이 제약에 따라 달라진다.** 이것이 이 결정의 실질적
비용이며 정직하게 분리해 보고한다.

```text
Top-K만      cardinality(uniform matroid) → marginal gain greedy → (1 − 1/e) ≈ 0.632
예산만       knapsack → density greedy + best-single → ½(1 − 1/e) ≈ 0.316
                                        (discount = 1.0이면 modular → ½)
둘 다        knapsack ∩ matroid → 방어 가능한 결합 보장 없음 → None 보고
```

- 비용은 예산이 있을 때만 의미가 있으므로, Top-K 단독 체제는 density가 아니라
  **marginal gain**으로 정렬한다. 그렇게 해야 `(1 − 1/e)`를 얻는다.
- 둘 다 활성일 때 `approximation_ratio`는 숫자가 아니라 `None`이다. 방어할 수
  없는 상수를 적는 것보다 낫다.
- `select_within_budget()`은 `select_candidates(top_k=..., budget=...)`으로
  대체된다. 제약을 하나도 주지 않으면 거부한다 — 조용히 전부 선택하는 것은
  호출자의 의도인 적이 없다.

**Consequences — 두 체제가 방법의 순위를 뒤집을 수 있다(측정됨).**
미학습 12개 앱, `--top-k 5`:

```text
                        recall      검증  요청
휴리스틱 prior          33/33 =1.00    60   294
학습 모델, 보장 없음     26/33 =0.79    60   312
학습 모델 + conformal    33/33 =1.00    43   204
```

같은 앱을 `--budget 20`으로 재면 prior가 0.55로 떨어진다. 손실은 전부 XSS이며
(SQLI는 양쪽 25/25, XSS는 prior 8/8 대 학습 8분의 1) 원인은 학습 모델이
`P(XSS | 반사) ≈ 0.29`를 **정확히** 학습했기 때문이다. 현재 feature set이
`xss_raw`와 `xss_escaped`를 구분하지 못하므로 어떤 보정 모델도 반사하는 XSS를
서로 구분할 수 없고, prior의 과신(0.81)은 K가 넉넉할 때만 우연히 이득이 된다.
예산이 빠듯해지면 같은 과신이 요청을 낭비해 손해로 바뀐다.

conformal 임계값이 이 격차를 메운다. XSS 음성(≈0.065)은 자르고 양성(≈0.46)은
남겨, 같은 recall을 검증 28%·요청 31% 적게 달성한다.

이는 §5의 baseline 비교를 K와 예산 두 표로 분리해야 하는 이유이자,
`safe_html_encoding_detected` 구현이 결정 계층 튜닝보다 우선인 이유다.

---

## ADR-028 — 취약도는 확률이며 severity는 동률 시 tie-break일 뿐이다

**Status:** Accepted (amended by ADR-029)

**Update (2026-08-14):** 이 방향(확률 상위 K, severity는 표시용)은 유지된다. 다만 이
ADR이 opt-in·표시용으로 남겨둔 `--discount`/예산 모드, `SeverityPolicy`,
`approximation_ratio`는 ADR-029가 코드에서 제거했다. 본문의 held-out 표는 결함
코퍼스 기준이라 재현되지 않는다(ADR-030).

**Date:** 2026-08-13

**Decision:** 선택의 1차 기준은 **취약할 확률**이다. 확률이 같을 때만 family
순서(SQLi > Reflected XSS > BAC)로 동률을 깬다. `severity`는 후보에 남지만
**순위 계산에 곱해지지 않으며 표시용 메타데이터다.**

기본 실행 모드는 `discount = 1.0`(중복성 할인 없음), 예산 없음이다. 즉
**확률 상위 K개를 그대로 반환한다.** 중복성 할인과 요청 예산은 opt-in이다.

이 결정은 ADR-023의 목적함수
`U(S) = Σ discount^(j-1) · P × severity`를 `Σ discount^(j-1) · P`로 바꾸고,
ADR-023이 기본값으로 삼았던 `discount = 0.5`를 1.0으로 되돌린다.

**Reason:** ADR-023은 목적을 **"예산 안에서 기대 발견 최대화"**로 잡았다.
그런데 과제의 실제 목표는 다르다.

> K가 10이면 그 웹사이트의 수많은 입력점 중 **가장 보안 취약도가 높은 10개**를
> 탐지한다. 전문가가 아닌 사람도 본인이 만든 웹사이트의 취약점을 공부하고
> 알아낼 수 있도록.

두 목적은 같지 않고, 측정 결과 **ADR-023의 기본값이 목표를 방해했다.**
미학습 애플리케이션 12개, K=5:

```text
휴리스틱 · 확률 상위 K          27/33 = 0.82
학습모델 · 확률 상위 K          32/33 = 0.97
학습모델 · 중복성 할인 0.5      26/33 = 0.79   <- 휴리스틱보다도 나쁨
```

중복성 할인의 근거("같은 코드 경로이므로 두 번째 확인의 가치가 낮다")는 검증
요청을 아끼는 관점에서는 맞지만, **"내 사이트에서 취약한 곳을 보여달라"는
관점에서는 틀렸다.** 한 라우트에 취약점이 3개면 사용자는 3개 다 알아야 한다.
하나만 보여주고 나머지를 생략하는 것은 이 제품이 할 일이 아니다.

severity 곱셈도 같은 이유로 뺀다. `P × severity`는 확률 0.5의 SQLi가 확률
0.7의 XSS보다 위에 오게 만드는데, 이는 "가장 취약도가 높은 K개"의 의미가
아니다.

**Consequences:**

- 기본 모드에서 목적함수는 cardinality 제약 하의 modular 합이므로 **greedy가
  곧 최적해다.** 근사가 없으므로 `approximation_ratio`는 `1.0`이다.
  ADR-027의 `1 − 1/e`는 `discount < 1.0`일 때만 적용된다.
- 예산 모드는 그대로 남는다. `EVALUATION_PROTOCOL.md` §6이 request budget
  곡선을 주 그래프로 지정하므로 그 질문 자체는 여전히 유효하다. 다만 **기본이
  아니라 opt-in**이다.
- `SeverityPolicy`는 표시용으로만 쓰인다. 리포트에는 계속 나온다.
- `evaluation/`의 순위 지표는 **영향받지 않는다.** 처음부터 확률 그 자체로
  정렬해 측정했으므로 §8-C의 수치는 변하지 않는다. 이는 평가 계층이 처음부터
  올바른 목표를 재고 있었다는 뜻이기도 하다.
- Layer 3(conformal)은 "몇 개를 뽑을지"라는 다른 질문에 답한다. K가 고정된
  기본 모드에서는 필수가 아니지만, K가 넉넉할 때 불필요한 검증을 줄이는 데
  유효하다(K=10에서 검증 118건 → 44건, recall 동일).

---

## ADR-029 — Remove the budget, VoI, and cost layers; unify analyze and decide

**Status:** Accepted

**Date:** 2026-08-14

**Decision:** ADR-026/027/028이 dormant·opt-in·display로 남겨둔 계층을 **코드에서
제거하고**, 두 CLI 경로를 하나로 합친다.

- `decision/greedy.py`(submodular/knapsack 예산 선택기), `decision/voi.py`
  (Value of Information), `decision/cost.py`(검증 비용·severity 정책)와 그 테스트를
  삭제한다.
- `decision/policy.run_decision_layer()`는 이제 **선택적 conformal 컷 + 확률
  Top-K argmax** 하나만 수행한다. `--budget`/`--discount`/`--exploration-budget`,
  `BudgetedSelection`, `approximation_ratio`, `binding_constraint`,
  `DecisionCandidate.severity`/`verification_cost`/`redundancy_key`,
  `DecisionOutcome.budget_covers_conformal_set`가 모두 사라진다. 동률 tie-break은
  family 순서→candidate_id로 남는다.
- 별도 `decide` 명령을 제거하고 **`analyze`와 `-u`가 알고리즘을 직접 수행**한다.
  `--top-k`는 유지, `--model`/`--conformal`을 추가한다. `corpus` 하위명령은 그대로다.
  휴리스틱 v0.1 리포트 형태(`summary`/`candidates`/`raw_rank_score`…)는 lean 결정
  리포트(`selection`/`verification_order`/`guarantee`/`warnings`)로 대체된다.

**Reason:** ADR-028이 기본을 확률 상위 K로 되돌린 뒤, 남은 예산·VoI·severity
기계장치는 **어느 것도 기본 경로에서 실행되지 않는 죽은 코드**가 되었다.

- VoI는 ADR-026이 이미 "배선해도 아무것도 바꾸지 않는다"고 측정했다. dormant 유지는
  "없는 기여가 있는 것처럼" 보이는 위험만 남긴다.
- 예산 selector는 ADR-028이 기본에서 뺀 뒤 opt-in으로만 남았는데, `feat/scoring`의
  목표(가장 취약한 K개 보고)와 다른 질문(예산 대비 발견)에 답한다. feature 4개·앱
  14개 규모에서 submodular 근사 보장·knapsack 기계장치는 데이터에 비해 과설계이고,
  심사에서 "왜 이 복잡도가 필요한가"를 방어하기 어렵다.
- cost/severity는 ADR-023 스스로 "측정값이 아니라 정책"이라 했고 ADR-028이 순위에서
  뺐으므로, 남길 이유가 없다.
- 두 CLI 경로(휴리스틱 `analyze` + 알고리즘 `decide`)를 유지하면 이후 모든 기능이
  "휴리스틱 경로에도 넣을지"를 매번 결정해야 한다. 하나로 합치면 그 부채가 사라진다.

**Alternatives considered:** 예산/VoI를 opt-in 코드로 유지(reject — 실행되지 않는
경로가 리뷰·테스트 비용만 늘리고 net diff에 죽은 계층이 남는다); 예산을 별도
`budget` 하위명령으로 분리(defer — 예산 대비 발견은 후속 연구로 남기고, 필요하면
그때 되살린다).

**Consequences:**

- main 대비 net diff에 `greedy.py`/`voi.py`/`cost.py`가 없다. 이들을 서술하는
  ADR-023, ADR-025(일부), ADR-026, ADR-027은 이 ADR로 대체되며 본문은 역사 기록으로
  보존한다.
- `analyze`의 JSON 계약이 바뀐다. frozen v0.1 형태를 검증하던 단위·통합 테스트를 새
  형태로 갱신했다.
- 예산 대비 발견 질문(`EVALUATION_PROTOCOL.md` §6)은 여전히 유효하나 지금은 측정
  도구(`evaluate_ranking`, `evaluate_heldout`)에만 남고 제품 경로에는 없다.

---

## ADR-030 — Break single-feature separability in the synthetic corpus

**Status:** Accepted

**Date:** 2026-08-14

**Decision:** `tools/corpus_target_site.py`가 behaviour마다 고정 길이 템플릿을
렌더링하던 것을 바꿔, `response_length_diff_ratio`가 라벨을 단독으로 결정하지
못하게 한다. 라우트마다 (a) 응답에 동일하게 붙는 재현 가능한 랜덤 크기의 정적
chrome(길이 비율의 분모를 흔듦)과 (b) 값 의존적 benign 결과 행(안전한 페이지도
입력에 따라 길이가 변함)을 추가한다. 라벨(behaviour)과 다른 feature(sql_error·
status·marker)의 의미는 바꾸지 않는다.

**Reason:** 이전 코퍼스는 behaviour마다 응답 길이가 고정이라 같은 behaviour의 모든
라우트가 동일한 `response_length_diff_ratio`를 냈다. 그래서 이 feature 하나의
임계값만으로 유형 안에서 라벨이 완벽히 갈렸고(단일 임계값 정확도 1.00), 모델이
어려운 문제를 푼 게 아니라 한 축의 lookup을 외운 것에 가까워 모든 지표가 부풀려졌다.
이는 코퍼스 설계 원칙 "Realism, not separability"와도 어긋났다.

**Consequences:**

- 길이 단독 임계값 정확도가 SQLi 1.00→0.75, XSS 1.00→0.81(다수결 기준선과 동일)로
  떨어지고, 판별력이 SQL 오류·상태·반사 feature로 이동한다. blind SQLi(길이 신호만)는
  현실처럼 탐지하기 어려워진다.
- ground truth는 바뀌지 않는다(라벨·behaviour 동일, 응답 크기만 변경). 코퍼스
  아티팩트(`corpus.jsonl`, `model.json`, `calibration-report.json`, `conformal.json`,
  `ranking-report.json`)를 재생성했다.
- 결함 코퍼스로 뽑았던 ADR-027·028 본문의 표(held-out 26/33·32/33 등,
  `P(XSS|반사)≈0.29`)는 더 이상 재현되지 않는다. 정직해진 수치로는 held-out에서 학습
  모델이 휴리스틱을 앞선다(0.91 대 0.76). 상세는 PR 본문 §3·§4의 재측정값을 따른다.

---

## ADR-031 — Probe sentinel and reflection-encoding features

**Status:** Accepted

**Date:** 2026-08-14

**Decision:** reflection marker에 위험 문자 sentinel을 붙이고, 인코딩을 관측하는
feature를 추가한다.

- `observation/planner.py`: 기본 marker 전략을 `sentinel-reflection-marker-v1`로
  올린다. marker = 식별 토큰(`VULNSPIDER_` + 16진수, 항상 영숫자) + sentinel
  `Z<>"'Z`. 식별 토큰과 sentinel을 **한 값에 함께** 보낸다. 기존
  `neutral-reflection-marker-v1`은 재현성을 위해 유지한다.
- `features/extraction.py`: `FEATURE_SCHEMA_VERSION`을 `feature-v0.2`로 올린다.
  `marker_reflected`는 이제 식별 토큰으로 판정하고(인코딩돼도 반사로 인식),
  `safe_html_encoding_detected`(sentinel 네 문자가 모두 entity면 1.0, 하나라도
  원본이면 0.0, sentinel 소실이면 미관측)와 `reflection_count_norm`
  (`min(등장/3, 1)`)을 추가한다.
- `scoring/calibration.py`: 두 새 feature를 XSS calibration 특징공간에 넣는다
  (`_CALIBRATION_ONLY_TERMS`). rule-based scoring 경로는 폐기됐으므로(ADR-029)
  `scoring/engine.py`는 건드리지 않아 음수 penalty가 `selection_priority`에 새지
  않는다.

**Reason:** `feat/scoring`의 지배적 오차원은 XSS 오탐이었다. 영숫자 marker는
이스케이프하는 안전한 앱과 원본을 출력하는 취약한 앱을 똑같이 `marker_reflected=1`
로 만들어, **어떤 순위 알고리즘도** 반사된 34개 중 20개 오탐을 걸러낼 수 없었다.
인코딩을 관측하려면 인코딩될 수 있는 문자를 먼저 보내야 하고, 그것은 feature
추출이 아니라 전송 내용(planner) 변경이다. sentinel만 보내면 WAF가 그것을 잘랐을
때 반사 자체가 사라져 후보가 안전해 보인다 — 오탐을 미탐으로 바꾸는 셈이다. 식별
토큰을 함께 보내면 세 상태를 구분한다: 반사 안 됨 / 식별 토큰만 반사(sentinel
소실 = 미관측) / sentinel 반사(인코딩 1.0 또는 원본 0.0).

**Safety:** 전송 내용이 바뀐다. sentinel은 `<`, `>`, `"`, `'` 네 문자로 스크립트가
아니고 파괴적이지 않으며 상태를 바꾸지 않는다. 전송 시 percent-encoding되고 서버가
디코딩한다. 요청 수는 늘지 않고(같은 baseline/probe 쌍), 대상은 loopback 한정이며
ADR-004(one-at-a-time)는 유지된다. 2인 리뷰 대상.

**Consequences:**

- 코퍼스를 feature-v0.2로 재생성했다. XSS 모델이 `safe_html_encoding_detected`
  가중치를 데이터에서 −4.8로 학습해, 반사된 34개 중 진짜 14개와 이스케이프된
  20개를 구분한다. out-of-fold Brier 0.133→**0.081**, 미학습 12개 앱 held-out
  recall@5 0.91→**1.00**, in-corpus Recall@3 0.744→**0.899**.
- `decision/`·`evaluation/`·`corpus/`는 변경이 없다(feature 개수에 무관).
- **미완/후속:** 현재 코퍼스는 `xss_raw`(항상 원본)와 `xss_escaped`(항상 일괄
  escape)만 있어 `safe_html_encoding_detected`가 완벽 분리자다(낙관적). 계획서 §6의
  부분 인코딩·속성 문맥·script 문맥·필터링 사례를 추가하면 이 feature도 오차를
  갖게 되어 더 정직해진다(ADR-030이 길이 feature에 한 것과 같은 후속). 계획서의
  `dangerous_reflection_context`(html.parser 문맥 분류)와 정적 feature
  (`numeric_value`, `id_like_name`)도 후속이다. 다중 probe-ready 문맥에서 penalty
  feature의 결합 규칙(현재 존재적 max)은 단일 문맥 코퍼스에는 영향이 없으나
  재검토 대상이다.

---

## ADR-032 — Focused verification과 rule-based confidence update

**Status:** Accepted

**Date:** 2026-08-18

**Decision:** 랭킹된 Top-K 위에 마지막 파이프라인 단계인 focused verification을
추가한다. 각 상위 후보에 대해 같은 계열의 *변형* 페이로드를 제안하고
(`verification/proposal.py`), 결정적 validator로 반드시 게이트한 뒤
(`verification/validator.py`), 승인된 것만 loopback 대상에 재전송해 feature
vector를 다시 수집하고(`planner.py` + 기존 executor/extractor), baseline vector와
차분해(`delta.py`), 검토된 규칙으로 confidence를 갱신한다(`confidence.py`). 결과는
`VerificationResult` 레코드(`docs/TEAM_INTERFACES_V0_2.md` §3)로 직렬화한다. CLI는
opt-in `--verify`/`--verify-output`로 별도 `vulnspider-verification.json`만 쓰며,
frozen v0.1 출력·분석 리포트·decision 리포트는 바뀌지 않는다.

**Context:** `docs/PROTOTYPE_V0_2.md` §4.3–4.4가 남긴 마지막 milestone(석현
소유). `AnalysisResult`는 이미 InputPoint별 baseline `FeatureVector`와 실행된
`ProbePlan`(baseline `RequestInstance` 포함)을 보존하므로, discovery를 건드리지
않고 재탐색을 계획할 수 있다.

**규칙(요지):**

- 차이가 작으면(discriminating feature 이동 없음, 관측 플립은 0값 아티팩트 제외)
  → **UNCHANGED**, prior 유지.
- 유형별 신호가 재현되면(baseline도 이미 의심) → **SUPPORTED(keep)**, prior 유지
  ("차이가 크지 않으면 confidence 유지").
- baseline이 놓친 신호가 새로 드러나면(예: sentinel `'`로는 안 났는데 out-of-range
  `-1`에서 SQL 에러) → **SUPPORTED(raise)** ("baseline으로는 의심이 크지 않았지만
  실제 취약 지점").
- 반사되지만 안전하게 entity-encoding됨 → **WEAKENED(lower)**.
- 응답은 크게 바뀌었지만 유형별 신호가 없음 → **INCONCLUSIVE_ERROR**, prior 유지
  ("단순 에러"). BOUNDARY 페이로드에서 흔하다.

**Safety:** 네트워크·페이로드 실행 변경이라 2인 리뷰 대상. 모델 출력은 신뢰하지
않으며 validator 승인 전에는 전송되지 않고(거부된 제안은 실행 provenance가 존재할
수 없게 `from_objects`에서 강제), 페이로드는 read-only(스택 쿼리·파괴적 키워드
금지, 상태 변경 없음)이고 loopback 한정이며 ADR-004(one-at-a-time)를 유지한다.
prior는 `RankScore`가 아니라 calibrated probability(ADR-022의 pre-verification
prior)에서 시작하므로 도메인 규칙 6·7을 지킨다.

**Alternatives:**

- 변화 크기만으로 취약/에러 판정 → 기각. 길이·상태는 어떤 페이로드에서도 흔들려
  구분자가 못 된다. `sql_error_pattern`(SQLi)과 raw 반사(XSS)만이 구분자다.
- RankScore를 confidence로 합산/대체 → 기각(규칙 6·7, contract forbidden
  reconstruction).
- 실제 LLM 클라이언트 즉시 구현 → 보류. provider-neutral 경계 + 결정적 기본
  proposer만 구현하고, GPT/Gemini는 같은 validator 게이트 뒤에 끼우는 후속
  milestone(API 비교 하니스·키 취급 필요)으로 둔다.

**Consequences:**

- 새 패키지 `src/vulnspider/verification/`(proposal/validator/planner/delta/
  confidence/result/focused)와 opt-in CLI 플래그, `test_verification.py`·
  `test_verification_cli.py` 추가. 전체 unit 682개 + format/lint/type green.
- `VerificationResult`는 이제 구현된 producer 레코드다. `VerificationEvidence`
  세부 스키마·confidence 임계값은 규칙 v1로 고정했고 팀 리뷰 대상이다.
- **미완/후속:** 실제 GPT/Gemini proposer, HTML verification 리포트, decision
  리포트와의 결합, per-payload 재현 시 소폭 가점 여부(현재 strict keep), FORM/POST
  대상 확대 검증.

---

## ADR-033 — Confidence 상수의 코퍼스 보정, 평가 arm, 최종 리포트 결합

**Status:** Accepted

**Date:** 2026-08-18

**Decision:** ADR-032의 confidence 갱신에서 손으로 고른 상수(`SUPPORT_GAIN=0.6`,
`WEAKEN_FACTOR=0.5`)를 제거하고, 검증 결과를 **범주형 신호**(SUPPORT_NEW,
SUPPORT_REPRODUCED, WEAKEN, INCONCLUSIVE, UNCHANGED, NOT_EXECUTED)로 보고, 그
신호의 **로그우도비(LLR)를 prior의 로그오즈에 더하는** 방식으로 바꾼다.

`logit(posterior) = logit(prior) + LLR(family, signal)`

LLR은 라벨된 검증 코퍼스에서 `P(signal|취약)/P(signal|안전)`로 추정하며(Dirichlet
평활), `|LLR|`을 `max_abs_llr`(기본 1.0 logit)로 클램프한다. 이는
`scoring/calibration.py`의 `NaiveBayesRates.log_likelihood_ratio`가 feature에
쓰는 것과 같은 weight-of-evidence 합성을 검증 신호에 적용한 것이다.

**"점수가 크게 변하지 않게":** 로그오즈 가법 갱신은 단조·유계이고, 캡이 한 번의
검증이 점수를 세게 흔들지 못하게 보장한다(기본 캡에서 prior 0.5는 최대 ±0.23
이동). 무학습 기본 모델(`VerificationConfidenceModel.default`)은 작은 고정 LLR을
쓰며 SUPPORT_REPRODUCED는 기본 0(재현은 기본적으로 유지) — 재현에 가점할지는
코퍼스가 결정한다(ADR-032가 남긴 open question을 데이터로 닫음).

**평가 arm:** `corpus/verification_fitting.py`가 leave-one-application-out로
prior의 Brier와 posterior의 Brier를 비교한다(`evaluate_verification_arm`). 개선이
양수면 학습된 LLR을 배포할 근거이고, 음수면 검증이 이 코퍼스에서 보정 정보를 더하지
못한다는 정직한 결과다(캡이 이미 보수성을 보장). 라벨/프로토콜은
`corpus/verification_collection.py`(`verification-corpus-v1` JSONL)가 소유하며,
`docs/EVALUATION_PROTOCOL.md` §3 키로 ground truth와 조인한다.

**최종 리포트 결합:** `--verify`를 켜면 검증을 리포트 생성 **이전**에 실행하고, 그
결과를 `reporting/decision_html_report.py`에 넘긴다. 리포트의 헤드라인 점수는 이제
검증 이전 확률이 아니라 **검증 이후 최종 신뢰도**(`CandidateVerification
.final_confidence`)이며, 후보 카드에 검증 판정(뒷받침/약화/보류)과 검증 전후 점수
변화를 함께 표시한다. 리포트는 아무것도 재계산하지 않고 권위 있는 값을 표시만 한다
(ARCHITECTURE.md).

**CLI:** `corpus verify-collect`(라벨 앱에서 검증 신호 수집), `corpus verify-fit`(
모델 적합 + `--report`로 arm 평가), analyze/`-u`의 `--verification-model`(적합 모델
로드; 기본은 보수적 내장 모델).

**Safety/규칙:** prior는 여전히 calibrated probability(ADR-022의 pre-verification
prior)이지 RankScore가 아니다(규칙 6·7). 신호 추출은 결정적이고 모델과 무관하므로
수집은 모델 독립이다. 네트워크/페이로드 실행 정책은 ADR-032와 동일(2인 리뷰).

**Alternatives:**

- 상수를 유지하고 손튜닝 → 기각. 근거 없는 값이라 확률 스케일을 오염시키고 방어 불가.
- outcome(SUPPORTED/WEAKENED) 단위로만 LLR 학습 → 기각. 재현/신규 구분이 사라져
  ADR-032의 "재현 유지" 의도를 잃는다. 그래서 더 세분화된 signal로 학습한다.
- 캡 없이 학습 LLR 사용 → 기각. 소규모 코퍼스에서 분리 가능한 신호가 과신을
  유발한다. 캡이 "크게 변하지 않게"를 보장한다.

**Consequences:**

- `confidence-rule-v1`→`v2`. `VerificationConfidence`에 `signal`·`model_version`
  추가, `VerificationResult` JSON에 반영. 기존 34개 검증 테스트는 기본 모델로 유지
  (수치는 더 완만). 신규 15개 테스트(calibration/arm/collection/CLI/report).
- **코퍼스 수집 완료:** `tools/build_verification_corpus.py`가
  `tools/corpus_target_site.py`의 라벨 loopback 앱(DVWA와 동일한 신호 계열: 에러
  기반/블라인드 SQLi, raw/이스케이프 XSS, 안전)을 띄워 실제 검증을 돌려 코퍼스를
  수집한다. 산출물: `data/corpus/verification-corpus.jsonl`(146 샘플, 14 앱),
  `verification-model.json`(적합 모델), `verification-arm.json`. **out-of-fold
  Brier 0.136→0.102(+0.034 개선).** 학습 결과 SUPPORT_REPRODUCED=+1.0(취약 20/안전
  0), WEAKEN=−1.0(안전 20/0), UNCHANGED은 SQLI에서 −0.407(블라인드 SQLi가 UNCHANGED로
  떨어져 약하게만 안전). NOT_EXECUTED·INCONCLUSIVE는 증거 없음이라 항상 0으로 고정,
  미관측 신호는 기본 LLR로 폴백(스무딩 아티팩트 방지). 적합 모델은
  `--verification-model`로 사용하며 내장 기본은 여전히 보수적 무학습 모델.
- **미완/후속:** 실제 DVWA 대상(로그인·세션·보안 쿠키 인증 크롤 필요, 현 크롤러
  미지원), 캡·평활 하이퍼파라미터의 코퍼스 기반 선택, 적합 모델을 기본값으로 승격할지
  여부.

---

## ADR-034 — 단일 대시보드 리포트와 INCONCLUSIVE 게이트 정밀화

**Status:** Accepted

**Date:** 2026-08-18

**Decision (리포트 통합):** 최종 산출물을 **하나의 end-to-end HTML 대시보드**로
모은다. 단순 `-u` 모드는 이제 `vulnspider-report.html`을 **기본 생성**하며
(`--no-html`로 끔, `--html-output`로 경로 지정), 이 대시보드가 URL→탐색→랭킹→검증
결과를 한 파일에 담는 "그 리포트"다(자체 완결형, 오프라인). decision **JSON**
리포트에도 검증 후 최종 신뢰도를 반영해(`decision_report`에 `verification` 요약과
후보별 `final_confidence`/`verification_outcome`/`prior_probability` 추가) JSON과
HTML이 같은 최종 점수를 제시한다. crawl/analysis/verification JSON은 유지하되,
읽는 리포트가 아니라 기계 판독용 export로 위치한다. `analyze` 서브커맨드는
`--html-output`가 기존처럼 옵트인(하위호환).

**Decision (검증 후 재정렬):** 리포트의 **표시 순서와 헤드라인 점수는 검증 후 최종
신뢰도** 기준으로 다시 정렬한다(HTML 카드·상단 후보 차트·decision JSON의
`verification_order` 모두). 단 **Top-K 선택(어떤 K개를 검증할지)은 여전히 검증 이전
확률**로 정한다 — 선택 멤버십은 바뀌지 않고 같은 집합을 최종 신뢰도로 재정렬만 한다.
정렬은 안정(stable)이라 미검증 시 기존 확률 순서가 유지되고, 원래 우선순위는 각
항목의 `selection_rank`로 보존한다. conformal recall 보장은 선택 로직의 일부라 검증
이전 확률 기준을 유지한다. 근거: "무엇을 먼저 검증할지"는 prior가 답하지만, 리포트가
제시하는 "최종 점수"라면 카드 배치도 그 점수와 일치해야 사용자 혼란이 없다.

**Decision (INCONCLUSIVE 정밀화):** `INCONCLUSIVE_ERROR`를 **실제 에러**에만
한정한다 — transport 실패, 또는 **payload가 유발한 5xx**(baseline이 5xx가 아니었던
경우). 길이만 바뀌거나 non-5xx(예: 400/404 입력 거부)로 바뀐 경우는 취약 신호가
없으면 benign difference로 보고 `UNCHANGED`로 유지한다. probe/baseline status code를
`update_confidence`에 전달해 판정한다(feature 스키마·scoring·corpus 불변).

**Context:** 사용자 요구 — end-to-end 웹 대시보드 하나만 원함, 그리고 boundary/길이
노이즈로 INCONCLUSIVE가 과다 생성되는 문제. INCONCLUSIVE와 UNCHANGED 모두 prior를
유지하므로 과다 생성은 점수가 아니라 리포트 라벨 노이즈 문제였고, 5xx 게이트가 그
라벨을 실제 서버 에러로만 한정한다.

**Alternatives:**

- 리포트를 계속 파일 여러 개로 → 기각(사용자 요구: 하나의 대시보드).
- INCONCLUSIVE를 length ratio로도 판정(기존) → 기각. marker와 mutation의 길이 차만
  으로도 트리거되어 오탐. status 기반이 정확.
- 새 feature(`server_error_5xx`) 추가 → 보류. status code를 confidence 규칙에 직접
  전달하는 편이 스키마/코퍼스를 건드리지 않아 더 작다.

**Consequences:**

- `-u`가 HTML 리포트를 기본 생성(파일 하나 추가). decision JSON 스키마에 검증 필드
  추가(하위호환: `probability`는 그대로 prior). `_material_context_change` 제거,
  `_payload_induced_server_error` 도입. 신규/수정 테스트로 5xx→INCONCLUSIVE,
  length-only→UNCHANGED, non-5xx→UNCHANGED 확인. 전체 unit 699 green.
- **미완/후속:** 요청 예산 상한·요청 간 딜레이·candidate별 baseline 재사용(요청 수
  2N→N+1, 추출기 provenance 완화 필요)은 이번에 범위 제외(요청에 따라 선택 안 됨).
  `analyze`도 HTML 기본화할지, JSON export를 옵션화할지는 후속 논의.

---

## ADR-035 — BAC 관측·랭킹·검증을 native 파이프라인에 통합

**Status:** Accepted

**Date:** 2026-08-19

**Decision:** 66e5321에서 개발한 BAC 관측 계층(`access/planner.py`·`executor.py`)을
현재 브랜치의 native 분석 경로에 통합한다. `_analyze_contexts`가 각 GET 컨텍스트에
대해 **CREDENTIAL_STRIP**(쿠키/Authorization 제거 재요청)·**IDENTIFIER_SUBSTITUTION**
(숫자 id +1 재요청)을 실행해 `AnalysisResult`에 `access_scoring_results`·
`access_probe_observations`를 담는다. `build_decision_candidates`는 BAC 후보를
calibrated probability로 SQLi/XSS와 함께 랭킹하고(BAC 모델은 optional — 없으면 조용히
제외), 대시보드는 BAC 후보를 endpoint·check_kind·reference/comparison 재전송으로
렌더한다. **BAC 전용 검증**(`verification/access_verify.py`)은 IDENTIFIER_SUBSTITUTION
후보를 다른 id(+2/+5/−1)로 재확인해, 여러 id에서 재현되면 confidence 유지(SUPPORT_
REPRODUCED), 하나도 재현 안 되면 약화(WEAKEN)한다 — injection과 같은 신호/LLR 모델
재사용. 이로써 ADR-014의 "BAC deferred(scorer만 있고 관측 없음)"를 관측·랭킹·검증까지
확장한다.

**Context:** 데모 앱의 IDOR를 스캔이 실제로 후보로 잡게 하려는 사용자 요청. GET 한정·
비파괴(ADR-012 non-goals 준수: 로그인/세션/역할 매트릭스 없음).

**Alternatives:**

- BAC를 selection_priority로만 표시(66e5321의 combined_report 방식) → 기각. 현재
  대시보드는 calibrated probability 기반이라 스케일 통일이 필요.
- BAC 검증을 injection verification 프레임(페이로드 mutation)에 억지로 넣기 → 기각.
  BAC는 페이로드가 아니라 식별자/자격증명 재확인이라 별도 경량 경로가 맞다.

**Consequences:**

- pipeline/cli_decision/decision_html_report 통합, `access/{planner,executor}.py`
  복원, `verification/access_verify.py` 신규. 전체 unit 710 green. 데모 스캔에서
  BAC 후보가 랭킹·대시보드·검증에 나타남.
- **한계/후속:** IDENTIFIER_SUBSTITUTION은 순차 id 앱에서 과탐 경향(데모에서 BAC 다수).
  CREDENTIAL_STRIP 전용 검증은 미구현(관측만). 부수로 e5ceb2d의 --top-k 상한 회귀
  (test_decision_cli top-k 50) 동반 수정.

---

## ADR-036 — 라벨 붙은 DemoShop 타깃과 live ranking evaluation

**Status:** Accepted

**Date:** 2026-08-24

**Decision:** 세 가지를 함께 정한다.

1. **평가용 타깃.** `demo_target_server.py`의 37개 입력점을 `tools/demo_shop.py`의
   **DemoShop**(라우트 32개, GET form 기반 입력점 100개, 취약 40 / 안전 60)으로
   교체한다. 정답은 사이트 자신이 소유하고 `data/demo/demoshop-ground-truth.json`에
   커밋한다. 안전 입력점은 일부러 어렵게 만든다(`safe_validated` 400,
   `safe_dynamic` 길이 변화, `safe_stripped` 위험문자 치환, `safe_type_error`
   파라미터 바인딩인데 캐스팅 오류로 진짜 DB 오류를 노출). 취약 입력점 중
   `sqli_blind`·`xss_conditional`은 현재 feature로는 놓치도록 둔다. 어떤 랭킹이든
   1.000이 나오는 타깃은 아무것도 측정하지 못하기 때문이다.
2. **live evaluation 단계.** `evaluation/live.py`가 한 번의 실제 스캔이 만든 후보
   pool을 ground truth와 조인해 세 arm을 **같은 후보·같은 라벨**로 채점한다:
   random predictor(전체가 한 동점 그룹 = §6-A rule 4의 정확한 기대값),
   focused verification을 뺀 파이프라인(보정 확률 순), 최종 VulnSpider
   (`final_confidence` 순). `--ground-truth`로 켜고 `live-evaluation-v1` JSON과
   콘솔 표로 남긴다. 한 스캔 = 애플리케이션 1개 = query 1개(§6-A rule 3)이므로
   `MAP@K`는 그 query의 average precision이다.
3. **검증 대상 정정.** `--verify`는 지금까지 `analysis.selection`(v0.1 휴리스틱
   Top-K)을 검증했지만 리포트는 보정 확률 Top-K를 싣는다. XSS encoding 감점
   (ADR-031)처럼 보정 전용 항이 순서를 바꾸면 두 집합이 완전히 어긋나, 리포트의
   어떤 후보에도 `final_confidence`가 붙지 않는다. `cli_decision.rank_analysis`로
   랭킹을 먼저 계산하고 `VerificationSelection`으로 그 집합·그 prior를 검증에
   넘긴다. `verify_analysis(selection=...)`를 생략하면 종전 동작이라
   `tools/build_verification_corpus.py`는 그대로다.

**Context:** "Random Predictor / focused verification 없는 파이프라인 / 최종
소프트웨어를 Precision·Recall·MAP으로 비교하고 싶다"는 요구. ADR-033이 verification
arm을 코퍼스 위에서 정의했지만, 제품이 실제로 출력하는 confidence로 측정하는 경로는
없었다. 그 경로를 만들자마자 3번 문제가 드러났다: 100개 입력점 타깃에서 두 Top-K의
교집합이 0이었다.

**Alternatives:**

- *리포트에서 오프라인으로 채점.* `decision-report-v1`에 후보 identity(path·
  parameter)가 없어 ground truth와 조인할 수 없다. 리포트 스키마를 넓히는 대신
  실행 중 권위 있는 `Endpoint`/`InputPoint`에서 키를 만든다(`corpus/collection`과
  동일 규칙).
- *검증이 계속 휴리스틱 Top-K를 보게 두기.* 검증 코퍼스 수집에는 맞지만 스캔
  리포트에는 틀리다. 그래서 기본값은 유지하고 호출자가 집합을 지정하게 했다.
- *arm을 코퍼스처럼 out-of-fold로.* live 스캔은 학습이 아니라 측정이므로 해당
  없음. 대신 미라벨 후보 수를 항상 함께 보고한다.

**Consequences:**

- 검증된 후보가 리포트 Top-K와 항상 일치한다. DemoShop 실측(top-k 20, 적합
  verification 모델): Precision@20 random 0.160 / no-verify 0.800 / full 0.850,
  MAP@20 0.049 / 0.714 / 0.763.
- 내장 기본 verification 모델은 `SUPPORT_REPRODUCED`의 LLR이 0이라(ADR-033)
  arm 간 차이가 0이 된다. 평가 실행은 `corpus verify-fit`으로 적합한 모델을
  `--verification-model`로 넘겨야 한다.
- verification은 Top-K만 방문하므로 `K == top_k`에서 두 arm은 **같은 집합**이고
  `Recall@K`/`Precision@K`가 대체로 같다. 차이는 순서에 민감한 `MAP@K`와
  `K < top_k`에서 드러난다. 단, 강등된 후보가 컷 밖으로 밀리면 미검증 후보가
  올라와 집합 자체가 바뀔 수 있다.
- DemoShop은 라우트가 32개라 기본 크롤 예산(10 페이지)으로는 부족하다. 평가는
  `analyze --url ... --max-pages 60 --max-requests 250`로 실행한다.

---

## ADR-037 — DemoShop 인증 영역과 네이티브 세션 쿠키 (BAC 실증)

**Status:** Accepted

**Date:** 2026-08-27

**Decision:** BAC를 데모에서 **진짜 취약점(true positive)과 정상 접근제어(true
negative)**로 실증하기 위해 세 가지를 함께 도입한다.

1. **네이티브 세션 쿠키 (정적 경로).** `CrawlPolicy.session_cookies`와 CLI
   `--cookie NAME=VALUE`(반복)로 운영자가 로그인 세션을 제공하면, 정적 크롤러가
   그 쿠키를 모든 요청에 실어 보내고(`Cookie` 헤더) 생성하는 모든
   `RequestTemplate`에 쿠키를 담는다(`extract_static_html(session_cookies=...)`).
   `RequestTemplate.id`가 쿠키를 포함(models.py)하므로 사후 부착은 불가능해,
   쿠키는 **템플릿 생성 시점**에 주입한다. 이로써 (a) 보호 자원이 200으로
   발견되고(크롤러는 4xx를 스킵한다), (b) `plan_credential_strip`이 계획될 전제
   (템플릿에 자격증명 존재)가 성립한다. 계정 생성/로그인 자동화/상태 변경은
   없다(AGENTS.md 준수) — 읽기 전용 GET, 세션은 운영자 제공.
2. **DemoShop 인증 영역(`/portal/`).** `/login?as=admin|user`가 서명된
   `demoshop_session` 쿠키를 발급. `/portal/order?ref`·`/portal/message?thread`는
   소유권 확인이 없는 **IDOR(취약)**, `/portal/card?card_id`는 소유권을 확인해
   치환 시 403인 **정상 접근제어(안전)**. 공개 상점과 분리되어(공개 index에서
   링크 안 함) 세션 쿠키로 별도 스캔한다. 공개 100 입력점/기존 정답은 불변.
3. **평가 보강.** endpoint-level인 CREDENTIAL_STRIP 후보(입력점 없음)는
   파라미터 단위 정답에 조인할 수 없어 live 평가에서 **에러 대신 건너뛴다**
   (`evaluation/live.py`). 크롤 리포트는 세션 토큰 값을 **마스킹**해 출력한다
   (이름 유지, 값 `<redacted>`; AGENTS.md 세션 시크릿 금지).

**Context:** DVWA BAC가 로그인 없이는 발현되지 않고(모든 user_id에 200
"Access denied") 우리 휴리스틱이 그 200을 IDOR 성공으로 오독한 것이 드러났다.
DemoShop에서도 지금까지 BAC 후보는 "인증이 아예 없어 아무나 200"이라 오탐과
성질이 같았다. 진짜 접근제어가 있는 자원에서만 true positive/negative가 구분되고,
그러려면 인증된 참조 요청이 필요하다.

**Alternatives:**

- *사후 템플릿에 쿠키 부착.* `RequestTemplate.id`가 쿠키 포함 → 참조 무결성
  파괴. 기각.
- *legacy `--input` 인증 크롤 픽스처.* 크롤러 변경은 없지만 discovery가 라이브가
  아니고 v0.2 주경로가 아님(AGENTS.md). 팀 결정으로 네이티브 방식 채택.
- *CREDENTIAL_STRIP에 endpoint-level 정답 부여.* GroundTruthKey가 비어있지 않은
  parameter_name을 요구 → 모델 확장 필요. 데모는 IDOR(입력점 있음) 중심으로
  두고 credential-strip 후보는 평가에서 스킵.

**Consequences:**

- `analyze --url .../portal/ --access-control --cookie ... --ground-truth ...`
  실측(top-10): IDOR 2개가 최종 confidence 0.953으로 1~2위, 정상 접근제어는
  0.524로 그 아래. Recall@2=1.000, MAP@K=1.000 (random 0.22~0.29).
- `--cookie`는 정적 경로 전용. `--dynamic`과 함께 쓰면 에러(브라우저 세션 임포트
  미지원). 공개 상점 스캔은 `--cookie` 없이 종전과 동일.
- 크롤러가 4xx를 스킵하므로 보호 자원은 유효한 세션으로만 발견된다. 잘못된
  토큰/쿠키 없음 → 403 → 미발견.

---

## ADR-038 — 두 실제-앱 탐지 갭 수정: submit 게이트 포함, BAC denial 게이트

**Status:** Accepted

**Date:** 2026-08-28

**Decision:** DVWA 케이스 스터디 준비 중 드러난 두 가지 갭(둘 다 실제 앱 부류의
문제)을 근본 수정한다.

1. **이름 있는 submit 컨트롤을 고정 요청 파라미터로 포함(SQLi 미탐 수정).**
   `html_extractor`는 submit/버튼을 비데이터 컨트롤로 완전히 스킵했다. 그러나
   브라우저는 폼 제출 시 활성화된 submit 버튼의 `name=value`를 함께 보내고, 많은
   핸들러가 그것으로 게이팅한다(`if (isset($_GET['Submit']))` — DVWA SQLi). 이제
   폼의 **첫 번째 이름 있는 submit/`<button type=submit>`** 을 요청 템플릿의
   query(GET)/form(POST)에 **고정값**으로 싣되, 주입 가능한 InputPoint로는 만들지
   않는다. 이름 없는 submit은 브라우저와 동일하게 미포함. `RequestTemplate.id`가
   쿼리/폼을 포함하므로 생성 시점에 넣는다.
2. **BAC denial 본문 게이트(오탐 수정).** `access_unauthorized_success`는 비교
   요청이 HTTP 2xx이면 무조건 1.0이었다. 앱 레벨 "Access denied / 로그인 필요"
   페이지를 **200**으로 주는 앱(DVWA BAC 익명)에서 이는 200 거부를 IDOR 성공으로
   오독한다. 이제 응답 본문에서 denial 문구(access denied/unauthorized/forbidden/
   로그인 필요/접근 거부 등, 대소문자·한영)를 탐지해: **비교 응답이 denial이면
   success=0.0**, **참조 응답 자체가 denial이면 관측 무효**(미인증이라 샐 게 없음)로
   처리한다. 접근제어 feature 스키마 `access-feature-v0.2`.

**Context:** 팀 계획의 외부 타깃(DVWA) 준비 중, SQLi는 submit 누락으로 미탐, BAC는
익명 200 거부를 0.95 오탐으로 잡는 것이 세션 내 실측으로 확인됐다. 둘 다 DVWA 전용
문제가 아니라 "submit 이름으로 게이팅하는 앱", "인가 거부를 200으로 주는 앱" 부류의
일반 문제다.

**Alternatives:**

- SQLi: URL 시딩(`?id=1&Submit=Submit`) 우회 — 케이스별 수동이라 일반 수정으로 대체.
  모든 submit을 다 포함? 브라우저는 하나만 보내므로 첫 번째만.
- BAC: 상태코드만 유지 + 인증 강제 — 익명 오탐은 남는다. denial 본문 탐지가 근본적.
  IDOR/자격증명제거의 유사도 의미 분리(ADR-037 C안)는 범위가 커서 후속 과제로 남김.

**Consequences:**

- DVWA SQLi가 URL 시딩 없이 탐지된다(`Submit=Submit` 자동 포함). DemoShop은 폼이
  이름 없는 `<button type=submit>`이라 영향 없음(공개 100 입력점·정답 불변).
- DVWA 익명 BAC 0.95 오탐이 사라진다(관측 무효). 실제 IDOR는 로그인 세션(`--cookie`,
  ADR-037)으로 확인해야 한다. DemoShop `/portal` IDOR(0.953)·정상(0.524) 판정 불변.
- 한계: denial 문구 사전에 없는 표현은 놓칠 수 있다(패턴 확장 가능). 전체 867 테스트
  통과.

---

## ADR-039 — Per-input-point 랜덤 예측기 비교군

**Status:** Accepted

**Date:** 2026-08-30

**Decision:** 라이브 랭킹 평가의 랜덤 비교군을 두 가지로 둔다.
`ARM_RANDOM`(균등 무작위 순위, 닫힌 형식 기댓값)은 그대로 두고, 더 직관적인
**per-input-point 랜덤 유형 추측기**를 `evaluation/random_predictor.py`로 추가한다.
각 입력점마다 `{SQLI, REFLECTED_XSS, BROKEN_ACCESS_CONTROL, SAFE}` 중 하나를
가중치(`--random-safe-weight W`)로 추첨해 그 family 후보만 양성(1.0)으로, 나머지는
음성(0.0)으로 둔 뒤, **동일한 `evaluate_ranking`** 으로 채점해 VulnSpider와 같은
지표(Recall/Precision/MAP/NDCG@K)로 비교한다. `--random-predictor`(analyze·simple
공통, `--ground-truth` 필요)로 켜면 평가 표/JSON에 네 번째 arm으로 붙는다.

**Context:** 팀이 비교군으로 "Random Predictor"를 쓰기로 했는데, 보고서 독자에게는
"입력점마다 취약 유형을 무작위로 찍는" 분류기가 균등-순위 baseline보다 이해하기 쉽다.
대부분의 입력점이 안전하므로 SAFE 가중을 줄 수 있어야 한다.

**Alternatives:**

- 균등-순위 baseline만 유지 — 엄밀하지만 "유형을 찍는다"는 직관을 못 준다. 두 개를
  함께 두어 독자가 고르게 한다.
- 단일 draw로 채점 — 잡음이 크다. `trials`회(기본 1000) 시드 고정 몬테카를로 평균을
  쓰되, 각 draw의 지표는 §6-A 규칙 4의 정확한 동점 기댓값이라 유형 추측만
  시뮬레이션된다(시드에 대해 결정적).
- `evaluate_live_run`에 arm을 넣기 — `live`가 `random_predictor`를 참조하면 순환
  import이 되고 런타임 힌트 해석(check_types)이 깨진다. arm 합류는 소비자
  (`cli_decision.run_live_evaluation`)에서 `dataclasses.replace`로 처리해 `live`는
  `ScoredCandidate`의 단방향 제공자로 남긴다.

**Consequences:**

- DemoShop 100 입력점(200 후보, 취약 32)에서 두 랜덤 arm은 거의 동일(P@K≈유병률 0.16)
  하며 VulnSpider(저-K에서 1.000)와 크게 대비된다 — 클래스 기반 랜덤도 균등 랜덤과
  같은 수준임을 보여 baseline의 타당성을 재확인한다.
- 기본 3-arm 표는 불변(옵션 플래그로만 추가). `live-evaluation-v1` 스키마는 arm 리스트에
  항목이 하나 느는 것뿐이라 버전 불변.
- 전체 테스트 통과(신규 `test_random_predictor.py` 포함); 모듈은 독립 브루트포스
  시뮬레이션과 오차 ~0.001로 일치.

---

## ADR-040 — 보고서용 표 산출물 + 넓은 데스크톱 대시보드

**Status:** Accepted

**Date:** 2026-08-30

**Decision:** 최종 보고서 탑재를 위해 두 가지를 개선한다.

1. **실행마다 보고서용 표 파일 생성.** 평가 단계(`--ground-truth`)가 켜지면 평가
   JSON 옆에 `reporting/report_tables.py`가 렌더한 표를 **Markdown + HTML** 두 형식으로
   함께 저장한다. `<eval>-table.{md,html}`은 arm(Random / 검증 없음 / Full / 선택적
   per-input-point 랜덤)별 Recall/Precision/MAP/NDCG@K 비교, `<eval>-inputs.{md,html}`은
   ground truth에서 뽑은 **입력점별 취약 유형** 표다. Markdown은 Notion/문서에 바로
   붙여넣고, HTML은 대시보드 팔레트로 스타일링돼 열람·스크린샷용. 지표·라벨은
   재계산하지 않고 포맷만 한다.
2. **대시보드를 넓은 데스크톱 레이아웃으로.** 결정 대시보드(`decision_html_report.py`)의
   findings를 `repeat(auto-fit,minmax(540px,1fr))` 그리드로 흘려 세로 스크롤 대신 가로로
   넓게 배치하고(후보 1개면 전체폭, 여럿이면 2열), 컨테이너 폭을 1240px로 넓히며 카드
   그림자·헤더를 다듬었다. 변경은 decision 전용 `_EXTRA_STYLE` override에만 넣어 공유
   `_DOCUMENT_STYLE`과 v0.1 리포트에는 영향이 없다.

**Context:** 팀이 최종 보고서에 지표 표와 데모 입력점 취약 유형을 바로 실을 형태를 원했고,
대시보드는 데스크톱 화면에서 세로로 길기보다 가로로 넓게 보이길 원했다.

**Consequences:**

- 평가가 있는 실행은 표 4개(md/html ×2)를 추가로 저장하고 CLI가 HTML 링크를 출력한다.
  기존 평가 JSON/텍스트 표는 그대로.
- 대시보드 findings 카드 구조·클래스(`article.finding`)는 불변이라 접힘/카운트 테스트에
  영향 없음. `finding`을 `section.findings` 그리드로 감쌌을 뿐.
- 표 렌더러는 순수 함수(입력: `LiveEvaluationReport`, `GroundTruthStore`)라 스캔 없이도
  테스트된다. 전체 898 테스트 통과.

---

## ADR-041 — Portable multi-screen result dashboard

Status: Accepted
Date: 2026-09-13

Decision:

- Replace the v0.2 decision report's long card wall with Korean overview,
  candidate-list, candidate-detail and reading-guide screens. Keep the existing
  HTML destination and one-file offline delivery using fragment navigation.
- Render endpoint/input-point ownership as an explicitly labeled map; no crawl
  edges or attack paths are inferred. Show selected candidate count separately
  from the existing highest-type-per-subject representative view.
- Present supplied calibration evidence, initial request pairs, individual
  VerificationResult payloads/validator decisions/execution references and
  final confidence. No score, verdict, request or payload is reconstructed.
  Missing provenance remains missing; BAC aggregates do not invent individual
  identifier payloads. Per-payload confidences are not presented as cumulative.
- Use plain explanations before expandable technical records. Defense guidance
  is conditional and never reports a successful exploit or a completed fix.
- Inline a fixed, data-independent script for navigation/focus, local search,
  filters, history and printing. Escape all dynamic text/attributes and restrict
  scripts to its SHA-256 CSP hash; default network/resource access is denied.
  CSS fragment navigation provides a modern-browser no-JavaScript fallback.

Context:

The user requested a service-like final graduation-project report that students
and professors outside web security can follow, with visual summaries and
separate detail pages showing why candidates deserve review.

Alternatives:

Separate HTML files would complicate artifact distribution/publication. An
external frontend framework/CDN would add offline and dependency requirements.
One long page would preserve the information overload the user asked to fix.

Consequences:

- `decision-html-v4` changes presentation only. CLI, JSON, scoring, selection,
  payload execution and frozen v0.1 report semantics remain compatible.
- Fragment addresses are scoped to one generated report. A new scan may reorder
  candidates. Older stored reports retain their original UI until regenerated.
- New presentation helpers live in `reporting/dashboard_assets.py`,
  `dashboard_layout.py`, and `dashboard_evidence.py`.
- Browser QA and independent Gate Review are recorded in the execution plan.

---

## ADR-042 — DemoShop storefront presentation and unified confidence labels

Status: Accepted
Date: 2026-09-13

Decision:

Honor the requested dashboard terminology: **상위 취약점 후보**, and **최종
신뢰도** as the display label for the currently available probability, including
unverified candidates. Retain source explanations and before/after evidence.
No `VerificationConfidence` is fabricated, no `RankScore` is relabeled as a
probability, and no JSON, scoring or verification contract changes.

Present DemoShop through a responsive storefront shell and four locally bundled
AI-generated product photos. Fixed asset routes map to explicitly allowlisted
files. Product, quantity and category UI selections use bounded fragments and
DOM updates; cart/checkout completion is a visual simulation with no persistence
or actual order/payment operation. Ordinary links retain bare canonical paths.

Context:

Graduation evaluators need recognizable shopping screens and understandable
report labels. The previous placeholder storefront was unsuitable for demos.

Consequences:

- `PAGES`, 100 query input points, default seeds, ground truth, `_fragment`
  response semantics, loopback scope and authentication rules remain unchanged.
- New styles/scripts load from local assets; intentional target vulnerabilities
  remain in the existing response fragments. Detailed raw responses sit behind
  a disclosure so ordinary shopping screens stay readable.
- The HTML presentation changes response-size denominators. Historical ranking
  measurements require a target revision and a fresh evaluation for comparison.
- No dependency was added. Static asset routing, canonical forms and navigation
  are covered by regression tests; browser QA checks the simulated purchase flow.

---

### Dashboard demonstration follow-up (2026-09-14)

The overview now connects discovery/observation/selection counts and compares
the first three representatives' supplied prior and final confidence on a fixed
0–100% scale. Selected candidate count remains distinct from collapsed display
count; missing verification never implies a gain or an executed payload.

DemoShop names and marker numbers are optional descriptive annotations read
from an existing, attributable baseline response and matching GET form. They
are escaped and never feed identities, scoring or selection. Missing, duplicate,
malformed or mismatched annotations retain canonical technical names. No target
module imports, ground-truth access, new requests or discovery contracts were
introduced. The implementation remains covered by ADR-041/042.

### Projector and recorded-evidence follow-up (2026-09-21)

`decision-html-v5` extends ADR-041/042 with a presentation story, larger
high-contrast typography, an opt-in projector view with persistent navigation,
representative verification-state counts and final-confidence bars. The top
two displayed representatives link to their recorded evidence, with no manual
proof or target-execution link. The user explicitly excluded the unfinished
DemoShop proof feature; its code/assets and fixture changes were removed.

Candidate detail displays bounded, escaped retained Baseline/Probe excerpts,
actual request values, status/size and provenance. Excerpt matching is only a
reading aid. Interpretations use supplied calibration evidence, distinguish
aggregate input-point signals from the displayed pair, and explain false
positives and missing/error records. A SQL error is not proof of SQL execution;
reflection alone is not proof of script execution. Status cards count displayed
representatives, not confirmed vulnerabilities. No score/confidence, JSON,
selection, feature extraction or network behavior changes.

## ADR-043 — Simple DemoShop member login and order ownership demonstration

**Status:** Accepted
**Date:** 2026-09-21

**Decision:** The storefront My Page link opens a parameter-free GET `/login`
screen. A single explicit POST button issues the existing `user` demo session
(uid 1042, display name `soohoon`) and redirects to fixed `/portal/`. POST
`/logout` clears that browser cookie and redirects to fixed `/login`. Named
credentials, role selectors, return URLs and scanner tokens are absent from the
shopper screen. Cookies use HttpOnly and SameSite=Lax; responses are no-store.

**Context:** `/account/login` is a public injection-evaluation fixture, previously
linked as My Page. Its destination inputs and email-link wording made the manual
login/BAC demonstration confusing. The real authenticated portal already exists
under ADR-037 and can be reused without changing scanner authentication.

**Consequences:**
- Preserve the 100 public canonical input points, seeds, ground truth, and
  `/account/login` response semantics. The new anonymous login page has no named
  input controls, no portal links and does not issue cookies on GET. Explicit
  legacy `/login?as=admin|user` lab helpers remain compatible.
- The protected order form still uses `ref` with seed `4100`. The new display
  identifies its owner as `soohoon` (1042); `4101` displays `sanghyun` (1043).
  Changing only the order number in the same session demonstrates the deliberate
  missing ownership check. Non-seed identifiers still produce synthetic records
  to preserve the existing IDOR fixture. Anonymous/forged sessions still get 403,
  and the ownership-checked payment-card negative control is unchanged.
- Login/logout only change a demo browser cookie. Empty POST bodies are required;
  query values never control the issued role or redirect. No account creation,
  order mutation, scanner execution, transport authority, dependency, domain
  contract or frozen v0.1 behavior changes. Deterministic tokens remain lab-only;
  browser logout is not server-side token revocation.
- Public navigation now includes a parameter-free login page and its empty POST
  form endpoint. No named input point is added. Page sizes change, so evaluations
  and response-size-derived rankings require fresh measurements.

### Order lookup navigation follow-up (2026-09-21)

Header/footer order links now use parameter-free `/login/orders`, which renders
the same one-button login for anonymous visitors and redirects existing sessions
to `/portal/order`. Explicit POST login has the same fixed destination; arbitrary
query values cannot select roles or destinations. Neither anonymous login entry
authenticates on GET or links protected resources into the public crawl.

Authenticated legacy `/orders?order_id=...` requests are redirect aliases to
`/portal/order?ref=...`; values are URL encoded, and old fixture examples
20240517/20240518 map to 4100/4101. The protected endpoint remains responsible for
displaying records. Anonymous `/orders` retains its four canonical inputs and
SQLi fixture behavior, with a member-login call to action. Public labels remain
unchanged: actual cross-member order records are served by the existing BAC
endpoint, not duplicated under the public SQLi endpoint. Evaluation runbooks use
anonymous public scans and separately authenticated portal scans as before.

### Member evidence demo follow-up (2026-09-23)

The three shared demo members are 한수훈 (1042), 전상현 (1043), and 이석현
(1044). Protected order/message pages compare the actual fixture owner UID to
the session UID and highlight a mismatch without requiring a confirmation marker.

The `/admin/users` fixture now uses disposable in-memory SQLite for member
lookup. Empty/default search selects a bound ID; other terms intentionally enter
a read-only SELECT unsafely, so the manual tautology returns actual member rows.
This replaces the constant member fragment and confirmation-only illustrated
SQL disclosure for this route. SQL errors/missing rows do not fabricate a leak.
The standard-library database is recreated per lookup, has query-only mode,
statement/string size limits and an instruction budget, and rejects stacked
statements. No persistent database, new dependency, transport permission,
canonical input, scanner verdict rule or frozen v0.1 behavior is introduced.
Preserve labels and seeds; regenerate response-derived evaluation measurements.

## New Decision Template

```text
## ADR-XXX — Title

Status: Proposed | Accepted | Rejected | Superseded
Date:

Decision:

Context:

Alternatives:

Consequences:
```
