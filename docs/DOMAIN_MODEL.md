# Domain Model

## 1. 목표

코드 전체에서 동일한 용어를 사용하기 위한 v0.1 도메인 명세다.

가장 중요한 규칙:

```text
Page != Endpoint != InputPoint != VulnerabilityCandidate
```

---

## 2. `Endpoint`

서버 기능의 정규화된 요청 대상.

권장 필드:

```text
id: str
method: HttpMethod
scheme: str
host: str
path: str
content_type: str | None
discovered_by: str
```

예:

```text
GET /search
POST /login
```

### Endpoint identity

v0.1 fingerprint 권장 입력:

```text
method + normalized_scheme + normalized_host + canonical_path
```

Query value는 Endpoint identity에 포함하지 않는다.

---

## 3. `InputPoint`

외부 입력을 독립적으로 변화시킬 수 있는 원자 단위.

권장 필드:

```text
id: str
endpoint_id: str
location: InputLocation
name: str
baseline_value: str | None
type_hint: str | None
source_page: str | None
auth_context_id: str | None
metadata: dict
fingerprint: str
```

### InputLocation

v0.1 필수:

```text
QUERY
FORM
```

미래 확장:

```text
JSON
PATH
HEADER
COOKIE
MULTIPART
```

v0.2 Dynamic discovery additionally implements `JSON_BODY` for value-free
top-level member names observed on an eligible blocked POST JSON attempt.
`JSON_BODY` has no RequestTemplate or request context in this implementation and
is always owned by `ProbeReadiness.NOT_READY`. The older reserved `JSON` enum
value remains distinct for compatibility and is not produced by this path.

### InputPoint identity

권장:

```text
endpoint_fingerprint
+ location
+ normalized_parameter_name
+ auth_context_id(optional)
```

예:

```text
GET /search :: query.q
GET /search :: query.page
POST /login :: form.username
POST /api/search :: json_body.keyword
```

---

## 4. `RequestTemplate`

특정 Endpoint 요청을 재구성하기 위한 원본 구조.

권장 필드:

```text
id: str
endpoint_id: str
method: HttpMethod
url: str
headers: dict[str, str]
query: dict[str, str]
form: dict[str, str]
cookies: dict[str, str]
```

원칙:

- Probe는 template을 복제한다.
- target InputPoint 하나만 변경한다.
- 나머지 입력은 동일하게 유지한다.

---

## 5. `ProbePlan`

관찰 요청 계획.

권장 필드:

```text
id: str
input_point_id: str
probe_family: ProbeFamily
baseline_request: RequestInstance
probe_request: RequestInstance
changed_fields: list[str]
```

검증 규칙:

```text
len(changed_fields) == 1
```

v0.1 ProbeFamily:

```text
REFLECTION_MARKER
TYPE_PERTURBATION
GENERIC_PERTURBATION
```

---

## 6. `ResponseSnapshot`

HTTP 응답 관찰값.

권장 필드:

```text
id: str
request_id: str
probe_plan_id: str | None
request_role: "baseline" | "probe" | None
status_code: int
elapsed_ms: float
body_bytes_hash: str
body_length_bytes: int
headers: dict[str, str]
decoded_text: str | None
encoding: str | None
redirect_location: str | None
execution_error: str | None
```

주의:

- 4xx/5xx도 정상적인 관찰 데이터다.
- Probe Executor에서 `raise_for_status()` 방식으로 버리지 않는다.

ProbePlan-owned observations carry `probe_plan_id`, `request_role`, and
`request_id`. A snapshot without matching plan ownership is a direct request
observation and must not be consumed as a baseline/probe pair member. Equal
`request_id` values can appear in different ProbePlans; observation ownership is
defined by the complete `(probe_plan_id, request_role, request_id)` tuple, not by
request bytes alone.

---

## 7. `ResponsePair`

동일 InputPoint에 대한 Baseline/Probe 응답 쌍.

```text
input_point_id
probe_plan_id
baseline_response_id
probe_response_id
```

---

## 8. `FeatureObservation`

단일 feature의 값과 관찰 상태.

권장 필드:

```text
name: str
value: float | bool | str | None
observed: bool
source: str
extractor_version: str
details: dict
```

핵심:

```text
observed=false, value=null
```

은

```text
observed=true, value=0
```

과 다르다.

---

## 9. `FeatureVector`

InputPoint 하나에 귀속되는 정량 feature 집합.

권장 필드:

```text
id: str
input_point_id: str
probe_run_ids: list[str]
feature_schema_version: str
features: dict[str, FeatureObservation]
```

---

## 10. `VulnerabilityCandidate`

랭킹의 원자 단위.

```text
InputPoint x VulnerabilityType
```

권장 필드:

```text
id: str
input_point_id: str
vulnerability_type: VulnerabilityType
rank_score: float | None
scorer_version: str | None
```

v0.1 VulnerabilityType:

```text
SQLI
REFLECTED_XSS
```

---

## 11. `ScoreEvidence`

RankScore 설명용 기여도.

권장 필드:

```text
candidate_id: str
feature_vector_id: str
vulnerability_type: VulnerabilityType
feature_name: str
feature_value: float | null
observed: bool
weight: float
contribution: float | null
reason: str
```

합계 규칙:

```text
raw_score = sum(contribution for observed evidence)
```

정규화가 있다면 raw score와 normalized score를 둘 다 보존한다.

05C에서 `observed=false`인 항은 `feature_value=null`과
`contribution=null`을 사용한다. 이 항은 숫자 합계에는 참여하지 않지만
누락 사실과 설정 weight를 evidence에 남긴다. 따라서 관찰된 `0.0`과
미관찰 값은 구분된다. `feature_vector_id`는 동일 InputPoint의 서로 다른
관찰 문맥에서 evidence가 섞이지 않도록 정확한 원본 vector를 가리킨다.

`ScoringResult`는 실제 `FeatureVector`와 `VulnerabilityCandidate`를 함께
받는 validated factory로만 생성한다. Factory는 두 객체의
`input_point_id`가 같은지 확인하고, 모든 evidence의 `candidate_id`,
`feature_vector_id`, `vulnerability_type`이 결과와 일치하는지 검증한다.
불투명한 `feature_vector_id` 문자열만으로 결과를 직접 생성하는 API는
지원하지 않는다.

---

## 12. 후속 버전 객체

v0.1에는 구현하지 않지만 이름은 예약한다.

### `VerificationEvidence`

Focused Verification 결과 근거.

### `Finding`

최종 상태:

```text
CONFIRMED
LIKELY
UNVERIFIED
REJECTED
```

### `AccessCandidate`

BAC용 관계형 후보. InjectionCandidate와 분리한다.

예:

```text
subject_context
endpoint
resource_reference
resource_owner_context
```

---

## 13. 예시

URL:

```text
/search?q=book&page=1
```

정규화 결과:

```text
Endpoint
  GET /search

InputPoint
  GET /search :: query.q
  GET /search :: query.page

Candidates
  query.q x REFLECTED_XSS
  query.q x SQLI
  query.page x REFLECTED_XSS
  query.page x SQLI
```

---

## 14. Probe-readiness clarifications

These rules refine the v0.1 model for the Probe Planning stage without adding
Probe execution.

### Endpoint ID and fingerprint

`Endpoint.id` is the relationship identifier used by other domain objects. The
raw deterministic endpoint fingerprint remains available as
`Endpoint.fingerprint`.

Fields named `endpoint_id` contain `Endpoint.id`. Fields named
`endpoint_fingerprint` contain the raw fingerprint used for deterministic
InputPoint identity.

### RequestTemplate identity

`RequestTemplate.id` identifies a preserved request context, not only an
endpoint. Its deterministic fingerprint includes:

- endpoint id and endpoint fingerprint
- method and URL
- canonical headers and cookies
- ordered query pairs
- ordered form pairs
- request context completeness
- context key
- request-context provenance

Two forms that share the same action and method but preserve different request
context must produce different `RequestTemplate` IDs. When a mapping is used for
query or form values, it is canonicalized by sorted key/value pairs. When ordered
pairs are used, their order and duplicate names are preserved.

Resolved request values do not erase provenance. Contexts with identical
resolved method/URL but different method/action provenance, such as explicit
`GET /search` versus unknown metadata resolved as `GET /search`, must not
silently deduplicate into one `RequestTemplate`.

### InputPoint to request context association

An `InputPoint` can be associated with one or more request contexts through
`InputPointRequestContext`. No future Probe Planner should infer the baseline
request solely from endpoint identity.

If one logical `InputPoint` has multiple baseline request variants, all variants
must be preserved and explicitly associated. v0.1 does not select a canonical
baseline silently. If associated contexts have conflicting baseline values, the
logical `InputPoint.baseline_value` is `null`; exact values remain in the
associated `RequestTemplate`. If all associated contexts agree on one value, the
convenience baseline may expose that value.

`InputPointRequestContext` associations must be validatable. A valid association
uses the same endpoint id, a compatible parameter location, a target name present
in the request context, and an existing occurrence index when the target name is
repeated.

Probe-consumable `InputPointRequestContext` instances are created through the
validated object factory, not from arbitrary raw ids. When an occurrence-level
`InputPoint` has a context-specific `baseline_value`, validation checks that the
value at the exact indexed occurrence in the associated `RequestTemplate` is the
same value. A `baseline_value` of `null` means the logical InputPoint has no
single canonical baseline and does not by itself fail association validation.

### Repeated parameter policy

Repeated query parameters are supported by preserving ordered parameter pairs in
`RequestTemplate.query` and by creating occurrence-level InputPoints when the
ordered occurrence evidence is available.

For example, `/search?tag=a&tag=b` creates distinct targetable InputPoints for
`query.tag` occurrence `0` and `query.tag` occurrence `1`. The occurrence index
participates in deterministic `InputPoint` identity so a future Probe Planner can
mutate exactly one intended occurrence.

The same ordered-pair representation is available for form controls so duplicate
same-name controls are not collapsed by `dict` semantics. Form/body repeated
names become occurrence-level targets only when the input evidence preserves a
stable form boundary and ordered occurrence evidence; otherwise the context must
be marked ambiguous/non-probe-ready rather than inventing ordering.

For actual URLs, the URL query string order is authoritative. Legacy JSON query
metadata is supplemental. If JSON metadata conflicts with the URL query, the
adapter preserves the URL request context and emits a deterministic warning.

### Legacy form completeness

Legacy-derived form request templates are `PARTIAL` by default because the
legacy static parser may omit hidden inputs. The adapter must not interpret the
absence of hidden fields as proof that no hidden fields existed.

The hidden-input limitation must be visible in request template metadata and/or
adapter warnings so future Probe Planning can distinguish complete context from
lossy legacy context.

Legacy evidence that lacks a stable form-instance boundary must not be used to
merge fields solely because they share source page, method, and action. Such
contexts are preserved separately, marked partial/ambiguous, and annotated with
`form-boundary-unavailable`. If stable form-boundary evidence is present, the
adapter preserves and uses it.

When the boundary is unavailable, ambiguous form context identity must not use
collector list position as a fabricated form-instance id. It uses deterministic
field evidence such as field name, type, observed value, method/action, source
page, provenance, and ambiguity state. Truly indistinguishable duplicate field
records may deduplicate deterministically, while remaining explicitly
partial/ambiguous/non-probe-ready.

### Missing method/action provenance

The adapter may keep convenience defaults, such as `GET` for an unknown form
method or the current page URL for an unknown form action, but those defaults are
assumptions. They must be recorded with provenance metadata and warnings.

Explicit legacy metadata, unknown legacy metadata, invalid metadata, and adapter
assumptions must remain distinguishable.

### FeatureVector identity

`FeatureVector.id` identifies a concrete observation set for one InputPoint and
the probe runs that produced it. Its deterministic fingerprint includes:

- `input_point_id`
- `feature_schema_version`
- canonical `probe_run_ids`
- feature names
- observed state
- feature values
- source and extractor version
- feature details

Equivalent vectors produce the same ID. Distinct observed values, observed
states, details, schema versions, or probe-run sets must not silently collide.

Feature details used in identity are restricted to JSON-like values with string
mapping keys. Nested mappings and lists are deep-frozen at construction so caller
mutation after model creation cannot change the semantic contents represented by
the `FeatureVector.id`. Unsupported values such as sets or arbitrary objects are
rejected.
