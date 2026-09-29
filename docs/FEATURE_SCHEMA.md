# Feature Schema — v0.1

## 1. 목적

Feature는 후보 우선순위화의 근거다. 따라서 모든 feature는:

1. 정의가 deterministic 해야 하고
2. 어느 InputPoint에서 생성됐는지 명확해야 하며
3. 미관찰과 0을 구분해야 하고
4. 버전이 있어야 한다.

v0.1 schema version:

```text
feature-v0.1
```

---

## 2. 공통 표현

```json
{
  "value": 1.0,
  "observed": true,
  "source": "reflection_marker_probe",
  "extractor_version": "reflection-v1",
  "details": {}
}
```

미관찰:

```json
{
  "value": null,
  "observed": false,
  "source": "not_run",
  "extractor_version": "reflection-v1",
  "details": {}
}
```

---

## 3. Static Features

### `numeric_value`

목적: baseline 값이 숫자형으로 해석 가능한지 표시.

정의:

```text
1.0: 전체 문자열이 정수 또는 실수 형태
0.0: 그 외
```

주의: 숫자형이라는 사실은 취약 증거가 아니라 약한 prior다.

---

### `id_like_name`

v0.1에서는 수집 가능하나 SQLi/XSS 기본 scorer에 높은 가중치를 주지 않는다.

예시 이름 패턴:

```text
id
user_id
product_id
itemId
```

---

### `input_location_query`

```text
1.0 if location == QUERY else 0.0
```

---

### `input_location_form`

```text
1.0 if location == FORM else 0.0
```

---

## 4. Differential Features

Baseline 응답 B와 Probe 응답 P를 비교한다.

### `status_code_changed`

```text
1.0 if B.status_code != P.status_code else 0.0
```

세부 정보에 before/after status 저장.

---

### `response_length_diff_ratio`

권장 정의:

```text
abs(len(P) - len(B)) / max(len(B), 1)
```

초기에는 clipping 가능:

```text
min(value, 1.0)
```

raw 값도 details에 보존.

---

### `response_time_diff_ratio`

v0.1 보조 feature.

단일 요청 timing은 노이즈가 크므로 높은 가중치 금지.

권장:

```text
abs(P_ms - B_ms) / max(B_ms, 1)
```

후속 버전에서는 반복 요청 median 사용.

---

### `redirect_changed`

```text
1.0 if redirect behavior or Location differs else 0.0
```

---

## 5. Reflection / XSS Features

### `marker_reflected`

Probe marker가 decoded response text에 존재하는지.

```text
1.0: exact marker found
0.0: not found
```

source:

```text
reflection_marker_probe
```

---

### `reflection_count_norm`

marker 등장 횟수의 정규화 값.

v0.1 권장:

```text
min(count / 3, 1.0)
```

---

### `safe_html_encoding_detected`

marker 주변의 특수 문자가 안전한 HTML entity로 변환되었는지.

v0.1에서는 구현 가능 범위를 좁힌다.

```text
1.0: configured probe sentinel의 위험 문자가 일관되게 entity encoding
0.0: 그렇지 않음
```

이 feature는 XSS score의 penalty 후보다.

주의:

- 단순 marker reflection만으로 XSS 확정 금지
- context parser가 불충분하면 `observed=false` 사용

---

### `dangerous_reflection_context`

v0.1 optional feature.

문맥 분류가 안정적으로 구현되기 전에는 scorer에서 제외해도 된다.

가능한 값의 수치화 예:

```text
0.0 text-safe/unknown
0.5 attribute-like
1.0 script-like dangerous context
```

불확실하면 추측하지 말고 미관찰 처리.

---

## 6. SQL Signal Features

### `sql_error_pattern`

Probe 응답에서 DB/SQL 관련 오류 패턴이 새롭게 나타나는지.

정의 원칙:

- baseline에도 동일 패턴이 있으면 강한 신호로 보지 않음
- probe에서 새롭게 등장해야 함
- pattern source/version 저장

값:

```text
1.0: new SQL-related error pattern
0.0: checked, not found
```

주의:

일반 500 오류만으로 1.0 금지.

---

### `type_perturbation_behavior_diff`

숫자형 baseline에 비파괴적인 type perturbation을 적용했을 때 유의미한 응답 차이가 있는지.

v0.1 권장 계산:

다음 신호의 weighted local combination으로 만들 수 있으나, 개별 feature와 중복 기여하지 않도록 scorer 설계 시 주의한다.

```text
status change
length diff
new SQL error pattern
redirect change
```

초기에는 별도 composite feature를 만들지 않고 개별 feature만 사용하는 것도 권장된다.

---

## 7. v0.1 기본 Scoring 초안

초기 가중치는 연구 결과가 아니라 **작동하는 baseline**이다. 이후 ground truth 실험으로 조정한다.

### XSS

```text
+ 35 * marker_reflected
+ 10 * reflection_count_norm
- 30 * safe_html_encoding_detected
+ 15 * dangerous_reflection_context   # observed일 때만
+ 10 * response_length_diff_ratio
```

### SQLi

```text
+ 15 * numeric_value
+ 20 * status_code_changed
+ 20 * response_length_diff_ratio
+ 35 * sql_error_pattern
+  5 * redirect_changed
```

### 05C implemented subset

현재 05B가 실제로 추출하는 feature만 사용한다. 아직 추출되지 않는
`numeric_value`, `reflection_count_norm`, `safe_html_encoding_detected`,
`dangerous_reflection_context`, `redirect_changed`는 05C에서 값을 만들거나
0으로 가장하지 않는다.

```text
SQLi raw RankScore:
+ 20 * status_code_changed
+ 20 * response_length_diff_ratio
+ 35 * sql_error_pattern
available range: 0..75

Reflected XSS raw RankScore:
+ 35 * marker_reflected
+ 10 * response_length_diff_ratio
available range: 0..45
```

두 score는 정규화하지 않으며 vulnerability probability나 최종 Confidence가
아니다. 서로 다른 scale의 verification-priority 신호다.

### Missing feature 처리

미관찰 feature는 numeric score 합계에 0의 효과만 주지만, evidence의
`contribution`은 관찰된 숫자 `0.0`으로 만들지 않고 `null`로 기록한다.

단:

- "관찰하지 않았음"을 "안전함"으로 해석하지 않는다.
- score evidence에 `observed=false`, `feature_value=null`,
  `contribution=null` 상태를 기록한다.

응답 본문이 디코딩되지 않은 경우(`ResponseSnapshot.decoded_text is None`)
본문 기반 feature(`marker_reflected`, `sql_error_pattern`)는 관찰된 `0.0`이
아니라 미관찰로 기록한다. `details.reason`은 `response-body-not-decoded`다.

---

## 7-1. Multi-context InputPoint 합성

aggregation version:

```text
input-point-existential-v1
```

### 왜 필요한가

`FeatureVector`는 probe run 하나가 아니라 **InputPoint 하나**에 귀속된다
(`docs/DOMAIN_MODEL.md` §9). Native Static 단일 시드 크롤에서는 InputPoint 하나가
probe-ready request context를 하나만 갖는 경우가 대부분이어서 두 단위가
우연히 일치했다.

Native Dynamic / Combined 수집은 같은 endpoint의 같은 파라미터를 서로 다른
값으로 여러 번 관측한다. 예를 들어 static이 `/search?q=one`을, 렌더링된 링크가
`/search?q=two`를 발견하면 `Endpoint`와 `InputPoint` fingerprint는 같고
`RequestTemplate`만 달라져 probe-ready context가 2개가 된다.

이때 probe run마다 `FeatureVector`를 만들면 같은 candidate id
(`InputPoint x VulnerabilityType`, ADR-002)가 한 번의 분석에서 여러 번
생성되어 Top-K 요약과 evidence 소유 관계가 어긋난다.

### 합성 규칙

같은 InputPoint의 probe run 결과들을 feature 단위로 합성한다.

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

- probe run이 하나뿐이면 원본 `FeatureVector`를 그대로 사용한다.
- `probe_run_ids`에는 그 InputPoint를 관측한 모든 `ResponsePair` id가 들어간다.
- `details`에 다음을 남긴다.

```text
aggregation              합성 정책 버전
aggregated_probe_run_ids 합성에 참여한 probe run
selected_probe_run_id    채택된 값을 만든 probe run
probe_run_values         run별 값 (미관찰이면 null)
unobserved_probe_runs    미관찰 run 수
```

### 근거와 주의

- `RankScore`는 취약 확률이 아니라 검증 우선순위다(ADR-003, 도메인 규칙 6).
  같은 InputPoint를 여러 request context로 관측했을 때 그중 하나에서라도
  신호가 보였다면 그 InputPoint의 검증 우선순위는 올라가야 한다.
- 미관찰 run은 관찰된 run을 가리지 못한다. 반대로 모든 run이 미관찰이면
  feature는 미관찰로 남는다(도메인 규칙 8).
- 서로 다른 run에서 온 값이 하나의 벡터에 모일 수 있으므로, 합성된 feature
  값은 단일 요청 한 쌍의 재현이 아니다. 어떤 run에서 왔는지는 항상
  `selected_probe_run_id`로 설명 가능해야 한다.
- 서로 다른 extractor version이 같은 feature 이름을 만들면 합성하지 않고
  실패한다.

---

## 8. Feature 추가 규칙

새 feature를 추가하기 전에 문서에 다음을 기록한다.

1. 이름
2. 목적
3. 정확한 계산식
4. 입력 데이터
5. 출력 범위
6. missing 조건
7. 오탐 가능성
8. 사용 scorer
9. extractor version
10. 테스트 fixture
11. prior weight (또는 prior를 두지 않는 이유) — §9
12. 어느 family의 `CalibrationFeatureSpace`에 들어가는가 — §9
13. 기존 feature와의 상관 (Naive Bayes 조건부 독립 가정에 영향) — §9

---

## 9. Calibrated scoring에서의 feature 취급 (ADR-022)

`scoring/calibration.py`는 §7의 가중합을 대체하지 않고 그 위에 얹힌다.
가중치는 logit 공간으로 rescale되어 Gaussian prior의 평균이 된다.

```text
prior weight_i = heuristic weight_i / prior_scale   (기본 prior_scale = 10.0)
logit_mean     = logit(base_rate) + RankScore / prior_scale
```

즉 학습 데이터가 없으면 `logit_mean` 순서는 §7의 RankScore 순서와 정확히
같다. feature 정의, 값 범위 `[0, 1]`, extractor version 규칙은 그대로다.

### Missing feature

미관측 feature는 logit 합에서 제외된다. §7의 "numeric score 합계에 0의 효과"와
동일한 동작이며, log-odds 공간에서는 "증거 없음 → posterior가 prior에 머무름"으로
정확히 읽힌다.

**알려진 한계:** 선형 모델에서 관측된 `0.0`과 미관측은 logit 기여가 모두 0이라
점수상 구분되지 않는다. `CalibrationEvidence.observed`와
`CalibratedProbability.observed_feature_count`에 상태는 보존되지만 점수는
구분하지 않는다. "관측하지 않았음을 안전함으로 해석하지 않는다"는 §7의
규칙은 evidence 수준에서 유지되며, 점수 수준에서 구분하려면 feature별
missingness indicator가 필요하다.

### 아직 추출되지 않는 feature

§7의 05C 주석은 그대로 유효하다. `numeric_value`, `reflection_count_norm`,
`safe_html_encoding_detected`, `dangerous_reflection_context`,
`redirect_changed`는 여전히 추출되지 않으며 값을 만들거나 0으로 가장하지
않는다. 보정 모델의 feature space는 실제로 추출되는 feature만 포함한다.

이들을 구현하면 feature 수가 4개에서 11개로 늘어난다. 학습기를 교체하는
것보다 이쪽이 ranking 성능 기여가 클 가능성이 높으므로, 결정 계층 튜닝보다
우선순위가 높다.
