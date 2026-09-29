# CODE_REVIEW.md

## 1. Scope

- 요청한 범위만 바뀌었는가?
- v0.1 out-of-scope 기능이 몰래 들어오지 않았는가?
- unrelated refactor가 없는가?

## 2. Domain Integrity

- Page/Endpoint/InputPoint/Candidate를 혼동하지 않았는가?
- FeatureVector가 올바른 InputPoint에 귀속되는가?
- Candidate가 `InputPoint x VulnerabilityType`인가?
- RankScore를 vulnerability probability처럼 표현하지 않는가?

## 3. Probe Attribution

- target InputPoint 하나만 변경하는가?
- baseline의 다른 query/form 값이 유지되는가?
- changed_fields가 기계적으로 검증되는가?

## 4. HTTP Semantics

- 4xx/5xx를 관찰 데이터로 보존하는가?
- redirect 후 scope를 다시 검사하는가?
- timeout/retry가 무한 루프를 만들지 않는가?
- encoding을 무조건 UTF-8로 강제하지 않는가?

## 5. Safety

- 허용되지 않은 host 요청 가능성이 없는가?
- suffix 기반 scope bypass가 없는가?
- destructive behavior가 없는가?
- request budget, depth, delay가 우회되지 않는가?

## 6. Feature Correctness

- feature 정의가 `docs/FEATURE_SCHEMA.md`와 일치하는가?
- missing과 zero를 구분하는가?
- baseline에도 있던 error pattern을 probe 신규 신호로 잘못 세지 않는가?
- raw details를 디버깅 가능하게 보존하는가?

## 7. Scoring

- scorer가 vulnerability type별로 분리되어 있는가?
- 미관찰 feature를 안전 신호로 취급하지 않는가?
- contribution 합계가 score 계산과 일치하는가?
- score evidence가 충분한가?

## 8. Tests

- happy path가 있는가?
- edge case가 있는가?
- negative case가 있는가?
- 네트워크 없는 unit test가 가능한가?
- regression 가능성이 있는 부분에 테스트가 있는가?

## 9. Maintainability

- 새 dependency가 정말 필요한가?
- 함수/모듈 책임이 섞이지 않았는가?
- docs와 구현이 어긋나지 않는가?
- future agent가 코드를 읽고 판단할 수 있는가?

## 10. Final Review Output

리뷰 에이전트는 다음 형식으로 보고한다.

```text
BLOCKER
- ...

MAJOR
- ...

MINOR
- ...

TEST GAPS
- ...

VERDICT
APPROVE | REQUEST_CHANGES
```
