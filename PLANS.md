# PLANS.md — Execution Plan Standard

복잡한 작업은 코드보다 먼저 실행 계획을 만든다.

## 언제 plan 파일을 만드는가?

다음 중 하나라도 해당하면 `docs/exec-plans/active/<task>.md`를 만든다.

- 3개 이상 모듈 변경
- 새 도메인 모델 추가
- 네트워크 동작 변경
- DB/schema 변경
- scoring/feature definition 변경
- 30분 이상 걸릴 가능성이 높은 작업
- 요구사항이 애매하거나 trade-off가 큰 작업

작은 작업은 Codex Plan mode나 짧은 task plan으로 충분하다.

---

## Required Plan Template

```markdown
# <Task Title>

## Goal
무엇을 달성하는가?

## Non-Goals
이번 작업에서 하지 않는 것은?

## Context Read
- AGENTS.md
- docs/...
- relevant code paths

## Current State
현재 코드와 동작은?

## Proposed Changes
1. ...
2. ...

## Interfaces / Data Changes
어떤 API, model, schema가 바뀌는가?

## Safety / Scope Impact
요청 범위, 네트워크, 권한에 영향이 있는가?

## Test Plan
- unit
- integration
- negative cases

## Acceptance Criteria
- [ ] ...

## Progress Log
- YYYY-MM-DD: ...

## Decision Log
- Decision: ...
- Reason: ...

## Open Questions
- ...
```

---

## Agent Rules

- Plan을 만든 뒤 구현 중 발견한 사실로 계속 업데이트한다.
- 이미 끝난 일을 미래형으로 남기지 않는다.
- 중요한 설계 결정은 `docs/DECISION_LOG.md`에도 반영한다.
- 완료하면 `active/`에서 `completed/`로 이동한다.
- plan은 보고서가 아니라 실행 상태 문서다.
