# AI Engineering Guide for VulnSpider

## 0. 먼저 결론

처음부터 "여러 에이전트가 알아서 프로젝트를 완성"하게 만들지 않는다.

VulnSpider에는 다음 순서가 가장 안전하다.

```text
Stage 1: 좋은 단일 Codex 작업
Stage 2: Harness 강화
Stage 3: 명시적 Review/Fix Loop
Stage 4: 역할 분리 Agents
Stage 5: 반복 업무 Skill/MCP/Automation
Stage 6: 필요할 때만 상위 Loop Engineering
```

핵심은 **모델보다 환경과 피드백 구조를 먼저 만든다**는 것이다.

---

# 1. 용어를 정확히 이해하기

## 1.1 Agent

단순 채팅 모델이 아니라 대략 다음을 가진 실행 주체다.

```text
Model
+ Instructions
+ Tools
+ Workspace access
+ State/context
+ Action/observation loop
```

코딩 에이전트는 파일을 읽고, 수정하고, 명령을 실행하고, 결과를 관찰한 뒤 다시 행동할 수 있다.

---

## 1.2 Agent Loop

가장 기본적인 반복 구조.

```text
Goal
  -> Reason / choose action
  -> Tool call
  -> Observe result
  -> Update plan
  -> Repeat
  -> Stop
```

예:

```text
"InputPoint model을 구현하라"
  -> docs 읽기
  -> 기존 코드 검색
  -> 파일 수정
  -> pytest 실행
  -> 실패 관찰
  -> 수정
  -> pytest 재실행
  -> diff review
  -> 완료
```

---

## 1.3 Harness Engineering

에이전트를 둘러싼 **작업 환경과 통제 시스템**을 설계하는 일이다.

VulnSpider에서는 다음이 harness다.

```text
AGENTS.md
structured docs/
PLANS.md
CODE_REVIEW.md
test suite
lint/type checks
sandbox/permissions
scope guard
git branches/worktrees
logs
acceptance criteria
review prompts
stop conditions
```

좋은 harness는 에이전트가 똑똑해지게 만드는 게 아니라, **틀린 일을 하기 어렵고 올바른 완료 조건을 확인하기 쉽게** 만든다.

---

## 1.4 Loop Engineering

아직 비교적 새로운 용어다. 실용적으로는:

> 사람이 매번 다음 prompt를 쓰는 대신, "일을 찾고 -> 에이전트에 배분하고 -> 결과를 검사하고 -> 수정 작업을 만들고 -> 다시 실행하는 시스템" 자체를 설계하는 것

으로 이해하면 된다.

VulnSpider 예:

```text
Issue/Goal
  -> Planner Agent
  -> Implementer Agent
  -> Tests
  -> Reviewer Agent
  -> findings?
       yes -> Fix Agent -> Tests -> Reviewer
       no  -> Human gate / merge
  -> next issue
```

중요:

- 무한 반복 금지
- 최대 iteration 필요
- 성공 조건 필요
- 비용/시간 budget 필요
- 같은 모델의 자기채점만 믿지 않기

---

## 1.5 Multi-Agent

여러 역할을 분리하는 방식.

예:

```text
Planner
Implementer
Reviewer
Test Analyst
Security Boundary Reviewer
```

하지만 "에이전트가 많을수록 좋다"는 뜻이 아니다.

첫 프로토타입에서는 2~3개 역할이면 충분하다.

---

# 2. VulnSpider에 권장하는 단계별 도입

## Stage 1 — Single Agent, Strong Task Spec

처음 3~5개 작업은 Codex 하나로 한다.

프롬프트 구성:

```text
Goal
Context
Constraints
Done when
```

예:

```text
Goal: Legacy crawler records를 InputPoint로 변환한다.
Context: AGENTS.md, DOMAIN_MODEL.md, legacy audit
Constraints: legacy read-only, query/form만, no network in unit tests
Done when: tests pass, q/page가 separate InputPoints, duplicates removed
```

### 왜 먼저 단일 에이전트인가?

실패 원인이:

- 모델 문제인지
- 문서 문제인지
- 테스트 문제인지
- 역할 조정 문제인지

분리해서 볼 수 있기 때문이다.

---

## Stage 2 — Harness 강화

에이전트가 같은 실수를 반복하면 prompt를 길게 쓰지 않는다.

반복 오류를 다음 중 하나로 승격한다.

```text
규칙 -> AGENTS.md
설계 -> docs/
검증 -> test
경계 -> linter/check script
반복 작업 -> skill
```

예:

문제:

```text
Codex가 FeatureVector를 endpoint 단위로 구현
```

나쁜 해결:

```text
매 prompt마다 "제발 input point 단위로 해"
```

좋은 해결:

```text
AGENTS.md non-negotiable rule
+ DOMAIN_MODEL.md
+ unit test
```

---

## Stage 3 — Explicit Review/Fix Loop

첫 자동화 루프는 이것만 만들면 된다.

```text
Implement
  -> Run tests
  -> Self-review diff
  -> Independent review
  -> Fix findings
  -> Re-run tests
  -> Stop if approved
```

권장 stop conditions:

```text
max_iterations = 3
all_required_checks_pass = true
review_blockers = 0
review_majors = 0
```

### 중요한 원칙

구현한 에이전트가 자기 코드를 좋게 평가할 가능성이 있으므로, 리뷰는 별도 thread/context가 낫다.

---

## Stage 4 — 최소 Multi-Agent

VulnSpider 초기에는 다음 3역할만 권장.

### A. Planner / Architect

책임:

- docs와 current code 읽기
- 작업 분해
- 인터페이스 영향 확인
- acceptance criteria 작성

코드 작성은 기본 금지.

### B. Implementer

책임:

- plan대로 최소 변경
- 테스트 작성
- 검증 실행

### C. Reviewer

책임:

- `CODE_REVIEW.md` 기준 독립 리뷰
- correctness/safety/test gap 지적

코드 수정은 기본 금지.

---

# 3. 첫 번째 실전 Loop

## Loop 이름

```text
Feature Task Loop
```

## 입력

```text
작업 prompt
관련 docs
현재 branch
```

## 실행

```text
1. Planner creates plan
2. Human checks only high-level plan
3. Implementer changes code
4. Implementer runs tests
5. Reviewer reviews diff
6. If REQUEST_CHANGES:
      Implementer fixes only findings
7. Re-run tests
8. Reviewer rechecks
9. Stop after approval or 3 iterations
```

## 실패 시

다음 질문을 한다.

```text
모델이 못했나?
아니면 harness에 capability가 없나?
```

예:

- 테스트 fixture 부족 -> fixture 추가
- docs 모호 -> docs 수정
- scope 검사 반복 실패 -> 공통 ScopeGuard와 tests 추가
- 명령어 기억 못함 -> AGENTS.md에 exact command 추가

---

# 4. Codex 사용법 권장

## 4.1 어려운 작업은 Plan first

코드부터 쓰게 하지 않는다.

먼저:

```text
Read relevant docs and code. Do not modify files. Produce a plan...
```

그 뒤 구현.

---

## 4.2 AGENTS.md는 백과사전이 아니다

현재 starter의 `AGENTS.md`처럼:

- mission
- core rules
- docs map
- verification loop

만 둔다.

세부 내용은 `docs/`에 둔다.

---

## 4.3 권한은 보수적으로 시작

처음에는:

- default sandbox
- 좁은 write scope
- 민감 명령 승인

을 유지한다.

특히 이 프로젝트는 네트워크 요청을 다루므로 자동 승인 범위를 급격히 넓히지 않는다.

---

## 4.4 Review를 명시적으로 시킨다

구현 후:

```text
Review the current diff against CODE_REVIEW.md. Do not edit files.
```

또는 Codex의 review 기능을 사용한다.

---

# 5. Skills는 언제 쓰나?

반복 작업이 3번 이상 안정적으로 반복될 때.

VulnSpider 후보:

```text
legacy-audit skill
feature-addition skill
scorer-change skill
experiment-run skill
review skill
```

예: `feature-addition` skill이 할 일

```text
1. FEATURE_SCHEMA 읽기
2. feature definition 검증
3. extractor 구현
4. missing semantics 확인
5. fixture 추가
6. scorer 영향 확인
7. tests
8. docs sync
```

처음부터 skill을 만들 필요는 없다.

---

# 6. MCP는 언제 쓰나?

외부 context가 정말 필요할 때만.

가능한 미래 사용:

- GitHub issue/PR context
- 실험 결과 저장 시스템
- 외부 문서 시스템

v0.1에서는 필수가 아니다.

원칙:

```text
repo에 둘 수 있는 안정 지식 -> docs/
자주 변하는 외부 지식/도구 -> MCP 고려
```

---

# 7. Worktree 사용 권장 시점

멀티에이전트가 같은 working tree를 동시에 수정하면 충돌한다.

병렬화할 때만:

```text
worktree A -> domain model task
worktree B -> legacy audit only
worktree C -> review branch
```

첫 1~2주에는 병렬 구현을 피하는 편이 낫다.

---

# 8. 너에게 권장하는 첫 2주 AI 운용

## Week 1

```text
Day 1: Legacy audit
Day 2: Human review of audit + docs correction
Day 3: Domain model
Day 4: Independent review + fix loop
Day 5: Legacy adapter
```

AI 방식:

```text
single agent
+ plan first
+ tests
+ independent reviewer thread
```

## Week 2

```text
Probe planner
Response snapshot
Feature extraction
Scoring baseline
Top-K JSON
```

AI 방식:

```text
Planner -> Implementer -> Reviewer loop
```

아직:

```text
full autonomous loop X
5-agent swarm X
LLM mutation X
MCP zoo X
```

---

# 9. 절대 피해야 할 패턴

## 9.1 "전체 프로젝트 만들어줘"

너무 큰 task다.

## 9.2 같은 thread를 영원히 사용

context가 커지고 과거 가정이 남는다.

작업 단위로 thread를 나누되 repo docs가 기억을 담당하게 한다.

## 9.3 테스트 없이 agent loop

실패를 감지할 센서가 없다.

## 9.4 같은 agent의 자기 승인만 사용

독립 review가 낫다.

## 9.5 반복 실패를 prompt 탓만 함

두 번 반복되면 harness 문제로 본다.

## 9.6 agent 수부터 늘림

coordination overhead만 증가한다.

---

# 10. 성숙도 체크리스트

## Level 0 — Chat

- 사람이 매번 prompt
- 테스트/규칙 약함

## Level 1 — Agent-ready repo

- AGENTS.md
- docs system of record
- tests
- review checklist

## Level 2 — Harnessed workflow

- plan template
- deterministic checks
- scope guard
- acceptance criteria

## Level 3 — Review loop

- implement -> test -> review -> fix
- max iteration
- stop conditions

## Level 4 — Specialized agents

- planner
- implementer
- reviewer

## Level 5 — Loop engineering

- work discovery
- automatic delegation
- result checks
- state/memory
- budget
- escalation

VulnSpider v0.1 목표는 **Level 2~3**이다.

그 이상은 프로젝트 본체가 안정된 뒤 올린다.
