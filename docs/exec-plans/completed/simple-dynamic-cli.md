# Simple Dynamic CLI

## Goal

사용자가 `vulnspider -u URL` 한 줄로 기존 Static + Dynamic + merge + Light
Probe 분석을 실행하고, 성공한 JSON 결과를 기본 파일명으로 안전하게 받게 한다.

## Non-Goals

- Discovery 계약, ProbePlanner, RequestExecutor 또는 분석 파이프라인 재설계
- 새로운 crawler policy framework
- 기존 `analyze` 명령의 opt-in Dynamic 의미 변경
- push, PR, merge

## Context Read

- `AGENTS.md`
- `README_START_HERE.md`
- `docs/ARCHITECTURE.md`
- `docs/GIT_WORKFLOW.md`
- `PLANS.md`
- `CODE_REVIEW.md`
- `docs/exec-plans/active/v0_2_native_dynamic_discovery_mvp.md`
- `src/vulnspider/cli.py`
- `src/vulnspider/pipeline.py`
- `src/vulnspider/discovery/dynamic_browser.py`
- `src/vulnspider/discovery/dynamic_crawler.py`
- `src/vulnspider/reporting/json_report.py`

## Current State

`vulnspider analyze --url URL`은 Static-only이고, `--dynamic`과 caller-owned
exact navigation/resource grant를 추가해야 combined pipeline을 실행한다. JSON
출력 경로와 Top-K는 필수이며 JSON writer는 목적지에 직접 쓴다.

## Proposed Changes

1. 최상위 `-u/--url`, `-o/--output`, `--static-only` adapter와 간단 사용법
   help를 추가한다. 간단 Dynamic은 기존 `analyze_url()`에 `top_k=10`과 기존
   보수적 crawler budget 기본값을 전달한다.
2. 간단 모드 권한에만 렌더링된 anchor에서 실제 추출된 exact same-origin GET
   navigation과 same-origin script/style 수동 리소스를 허용한다. 기존 exact
   navigation/resource grant는 합집합으로 유지한다.
3. JSON을 같은 디렉터리의 임시 파일에 완전히 쓴 뒤 `os.replace()`로 교체해
   실패 시 기존 성공 파일이나 무파일 상태를 보존한다.
4. focused unit/real-Chromium integration 테스트, help/호환성 테스트, 문서를
   갱신한다.

## Interfaces / Data Changes

`DynamicRequestAuthority`에 기본 `False`인 간단 모드용 두 boolean capability를
추가한다. 기본 생성과 기존 CLI 생성은 계속 exact-only이다. browser session의
navigation 호출은 crawler가 이미 렌더링된 anchor에서 추출한 URL일 때만 그
exact URL을 한 navigation 동안 임시 승인할 수 있다.

## Safety / Scope Impact

간단 모드는 root와 exact same origin(동일 scheme/host/effective port)만 허용한다.
자동 navigation은 기존 rendered DOM extractor가 산출한 GET anchor 후보에만
한정하며 기존 page/depth/time/navigation/request budget을 통과한다. 자동 수동
리소스는 GET script/style만 허용한다. fetch/XHR, WebSocket, EventSource, POST,
form submit, popup, child-frame document, cross-origin 및 다른 port는 기존 guard에서
차단한다. 고급 `analyze --dynamic`의 exact-only 기본 정책은 바뀌지 않는다.

## Test Plan

- unit: 간단 Dynamic 호출/default output/`-o`/Static-only/help/기존 analyze
  URL 및 input 호환성/atomic replacement/권한 결정
- integration: 실제 Chromium에서 same-origin external script가 만든 anchor를
  따라가며 cross-origin, POST/form, fetch/XHR, WebSocket, EventSource, popup,
  iframe transport와 민감 sentinel이 0인지 검증
- regression: final Gate, 전체 unittest, Native Static E2E, v0.1 smoke,
  format/lint/type/diff
- review: 독립 Gate Review 정확히 1회; Critical/High만 최대 한 번 수정

## Acceptance Criteria

- [x] `vulnspider -u URL`이 combined Dynamic pipeline을 호출한다.
- [x] 기본 `vulnspider-result.json`과 `-o`가 atomic하게 동작한다.
- [x] `--static-only`가 기존 Native Static-only 경로를 호출한다.
- [x] 기존 `analyze --url`과 `analyze --input`이 호환된다.
- [x] 렌더링된 same-origin GET anchor만 자동 navigation된다.
- [x] cross-origin/다른 port, POST/form, fetch/XHR, WebSocket, EventSource,
  popup, iframe traversal은 기본 차단된다.
- [x] raw DOM과 민감 sentinel이 stdout/stderr/JSON에 없다.
- [x] CLI help에 간단 사용법이 표시된다.
- [x] 지정 검증과 독립 Gate Review가 통과한다.
- [x] focused commit 메시지가 `feat(cli): add simple dynamic scan command`이다.

## Progress Log

- 2026-08-04: 기준 `fa29b55`, 브랜치 `feat/native-dynamic-discovery`, clean
  worktree와 기존 CLI/Dynamic guard/Final Gate를 확인했다.
- 2026-08-04: 간단 CLI adapter, extraction-only rendered authority, exact
  per-navigation browser grant, same-origin script/style policy, atomic JSON
  replacement, CLI/help/unit/real-Chromium tests와 ADR-019를 구현했다.
- 2026-08-04: focused CLI 41/41, Final Gate 8/8 (`FINAL=PASS`, skipped/failed/
  missing 0), 전체 unittest 427/427, Native Static E2E 1/1, v0.1 smoke 7/7,
  format/lint/type/diff check가 통과했다.
- 2026-08-04: 독립 Gate Review를 정확히 1회 수행했고 Critical/High/Minor/
  Test Gap 0건으로 `PASS`를 받았다. 수정 루프는 사용하지 않았다.

## Decision Log

- Decision: 간단 모드 기본 Top-K는 기존 문서 예시와 일치하는 10으로 둔다.
- Reason: 사용자용 명령에서 필수 인자를 제거하면서 selection semantics는
  그대로 재사용한다.
- Decision: 자동 navigation은 authority의 origin-wide 영구 grant가 아니라
  crawler가 렌더링된 anchor에서 꺼낸 exact URL의 단일 navigation grant로 둔다.
- Reason: page script의 location 변경이 authority를 획득하지 못하게 한다.
- Decision: 자동 수동 리소스는 기존 분류 중 script/style만 허용한다.
- Reason: 렌더링에 필요한 최소 GET 리소스를 허용하면서 fetch/XHR는 기본 차단한다.

## Open Questions

- 없음.
