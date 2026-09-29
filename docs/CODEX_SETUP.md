# Codex Setup and Operating Guide — Windows 11

## 1. 권장 시작 방식

VulnSpider v0.1에서는 다음 우선순위를 권장한다.

### Option A — Codex App on Windows

추천 대상:

- 초보자
- diff를 눈으로 검토하고 싶은 경우
- 여러 thread를 분리하고 싶은 경우
- 나중에 worktree/automation을 쓰려는 경우

### Option B — Codex CLI native on Windows

추천 대상:

- 터미널 중심 개발
- 반복 명령과 Git workflow에 익숙한 경우

### Option C — WSL2

추천 대상:

- Linux-native toolchain이 꼭 필요한 경우

VulnSpider v0.1은 Python 중심이므로 **처음에는 native Windows App/CLI로 충분**하다. 불필요하게 환경 복잡도를 늘리지 않는다.

---

## 2. CLI 설치의 한 가지 방법

Node.js가 설치되어 있다면:

```powershell
npm install -g @openai/codex
```

실행:

```powershell
codex
```

로그인 안내를 따른다.

설치 방식과 명령은 바뀔 수 있으므로 문제가 있으면 최신 OpenAI Codex 공식 문서를 기준으로 한다.

---

## 3. 프로젝트 폴더 준비

예:

```powershell
mkdir C:\dev\vulnspider
cd C:\dev\vulnspider
git init
```

이 starter package의 파일을 repository root에 복사한다.

결과:

```text
vulnspider/
├─ AGENTS.md
├─ PLANS.md
├─ CODE_REVIEW.md
├─ README_START_HERE.md
├─ docs/
├─ prompts/
└─ reference/
```

기존 WHSPIDER를:

```text
reference/whspider_legacy/
```

에 둔다.

처음에는 legacy repo의 `.git` 중첩 여부를 확인한다. 단순 복사, subtree, submodule 중 하나를 팀 정책으로 결정하되 v0.1에서는 가장 이해하기 쉬운 방식을 사용한다.

---

## 4. 첫 실행

repository root에서 Codex를 연다.

CLI:

```powershell
codex
```

첫 메시지는 구현 요청이 아니라 repository 이해 확인으로 시작해도 좋다.

예:

```text
Read AGENTS.md and README_START_HERE.md. Do not modify files.
Summarize the v0.1 mission, non-goals, core domain units, and required verification loop.
List any contradictions you find between the repository docs.
```

이 결과가 틀리면 코드 작업을 시작하지 않는다. 문서부터 고친다.

---

## 5. 첫 실제 작업

새 thread에서:

```text
prompts/01_LEGACY_AUDIT.md
```

내용을 전달한다.

중요:

- audit task에서 코드 변경 금지
- 결과는 `docs/LEGACY_AUDIT.md`
- 네가 결과를 읽고 이상한 재사용 판단을 확인

---

## 6. Plan 사용

복잡한 task는 코드 전에 plan을 만든다.

권장:

- Codex Plan mode 사용
- 또는 `PLANS.md` 기반 execution plan 파일 생성

우리 프로젝트에서는 3개 이상 모듈이 바뀌거나 네트워크/feature/scoring semantics가 바뀌면 plan 파일을 권장한다.

---

## 7. Review 사용

구현 후 같은 thread의 self-review만 믿지 않는다.

권장:

1. implementer thread 종료
2. 새 reviewer thread 생성
3. `prompts/06_INDEPENDENT_REVIEW.md` 사용
4. findings를 implementer/fix thread에 전달
5. 재검증

CLI/App의 review 기능을 사용할 수 있지만, repository의 `CODE_REVIEW.md`를 함께 기준으로 삼는다.

---

## 8. 권한과 Sandbox

초보 단계:

- 기본 sandbox/approval 유지
- project directory 외 write를 쉽게 허용하지 않기
- 네트워크 관련 권한을 무조건 자동 승인하지 않기

이 프로젝트는 웹 요청을 다루므로 특히 중요하다.

native Windows sandbox 설정을 바꿀 필요가 생기면 최신 공식 문서를 확인하고, 강한 격리를 우선한다.

---

## 9. Thread 운영

권장 분리:

```text
Thread A: legacy audit
Thread B: domain model implementation
Thread C: independent review
Thread D: legacy adapter
```

한 thread에 프로젝트 전체 역사를 계속 누적하지 않는다.

기억은 conversation이 아니라:

```text
AGENTS.md
docs/
execution plans
tests
Git history
```

가 담당한다.

---

## 10. Multi-Agent는 언제 켜나?

다음 조건이 된 뒤:

- domain model 안정
- test commands 안정
- review checklist 안정
- acceptance criteria 기계화

그 뒤 codebase exploration이나 독립 review처럼 병렬성이 높은 작업에 subagent를 고려한다.

첫 주에는 필요 없다.

---

## 11. Skill은 언제 만드나?

같은 workflow를 3번 이상 반복하고 절차가 안정됐을 때.

첫 후보:

```text
vulnspider-feature-addition
vulnspider-independent-review
vulnspider-experiment-run
```

처음부터 만들지 않는다.

---

## 12. 너의 첫 실제 순서

```text
1. starter files copy
2. legacy crawler copy/reference
3. git initial commit
4. Codex docs comprehension check
5. Prompt 01 legacy audit
6. human review
7. Prompt 02 scaffold
8. Prompt 03 domain model
9. independent review
10. fix loop
```
