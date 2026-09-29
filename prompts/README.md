# Codex Prompt Sequence

권장 순서:

```text
00_REPO_COMPREHENSION.md
  -> docs 이해 검증, 코드 수정 없음

01_LEGACY_AUDIT.md
  -> 기존 WHSPIDER 전체 audit, 코드 수정 없음

02_REPOSITORY_SCAFFOLD.md
  -> 최소 Python scaffold

03_DOMAIN_MODEL.md
  -> Endpoint/InputPoint/Candidate typed model

04_LEGACY_ADAPTER.md
  -> legacy records -> normalized InputPoints

05_PROBE_FEATURE_SCORING.md
  -> Probe -> Feature -> Score -> Top-K JSON vertical slice

06_INDEPENDENT_REVIEW.md
  -> 새 thread에서 독립 리뷰

07_FIX_REVIEW_LOOP.md
  -> findings 수정 및 재검증
```

처음에는 한 번에 하나씩 실행한다.

각 prompt가 끝날 때:

1. git diff 확인
2. 실제 실행한 test/check 확인
3. 사람이 acceptance criteria를 확인
4. commit
5. 다음 prompt

프로젝트 전체를 한 prompt로 합치지 않는다.
