# analyze와 decide를 하나의 파이프라인으로 통합

**Status:** Planned — 아직 착수하지 않음. 진행 여부는 팀 결정.

## Goal

`analyze`(휴리스틱)와 `decide`(결정 계층) 두 실행 경로를 **하나로** 합친다.
결정 계층이 기본 경로가 되고, 휴리스틱 순위는 제품 경로에서 빠져
`EVALUATION_PROTOCOL.md` §5의 **Baseline D(평가 비교군)로만** 남는다.

## 왜 지금인가

`feat/scoring`은 결정 계층을 **의도적으로 별도 명령으로** 붙였다(ADR-022).
frozen v0.1 의미를 건드리지 않으려는 판단이었고 그 시점에는 옳았다.

지금은 틀린 구조다. 다음 작업이 LLM 페이로드 변형과 그 결과에 따른
`VerificationConfidence` 갱신인데, 경로가 둘이면 **기능마다 "휴리스틱 쪽에도
붙일 것인가"를 매번 결정해야 하고 파이프라인 두 벌을 유지해야 한다.** 유지될
수 없는 구조이며, 붙이기 전에 합치는 편이 싸다.

## Non-Goals

- 결정 계층 알고리즘 변경. Layer 1/2/3은 그대로 쓴다.
- VoI 활성화. ADR-026의 판단은 유효하다.
- Feature 확장. `xss-context-features.md`와 독립이며 순서 제약도 없다.
- 크롤러 인증, 실제 앱 코퍼스.

## 착수 전에 반드시 읽을 것

- ADR-022 (왜 나눴는가), ADR-023, ADR-024, ADR-027 (Top-K 주 파라미터)
- `docs/DECISION_LAYER_OVERVIEW.md` — 결정 계층 전체 설명
- `AGENTS.md` "Frozen v0.1 Scope" — 무엇이 frozen인지
- `docs/TEAM_INTERFACES_V0_2.md` §2 — `RankedCandidateContext` 소비자

## 현재 상태

```text
vulnspider analyze --url ... --top-k K --output R [--html-output H]
  -> analyze_url() -> select_top_k() -> SelectionOutcome
  -> json_report / html_report          (휴리스틱 selection_priority 순서)

vulnspider decide --url ... --top-k K [--budget B] [--model M] [--conformal C]
  -> analyze_url() -> select_top_k(전체) -> handoff
  -> 보정 확률 -> 제약 하 선택 -> DecisionOutcome
  -> decision_report / decision_html_report
```

두 명령이 **같은 `analyze_url()`을 호출**하고 그 뒤가 갈라진다. 즉 discovery와
probe 실행은 이미 공유하고 있고, 갈라지는 것은 순위·선택·리포팅뿐이다.

## ⚠️ 병합이 실제로 바꾸는 것

"`--model`을 안 주면 휴리스틱 prior라 동작이 같다"는 **사실이 아니다.** 착수
전에 이 차이를 정확히 알고 있어야 한다.

| | `analyze` (현재) | 결정 계층 |
|---|---|---|
| 순위 기준 | `selection_priority` = raw/max | 보정 확률 (분산 damping 포함) |
| 선택 | 상위 K개 단순 절단 | submodular + **중복성 할인** |

`logit_mean`은 `RankScore`의 아핀 변환이라 **순위는 같지만**, 두 가지가 다르다.

1. `probability`는 분산 damping 때문에 `logit_mean`의 단조 함수가 아니다.
2. **중복성 할인이 선택을 바꾼다.** 같은 endpoint의 두 번째 후보가 밀려난다.

따라서 병합은 frozen v0.1 동작을 **실제로 바꾼다.** ADR에 이 사실을 숨기지 말고
명시해야 하며, "무해한 리팩터링"으로 서술하면 안 된다.

`discount=1.0`으로 두면 중복성 할인은 사라지지만 damping은 남는다. 완전한
동작 보존은 불가능하다.

## 영향 범위

`select_top_k` / `SelectionOutcome` 소비자:

```text
pipeline.py                      analyze_* 세 진입점
reporting/json_report.py         v0.1 JSON 리포트
reporting/html_report.py         v0.1 HTML 리포트
reporting/analysis_report.py     simple 모드 리포트
selection/combined.py            BAC 병합
selection/handoff.py             MutationHandoff (다른 오너의 소비자)
cli_decision.py                  결정 계층 진입
```

**다른 오너에게 영향이 간다.** `RankedCandidateContext`를 받는 mutation 모듈
(석현)이 있고, `docs/TEAM_INTERFACES_V0_2.md`가 계약 변경 시 영향 오너 리뷰를
요구한다. 착수 전에 알려야 한다.

## 제안 설계

```text
vulnspider analyze --url ... --top-k K [--budget B] [--model M] [--conformal C]
                   --output R [--html-output H]
```

1. **결정 계층이 기본 경로.** `analyze`가 보정 확률로 순위를 매기고 제약 하에
   선택한다.
2. `--model` 없으면 휴리스틱 prior로 동작한다. 근거는 유지되지만 선택은
   달라진다(위 표).
3. **휴리스틱 `select_top_k`는 제품 경로에서 뺀다.** 삭제하지 않고
   `evaluation/baselines.py`의 Baseline D로만 남긴다 — 이미 그렇게 구현돼 있다.
4. HTML 리포트는 결정 대시보드로 통일한다. `html_report.py`의 후보 렌더링은
   이미 공유 중이므로 중복이 생기지 않는다.
5. `decide`는 한동안 `analyze`의 alias로 두고 deprecation 안내를 출력한다.
   바로 지우면 팀원 스크립트가 깨진다.
6. `--input` 레거시 경로와 `-u` 단순 모드도 같은 결정 계층을 타게 한다.

### 고려한 대안

- **`analyze --calibrated` 플래그** — 경로가 여전히 둘이라 목적을 달성하지
  못한다. LLM 모듈이 어느 쪽에 붙는지 문제가 그대로 남는다. reject.
- **`decide`를 주 명령으로 승격하고 `analyze` 폐기** — 명령 이름이 바뀌어
  팀원 스크립트와 문서가 전부 깨진다. `analyze`가 이미 알려진 이름이므로
  그쪽을 살리는 편이 싸다. reject.
- **현행 유지** — LLM 모듈을 두 경로에 붙여야 한다. reject.

## Safety / Scope

- 네트워크 동작은 바뀌지 않는다. discovery와 probe 실행은 이미 공유한다.
- 요청 수는 늘지 않는다. 오히려 예산 제약으로 줄어들 수 있다.
- frozen 명령 표면 변경이므로 **ADR + 2인 리뷰** 대상이다(`AGENTS.md`).

## Test Plan

- `analyze`의 기존 플래그가 전부 그대로 파싱되는지
- `--input` 레거시 경로가 결정 계층을 타는지
- `-u` 단순 모드가 동작하는지
- `decide` alias가 같은 결과를 내고 deprecation을 출력하는지
- 기존 리포트 테스트를 결정 계층 출력 기준으로 갱신
- **회귀:** 휴리스틱 순위가 Baseline D로 여전히 계산 가능한지
  (`evaluate_ranking.py`가 계속 동작해야 한다)
- 코퍼스 재생성 후 수치가 변하지 않는지 (`corpus collect`는 순위를 쓰지 않으므로
  변하지 않아야 한다 — 변하면 어딘가 잘못된 것)

## Acceptance Criteria

- [ ] `analyze` 하나로 URL부터 최종 리포트까지 결정 계층으로 수행
- [ ] 휴리스틱은 Baseline D로만 남고 제품 경로에서 빠짐
- [ ] `decide`는 alias + deprecation 안내
- [ ] `--input`, `-u` 포함 모든 진입점이 같은 경로
- [ ] ADR 기록 (frozen 동작 변경을 명시)
- [ ] 영향 오너 리뷰 (mutation 모듈)
- [ ] `evaluate_ranking.py` 비교표가 계속 동작
- [ ] 전체 테스트 통과, 의존성 0개 유지

## 착수 시 첫 명령

```bash
git switch feat/unify-pipeline
PYTHONPATH=src python -B -m unittest discover -s tests/unit -t .
PYTHONPATH=src python tools/evaluate_ranking.py
```

두 번째와 세 번째가 **병합 전 기준선**이다. 병합 후 첫 번째는 통과해야 하고,
세 번째의 Baseline D 행은 값이 변하지 않아야 한다.

## Open Questions

- `decide` alias를 언제 제거할 것인가. 한 마일스톤 뒤를 제안한다.
- `discount` 기본값을 유지할 것인가. 제품 경로가 되면 중복성 할인이 모든
  사용자에게 적용되므로, 실제 앱에서 재검토가 필요하다.
- 휴리스틱 JSON 리포트(`json_report.py`)를 남길 것인가. 재현성 비교에 필요할
  수 있으므로 당장 지우지 않기를 제안한다.
