# DemoShop 평가 환경과 live ranking evaluation

## Goal

1. 데모 타깃을 실제 웹사이트(온라인 쇼핑몰)처럼 만들고, 입력점을 100개로 늘려
   취약/안전이 섞인 라벨 붙은 평가 대상으로 만든다. 각 입력점이 왜 취약한지
   (혹은 왜 안전한지)를 데모 서버 안에서 시각적으로 확인할 수 있어야 한다.
2. 한 번의 실제 스캔 결과를 **VulnSpider가 낸 점수(확률/confidence)** 기준으로
   `Precision@K` / `Recall@K` / `MAP@K` / `NDCG@K`로 채점하고, 그 값을 화면과
   JSON으로 남기는 파이프라인 단계를 만든다. 비교군은 Random predictor,
   focused verification을 뺀 파이프라인, 최종 VulnSpider 세 가지다.

## Non-Goals

- 새로운 취약점 패밀리, 새로운 feature, 새로운 스코어러.
- 여러 애플리케이션 평균(§6-A rule 3의 query 여러 개). 한 번의 스캔은 query 1개다.
- ZAP 등 외부 스캐너 비교.
- 코퍼스 기반 offline 비교표(`tools/evaluate_ranking.py`) 대체. 그것은 그대로 둔다.

## Context Read

- `AGENTS.md`, `PLANS.md`
- `docs/EVALUATION_PROTOCOL.md` §5, §6, §6-A
- `docs/DECISION_LOG.md` ADR-025, ADR-031, ADR-032, ADR-033
- `src/vulnspider/evaluation/{metrics,baselines}.py`
- `src/vulnspider/{cli,cli_decision}.py`, `src/vulnspider/verification/focused.py`
- `tools/corpus_target_site.py`, `demo_target_server.py`

## Current State

- `demo_target_server.py`: 15개 라우트, 입력점 37개. 취약/안전 구분이 거의
  자명해서 어떤 랭킹이든 `Precision@K = 1.000`이 나온다. 정답(ground truth)을
  파일로 내보내는 수단이 없다.
- `evaluation/`는 저장된 코퍼스에 대한 offline 비교만 계산한다. 검증 증거는
  코퍼스에 없으므로 "focused verification이 순위를 개선하는가"에는 답할 수 없다.
- `--verify`는 `analysis.selection`(v0.1 휴리스틱 Top-K)을 검증하는데 리포트는
  보정 확률 Top-K를 싣는다. 두 집합이 어긋나면 리포트의 어떤 후보에도
  `final_confidence`가 붙지 않는다.

## Proposed Changes

1. `tools/demo_shop.py` — DemoShop. 32개 라우트, GET form 기반 입력점 100개
   (취약 40: XSS 19 / SQLi 13 / BAC 8, 안전 60). 라우트마다 상수 chrome으로
   응답 길이를 흩어 `response_length_diff_ratio`가 라벨 조회가 되지 않게 한다.
   `/_lab`는 입력점별 판정·이유·관측 신호·정상/공격 재현 링크를 보여준다
   (상점에서 링크하지 않는다 — 크롤되면 baseline이 오염된다).
2. `demo_target_server.py` — 실행기로 축소. `--ground-truth PATH`로 정답 JSON을
   내보낸다. 정답 파일은 `data/demo/demoshop-ground-truth.json`에 커밋한다.
3. `src/vulnspider/evaluation/live.py` — 한 스캔의 후보 pool을 ground truth와
   조인하고 3개 arm(random / prior / final)을 같은 후보·같은 라벨로 채점한다.
4. `cli_decision.rank_analysis` + `analyze_and_report(ranking=...)` — 랭킹 계산을
   분리해서 **검증 전에** Top-K를 정한다.
   `verification.focused.VerificationSelection`으로 그 집합을 검증에 넘긴다.
5. `cli` — `--ground-truth`, `--eval-output`, `--eval-cutoffs`, `--application-id`.

## Interfaces / Data Changes

- 신규: `VerificationSelection`(옵션 인자). 생략하면 기존 동작 그대로.
- 신규: `DecisionRanking`, `rank_analysis`, `analyze_and_report(ranking=...)`.
- 신규 리포트: `live-evaluation-v1` JSON (arms + 후보별 prior/final/label).
- 기존 리포트 스키마(`decision-report-v1`, `verification-report-v1`) 변경 없음.

## Safety / Scope Impact

- 요청 범위 변화 없음. 평가 단계는 순수 계산이며 네트워크를 쓰지 않는다.
- DemoShop은 127.0.0.1에만 바인딩하는 GET 전용 서버다.
- `--verify`의 대상 집합이 바뀐다(휴리스틱 Top-K → 보정 확률 Top-K). 요청 수는
  동일하고 대상만 리포트와 일치하게 된다. ADR-036에 기록한다.

## Test Plan

- unit `tests/unit/test_evaluation_live.py`: 조인(미라벨/BAC/미상 입력점),
  random arm = prevalence, 검증 재정렬이 full arm에만 반영, 직렬화, 실패 조건.
- unit `tests/unit/test_demo_shop.py`: 입력점 100개, 커밋된 정답 파일 일치,
  numeric seed만 BAC 라벨, 라우트별 상태코드, 길이 보존 sanitiser, 색인/lab.
- unit `tests/unit/test_verification.py`: 명시적 selection이 휴리스틱 Top-K를
  대체한다.
- 실제 DemoShop 대상 end-to-end 1회(수동): 지표가 arm별로 달라지는지 확인.

## Acceptance Criteria

- [x] DemoShop 입력점 100개, 라우트 32개, 크롤이 100개를 모두 발견
- [x] `/_lab`에서 입력점별 취약 이유와 재현 링크 확인 가능
- [x] `data/demo/demoshop-ground-truth.json` 커밋, 테스트로 drift 방지
- [x] `--ground-truth`로 스캔 후 지표 표 출력 + `live-evaluation-v1` JSON 저장
- [x] focused verification이 리포트 Top-K를 검증
- [x] 전체 테스트/정적 검사 통과

## Progress Log

- 2026-08-24: 구현 완료. DemoShop 대상 실측(top-k 20, 적합 검증 모델 사용):
  Precision@20 random 0.160 / no-verify 0.800 / full 0.850,
  MAP@20 0.049 / 0.714 / 0.763, Recall@20 0.100 / 0.500 / 0.531.
- 2026-08-24: `--verify` 대상 불일치를 발견해 함께 고침(ADR-036).
