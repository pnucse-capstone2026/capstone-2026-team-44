# feat/confidence-update — 검증 기반 신뢰도 갱신 · BAC 파이프라인 · 리포트 개선

## 한 줄 요약

랭킹된 Top-K 후보에 **focused verification**(변형 페이로드 재전송 → 특징 재수집 → 규칙 기반 신뢰도 갱신)을 붙여 v0.2 파이프라인의 마지막 단계를 완성하고, **Broken Access Control(BAC)** 관측·랭킹·검증을 통합했으며, 최종 산출물을 **단일 웹 대시보드** 하나로 정리했습니다.

---

## 무엇을, 왜

기존 파이프라인은 크롤링 → 입력점 추출 → 특징 수집 → 보정 확률로 Top-K 랭킹까지였습니다. 이 브랜치는 그 뒤에 **"정말 취약한가"를 한 번 더 확인하는 단계**를 더합니다.

- 상위 후보에 대해 같은 유형의 **변형 페이로드**(특수문자 섞기, 인덱스 범위 밖 등)를 만들고,
- **필수 결정적 검증기(validator)** 를 통과한 것만 loopback 대상에 **재전송**하여,
- 새로 수집한 **Feature Vector를 baseline과 비교**하고,
- 그 차이를 **검토된 규칙 + 코퍼스 보정 계수**로 해석해 **최종 신뢰도**를 갱신합니다.

핵심 설계 원칙: **선택(Top-K)은 검증 이전의 보정 확률(prior)로**, **표시 순서·최종 점수는 검증 이후 신뢰도로**. 둘은 분리된 개념이며(도메인 규칙 6/7), prior는 `RankScore`가 아니라 calibrated probability입니다.

---

## 주요 변경

### 1. Focused verification 파이프라인 (`src/vulnspider/verification/`, ADR-032)

5단계 루프:

| 단계 | 모듈 | 하는 일 |
|---|---|---|
| ① propose | `proposal.py` | provider-neutral `PayloadProposer` + 기본 `DeterministicMutationProposer`(SQL_META/HTML_SENTINEL/BOUNDARY) |
| ② validate | `validator.py` | **필수** 결정적 게이트. 승인 전에는 절대 실행하지 않음(고정 거부 분류) |
| ③ re-probe | `planner.py` | 검증된 값 하나만 baseline `RequestInstance`에 주입해 재전송(v0.1 executor/extractor 재사용) |
| ④ delta | `delta.py` | 새 Feature Vector와 baseline의 차이 계산 |
| ⑤ confidence | `confidence.py` | 규칙 + 보정 LLR로 신뢰도 갱신 |

오케스트레이션은 `focused.py`(`verify_analysis`).

### 2. 코퍼스 보정 (ADR-033)

손으로 고른 상수를 **코퍼스 학습 (family, VerificationSignal)별 로그우도비(LLR)** 로 대체했습니다.

```
logit(posterior) = logit(prior) + LLR(family, signal)      (|LLR| ≤ 1.0 캡)
```

- 신호 분류가 세분화됨: `SUPPORT_NEW / SUPPORT_REPRODUCED / WEAKEN / INCONCLUSIVE / UNCHANGED / NOT_EXECUTED`
- `NOT_EXECUTED`·`INCONCLUSIVE`는 근거 없음이므로 0으로 고정, family 내 미관측 신호는 기본 LLR로 폴백(스무딩 아티팩트 방지)
- 학습 모델 커밋: `data/corpus/verification-model.json` (+ `verification-corpus.jsonl` 146 샘플 / 14 loopback 앱)
- **out-of-fold Brier 0.136 → 0.102**

### 3. 단일 대시보드 (ADR-034)

- `-u` 실행이 기본으로 `vulnspider-report.html`을 생성(`--no-html`로 생략).
- 헤드라인 점수 = **검증 이후 신뢰도**. decision JSON도 후보별 `final_confidence` / `verification_outcome` / `prior_probability` + `verification` 요약을 담아 HTML과 일치.
- **INCONCLUSIVE 게이트 강화**: 전송 실패 또는 페이로드로 유발된 5xx(baseline이 5xx가 아닐 때)만 해당. 길이만 다르거나 non-5xx 차이는 `UNCHANGED`.

### 4. BAC(Broken Access Control) 파이프라인 (ADR-035)

- **관측**(`access/planner.py`·`executor.py`): `CREDENTIAL_STRIP`(쿠키·Authorization 제거)와 `IDENTIFIER_SUBSTITUTION`(숫자 id 치환) — 둘 다 **GET 전용·비파괴** 재요청.
- **랭킹**: `build_decision_candidates`가 BAC 후보를 calibrated probability로 SQLi/XSS와 함께 통합 랭킹(BAC 모델 optional).
- **대시보드**: BAC 후보를 endpoint·check_kind·reference/comparison 응답으로 렌더.
- **검증**(`verification/access_verify.py`): `IDENTIFIER_SUBSTITUTION` 후보를 다른 id(+2/+5/−1)로 재확인 → 재현 유지(`SUPPORT_REPRODUCED`) / 미재현 약화(`WEAKEN`).
- **opt-in**: access 프로브는 추가 네트워크 요청을 발생시키므로 **`--access-control` 플래그(기본 off)** 로만 활성화. 플래그가 없으면 기존 요청 예산 그대로.

### 5. 리포트 UX 개선

- **유형별 선택 건수**를 건수 내림차순 정렬(많은 유형이 위).
- **방어 지침(Countermeasures)을 케이스별로 세분화**(`reporting/guidance.py`): SQLi 에러형/추론형, XSS 문맥별 인코딩, BAC IDOR/인증우회 — 요지 + 핵심 대응 + 추가 방어 + 확인 포인트. 기존에 지침이 없던 BAC도 추가.
- **"선택된 후보 확률 비교" 차트**: 전체 폭 + 다열 배치 + 상위 8개만 표시하고 나머지는 `더보기`(`<details>`)로 접어, k가 커도 세로 스크롤이 과하지 않도록.

### 6. 데모/기타

- `-u` 모드에 `-k`/`--top-k` 노출(최대 20으로 캡).
- 데모 앱 다양화 + **BAC 오탐 정밀화**: SQLi 파라미터 seed를 비숫자로 바꿔 공개 조회 페이지가 IDOR 후보로 잡히던 오탐 제거(BAC 후보 13 → 2, 진짜 IDOR만).

---

## 사용법

```bash
# 1) 로컬 데모 타겟 실행 (별도 터미널)
python demo_target_server.py            # http://127.0.0.1:8899

# 2) k=20 정적 스캔 + 검증 + BAC + 대시보드
PYTHONPATH=src python -m vulnspider -u http://127.0.0.1:8899/ \
  --static-only -k 20 \
  --access-control \
  --verify --verification-model data/corpus/verification-model.json \
  --html-output vulnspider-report.html \
  --crawl-output vulnspider-crawl.json \
  --verify-output vulnspider-verification.json \
  -o vulnspider-analysis.json
```

- `-k/--top-k`: 관측할 상위 후보 수(최대 20). `--access-control`: BAC 관측(opt-in).
- `--verify` + `--verification-model`: focused verification 실행 및 보정 모델 적용.
- 산출물: 대시보드 HTML(주 리포트), analysis/crawl/verification JSON.

---

## 테스트

- **유닛 720 · 통합 59 통과**, format/lint/type 전부 통과.
- E2E 매트릭스 15개 시나리오(정적/동적, verify, access, k 경계 1/20/21/0/−1, HTML on/off, native/conformal/model, 에러 케이스) — 파이프라인 미처리 예외 **0건**, 모든 경계·에러 케이스 graceful.

---

## 안전성 (리뷰 포인트)

- **validator 승인 전 페이로드 실행 금지** — 거부된 값은 실행 provenance가 생기지 않음(테스트로 증명).
- **read-only · loopback/localhost 한정 · 한 번에 한 가지만**(ADR-004). BAC 프로브는 **GET 전용·비파괴**.
- prior는 calibrated probability이며 **LLM이 최종 판단하지 않음**(규칙/보정 계수가 결정).
- **실제 LLM proposer는 본체 파이프라인과 아직 코드 통합되지 않았습니다** — `src/vulnspider/verification/`에서는 결정적 기본기가 `no-model` provider로 동작합니다. 석현의 실제 proposer는 **로컬 파인튜닝 모델**(`payload_verifier_v2/`, 3B GGUF `vulnspider-3b_v3`, `llama_cpp` 로컬 추론 — 클라우드 API 아님)로, `main`을 제외한 브랜치들(`integration/v0.2`·`feat/local_ai_verifier`·이 브랜치)에 **독립 실행 도구로 존재**하며 `vulnspider-*.json`을 입력으로 받습니다(현재 `src`는 이 모듈을 참조하지 않음). 이를 provider-neutral `PayloadProposer` 뒤로 끼워 넣는 코드 통합이 후속 과제입니다.
- **네트워크/페이로드 실행이 바뀌는 변경 → 2인 리뷰 대상**.

---

## 알려진 한계 / 후속

- 실제 LLM proposer(석현의 `payload_verifier_v2/` 로컬 파인튜닝 모델)는 독립 도구로 repo에 존재하나(`main` 제외 브랜치들) **본체 파이프라인과 코드 통합은 미완**(`src`의 참조 0건) — 현재 `src`에서는 결정적 기본기가 그 자리를 대체.
- 코퍼스가 6개 신호 중 3개만 실측(`SUPPORT_NEW`/`INCONCLUSIVE`/`NOT_EXECUTED` 미관측 → 기본값).
- BAC 관측은 opt-in(요청 예산 이유). `IDENTIFIER_SUBSTITUTION`은 순차 id 과탐 여지(데모는 seed 정밀화로 완화), `CREDENTIAL_STRIP` 전용 검증은 미구현.
- 요청 예산/rate-limit/baseline 재사용 미적용(사용자 보류).
- 실제 DVWA는 인증 크롤이 필요해 현재 도구 범위 밖(합성 loopback fixtures 기준).

관련 ADR: **ADR-032/033/034/035**, `docs/DECISION_LOG.md`.
