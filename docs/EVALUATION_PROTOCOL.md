# Evaluation Protocol

## 1. 목적

VulnSpider의 핵심 주장은 "모든 입력점을 깊게 검사하지 않고도 검증 가치가 높은 후보를 상위에 배치한다"는 것이다.

따라서 평가도 단순 탐지 개수보다 ranking과 request budget 효율을 중심으로 설계한다.

---

## 2. v0.1 평가 단계

v0.1에서는 본격적인 최종 논문 평가보다 **평가 가능성 확보**가 목표다.

필수:

- feature cache 가능
- candidate-level ground truth key 정의
- deterministic scorer version 기록
- request count 기록
- timing 기록

---

## 3. Ground Truth Key

권장 최소 단위:

```text
(application_id,
 method,
 canonical_path,
 parameter_location,
 parameter_name,
 vulnerability_type)
```

예:

```text
(dvwa, GET, /vulnerabilities/sqli/, query, id, SQLI)
```

정상 입력점도 포함해야 false positive를 평가할 수 있다.

---

## 4. 데이터 누수 방지

금지:

- 같은 route family의 거의 동일한 InputPoint를 무작위 row split로 train/validation에 분산
- test app을 보면서 weight 조정
- ground truth에 맞춰 feature definition을 사후 수정하고 같은 test 결과를 최종 성능으로 재사용

권장:

### 데이터 충분

- GroupKFold
- group = application 또는 challenge/route family

### 데이터 적음

- Development apps: weight 설계/튜닝
- Completely unseen app: final holdout

자체 제작 앱을 test-only로 유지하는 방식을 우선 고려한다.

---

## 5. 비교군

### Baseline A — All-input verification

모든 후보를 동일하게 검증한다고 가정.

### Baseline B — Random 예측기

무작위 예측기. "그냥 적게/아무렇게나 뽑아도 되는가?"에 답한다. 두 변형을 쓴다.

**B-1. Uniform random ordering** (`ARM_RANDOM`, 항상 켜짐). 모든 후보에 같은
점수를 줘 전체가 하나의 동점군이 되게 한다. `metrics`가 §6-A 규칙 4로 그 순위의
기댓값을 **닫힌 형식으로** 계산하므로 시드도 시뮬레이션도 없다. `Precision@K`는
정확히 유병률(vulnerable/candidates)로 수렴한다.

**B-2. Per-input-point 랜덤 유형 추측** (`--random-predictor`,
`evaluation/random_predictor.py`). 더 직관적인 랜덤 분류기다. 각 **입력점**마다
`{SQLI, REFLECTED_XSS, BROKEN_ACCESS_CONTROL, SAFE}` 중 하나를 가중치로 추첨하고,
그 유형의 `InputPoint × family` 후보만 양성(점수 1.0)으로, 나머지·SAFE·해당 family가
없는 경우는 음성(0.0)으로 둔다. 대부분의 입력점이 안전하므로 `--random-safe-weight W`
로 SAFE에 더 큰 가중치를 줄 수 있다(W=1 균등, W>1 기권 성향). 이 2단 점수도 **동일한**
`evaluate_ranking`으로 채점되어 VulnSpider와 같은 지표로 비교된다. 추측이 무작위라
한 draw는 잡음이므로, 지표는 `trials`회(기본 1000) 시드 고정 몬테카를로의 평균이다.
각 draw의 지표 자체는 §6-A 규칙 4의 정확한 동점 기댓값이라, 유형 추측만 시뮬레이션되고
동점 내 순서는 시뮬레이션되지 않는다(결과는 시드에 대해 결정적).

### Baseline C — Static heuristic only

예:

- numeric parameter 우선
- reflection 유무만 사용

### Baseline D — Heuristic weighted sum (현행 v0.1/v0.2)

`scoring/engine.py`의 손으로 정한 가중합 + `selection_priority` 고정 Top-K.
ADR-022 이후 이것은 **제안 기법의 특수 케이스**다: 학습 데이터가 0개일 때
보정 모델의 `logit_mean`이 이 순서를 정확히 재현한다. 따라서 이 비교는
"휴리스틱 대 ML"이 아니라 "코퍼스가 휴리스틱을 얼마나 개선하는가"를 측정한다.

### Proposed — Calibrated scoring + budgeted sequential selection

ADR-022/023/024의 3계층:

1. 보정 확률(베이지안 로지스틱 회귀, 휴리스틱을 prior로)
2. Top-K 제약 submodular 선택, 선택적 요청 예산 (ADR-027)
3. Conformal recall 보장으로 집합 크기 결정

### Ablation arms

계층별 기여를 분리하려면 각각을 끈 상태를 측정한다.

- Layer 1만: 보정 확률 + 고정 Top-K
- Layer 1+2: Top-K 제약 선택 (VoI는 휴면, ADR-026)
- `discount = 1.0`: 중복성 모델링을 끈 modular 효용
- Naive Bayes LLR 대 로지스틱 회귀: 조건부 독립 가정 위반의 비용

### Secondary External Reference

ZAP 등은 보조 참고 비교로 두고, 주된 인과 비교는 내부 baseline과 수행한다.

---

## 6. 핵심 지표

### `Recall@K` / Top-N Hit Rate

실제 positive 후보 중 상위 K에 포함된 비율.

### `Precision@K`

상위 K 중 실제 positive 비율.

### `MAP@K`

여러 query/group에서 positive가 상위에 배치되는 정도.

### `NDCG@K`

순위 품질 보조 지표.

### `Request Reduction`

```text
1 - selected_verification_requests / all_verification_requests
```

### `Candidate Reduction`

```text
1 - TopK / all_candidates
```

### `Vulnerabilities Found vs Request Budget`

강력 추천 그래프:

```text
x = verification request budget
y = cumulative true vulnerabilities found
```

---

## 6-A. Ranking 지표의 판정 규칙

§6의 지표는 정의만으로는 계산이 확정되지 않는다. 아래 5개를 먼저 고정한다.
숫자를 뽑은 뒤에 바꾸면 모든 결과를 다시 뽑아야 한다.

### 1. 세는 단위

주 지표는 **candidate-level**이다. 단위는 ADR-002의 `InputPoint x
VulnerabilityType`이며 ground truth key와 정확히 1:1로 대응한다.

쿼리 값 다양성은 문제가 되지 않는다. `/product?id=1`과 `/product?id=2`는
`canonical_path`가 같고 `InputPoint`가 `(QUERY, id)`로 동일하므로 도메인 모델이
이미 하나로 합친다.

실제 위험은 **경로 세그먼트 템플릿**이다. `canonical_path()`는 숫자 세그먼트를
정규화하지 않으므로 `/product/1`과 `/product/2`는 서로 다른 Endpoint가 된다.
여기에 쿼리 파라미터가 붙으면 **버그 1개가 candidate N개로 계산**되어 recall이
부풀거나 무너진다.

따라서 **bug-level 집계를 병기**한다. 경로의 숫자/16진/UUID 세그먼트를
placeholder로 치환한 키로 candidate를 묶고, 그 그룹의 candidate 중 **하나라도**
상위 K에 있으면 해당 버그를 찾은 것으로 센다.

현재 합성 코퍼스는 라우트마다 경로가 서로 달라 두 단위가 같은 값을 낸다.
차이는 실제 앱에서 드러난다.

### 2. 미라벨 candidate

발견됐지만 ground truth에 없는 candidate는 **비관련(non-relevant)으로 센다.**
IR의 표준 처리이며, 랭킹에서 제외하는 방식은 미라벨을 늘릴수록 precision이
좋아지는 조작 여지를 만든다. 모든 결과에 미라벨 개수를 함께 보고한다.

### 3. query 단위

`MAP`과 `NDCG`는 query별로 계산한 뒤 평균한다. 여기서 **query 1개 = application
1개**다. §4의 leakage 단위와 같다.

전체 candidate를 하나의 랭킹으로 pool하면 candidate가 많은 애플리케이션이
평균을 지배하므로 금지한다. positive가 없는 application은 `MAP`/`NDCG` 평균에서
제외하고 제외 개수를 보고한다.

### 4. 동점

동점은 실재한다. 현재 코퍼스의 `app01`은 candidate 10개에 서로 다른 확률이
8개뿐이다. 동점 그룹이 K 경계에 걸치면 tie-break 순서만으로 `Recall@K`가 바뀐다.

`selection`의 tie-break은 `candidate_id`이며 이는 재현 가능하지만 임의다. 평가는
이 임의성에 의존하지 않는다. **동점 그룹 내에서 균등 무작위 순서를 가정한
기대값으로 계산한다.**

크기 `g`, 관련 문서 `R`개인 동점 그룹에서 `r`개만 상위 K에 들어가면 기대 적중은
`r x R / g`다. `NDCG`는 선형성으로 각 위치 할인의 기대값을 취하고, `AP`는
McSherry-Najork(2008)의 기대 average precision을 사용한다.

Baseline B(무작위 Top-K)는 전체가 하나의 동점 그룹인 특수 케이스이므로 이
기계장치가 시뮬레이션 없이 정확한 기대값을 준다.

### 5. Top-K와 예산은 분리한다

`Recall@K`는 **순위 품질**을, `Recall@Budget`은 **실제로 검증되는 것**을 잰다.
candidate마다 검증 비용이 다르므로(SQLI 6, XSS 3) 두 집합은 같지 않다. 별도
표로 보고하고 한 표에 섞지 않는다.

---

## 6-B. 실행 중 측정 (live ranking evaluation, ADR-036)

§6의 지표를 **저장된 코퍼스**가 아니라 **한 번의 실제 스캔**에 대해 계산하는 경로다.
코퍼스에는 검증 증거가 없어서 "focused verification이 순위를 개선하는가"에 답할 수
없기 때문에 따로 둔다. 구현은 `src/vulnspider/evaluation/live.py`,
실행은 `analyze --ground-truth`다.

### 비교군

같은 후보 pool·같은 라벨을 쓰고 **정렬 기준만** 다르다.

| arm | 정렬 기준 | 무엇을 답하는가 |
| --- | --- | --- |
| `Random predictor` | 전부 동점 | "그냥 아무거나 K개 뽑으면?" (§5 Baseline B) |
| `VulnSpider without focused verification` | 보정 확률(prior) | 검증 단계를 뺀 파이프라인 |
| `VulnSpider (full pipeline)` | `final_confidence` | 출하되는 제품 |

Random arm은 전체가 하나의 동점 그룹이므로 §6-A rule 4의 기계장치가 시뮬레이션
없이 기대값을 준다. `Precision@K`는 K와 무관하게 prevalence다.

### 읽는 법 (중요)

- verification은 Top-K만 방문한다. 따라서 `K == top_k`에서 두 VulnSpider arm은
  **같은 집합**을 갖고 `Recall@K`/`Precision@K`가 대체로 같다. 차이는 순서에
  민감한 `MAP@K`와 `K < top_k`에서 나타난다. 강등된 후보가 컷 밖으로 밀리면
  미검증 후보가 올라와 집합이 바뀌므로 `Recall@K`도 조금 움직일 수 있다.
- 한 번의 스캔 = 애플리케이션 1개 = **query 1개**(§6-A rule 3)다. 따라서 `MAP@K`는
  그 query의 average precision이고, 여러 앱 평균이 필요하면 스캔을 여러 번 돌려
  각 리포트를 합쳐야 한다.
- 내장 기본 verification 모델은 `SUPPORT_REPRODUCED`의 LLR이 0이므로(ADR-033)
  두 arm이 정확히 같아진다. `corpus verify-fit`으로 적합한 모델을
  `--verification-model`로 넘겨야 검증 단계의 기여가 보인다.
- 미라벨 후보는 비관련으로 세고(§6-A rule 2) 개수를 리포트에 함께 남긴다.

### 대상: DemoShop

`tools/demo_shop.py`가 서비스하는 라벨 붙은 온라인 쇼핑몰이다. 라우트 32개,
GET form 기반 QUERY 입력점 **100개**(취약 40 = Reflected XSS 19 / SQLi 13 /
BAC 8, 안전 60). 정답은 `data/demo/demoshop-ground-truth.json`에 커밋되어 있고,
`tests/unit/test_demo_shop.py`가 사이트와의 drift를 막는다.

안전 입력점은 일부러 어렵다. `safe_validated`(400 응답 →
`status_code_changed`), `safe_dynamic`(길이만 변함), `safe_stripped`(위험문자를
치환해 `safe_html_encoding_detected`를 **미관측**으로 만든다),
`safe_type_error`(바인딩 파라미터인데 캐스팅 오류로 진짜 DB 오류를 노출 →
`sql_error_pattern` 발화, 재검증에서도 재현되어 verification도 못 걸러낸다).
취약 입력점 중 `sqli_blind`·`xss_conditional`은 현재 feature set이 구조적으로
놓치도록 남겨 뒀다. `/_lab`이 입력점별 판정·이유·재현 링크를 보여준다.

### 실행

```bash
python demo_target_server.py            # http://127.0.0.1:8899 (별도 창)

PYTHONPATH=src python -m vulnspider analyze \
  --url http://127.0.0.1:8899/ --max-pages 60 --max-requests 250 \
  --top-k 20 --output analysis.json \
  --verify --verify-output verify.json \
  --verification-model data/corpus/verification-model.json \
  --ground-truth data/demo/demoshop-ground-truth.json \
  --eval-output evaluation.json
```

### 측정값 (2026-08-24, top-k 20, 후보 200개 중 취약 32개, 미라벨 0)

| 지표@20 | Random | verification 없음 | 최종 |
| --- | --- | --- | --- |
| `Recall@20` | 0.100 | 0.500 | 0.531 |
| `Precision@20` | 0.160 | 0.800 | 0.850 |
| `MAP@20` | 0.049 | 0.714 | 0.763 |
| `NDCG@20` | 0.160 | 0.842 | 0.877 |

`K <= 5`에서는 세 지표 모두 1.000이다. 오류 기반 SQLi 8개가 상위를 독점하고 그
8개가 전부 진짜이기 때문이며, 타깃이 쉬워서가 아니라 그 구간이 실제로 정확하다는
뜻이다. `K = 10` 이후 `safe_type_error` 3개가 섞여 들어오면서 값이 내려간다.

### Broken Access Control — 인증 영역 (ADR-037)

BAC는 **세션**이 있어야 의미 있게 평가된다(두 access feature는 참조 요청이
인증된 2xx여야 한다). DemoShop의 인증 영역 `/portal/`은 IDOR 취약 2개
(`order?ref`, `message?thread` — 소유권 확인 없음)와 정상 접근제어 1개
(`card?card_id` — 치환 시 403)로 구성되고, 공개 상점과 분리되어 세션 쿠키로 별도
스캔한다. 크롤러는 4xx를 스킵하므로 보호 자원은 유효 세션으로만 발견된다.

```bash
# 로그인 → 세션 쿠키 확보(운영자 제공). VulnSpider는 로그인하지 않는다.
#   http://127.0.0.1:8899/login?as=admin  → demoshop_session=<token>
PYTHONPATH=src python -m vulnspider analyze \
  --url http://127.0.0.1:8899/portal/ --access-control \
  --cookie demoshop_session=<token> \
  --max-pages 20 --max-requests 100 --top-k 10 \
  --output portal-analysis.json \
  --ground-truth data/demo/demoshop-ground-truth.json \
  --application-id demoshop --eval-output portal-eval.json
```

측정값 (top-10, 후보 9개 중 취약 2개, 미라벨 0):

| 후보 (최종 confidence 순) | 최종 | 라벨 |
| --- | --- | --- |
| `/portal/message?thread` (IDOR) | 0.953 | 취약 |
| `/portal/order?ref` (IDOR) | 0.953 | 취약 |
| `/portal/card?card_id` (접근제어) | 0.524 | 안전 |

`Recall@2` 1.000 / `MAP@K` 1.000 (random 0.22~0.29). IDOR 2개가 상위, 정상
접근제어는 그 아래로 올바르게 분리된다. endpoint-level인 CREDENTIAL_STRIP 후보는
파라미터 단위 정답에 조인할 수 없어 평가에서 제외된다(랭킹·대시보드에는 표시).

---

## 7. Ablation

### 7.1 완료 — 생성 모델 대 판별 모델 (Naive Bayes LLR vs 로지스틱 회귀)

같은 코퍼스, 같은 feature, 같은 결측 처리, 같은 leave-one-application-out
out-of-fold 분할에서 가중치 추정 방식만 바꿔 측정했다.

- **NB-LLR**: 가중치 = `log(P(f=1|취약) / P(f=1|안전))`. 클래스별 주변분포에서
  각각 독립적으로 추정하며 조건부 독립을 가정한다.
- **로지스틱**: 가중치를 사전분포 하에 결합 적합한다(ADR-022).

```text
                 Brier    ECE      Rec@1   Rec@3   MAP@5   NDCG@5
NB-LLR           0.1837   0.1954   0.280   0.625   0.663   0.765
로지스틱          0.1134   0.1146   0.405   0.869   0.871   0.911
always-base-rate 0.1858     —        —       —       —       —
```

**결과 해석.** NB-LLR의 Brier(0.1837)는 상수 예측기(0.1858)와 사실상 같다.
확률로는 쓸 수 없다. 그런데 ranking은 무작위(Rec@3 = 0.303)보다 두 배 이상
낫다. **순위는 어느 정도 매기지만 확률이 망가지는** 전형적인 NB 실패 양상이다.

이는 ADR-022를 독립적으로 뒷받침한다. 예산 배분은 서로 다른 family의 기대
효용을 실제로 더해야 하므로 **보정된 확률이 필요하고, 순위만 맞는 점수로는
불충분하다.** 순위 지표만 봤다면 NB-LLR도 "쓸 만하다"고 결론냈을 것이다.

**해석상 주의.** 이 격차를 "조건부 독립 가정의 비용"이라고만 말하면 부정확하다.

- 이 코퍼스의 feature 상관은 약하다: `corr(status_code_changed,
  response_length_diff_ratio) = 0.193`. 독립 가정 위반이 격차 전부를 설명하지
  못한다.
- 실제 차이는 **생성적 추정(주변분포에서 개별 추정, 축소 없음) 대 판별적
  적합(사전분포 하 결합 적합)** 전체다.
- 여기 쓰인 NB는 **presence-only Bernoulli NB**다. `log(p₁/p₀)`만 쓰고 부재 항
  `log((1-p₁)/(1-p₀))`은 쓰지 않는다. 이는 단순화가 아니라 제약이다. 완전한
  Bernoulli NB는 "feature 부재"를 증거로 취급해야 하는데, 그러면 미관측과
  관측된 0을 구분하라는 도메인 규칙 8과 충돌한다. presence-only가 이
  프로젝트에서 원칙적으로 가능한 유일한 변형이다.

CLI 플래그는 두지 않는다. 이 결과는 1회성 측정이며 재현 절차는 위 정의로
충분하다.

### 7.2 후속 실험

- XSS에서 encoding feature 제거
- SQLi에서 SQL error pattern 제거
- differential features 전체 제거
- static features 전체 제거
- 중복성 할인 제거 (`discount = 1.0`, ADR-023)

질문:

> 어떤 feature family가 실제 ranking 향상에 기여하는가?

---

## 8. Reproducibility

모든 실험 결과에 기록:

```text
commit hash
feature_schema_version
scorer_version
target app version
seed
request limits
probe policy
weight config
```

---

## 8-A. 결정 계층 전용 지표

ADR-022/023/024가 추가한 계층은 ranking 지표만으로 평가할 수 없다.

### Calibration quality (Layer 1)

순위가 맞아도 확률이 틀리면 예산 배분이 틀린다. 따라서 순위 지표와 별도로
측정한다.

```text
Brier score       = mean((p_i - y_i)^2)
Expected Calibration Error (ECE)
Reliability diagram (10 bins)
```

`selection_priority`는 확률이 아니므로 이 지표로 평가할 수 없다. 이것이
ADR-022을 정당화하는 실험적 근거다.

### Budget efficiency (Layer 2)

```text
x = verification request budget B
y = cumulative true vulnerabilities found
```

같은 그래프에서 Baseline A/B/C/D와 제안 기법을 비교한다. 추가로:

```text
Requests-to-first-finding
Requests-to-80%-recall
Achieved utility / brute-force optimum   (소규모 인스턴스 한정)
```

마지막 항목은 근사 보장이 실제로 얼마나 느슨한지를 보여준다. 이론 하한은
`½(1 − 1/e) ≈ 0.316`이지만 실측은 이보다 훨씬 높을 것으로 예상되며,
`tests/unit/test_decision_greedy.py`가 이미 brute force와 비교한다.

### Guarantee validity (Layer 3)

```text
Nominal risk        = α
Realised risk       = mean(1 - Recall) on held-out applications
Coverage violation  = Realised - Nominal
Selected set size vs fixed Top-K at equal recall
```

**Realised가 Nominal을 넘는 것 자체가 결과다.** conformal의 exchangeability
가정이 웹 애플리케이션 간에 성립하지 않는다는 증거이며, 숨기지 말고
보고한다. 마지막 항목이 효율 주장의 핵심이다: 같은 recall을 더 적은 후보로
달성하는가?

### Attainability

`α ≥ 1/(n+1)`이 아니면 보장은 계산되지 않는다. recall 90% 보장에는 보정
application이 최소 9개 필요하다. 확보한 애플리케이션 수를 먼저 보고하고,
미달이면 보장 대신 관측된 recall만 보고한다.

---

## 9. v0.1에서 하지 않는 평가

- LLM 모델 간 비교
- BAC 완전 자동화 성능
- 인터넷 실서비스 일반화 주장
- "상용 스캐너보다 우수"라는 광범위 주장

v0.1은 ranking pipeline이 평가 가능한 구조인지 확인하는 단계다.

---

## 8-B. 현재 코퍼스와 측정된 결과 (ADR-025)

### 코퍼스

`tools/build_corpus.py`가 loopback 라벨 애플리케이션에 실제 파이프라인을
실행해 수집한다. 재현:

```text
PYTHONPATH=src python tools/build_corpus.py --applications 14
```

산출물은 `data/corpus/`에 있다. 현재 규모:

```text
14 applications, 146 samples (36 vulnerable, 110 safe)
SQLI          73 samples (22 vulnerable)
REFLECTED_XSS 73 samples (14 vulnerable)
```

feature 값은 전부 실제 HTTP 응답에서 추출된 것이며 합성하지 않는다. 라벨은
애플리케이션 동작을 `tools/corpus_target_site.py`에서 직접 작성했기 때문에
알려져 있다.

### 학습된 가중치

```text
SQLI          intercept=-3.857
              status_code_changed        =-0.451   (heuristic: +20)
              response_length_diff_ratio =+4.428   (heuristic: +20)
              sql_error_pattern          =+3.770   (heuristic: +35)

REFLECTED_XSS intercept=-4.198
              marker_reflected           =+3.184   (heuristic: +35)
              response_length_diff_ratio =+0.948   (heuristic: +10)
```

`status_code_changed`의 부호가 뒤집힌 것이 가장 중요한 결과다. 휴리스틱은
+20을 주지만, 데이터에서는 약한 **음의** 신호다. 코퍼스의 `safe_validation`
라우트가 비숫자 입력에 400을 반환하기 때문이다 — 즉 상태 코드 변화는 취약점
신호가 아니라 **입력 검증이 동작한다는 신호**이기도 하다. 손으로 정한 가중치가
실제로 틀릴 수 있음을 보여주는 구체적 사례다.

### 보정 품질 (out-of-fold, leave-one-application-out)

```text
fitted (out-of-fold)   Brier=0.1134  ECE=0.1146
heuristic baseline     Brier=0.2150  ECE=0.2862
always-base-rate       Brier=0.1858
```

두 가지를 확인한다. 학습 모델은 Brier를 약 47% 개선한다. 그리고 **현행
휴리스틱은 base rate를 항상 예측하는 상수 예측기보다 나쁘다**(0.2150 >
0.1858). 즉 현행 점수는 순위로는 쓸 수 있어도 확률로는 쓸 수 없으며, 이것이
ADR-022의 실험적 근거다.

### Conformal 보장

```text
threshold=0.4188, target recall 0.90
empirical risk 0.0000 <= corrected bound 0.0357 (14 applications)
```

### Held-out 성능 (학습에 쓰이지 않은 12개 애플리케이션)

재현:

```text
PYTHONPATH=src python tools/evaluate_heldout.py --top-k 5
PYTHONPATH=src python tools/evaluate_heldout.py --top-k 5 --budget 20
```

코퍼스(app 0-13)와 겹치지 않는 app 100-111에서 측정한다. **K 제약과 예산
제약을 반드시 분리해 보고한다(§6-A 규칙 5).** 두 표가 서로 다른 것을 재며
방법의 순위가 뒤집힐 수 있다.

**Top-K 5 (기본 모드 — 확률 상위 K, ADR-028)**

```text
                        recall      검증  요청
휴리스틱 prior          27/33 =0.82    60   267
학습 모델               32/33 =0.97    60   285
학습 모델 + conformal    32/33 =0.97    43   204
```

**Top-K 10**

```text
                        recall      검증  요청
휴리스틱 prior          33/33 =1.00   118   537
학습 모델               33/33 =1.00   118   537
학습 모델 + conformal    33/33 =1.00    44   207
```

### 읽는 법

- **K=5에서 학습 모델이 0.82 → 0.97.** 과제 목표("가장 취약도가 높은 K개를
  탐지")에 대한 직접적인 개선이다.
- **K=10은 포화 구간이다.** 앱당 후보가 8~14개뿐이라 셋 다 1.00에 도달한다.
  다만 conformal은 **같은 recall을 검증 118건 대신 44건**으로 달성한다.
  K가 넉넉할 때 불필요한 검증을 걷어내는 것이 Layer 3의 역할이다.

### ⚠️ ADR-028 이전 측정에 대한 주의

ADR-028 이전에는 기본 목적함수가 `P × severity`에 중복성 할인
(`discount = 0.5`)을 적용한 것이었고, 그 설정에서 K=5 학습 모델은 **0.79로
휴리스틱(1.00)보다 나빴다.** 원인은 모델이 아니라 목적함수였다 — 중복성
할인이 같은 라우트의 취약점을 의도적으로 빼기 때문이다.

같은 모델을 확률 순으로 정렬하면 0.97이다. **목적함수를 목표에 맞추는 것이
모델을 바꾸는 것보다 큰 차이를 냈다.**

주의: 이 수치는 §8-B "알려진 한계"의 합성 애플리케이션에서 나온 것이며 실제
웹 애플리케이션 성능이 아니다.

### 알려진 한계 (이 코퍼스 한정)

- **애플리케이션이 합성이다.** DVWA, WebGoat, Juice Shop 같은 실제 취약 앱이
  아니다. 라우트 구조가 단순하고 응답 형태가 규칙적이므로 위 수치를 실제
  웹 애플리케이션 성능으로 일반화하면 안 된다. 실제 앱으로의 확장은 다음
  작업이며, 파이프라인(`corpus collect`)은 이미 임의의 승인된 타겟에 대해
  동작한다.
- **XSS는 원리적으로 분리 불가능하다.** `xss_raw`와 `xss_escaped`가 모두
  `marker_reflected=1`을 만든다. 현재 4개 feature로는 구분할 수 없고, 학습된
  `P(XSS | reflected) ≈ 0.3`은 그 사실의 정직한 반영이다. 이 한계를 없애려면
  `safe_html_encoding_detected`와 `dangerous_reflection_context`가 필요하다.
- **응답 길이 가중치가 크다.** 합성 앱에서 취약 라우트의 길이 변화가 실제보다
  일관되기 때문일 가능성이 높다. 실제 앱에서 재측정해야 한다.

---

## 8-C. Ranking 지표 측정 결과

재현:

```text
PYTHONPATH=src python tools/evaluate_ranking.py -o data/corpus/ranking-report.json
```

14 applications, 146 candidates, 36 relevant, 0 unlabeled. 유병률 0.2466.
Proposed는 leave-one-application-out **out-of-fold** 확률로 순위를 매긴다.

```text
Recall@K          K=1     K=3     K=5     K=10
  B random        0.101   0.303   0.505   0.903
  C reflection    0.122   0.359   0.586   0.928
  D heuristic     0.253   0.631   0.917   1.000
  Proposed        0.405   0.869   0.946   1.000

Precision@K       K=1     K=3     K=5     K=10
  B random        0.247   0.247   0.247   0.247
  C reflection    0.294   0.288   0.285   0.255
  D heuristic     0.607   0.512   0.457   0.279
  Proposed        0.929   0.714   0.471   0.279

MAP@K             K=1     K=3     K=5     K=10
  B random        0.247   0.212   0.274   0.384
  C reflection    0.294   0.254   0.330   0.434
  D heuristic     0.607   0.521   0.649   0.692
  Proposed        0.929   0.845   0.871   0.894

NDCG@K            K=1     K=3     K=5     K=10
  B random        0.247   0.287   0.387   0.559
  C reflection    0.294   0.340   0.452   0.603
  D heuristic     0.607   0.621   0.761   0.804
  Proposed        0.929   0.884   0.911   0.939
```

Baseline A(전수 검증)는 정의상 recall 1.00이며 비용은 candidate 146개에 657
요청이다. 다른 행은 "A의 결과 중 얼마를 A의 비용 중 얼마로 얻는가"로 읽는다.

### 읽는 법

- **Proposed가 모든 지표, 모든 K에서 우위다.** MAP@10 기준 0.692 → 0.894
  (+29%), NDCG@10 기준 0.804 → 0.939.
- **차이는 작은 K에서 가장 크다.** Precision@1은 0.607 → 0.929이지만
  Precision@5는 0.457 → 0.471로 거의 같다. 예산이 빠듯할수록 보정 확률의
  이득이 크고, 예산이 넉넉하면 순서가 덜 중요해진다는 뜻이다. 검증 예산이
  제약이라는 이 과제의 전제와 정확히 맞물린다.
- **K=10은 포화 구간이다.** 애플리케이션당 candidate가 8-14개뿐이라 K=10이면
  대부분을 포함한다. D와 Proposed의 Recall@10이 둘 다 1.000인 것은 알고리즘이
  같아서가 아니라 K가 너무 커서다. 이 코퍼스에서는 **K=1, 3이 정보량이 있는
  구간**이다.
- **Baseline C가 B보다 아주 조금 낫다.** reflection 유무만으로는 거의 아무것도
  못 한다는 뜻이며, §8-B의 `xss_escaped` 구분 불가 문제와 같은 원인이다.

### 구현 검증

`Baseline B`는 전체가 하나의 동점 그룹이므로 §6-A 규칙 4의 기대값 계산이
정확한 무작위 기대값을 준다. 따라서 **Precision@K가 모든 K에서 유병률과 정확히
같아야 하고**, 실제로 0.247 = 36/146이 나온다. 이는 동점 처리와 Baseline B를
동시에 검증하는 항등식이다.

동점 처리 자체는 `tests/unit/test_evaluation_metrics.py`가 **모든 순열을 전수
열거한 기대값**과 소수점 9자리까지 일치함을 확인한다(Recall, NDCG,
McSherry-Najork expected AP 각각).

### bug-level

현재 코퍼스는 라우트마다 경로가 달라 bug-level 집계가 candidate-level과 완전히
동일한 표를 낸다(146개 → 146개). 두 단위의 차이는 경로 세그먼트가 템플릿화된
실제 앱에서만 드러난다.

---

## 10. 결정 계층의 명시적 한계

논문에서 먼저 밝히고 시작한다. 심사에서 지적당하는 것보다 낫다.

### Exchangeability

Conformal 보장은 보정 그룹과 대상이 교환 가능하다고 가정한다. DVWA와 자체
제작 Spring 앱은 교환 가능하지 않다. 대응은 leave-one-app-out 보정과 실측
위반율 보고이며, 보장은 "이 애플리케이션 분포에 대해"로 한정해 서술한다.

### 관측된 0과 미관측

선형 모델에서 관측된 `0.0`과 미관측 feature는 logit 기여가 모두 0이라 점수
상 구분되지 않는다. `CalibrationEvidence.observed`와
`observed_feature_count`로 노출은 하지만 점수는 구분하지 않는다. 구분하려면
feature별 missingness indicator가 필요하고 이는 현재 코퍼스 규모를 넘는다.

### Cost와 severity는 정책이다

`DEFAULT_FAMILY_COSTS`와 `DEFAULT_FAMILY_SEVERITY`는 측정값이 아니다.
실측 요청 수로 대체하기 전까지 예산 효율 수치는 이 정책에 조건부다.

### Redundancy key의 해상도

**해소됨 (ADR-025).** `cli_decision.build_decision_candidates()`가 analysis의
`InputPoint`에서 endpoint fingerprint를 조회해 `redundancy_key`로 넘긴다.
`decision_candidate_from_context()`를 endpoint 신원 없이 직접 호출하면 여전히
input point 참조로 후퇴하므로, 그 경로를 쓰는 소비자는 명시적으로 넘겨야 한다.

### 조건부 독립

Naive Bayes 계열은 `status_code_changed`와 `response_length_diff_ratio`의
상관을 무시한다. 로지스틱 회귀는 이 가정을 두지 않으므로, 두 모델의 성능
차이가 그 위반의 비용을 측정한다. VoI가 사용하는 우도는 Naive Bayes 쪽에서
오므로 이 한계는 Layer 2에도 전이된다.
