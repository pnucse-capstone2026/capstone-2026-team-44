# Feature 확장 — 반사 인코딩 탐지 (팀 공유용)

> 브랜치: **`feat/xss-context-features`** (base: `feat/scoring`)
> `feat/scoring`이 남긴 **가장 큰 오차원(XSS 오탐)** 을 feature 하나로 없앤 작업이다.
> ML 배경이 없어도 읽을 수 있게 개념부터 설명한다.

---

## 0. 30초 요약

`feat/scoring`의 측정에서 제일 큰 문제는 **XSS 오탐**이었다. 우리 marker가 반사되는
XSS 후보 34개 중 진짜 취약은 14개뿐인데, **어떤 순위 알고리즘으로도 나머지 20개를
걸러낼 수 없었다.** 알고리즘 탓이 아니라 **feature 탓**이었다. 이 브랜치가 그 feature
한계를 고친다.

| | 이전 (`feat/scoring`) | 이후 (이 브랜치) |
|---|---|---|
| probe marker | 영숫자만 (`VULNSPIDER_...`) | 영숫자 + **위험 문자 sentinel** (`...Z<>"'Z`) |
| 이스케이프 구분 | 불가능 (안전/취약이 똑같이 `marker_reflected=1`) | **`safe_html_encoding_detected`** 로 구분 |
| out-of-fold Brier | 0.133 | **0.081** (오라클 0.063) |
| in-corpus Recall@3 | 0.744 | **0.899** (오라클 0.964) |
| held-out recall@5 (미학습 12앱) | 0.91 | **1.00** |

---

## 1. 이 브랜치가 푸는 문제

`feat/scoring`에서 확률 모델을 잘 만들었는데도 XSS에서 recall이 낮았다. 이유를
데이터로 파보니 이랬다.

우리는 취약점을 찾을 때 **marker(표식)** 라는 특별한 값을 파라미터에 넣어 보낸다.
예전 marker는 `VULNSPIDER_` + 16진수처럼 **영숫자뿐**이었다. 응답에 이 marker가 그대로
나오면(`marker_reflected = 1`) "입력이 화면에 반사된다" → XSS 의심, 이라고 봤다.

문제는 **반사된다고 다 취약한 게 아니라는 것**이다.

```text
xss_raw      화면 출력: ...VULNSPIDER_ABC123<script>...      ← 위험 (원본 그대로)
xss_escaped  화면 출력: ...VULNSPIDER_ABC123&lt;script&gt;.. ← 안전 (이스케이프됨)
```

안전한 앱은 `<`를 `&lt;`로 바꿔서(HTML 이스케이프) 공격을 막는다. 그런데 **우리 marker는
영숫자라서 이스케이프할 게 없다.** `VULNSPIDER_ABC123`은 안전한 앱에서도 취약한 앱에서도
**똑같이 그대로** 나온다. 그래서 `marker_reflected`가 둘 다 `1`이 되고, 모델은 이 34개를
전부 같은 확률(≈0.41)로 볼 수밖에 없었다. **20개는 어떤 알고리즘도 못 거르는 구조적
오탐**이었다.

---

## 2. 아이디어 — 위험 문자를 "안전하게" 흘려보내 인코딩을 관측한다

인코딩되는지 보려면 **인코딩될 수 있는 문자를 먼저 보내야 한다.** 그래서 marker에 위험
문자 네 개(`<`, `>`, `"`, `'`)로 된 **sentinel(감지용 꼬리표)** 을 붙였다.

```text
이전:  VULNSPIDER_<16진수>                  (식별 토큰만)
이후:  VULNSPIDER_<16진수>Z<>"'Z            (식별 토큰 + sentinel)
```

그러면 응답을 보고 판단할 수 있다.

```text
안전한 앱:  ...VULNSPIDER_...Z&lt;&gt;&quot;&#x27;Z...   → 네 문자 모두 이스케이프
위험한 앱:  ...VULNSPIDER_...Z<>"'Z...                   → 원본 그대로
```

`Z`는 양쪽을 감싸는 **구분자**다. 위험 문자가 `&lt;`로 바뀌어도 `Z`는 알파벳이라 그대로
남아서, 응답 어디에 sentinel이 반사됐는지 찾을 수 있다.

### 2.1 왜 식별 토큰과 sentinel을 "함께" 보내나 (핵심 설계)

sentinel만 보내면 함정이 있다. WAF(방화벽)나 입력 필터가 `<>"'`를 **아예 잘라버리면**
반사 자체가 사라져서, **취약한 앱인데 "안전"해 보인다.** 오탐을 줄이려다 더 나쁜
**미탐(놓침)** 을 만드는 것이다.

식별 토큰(영숫자, 항상 살아남음)을 **함께** 보내면 세 상태를 구분할 수 있다.

```text
식별 토큰 없음                    → 반사 안 됨            (marker_reflected = 0)
식별 토큰 있음 + sentinel 없음     → 필터에 잘림          → 인코딩 여부 "미관측"
식별 토큰 있음 + sentinel 이스케이프 → 안전               → safe_html_encoding = 1.0
식별 토큰 있음 + sentinel 원본      → 위험               → safe_html_encoding = 0.0
```

두 번째 줄이 중요하다. "판단 못 함"과 "안전"은 **다르다.** 필터링된 걸 안전으로 처리하면
WAF 있는 모든 앱이 안전해 보인다. 그래서 잘린 경우는 **미관측**으로 남긴다(도메인 규칙:
"미관측은 관측된 0이 아니다").

### 2.2 안전한가?

전송 내용이 바뀌므로 짚고 넘어간다.

- sentinel은 **네 글자뿐**이고 **스크립트가 아니다.** 실행 가능한 payload가 아니라
  "이 문자가 이스케이프되나?"를 보는 **탐침**일 뿐이다(Burp·ZAP 같은 스캐너가 반사 문맥
  확인용으로 흔히 쓰는 방식).
- 전송할 때 percent-encoding되고(`%3C%3E...`) 서버가 디코딩한다. **우리 요청 구조를 깨지
  않는다.**
- 요청 수는 **안 늘어난다.** 같은 baseline/probe 한 쌍에서 feature만 더 뽑는다.
- 대상은 여전히 **loopback/localhost 한정**, 한 번에 하나만 바꾸는 규칙(ADR-004) 유지.

---

## 3. 새 feature — `safe_html_encoding_detected`

sentinel의 네 문자가 **일관되게** entity(`&lt;` 등)로 바뀌었는지 본다.

```text
1.0     네 문자 모두 entity로 변환         → 안전 (penalty 신호)
0.0     하나라도 원본 그대로               → 위험 (탈출 여지)
미관측   sentinel이 응답에 없음(필터링) 또는 본문 디코딩 실패
```

**부분 인코딩은 0.0으로 본다.** 하나라도 원본이면 그 문자로 탈출할 수 있기 때문이다.

같이 추가한 `reflection_count_norm`은 marker가 몇 번 반사됐는지를 `min(횟수/3, 1)`로
정규화한 값이다(싸고 정의가 이미 확정된 feature).

**중요 — `marker_reflected`의 의미가 바뀌었다.** 이제 전체 marker가 아니라 **식별
토큰**으로 반사를 판정한다. 이스케이프된 경우 위험 문자가 `&lt;`로 바뀌어 전체 marker는
사라지지만, 식별 토큰은 살아남으므로 **여전히 "반사됨"으로 잡힌다.** 그리고 인코딩 여부는
`safe_html_encoding_detected`가 따로 답한다. 두 질문을 분리한 것이다.

---

## 4. 결과

⚠️ 전부 합성 loopback 앱 기준이다. 실제 웹 앱 성능이 아니다.

코퍼스: 14개 앱, 후보 146개(취약 36 / 안전 110), 기저율 0.247

**학습된 XSS 계수** (`data/corpus/model.json`) — 데이터가 penalty를 직접 배웠다:

```text
intercept                    -3.55
marker_reflected             +4.39   (반사되면 의심 ↑)
safe_html_encoding_detected  -4.80   (이스케이프되면 의심 ↓↓)   ← 새 feature
reflection_count_norm        +2.19
response_length_diff_ratio   +0.73
```

**핵심 — 반사된 XSS 후보 34개가 완벽히 갈렸다:**

```text
safe_html_encoding = 0.0 (원본)      → 14개, 전부 취약     ← 진짜
safe_html_encoding = 1.0 (이스케이프) → 20개, 전부 안전     ← 이전엔 못 걸르던 오탐
```

**순위 품질 (학습 코퍼스, out-of-fold)**

| 방식 | Rec@3 | Rec@5 | P@1 | NDCG@5 | MAP@5 |
|---|---|---|---|---|---|
| 휴리스틱 가중합 | 0.565 | 0.679 | 0.786 | 0.679 | 0.604 |
| **제안 (이 브랜치)** | **0.899** | **0.958** | **1.000** | **0.957** | **0.930** |
| 오라클 상한 | 0.964 | — | — | — | 1.000 |

**캘리브레이션:** Brier 0.133 → **0.081** (오라클 0.063), ECE 0.169 → **0.066**.

**처음 보는 앱 12개** (학습 미사용), Top-K 5:

| 구성 | recall | 검증 |
|---|---|---|
| 휴리스틱 prior | 25/33 = 0.76 | 60 |
| 학습 모델 | **33/33 = 1.00** | 60 |
| 학습 모델 + conformal | **33/33 = 1.00** | 58 |

이전 브랜치에서 XSS held-out이 8분의 1이던 것이, 이제 전체 33/33에 기여한다.

---

## 5. 정직한 한계와 다음 작업

**지금 수치는 다소 낙관적이다.** 현재 코퍼스는 `xss_raw`(항상 원본)와 `xss_escaped`
(항상 일괄 이스케이프)만 있어서 `safe_html_encoding_detected`가 **완벽 분리자**가 된다.
그래서 held-out이 1.00까지 나온다. 이건 `feat/scoring`에서 고쳤던 "길이 feature가 라벨을
완벽 분리하던 문제"(ADR-030)와 **같은 종류의 낙관 편향**이다.

**다음 증분(계획서 §6)에서 어려운 사례를 넣으면 더 정직해진다:**

```text
xss_partial_escape   < 만 막고 " 는 통과       → 속성 탈출 가능, 취약
xss_attribute        속성 값에 반사, escape됨   → 안전
xss_script_context   <script> 안에 반사, escape → 여전히 취약 (feature가 틀리는 하드 케이스)
xss_filtered         위험 문자를 제거          → 안전하지만 sentinel 소실 (3상태 검증)
```

특히 `xss_script_context`는 이스케이프돼도(`safe_html_encoding=1.0`) `<script>` 블록
안이라 여전히 취약하다 — **feature가 틀리는** 정직한 경우다. 이걸 넣으면 수치는
내려가지만 방어 가능해진다.

**그 외 후속:** `dangerous_reflection_context`(반사 문맥을 text/attribute/script로 분류),
정적 feature `numeric_value`·`id_like_name`(SQLi용). SQLi/BAC feature는 현재 코퍼스에
신호가 없어(파라미터가 전부 숫자, BAC는 관측 파이프라인 없음) 코퍼스 확장이 선행돼야
의미가 생긴다.

---

## 6. 어떻게 돌려보나

```bash
PYTHONPATH=src python tools/build_corpus.py --applications 14   # 코퍼스 재수집 + 모델 학습
PYTHONPATH=src python tools/evaluate_ranking.py --corpus data/corpus/corpus.jsonl
PYTHONPATH=src python tools/evaluate_heldout.py --top-k 5       # XSS 개선 확인
```

단위 583(신규 15) + 통합 54 테스트, format/lint/type 전부 통과. 의존성 추가 없음.

---

## 7. 용어집

| 용어 | 뜻 |
|---|---|
| **marker (표식)** | 취약점을 찾으려고 파라미터에 심어 보내는 특별한 값 |
| **식별 토큰** | marker의 영숫자 부분(`VULNSPIDER_...`). 항상 살아남아 반사 판정에 씀 |
| **sentinel** | marker 뒤에 붙인 위험 문자 4개(`<>"'`). 인코딩 여부를 보기 위한 탐침 |
| **HTML 이스케이프** | `<`를 `&lt;`로 바꿔 공격을 막는 방어. 이게 되면 안전 |
| **`safe_html_encoding_detected`** | sentinel이 이스케이프됐나. 1.0 안전 / 0.0 위험 / 미관측 |
| **`marker_reflected`** | 입력이 화면에 반사됐나(이제 식별 토큰 기준) |
| **오탐 / 미탐** | 오탐=안전한데 위험이라 함, 미탐=위험한데 놓침 |
| **오라클 상한** | 완벽 탐지를 가정한 이론상 최대 성능. 미달이 정상 |

---

*원본: `src/vulnspider/observation/planner.py`, `features/extraction.py`,
`data/corpus/` · 결정 근거는 `docs/DECISION_LOG.md` ADR-031 · 계획은
`docs/exec-plans/active/xss-context-features.md`.*
