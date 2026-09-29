# DVWA 케이스 스터디 계획 (외부 타당성 검증)

## 1. 목적과 역할

평가 환경은 두 축이다.

- **DemoShop (로컬)** — 우리가 정답을 소유하는 100 입력점 타깃. **정량 랭킹 지표**
  (Precision@K / Recall@K / MAP@K, 3-arm)의 주 무대.
- **DVWA (Docker loopback)** — 우리가 만들지 않은 제3자 앱. **외부 타당성**을 보이는
  용도. DVWA는 취약점 페이지마다 입력점이 사실상 1개라 "랭킹"을 뽑기엔 얇으므로,
  **취약 유형별 케이스 스터디**(per-vuln 정탐/오탐)로 제시한다. 랭킹 표를 억지로
  만들지 않는다.

대상 취약 유형은 팀 계획대로 **SQLi · Reflected XSS · Broken Access Control** 3가지.

> 왜 Juice Shop이 아니라 DVWA인가: Juice Shop은 Angular SPA + REST(POST-JSON)라
> VulnSpider가 프로브할 수 없는 구조다(주입 플래너는 GET의 QUERY/FORM만 처리 ―
> `observation/planner.py`, 접근제어 플래너는 GET 전용). DVWA는 고전 PHP 폼(GET)
> 이라 VulnSpider의 능력 범위에 정확히 맞는다. SPA/JSON 확장은 Future Work.

## 2. 대상 페이지와 정답

security=low 기준. 정답 파일: `data/demo/dvwa-ground-truth.json` (application_id `dvwa`).

| 페이지 | 입력점 | 취약 유형 | 라벨 |
| --- | --- | --- | --- |
| `/vulnerabilities/sqli/` | `id` (GET) | SQLI | **취약** (REFLECTED_XSS는 안전) |
| `/vulnerabilities/xss_r/` | `name` (GET) | REFLECTED_XSS | **취약** (SQLI는 안전) |
| `/vulnerabilities/bac/` | `user_id` (GET) | BROKEN_ACCESS_CONTROL | **취약** (SQLI·REFLECTED_XSS는 안전) |

VulnSpider는 입력점마다 SQLI·REFLECTED_XSS 후보를, 숫자 seed에는 BAC 후보까지
만든다. 그래서 위 3개 페이지에서 후보 7개(취약 3 / 안전 4)가 나오고, 이 "같은
입력점의 다른 유형은 안전"이 곧 오탐 측정용 negative가 된다.

## 3. 사전 준비

```bash
# DVWA 컨테이너 (예: localhost:4280), 보안 등급 low
#   docker run --rm -it -p 4280:80 vulnerables/web-dvwa   # 또는 기존 컨테이너
#   브라우저에서 로그인(admin/password) → DVWA Security = Low 로 설정
```

- SQLi·XSS 페이지는 이 인스턴스에서 익명 접근이 가능했다(로그인 없이 200). 안 되면
  로그인 세션 쿠키를 `--cookie`로 넘긴다(§4-C와 동일 방식).
- **BAC 페이지는 로그인이 필수**다(뒤 §4-C 참고).

## 4. 케이스별 실행

각 케이스는 **독립 스캔**이다(페이지마다 요청 컨텍스트 조건이 달라서). 모두 같은
정답 파일을 쓰고, 평가는 그 스캔이 발견한 후보만 채점한다.

### 4-A. SQLi — `id` (탐지 O)

DVWA SQLi 핸들러는 `$_GET['Submit']`이 있어야 쿼리를 실행한다. **이제 크롤러가
이름 있는 submit 버튼(`name="Submit"`)을 고정 파라미터로 자동 포함**하므로(ADR-038),
URL 시딩 없이 페이지만 크롤하면 된다.

```bash
PYTHONPATH=src python -m vulnspider analyze \
  --url "http://localhost:4280/vulnerabilities/sqli/" \
  --max-pages 2 --max-requests 20 --top-k 5 \
  --verify --verify-proposer llm \
  --verification-model data/corpus/verification-model.json \
  --output dvwa-sqli.json --html-output dvwa-sqli-dashboard.html \
  --ground-truth data/demo/dvwa-ground-truth.json \
  --application-id dvwa --eval-output dvwa-sqli-eval.json
```

- **기대**: `id`의 SQLI 후보가 상위(요청에 `Submit=Submit`이 자동 포함되어 쿼리가
  실행되고 SQL 오류가 관측됨), REFLECTED_XSS는 낮음.
- 참고: 폼에 이름 없는 submit(`<input type=submit>` name 없음)만 있으면 브라우저도
  아무것도 안 보내므로 그대로 미포함이다(정상).

### 4-B. Reflected XSS — `name` (탐지 O, 클린)

```bash
PYTHONPATH=src python -m vulnspider analyze \
  --url "http://localhost:4280/vulnerabilities/xss_r/?name=test" \
  --max-pages 2 --max-requests 20 --top-k 5 \
  --verify --verify-proposer llm \
  --verification-model data/corpus/verification-model.json \
  --output dvwa-xss.json --html-output dvwa-xss-dashboard.html \
  --ground-truth data/demo/dvwa-ground-truth.json \
  --application-id dvwa --eval-output dvwa-xss-eval.json
```

- **기대**: `name`의 REFLECTED_XSS 후보가 상위(세션 내 실측 0.78, raw 반사). 게이팅
  없음 — 가장 깨끗한 케이스.

### 4-C. Broken Access Control — `user_id` (로그인 세션 필요 + 주의)

DVWA의 이 BAC 변형은 **`user_id` 쿠키(로그인 시 설정)** 가 있어야 프로필을
보여준다. 로그인 없이는 모든 user_id가 "Access denied / regular_user"(200 동일)라
IDOR가 발현되지 않는다. 따라서 **로그인 후 세션 쿠키를 `--cookie`로 넘긴다.**

```bash
# 브라우저 로그인 후 개발자도구에서 쿠키 복사:
#   PHPSESSID=<...>, security=low, (그리고 이 변형이 요구하는 user_id 쿠키)
PYTHONPATH=src python -m vulnspider analyze \
  --url "http://localhost:4280/vulnerabilities/bac/?user_id=1" \
  --access-control \
  --cookie PHPSESSID=<세션> --cookie security=low \
  --max-pages 2 --max-requests 20 --top-k 5 \
  --output dvwa-bac.json --html-output dvwa-bac-dashboard.html \
  --ground-truth data/demo/dvwa-ground-truth.json \
  --application-id dvwa --eval-output dvwa-bac-eval.json
```

- **기대(인증 상태)**: 참조 요청이 인증된 200으로 프로필을 반환하고, `user_id`를
  치환하면 다른 사용자의 프로필(200, 다른 내용)이 나와 **IDOR로 탐지**된다.
- **익명 오탐은 이제 게이트됨(ADR-038).** 로그인 없이 돌리면 참조·비교가 모두 200
  "Access denied" 페이지인데, 접근제어 feature가 **denial 본문을 탐지**해 관측 무효로
  처리한다 — 이전의 0.95 오탐이 사라진다. 다만 그건 "탐지"가 아니라 "미인증이라
  관측 불가"이므로, **실제 IDOR를 보려면 반드시 로그인 세션으로 실행**해야 한다.
- **주의(실행 시 확인)**: 인증 상태에서 프로필이 사용자별로 실제 달라지는지 응답을
  눈으로 확인하고 결과를 확정할 것. BAC는 세 케이스 중 **가장 조건이 까다로운**
  케이스다(로그인 필수).

## 5. 3개 비교군

케이스마다 위 스캔 **한 번**이 3개 arm을 자동으로 낸다(`evaluation/live.py`):

| 비교군 | live 평가 arm |
| --- | --- |
| Random Predictor | `Random predictor` |
| VulnSpider (상세 검증 없음) | `VulnSpider without focused verification` (검증 전 보정 확률) |
| VulnSpider (LLM Full Suite) | `VulnSpider (full pipeline)` (`--verify --verify-proposer llm` 후 confidence) |

- LLM 검증은 `--verify-proposer llm --llm-model <gguf>`가 필요하다(`feat/merge-local-ai`,
  `models/README.md`). 모델이 없으면 `deterministic`로 대체하고 그 사실을 명시한다.
- 내장 기본 검증 모델은 `SUPPORT_REPRODUCED` LLR이 0이라 두 VulnSpider arm이 같아지므로,
  반드시 `--verification-model data/corpus/verification-model.json`을 준다.

## 6. 제시 포맷 (보고서)

DVWA는 **케이스 스터디**로 제시한다 — 얇은 랭킹 표 대신:

1. **케이스별 결과 표**: 유형 · 입력점 · 발견 여부 · 최종 confidence · 판정(정탐/오탐)
   · 특이사항(Submit 시딩 / 로그인 필요).
2. **Discovery coverage**: 정답의 취약 입력점 3개 중 몇 개를 크롤이 실제로 발견했나.
   (live 평가의 Recall은 *발견된 후보 안에서의* 랭킹 recall이므로, "발견 못 한 것"은
   별도로 보고 — §7.)
3. **3-arm 비교**: 케이스별로 random vs prior vs full을 나란히. 세 케이스를 합치면
   query 3개로 묶어 **평균 MAP**(DemoShop과 합치면 여러-앱 평균)까지 낼 수 있다.

## 7. 알려진 한계 (정직하게 명시)

- **Discovery recall ≠ 탐지 recall.** live 평가는 크롤이 발견한 후보만 채점한다.
  발견 못 한 취약점(예: Submit 미시딩 시 SQLi)은 랭킹 recall을 깎지 않으므로,
  **discovery coverage를 항상 함께 보고**한다.
- **SQLi Submit 게이팅** — **해결됨(ADR-038)**: 이름 있는 submit 버튼을 고정
  파라미터로 자동 포함한다. 이름 없는 submit만 있는 폼은 브라우저와 동일하게 미포함.
- **BAC 상태코드 휴리스틱** — 200 인가 거부 오탐은 **denial 본문 탐지로 게이트됨
  (ADR-038)**. 다만 (a) denial 문구가 사전에 없는 언어/표현이면 놓칠 수 있고,
  (b) IDOR/자격증명제거의 응답 유사도 의미 분리는 여전히 후속 과제(§4-C, ADR-037 C안).
- **SPA/REST(POST-JSON) 미지원** — Juice Shop류는 현재 관측 모델 밖(§1). Future Work.
- **얇은 표면** — DVWA는 페이지당 입력점 1개라 랭킹이 아닌 케이스 스터디로 제시한다.
  풍부한 다중 입력점 랭킹은 DemoShop이 담당.

## 8. 체크리스트

- [ ] DVWA 컨테이너 기동, security=low, (BAC용) 로그인 세션 확보
- [ ] `data/demo/dvwa-ground-truth.json` 값을 실제 스캔으로 확인·확정
      (특히 `id`가 XSS로도 반사되는지, `user_id`가 주입에도 반응하는지)
- [ ] 케이스 3개 실행 → eval JSON·대시보드 수집
- [ ] discovery coverage 계산(취약 3개 중 발견 수)
- [ ] 케이스별 결과 표 + 3-arm + 한계 서술로 보고서 섹션 작성
