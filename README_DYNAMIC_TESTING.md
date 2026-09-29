# 공개 웹사이트 대상 동적 스캔 테스트 가이드

`http://testaspnet.vulnweb.com/` 같은 **스캔 학습용 공개 테스트 사이트**에 VulnSpider를
실제로 돌려보는 방법을 정리한 문서입니다. 설치 → 실행 명령 → 출력 → 주의사항 순서로 설명합니다.

> ⚠️ **승인된 대상만 스캔하세요.** `*.vulnweb.com`(Acunetix), `testphp.vulnweb.com`,
> `testhtml5.vulnweb.com` 등은 스캐너 테스트용으로 **공개 허용**된 사이트입니다. 그 외
> 사이트는 소유자의 명시적 허가 없이 스캔하지 마세요.

---

## 0. 핵심 요약 (TL;DR)

```powershell
# (한 번만) 프로젝트 + 동적 크롤 dependency 설치
python -m pip install -e ".[dynamic]"
python -m playwright install chromium

# 공개 테스트 사이트에 동적 스캔 → 대시보드 HTML 생성
$env:PYTHONPATH = "src"
python -m vulnspider --url http://testaspnet.vulnweb.com/ --top-k 20
# 결과: vulnspider-report.html (대시보드), vulnspider-analysis.json, vulnspider-crawl.json
```

playwright 설치가 부담되면 **정적 모드**로 바로 시작할 수 있습니다:

```powershell
$env:PYTHONPATH = "src"
python -m vulnspider --url http://testaspnet.vulnweb.com/ --top-k 20 --static-only
```

---

## 1. 사전 준비

| 항목 | 내용 |
|---|---|
| Python | 3.11 이상 |
| 코드 경로 | 이 저장소의 `src`를 `PYTHONPATH`에 넣고 실행 (아래 "실행 함정" 참고) |
| 동적 크롤 | `python -m pip install -e ".[dynamic]"` + `python -m playwright install chromium` |
| (선택) 로컬 LLM 검증 | `models\vulnspider-3b_v3.gguf` + `llama-cpp-python` — [models/README.md](../models/README.md) 참고 |

### ⚠️ 실행 함정 (반드시 이 방식으로)

이 저장소의 코드로 실행하려면 **반드시** 다음처럼 실행합니다:

```powershell
$env:PYTHONPATH = "src"
python -m vulnspider <명령>
```

- `python -m vulnspider.cli ...` → **아무것도 하지 않고 조용히 종료**됩니다(모듈에 실행 가드 없음). 항상 `python -m vulnspider`(= `__main__.py`)를 쓰세요.
- 설치된 `vulnspider` 콘솔 스크립트는 **다른 위치의 오래된 설치본**을 실행할 수 있습니다. 이 저장소 코드를 확실히 쓰려면 위처럼 `PYTHONPATH=src python -m vulnspider`를 사용하세요.

---

## 2. 두 가지 실행 모드

### (A) 심플 모드 — "URL만 주면 알아서" (권장)

서브커맨드 없이 `--url`만 주면 크롤 → 분석 → 랭킹 → 대시보드까지 한 번에 수행합니다.
**기본이 동적(브라우저) 크롤**입니다.

```powershell
$env:PYTHONPATH = "src"
python -m vulnspider --url http://testaspnet.vulnweb.com/ --top-k 20
```

주요 옵션:

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `--url URL` | (필수) | 스캔 시작 루트 URL |
| `--top-k N` | 10 (최대 20) | 상위 후보 개수 |
| `--static-only` | 꺼짐 | 브라우저 없이 정적 크롤만 (playwright 불필요) |
| `--output PATH` | `vulnspider-analysis.json` | 분석/결정 리포트 JSON |
| `--html-output PATH` | `vulnspider-report.html` | **대시보드 HTML** |
| `--crawl-output PATH` | `vulnspider-crawl.json` | 크롤 결과 JSON |
| `--no-html` | 꺼짐 | HTML 리포트 생략 |
| `--dynamic-allow-navigation URL` | — | 동적 크롤이 추가로 방문해도 되는 페이지(여러 번 지정 가능) |
| `--dynamic-allow-resource CATEGORY=URL` | — | 동일 출처 외 리소스 허용 |
| `--access-control` | 꺼짐 | Broken Access Control 프로빙 추가(요청 증가) |

### (B) analyze 모드 — 정밀 제어

`analyze` 서브커맨드는 **기본이 정적** 크롤이고, `--dynamic`으로 브라우저 크롤을 켭니다.
크롤러 예산(페이지 수/깊이/시간) 등을 세밀하게 조절할 때 씁니다.

```powershell
$env:PYTHONPATH = "src"
python -m vulnspider analyze --url http://testaspnet.vulnweb.com/ `
    --top-k 20 `
    --output analysis.json `
    --html-output dashboard.html `
    --dynamic `
    --dynamic-max-pages 40 `
    --dynamic-max-depth 3
```

정적 크롤 예산 옵션: `--max-pages`, `--max-depth`, `--max-requests`,
`--timeout-seconds`, `--max-redirects`.
동적 크롤 예산 옵션: `--dynamic-max-pages`, `--dynamic-max-depth`,
`--dynamic-max-navigation-attempts`, `--dynamic-max-route-actions`,
`--dynamic-max-elapsed-seconds`, `--dynamic-navigation-timeout-seconds`,
`--dynamic-max-redirects`, `--dynamic-request-decision-budget`.

---

## 3. 로컬 LLM 검증(Confidence Update)은 loopback 전용 ⚠️

`--verify`(변형 페이로드 재프로브 + 확신도 갱신) 단계는 **안전 가드에 의해
`localhost`/loopback IP 대상에만** 허용됩니다. 즉:

- ✅ 외부 공개 사이트: **크롤 · 분석 · 랭킹 · 대시보드**까지 가능 (`--verify` 없이)
- ❌ 외부 공개 사이트 + `--verify` → `verification permits only localhost or loopback IP targets` 오류로 중단

이는 실제 변형 페이로드를 외부 서버로 전송하지 않도록 하는 **설계상 의도**입니다.
로컬 LLM 검증까지 확인하려면 **동봉된 데모 서버**(loopback)나 로컬 미러를 대상으로 하세요:

```powershell
# 터미널 1: loopback 데모 상점 (DemoShop, 입력점 100개)
python demo_target_server.py            # http://127.0.0.1:8899
                                        # 입력점 지도: /_lab

# 터미널 2: 로컬 LLM proposer로 검증까지 포함한 전체 파이프라인
$env:PYTHONPATH = "src"
python -m vulnspider analyze --url http://127.0.0.1:8899/ `
    --max-pages 60 --max-requests 250 `
    --top-k 20 `
    --output analysis.json --html-output dashboard.html `
    --verify --verify-proposer llm `
    --llm-model models\vulnspider-3b_v3.gguf `
    --verify-output verify.json
```

DemoShop은 라우트가 32개라 기본 크롤 예산(10 페이지)으로는 입력점을 다 찾지
못합니다. `--max-pages 60 --max-requests 250`을 함께 주세요.

랭킹 지표까지 보려면 정답 파일을 붙입니다 (`docs/EVALUATION_PROTOCOL.md` §6-B):

```powershell
python -m vulnspider analyze --url http://127.0.0.1:8899/ `
    --max-pages 60 --max-requests 250 --top-k 20 --output analysis.json `
    --verify --verify-output verify.json `
    --verification-model data\corpus\verification-model.json `
    --ground-truth data\demo\demoshop-ground-truth.json `
    --eval-output evaluation.json
```

`--verify-proposer` 값: `deterministic`(기본, 재현 가능한 규칙 기반) 또는
`llm`(로컬 파인튜닝 `vulnspider-3b`). LLM이 낸 페이로드도 전송 전 반드시
결정적 `PayloadValidator`를 통과합니다.

---

## 4. 산출물

| 파일 | 내용 |
|---|---|
| `vulnspider-report.html` (`--html-output`) | **최종 대시보드** — 후보 랭킹·확신도 |
| `vulnspider-analysis.json` (`--output`) | 결정 리포트(JSON) |
| `vulnspider-crawl.json` (`--crawl-output`) | 크롤 결과(입력점·엔드포인트) |
| `*-detail.html` (`--verify` 시 자동) | **입력점별 검증 상세** — baseline → 변형 페이로드 → 결과 → 확신도 |
| `vulnspider-verification.json` (`--verify-output`) | 검증 상세(변형 페이로드·결과·확신도) — `--verify` 시 |

### 입력점별 검증 상세 리포트 (자동)

`--verify`와 `--html-output`을 함께 주면 대시보드 옆에 **입력점별 상세 리포트**가
자동으로 생성됩니다(`dashboard.html` → `dashboard-detail.html`). 입력점마다
**baseline 요청 → 변형 페이로드 요청(전체 URL) → 검증기 통과/차단 → feature delta →
prior→final 확신도**를 보여줍니다. 스캔이 끝나면 CLI가 대시보드와 상세 리포트의 클릭
가능한 `file://` 링크를 함께 출력하므로, 링크를 누르면 브라우저에서 바로 열립니다.

- 경로 변경: `--verify-detail-output <path>`
- 생성 생략: `--no-verify-detail`
- 스캔 종료와 동시에 브라우저로 열기: `--open` (대시보드·상세 리포트 모두 열림)

이미 `verify.json`(+ `--crawl-output` 크롤 JSON)이 디스크에 있다면 아래 도구로도 같은
리포트를 만들 수 있습니다. 입력점 id가 결정적 지문이라 **같은 대상**에 대한 어떤 크롤
결과든 조인됩니다(`--crawl` 생략 시 파라미터 원본값만 표시):

```powershell
$env:PYTHONPATH = "src"
python tools\verification_detail_report.py `
    --verify verify.json `
    --crawl vulnspider-crawl.json `
    --out verification-detail.html
```

---

## 5. 자주 겪는 문제

| 증상 | 원인 / 해결 |
|---|---|
| 실행해도 아무 출력·파일 없음 | `python -m vulnspider.cli`로 실행함 → `python -m vulnspider`로 변경 |
| `ModuleNotFoundError: playwright` 또는 브라우저 오류 | 동적 모드인데 playwright 미설치 → 설치하거나 `--static-only`/`analyze`(정적) 사용 |
| `verification permits only localhost ...` | 외부 대상에 `--verify` 사용 → 외부는 `--verify` 제거, 검증은 loopback 대상에서만 |
| 후보가 거의 안 잡힘 | 정적 크롤로는 JS 렌더 링크를 못 볼 수 있음 → 동적 모드 사용, `--dynamic-max-pages/-depth` 상향 |
| 다른 저장소 코드가 실행되는 듯함 | 오래된 editable 설치본이 가림 → `PYTHONPATH=src`를 명시 |

---

## 6. 예시: testaspnet.vulnweb.com 빠른 시작

```powershell
# 1) (최초 1회) 프로젝트 + 브라우저 dependency
python -m pip install -e ".[dynamic]"
python -m playwright install chromium

# 2) 동적 스캔 + 대시보드
$env:PYTHONPATH = "src"
python -m vulnspider --url http://testaspnet.vulnweb.com/ --top-k 20 `
    --html-output vulnweb-report.html

# 3) 브라우저로 vulnweb-report.html 열어 결과 확인
```

> 로컬 LLM 확신도 갱신까지 시연하려면 3장의 데모 서버(loopback) 예시를 사용하세요.
> 외부 사이트에서는 크롤·분석·랭킹까지만 수행됩니다.
