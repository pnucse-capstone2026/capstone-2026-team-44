# DVWA 테스트 결과 리포트 (실측)

외부 타당성 검증: 우리가 만들지 않은 제3자 취약 앱(DVWA)에서 VulnSpider가 알려진
취약점을 실제로 상위로 플래그하는지 확인한다. 취약 유형별 **케이스 스터디**로
제시한다(§ DVWA는 페이지당 입력점 1개라 랭킹이 아닌 per-vuln 검증).

> 하나의 입력점은 SQLi·XSS 두 유형으로 **채점**되지만, **최종 대시보드 리포트는
> 입력점당 점수가 높은 유형 하나만** 표시한다(2개 대상으로 오해되지 않도록). 아래
> 표의 각 케이스에서 "취약"으로 표시된 행이 대시보드에 노출되는 최종 findings이고,
> 교차 유형(안전) 행은 채점 결과일 뿐 대시보드에는 접혀서 표시되지 않는다. 지표는
> 후보 단위로 계산된다(§6-A).

## 실행 환경

| 항목 | 값 |
| --- | --- |
| 타깃 | DVWA (Docker `vulnerables/web-dvwa`, loopback `localhost:4280`) |
| 보안 등급 | Low |
| 인증 | admin 로그인 세션 쿠키(`PHPSESSID`, `security=low`)를 `--cookie`로 주입 |
| 스캐너 | VulnSpider (`analyze`, 정적 경로, `--max-depth 0`로 대상 페이지만) |
| 검증 | focused verification 켬(`--verify`), `data/corpus/verification-model.json` |
| 정답 | `data/demo/dvwa-ground-truth.json` (`--application-id dvwa`) |
| 비교군 | Random / VulnSpider(검증 없음) / VulnSpider(full pipeline) |

## 케이스별 결과 (실측)

### 케이스 A — SQL Injection (`/vulnerabilities/sqli/`, `id`)

발견된 입력점 1개(`id`) → 후보 2개(SQLI/XSS).

| 후보 | prior | final | 라벨 | 판정 |
| --- | --- | --- | --- | --- |
| `id` · **SQLI** | 0.875 | **0.950** | 취약 | ✅ 정탐 (검증 SUPPORTED) |
| `id` · Reflected XSS | 0.385 | 0.187 | 안전 | ✅ (검증 WEAKENED로 하향) |

3-arm (K=1):

| arm | P@1 | R@1 | MAP@1 | NDCG@1 |
| --- | --- | --- | --- | --- |
| Random predictor | 0.500 | 0.500 | 0.500 | 0.500 |
| VulnSpider (검증 없음) | 1.000 | 1.000 | 1.000 | 1.000 |
| **VulnSpider (full)** | **1.000** | **1.000** | **1.000** | **1.000** |

> **핵심**: 이번 릴리스의 submit-게이트 수정(ADR-038) 덕분에, **URL 시딩 없이** 페이지만
> 크롤해도 요청에 `Submit=Submit`이 자동 포함되어 DVWA 핸들러가 쿼리를 실행한다.
> probe(`id=…'`)에 대해 실제로 `You have an error in your SQL syntax …`가 관측됐고,
> focused verification이 이 SQL 오류를 재현해 confidence를 0.875 → 0.950으로 올렸다.

### 케이스 B — Reflected XSS (`/vulnerabilities/xss_r/`, `name`)

발견된 입력점 1개(`name`) → 후보 2개.

| 후보 | prior | final | 라벨 | 판정 |
| --- | --- | --- | --- | --- |
| `name` · **Reflected XSS** | 0.777 | **0.904** | 취약 | ✅ 정탐 (검증 SUPPORTED) |
| `name` · SQLI | 0.223 | 0.161 | 안전 | ✅ |

3-arm (K=1):

| arm | P@1 | R@1 | MAP@1 | NDCG@1 |
| --- | --- | --- | --- | --- |
| Random predictor | 0.500 | 0.500 | 0.500 | 0.500 |
| VulnSpider (검증 없음) | 1.000 | 1.000 | 1.000 | 1.000 |
| **VulnSpider (full)** | **1.000** | **1.000** | **1.000** | **1.000** |

> raw 반사(marker가 이스케이프 없이 출력)를 검증이 확인해 0.777 → 0.904로 강화했다.

### 케이스 C — Broken Access Control

**이 이미지에는 BAC 모듈이 없다.** `vulnerables/web-dvwa`의 모듈은 brute, exec, csrf,
fi, sqli, sqli_blind, upload, weak_id, xss_d/r/s 등이며 `/vulnerabilities/bac/`는
**404**다(이전에 테스트한 인스턴스는 BAC 모듈이 추가된 커스텀 이미지였음).

따라서 DVWA에서의 BAC 실측은 **BAC 모듈이 있는 이미지가 필요**하다. 그동안 BAC의
정탐/오탐 능력은 우리가 통제하는 **DemoShop `/portal/`**에서 실측으로 입증돼 있다
(인증 세션, IDOR 2건 0.953 / 정상 접근제어 0.524, `Recall@2`·`MAP@K` 1.000).
또한 ADR-038의 denial-게이트로 "익명 200 거부"를 IDOR 성공으로 오독하던 문제가
제거됐다(단위 테스트로 검증). BAC 모듈이 있는 DVWA에서는 로그인 세션(`--cookie`)으로
재확인하면 된다.

## Discovery coverage

| 페이지 | 정답 취약 입력점 | 발견됨 | 비고 |
| --- | --- | --- | --- |
| `/vulnerabilities/sqli/` | `id` (SQLI) | 1/1 | submit 게이트 자동 포함 |
| `/vulnerabilities/xss_r/` | `name` (XSS) | 1/1 | — |
| `/vulnerabilities/bac/` | `user_id` (BAC) | — | 이 이미지에 모듈 없음(404) |

## 요약

- **SQLi·XSS: 실측 정탐.** 두 케이스 모두 취약 후보가 1위, 교차 유형(안전) 후보는 하위.
  P@1/R@1/MAP@1 = **1.000** vs 랜덤 **0.500**. focused verification이 두 정탐을 강화했다.
- **submit-게이트 수정(ADR-038)이 실제 DVWA에서 end-to-end로 동작**함을 확인 — 이전에는
  Submit 누락으로 SQLi가 미탐(0.22)이었으나, 이제 시딩 없이 0.950으로 탐지.
- **BAC는 모듈이 있는 이미지 필요.** 능력 입증은 DemoShop `/portal/`이 담당하고, denial-
  게이트로 익명 오탐은 제거됨.

## 재현 명령 (사용한 그대로)

```bash
# 로그인 세션 쿠키는 브라우저 로그인 후 F12 → Cookies 에서 복사
PYTHONPATH=src python -m vulnspider analyze \
  --url "http://localhost:4280/vulnerabilities/sqli/" \
  --cookie "PHPSESSID=<세션>" --cookie "security=low" \
  --max-depth 0 --max-pages 1 --top-k 5 \
  --verify --verification-model data/corpus/verification-model.json \
  --output dvwa-sqli.json --html-output dvwa-sqli-dashboard.html \
  --ground-truth data/demo/dvwa-ground-truth.json \
  --application-id dvwa --eval-output dvwa-sqli-eval.json
# XSS는 --url .../xss_r/ 로 동일하게
```

> `--max-depth 0`은 대상 페이지만 크롤해 다른 모듈의 입력점이 섞이지 않게 한다.
> 로그인 세션이 필요한 이유: DVWA는 미인증 요청을 login.php로 리다이렉트한다.
