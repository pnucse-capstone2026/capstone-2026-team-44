# VulnSpider 결과 팩

보고서·시연에 싣는 모든 수치의 **단일 출처**. 아래 실행을 한 번에 캡처한다.

| 항목 | 값 |
| --- | --- |
| 생성 시각 | 2026-09-21 13:45 UTC |
| VulnSpider 버전 | 0.1.0 |
| git 커밋 | c023d01 |
| Python | 3.12.6 |
| 검증 모델 | 있음 (data/corpus/verification-model.json) |
| 랜덤 예측기 | per-input-point, safe-weight 4, 시드 0, 1000 trials |

각 시나리오 폴더에는 `dashboard.html`, `verification-detail.html`, `evaluation.json`, `evaluation-table.{md,html}`(3-arm 비교), `evaluation-inputs.{md,html}`(입력점별 취약 유형), `command.txt`, `run.log`가 들어 있다.

> 참고: `VulnSpider (full pipeline)`은 `without focused verification`의 상위 K 후보를 focused verification으로 재검증한 뒤의 랭킹이다. 두 arm의 지표가 같으면 검증이 순위를 바꿀 여지가 없었다는 뜻이고, 다르면 검증이 경계의 후보를 바로잡은 것이다 — 시나리오별 '검증 효과' 줄이 실제 수치로 말해 준다. 랭킹은 응답 바이트에 민감하므로 타깃 HTML이 바뀌면 수치는 이 팩을 다시 생성해서 인용한다.

## DemoShop — 공개 상점 (Static + Focused Verification)

- 대상: `http://127.0.0.1:8899/`
- 폴더: [`demoshop/`](demoshop/)
- 상태: **ok**

```bash
PYTHONPATH=src python -m vulnspider analyze --url http://127.0.0.1:8899/ --top-k 20 --max-pages 40 --max-requests 220 --output docs/results/demoshop/analysis.json --html-output docs/results/demoshop/dashboard.html --verify --verification-model data/corpus/verification-model.json --verify-output docs/results/demoshop/verification.json --verify-detail-output docs/results/demoshop/verification-detail.html --ground-truth data/demo/demoshop-ground-truth.json --application-id demoshop --eval-output docs/results/demoshop/evaluation.json --random-predictor --random-safe-weight 4
```

| Arm | P@1 | R@1 | MAP@1 | P@5 | R@5 | MAP@5 | P@10 | R@10 | MAP@10 | P@20 | R@20 | MAP@20 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Random predictor | 0.160 | 0.005 | 0.160 | 0.160 | 0.025 | 0.087 | 0.160 | 0.050 | 0.064 | 0.160 | 0.100 | 0.049 |
| VulnSpider without focused verification | 1.000 | 0.031 | 1.000 | 1.000 | 0.156 | 1.000 | 0.800 | 0.250 | 0.789 | 0.750 | 0.469 | 0.671 |
| **VulnSpider (full pipeline)** | 1.000 | 0.031 | 1.000 | 1.000 | 0.156 | 1.000 | 0.800 | 0.250 | 0.789 | 0.800 | 0.500 | 0.715 |
| Random predictor (per-input-point type guess) | 0.161 | 0.005 | 0.161 | 0.161 | 0.025 | 0.087 | 0.161 | 0.050 | 0.065 | 0.161 | 0.101 | 0.050 |

- 검증 효과: focused verification이 상위 K 안의 순위를 바로잡았다 — P@20 0.750→0.800, R@20 0.469→0.500, MAP@20 0.671→0.715, NDCG@20 0.809→0.842.

## DemoShop — 인증 영역 BAC (`/portal/`, user 세션)

- 대상: `http://127.0.0.1:8899/portal/`
- 폴더: [`demoshop-bac/`](demoshop-bac/)
- 상태: **ok**

```bash
PYTHONPATH=src python -m vulnspider analyze --url http://127.0.0.1:8899/portal/ --access-control --cookie demoshop_session=<redacted> --top-k 20 --max-pages 20 --max-requests 100 --output docs/results/demoshop-bac/analysis.json --html-output docs/results/demoshop-bac/dashboard.html --verify --verification-model data/corpus/verification-model.json --verify-output docs/results/demoshop-bac/verification.json --verify-detail-output docs/results/demoshop-bac/verification-detail.html --ground-truth data/demo/demoshop-ground-truth.json --application-id demoshop --eval-output docs/results/demoshop-bac/evaluation.json --random-predictor --random-safe-weight 4
```

| Arm | P@1 | R@1 | MAP@1 | P@5 | R@5 | MAP@5 | P@10 | R@10 | MAP@10 | P@20 | R@20 | MAP@20 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Random predictor | 0.222 | 0.111 | 0.222 | 0.222 | 0.556 | 0.291 | 0.222 | 1.000 | 0.400 | 0.222 | 1.000 | 0.400 |
| VulnSpider without focused verification | 1.000 | 0.500 | 1.000 | 0.400 | 1.000 | 1.000 | 0.222 | 1.000 | 1.000 | 0.222 | 1.000 | 1.000 |
| **VulnSpider (full pipeline)** | 1.000 | 0.500 | 1.000 | 0.400 | 1.000 | 1.000 | 0.222 | 1.000 | 1.000 | 0.222 | 1.000 | 1.000 |
| Random predictor (per-input-point type guess) | 0.239 | 0.120 | 0.239 | 0.224 | 0.561 | 0.301 | 0.222 | 1.000 | 0.408 | 0.222 | 1.000 | 0.408 |

- 검증 효과: 검증 전 랭킹이 이미 최적이라 `full pipeline`과 `without focused verification`의 랭킹 지표가 **동일**하다. 기여는 각 후보의 **confidence 값**(대시보드·`verification-detail.html`)에서 드러난다.
