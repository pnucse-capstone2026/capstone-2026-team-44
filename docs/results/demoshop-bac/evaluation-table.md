# 랭킹 평가 지표 — demoshop

- 대상: `http://127.0.0.1:8899/portal/`
- 후보 9개 · 취약 2개 · 미라벨 0개 · 검증 9개 · Top-K 20
- 지표 버전: `ranking-metrics-v1`

## Recall@K

| Arm | K=1 | K=3 | K=5 | K=10 | K=20 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Random predictor | 0.111 | 0.333 | 0.556 | 1.000 | 1.000 |
| VulnSpider without focused verification | 0.500 | 1.000 | 1.000 | 1.000 | 1.000 |
| **VulnSpider (full pipeline)** | 0.500 | 1.000 | 1.000 | 1.000 | 1.000 |
| Random predictor (per-input-point type guess) | 0.120 | 0.341 | 0.561 | 1.000 | 1.000 |

## Precision@K

| Arm | K=1 | K=3 | K=5 | K=10 | K=20 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Random predictor | 0.222 | 0.222 | 0.222 | 0.222 | 0.222 |
| VulnSpider without focused verification | 1.000 | 0.667 | 0.400 | 0.222 | 0.222 |
| **VulnSpider (full pipeline)** | 1.000 | 0.667 | 0.400 | 0.222 | 0.222 |
| Random predictor (per-input-point type guess) | 0.239 | 0.228 | 0.224 | 0.222 | 0.222 |

## MAP@K

| Arm | K=1 | K=3 | K=5 | K=10 | K=20 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Random predictor | 0.222 | 0.220 | 0.291 | 0.400 | 0.400 |
| VulnSpider without focused verification | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| **VulnSpider (full pipeline)** | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| Random predictor (per-input-point type guess) | 0.239 | 0.230 | 0.301 | 0.408 | 0.408 |

## NDCG@K

| Arm | K=1 | K=3 | K=5 | K=10 | K=20 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Random predictor | 0.222 | 0.290 | 0.402 | 0.580 | 0.580 |
| VulnSpider without focused verification | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| **VulnSpider (full pipeline)** | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| Random predictor (per-input-point type guess) | 0.239 | 0.300 | 0.410 | 0.586 | 0.586 |
