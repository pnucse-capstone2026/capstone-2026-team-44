# 랭킹 평가 지표 — demoshop

- 대상: `http://127.0.0.1:8899/`
- 후보 200개 · 취약 32개 · 미라벨 0개 · 검증 20개 · Top-K 20
- 지표 버전: `ranking-metrics-v1`

## Recall@K

| Arm | K=1 | K=3 | K=5 | K=10 | K=20 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Random predictor | 0.005 | 0.015 | 0.025 | 0.050 | 0.100 |
| VulnSpider without focused verification | 0.031 | 0.094 | 0.156 | 0.219 | 0.469 |
| **VulnSpider (full pipeline)** | 0.031 | 0.094 | 0.156 | 0.219 | 0.500 |
| Random predictor (per-input-point type guess) | 0.005 | 0.015 | 0.025 | 0.050 | 0.101 |

## Precision@K

| Arm | K=1 | K=3 | K=5 | K=10 | K=20 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Random predictor | 0.160 | 0.160 | 0.160 | 0.160 | 0.160 |
| VulnSpider without focused verification | 1.000 | 1.000 | 1.000 | 0.700 | 0.750 |
| **VulnSpider (full pipeline)** | 1.000 | 1.000 | 1.000 | 0.700 | 0.800 |
| Random predictor (per-input-point type guess) | 0.161 | 0.161 | 0.161 | 0.161 | 0.161 |

## MAP@K

| Arm | K=1 | K=3 | K=5 | K=10 | K=20 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Random predictor | 0.160 | 0.107 | 0.087 | 0.064 | 0.049 |
| VulnSpider without focused verification | 1.000 | 1.000 | 1.000 | 0.688 | 0.657 |
| **VulnSpider (full pipeline)** | 1.000 | 1.000 | 1.000 | 0.688 | 0.701 |
| Random predictor (per-input-point type guess) | 0.161 | 0.108 | 0.087 | 0.065 | 0.050 |

## NDCG@K

| Arm | K=1 | K=3 | K=5 | K=10 | K=20 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Random predictor | 0.160 | 0.160 | 0.160 | 0.160 | 0.160 |
| VulnSpider without focused verification | 1.000 | 1.000 | 1.000 | 0.797 | 0.803 |
| **VulnSpider (full pipeline)** | 1.000 | 1.000 | 1.000 | 0.797 | 0.836 |
| Random predictor (per-input-point type guess) | 0.161 | 0.161 | 0.161 | 0.161 | 0.161 |
