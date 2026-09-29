> [!IMPORTANT]
> **⚙️ 테스트 전 필독 — 모델 파일 위치 & 사용법**
>
> **1. 모델 파일은 반드시 저장소 루트의 `models/` 디렉토리에 둔다.**
> - `models/vulnspider-3b_v3.gguf` — 파인튜닝 모델 본체 (~1.8GB)
> - `models/llama_cpp_python-0.3.34-py3-none-win_amd64.whl` — 실행 엔진
>
> 두 파일은 **게이트 저장소**(HF `lsk0228/vulnspider-3b_v3`)라 repo에 포함되지 않으며
> (`.gitignore` 처리됨), **받는 방법과 저장 경로는 반드시 `models/README.md`를 따른다.**
>
> **2. 테스트는 `README_DYNAMIC_TESTING.md`(= `docs/DYNAMIC_TESTING.md`)의 명령을 그대로 참고**해
> 진행한다. 실행은 **반드시** `PYTHONPATH=src python -m vulnspider ...` 형태로 한다
> (`python -m vulnspider.cli` 또는 설치된 `vulnspider` 콘솔 스크립트는 **사용 금지** — 전자는
> 조용히 종료되고, 후자는 오래된 설치본을 가리킬 수 있음).
>
> ```powershell
> # 0) 실행 엔진 설치 (models/ 안의 whl)
> pip install .\models\llama_cpp_python-0.3.34-py3-none-win_amd64.whl
> # 1) loopback 데모 서버
> python demo_target_server.py            # http://127.0.0.1:8899
> # 2) 실제 로컬 LLM으로 검증까지 (별도 터미널)
> $env:PYTHONPATH = "src"
> python -m vulnspider analyze --url http://127.0.0.1:8899/ --top-k 20 `
>     --verify --verify-proposer llm --llm-model models\vulnspider-3b_v3.gguf `
>     --output analysis.json --verify-output verify.json --html-output dashboard.html
> ```

# feat: 로컬 파인튜닝 LLM을 Payload Proposer로 본체 파이프라인에 통합

`feat/merge-local-ai` — confidence-update 검증 단계의 페이로드 제안기를, 규칙 기반
단순 모듈에서 **실제 로컬 파인튜닝 LLM**(`vulnspider-3b`, 석현의 `payload_verifier_v2`)으로
교체할 수 있게 통합한다. 안전 경계는 그대로 유지된다.

## 요약

- 기존 confidence-update 파이프라인은 provider-중립 `PayloadProposer` 프로토콜을 갖고 있었고,
  기본값은 재현 가능한 `DeterministicMutationProposer`(단순 모듈)였다.
- 이 PR은 그 프로토콜 뒤에 **로컬 GGUF 모델을 구동하는 `LocalLLMMutationProposer`**를 붙여,
  `--verify-proposer llm`으로 실제 LLM이 변형 페이로드를 제안하도록 한다.
- **모델 출력은 여전히 신뢰하지 않는다**: 모든 제안은 전송 전에 결정적 `PayloadValidator`를
  통과해야 하고, 재프로브는 loopback 대상에만, 최종 confidence 숫자는 규칙이 정한다.
- XSS에서 파이프라인의 반영/인코딩 feature가 측정 가능하도록 **하이브리드 센티넬 마커**를 도입.
- 실제 환경에 모델을 설치해 데모 서버 대상 end-to-end로 검증 완료.

## 배경

`docs/PROTOTYPE_V0_2.md` §4.3 / `AGENTS.md`가 명시하듯, proposer는 *제안*만 하고
실행 여부는 결정적 validator가 정한다. `verification/proposal.py`의 docstring도
"A real GPT/Gemini client implements this exact method behind the same validator
gate"라고 이 드롭인을 예고하고 있었다. 이 PR은 그 자리를 실제 로컬 모델로 채운다.

모델/프롬프트의 원본은 in-repo `payload_verifier_v2/`(석현 작성, Qwen2.5 파인튜닝 →
`vulnspider-3b_v3.gguf`, `llama-cpp-python`)이며, 클라우드 API가 공격 페이로드 생성을
거부하는 문제 때문에 로컬 추론을 택했다.

## 주요 변경

### 1. 로컬 LLM proposer (`src/vulnspider/verification/llm_proposal.py`, +388)
- `LocalLLMMutationProposer`가 `PayloadProposer` 프로토콜(`propose(MutationSubject) ->
  tuple[PayloadProposal, ...]`)을 구현. `llama_cpp.Llama`로 GGUF를 **lazy 로드**하고,
  테스트용으로 `llm=` 클라이언트를 주입할 수 있다.
- 프롬프트는 모델이 학습된 형식(`payload_verifier_v2/generate_dataset.py`)과 **바이트 단위로
  호환**되게 재현: 학습 SYSTEM_PROMPT(vendored) + 최소 후보 JSON + `(Assume Type-specific
  rules are applied here)` 센티넬. 이로써 본체는 런타임에 `payload_verifier` 패키지에 의존하지
  않는다(GGUF + `llama-cpp-python`만 있으면 됨).
- 모델 `kind` → `family` 매핑: `SQLI → SQL_META`, `REFLECTED_XSS → HTML_SENTINEL`.
- 실패/빈 출력 시 **크래시 없이 빈 제안**으로 degrade → 오케스트레이터가 NOT_EXECUTED로 처리하고
  prior를 유지.

### 2. 하이브리드 센티넬 마커 (XSS)
- 문제: 파이프라인의 인코딩 탐지(`safe_html_encoding_detected`)는 `식별자 + "Z" +
  <위험문자> + "Z"` 구조를 요구하는데, 자유형 LLM 값에는 `Z`가 없어 검증 프로브에서
  **관측 불가**(초기 실측 k=20에서 38/38 미관측).
- 해결: XSS는 모델 값을 마커의 *영역*으로 감싼다 →
  `mutated_value = verification_identifier() + "Z" + region + "Z"`
  (region = 모델 값에서 `Z`·비ASCII만 제거, ≤96자). 영숫자 식별자는 인코딩에도 살아남아
  **반영 탐지가 견고**해지고, 영역의 `<>"'`로 **인코딩 여부를 실제 측정**한다.
- SQLi는 그대로(마커 불필요; `sql_error`/status/length로 판정).

### 3. 프롬프트 소폭 개선 (학습 형식 유지)
- XSS: raw `<>"'`를 그대로 쓰고 URL/HTML-엔티티 인코딩 금지. 공통: 원본 값과 다르게.
- 학습 프롬프트에 짧게 *덧붙이는* 방식이라 파인튜닝 앵커를 해치지 않는다.

### 4. CLI 연결 (`src/vulnspider/cli.py`, +80)
- `--verify-proposer {deterministic,llm}`(기본 deterministic), `--llm-model PATH`
  (env `VULNSPIDER_LLM_MODEL`) — `analyze`/simple 양쪽. 모델 미설치/경로 오류는 요청 전에
  명확한 `CLIError`로 표면화.

### 5. 검증 계약 확장 (`src/vulnspider/verification/result.py`, +6)
- `VerificationResult`에 `based_on_value`(baseline 원본값)·`rationale`(모델 근거) 추가
  (순수 additive, contract-version 불변) — 상세 리포트가 baseline과 근거를 표시하도록.

### 6. 도구
- `tools/verification_detail_report.py`(+372): 입력점별 **baseline → 변형 요청(전체 URL) →
  검증기 판정 → 결과 → confidence 갱신**을 설명하는 self-contained HTML 리포트(크롤 JSON을
  조인해 요청 URL 복원).
- `tools/llm_verify_demo.py`(+89): 크롤 없이 실제 모델을 구동하는 sanity 체크.

### 7. 문서
- `docs/DYNAMIC_TESTING.md` + `README_DYNAMIC_TESTING.md`: 공개 테스트 사이트(vulnweb) 대상
  동적 스캔 사용법, **`--verify`는 loopback 전용**이라는 안전 제약, 트러블슈팅.
- `models/README.md`: 게이트된 GGUF/whl 설치 위치·방법.

### 8. CLI 실행 UX (`cli.py`, `focused.py`)
- 파이프라인 단계별 진행 로그(stderr): `[*] 크롤+분석 → [OK] → [*] 검증(후보별 i/N) → [OK]
  counts → [*] 리포트 → [OK]`. 긴 LLM 검증 단계가 더 이상 조용하지 않다.
- 실패 시 **어느 단계에서** 무슨 예외가 났는지 상세 출력(`error [stage]: Type: msg`).
- 완료 시 **대시보드 `file://` 링크**를 항상 제시하고, `--open`이면 브라우저로 자동 실행.
  `analyze` 모드에도 완료 요약을 추가(이전엔 없어서 무출력이었음).
- `VerificationConfig.progress` 콜백(관측 전용) 추가 — 검증 대상/결과는 바뀌지 않음.

## 안전 불변식

- 모델 출력은 신뢰하지 않는 입력. **모든 제안은 결정적 `PayloadValidator` 통과 후에만 전송**
  (길이 ≤256·printable ASCII·`;` 금지·파괴적 SQL 키워드 금지).
- 재프로브는 **loopback(localhost/loopback IP) 대상에만** 허용.
- 오케스트레이터가 transport·loopback 가드·prior·최종 confidence를 소유. **LLM은 최종 숫자를
  정하지 않는다.**

## 결과 / 측정

실제 모델 설치(`vulnspider-3b_v3.gguf` 1.8GB + `llama-cpp-python` prebuilt whl) 후 loopback
데모 서버(`demo_target_server.py`, `127.0.0.1:8899`) 대상 end-to-end:

- **k=20**: 후보 20개, 변형 페이로드 95개, 검증기 통과 75/차단 20, provider 전부
  `local-llm-vulnspider-3b`.

**하이브리드 마커 before → after (동일 타깃, k=20):**

| 지표 | before (자유형 값) | after (하이브리드) |
|---|---|---|
| XSS 인코딩 관측 | 0 / 38 | **14 / 38** |
| confidence 움직인 후보 | 0 | **11** (XSS 9×−0.169, SQLi 2×−0.056) |
| XSS 후보 판정 | 9 UNCHANGED · 6 INCONCLUSIVE | **9 WEAKENED** · 4 UNCHANGED · 1 INCONCLUSIVE |

- WEAKEN은 정당함: 관측된 인코딩 14개가 전부 1.0(안전 인코딩)이고, 검증된 top-20이 마침
  safe/xss_escaped 라우트였다(파이프라인이 false-positive XSS를 올바르게 약화).
- 하이브리드가 **raw 반영 → SUPPORTED, safe 인코딩 → WEAKENED**로 양방향 정상 동작함을
  결정적 테스트로 증명(`HybridMarkerXssTests`).

## 테스트

- 유닛 전체 **739 passed, 176 subtests** (신규 `tests/unit/test_llm_proposal.py`,
  하이브리드 raw→SUPPORT / safe→WEAKEN 회귀 포함).
- 실제 모델 추론은 fake LLM 주입으로 대체해 모델 없이도 매핑/degrade/full verify 루프를 커버.

## 실행 방법

```powershell
# 실행 엔진 + 모델 (게이트 저장소, models/ 아래 gitignore)
pip install .\models\llama_cpp_python-0.3.34-py3-none-win_amd64.whl

# loopback 데모 서버 대상 실제 LLM 검증
python demo_target_server.py            # 127.0.0.1:8899
$env:PYTHONPATH = "src"
python -m vulnspider analyze --url http://127.0.0.1:8899/ --top-k 20 `
    --verify --verify-proposer llm --llm-model models\vulnspider-3b_v3.gguf `
    --output analysis.json --verify-output verify.json --html-output dashboard.html

# 입력점별 상세 리포트
python tools\verification_detail_report.py --verify verify.json `
    --crawl vulnspider-crawl.json --out verification-detail.html
```

> ⚠️ 반드시 `python -m vulnspider`로 실행(모듈 `vulnspider.cli`는 실행 가드가 없어 조용히 종료).
> 설치된 `vulnspider` 콘솔 스크립트는 오래된 설치본을 가리킬 수 있음.

## 한계 / 후속

- 이번 run에서 **SUPPORTED XSS가 0**인 이유는 진짜 취약한 `xss_raw` 파라미터가 랭킹 top-K에
  안 든 **선택 아티팩트**(검증/모델 문제 아님). → 랭킹이 raw 반영 파라미터를 올리도록 후속.
- `SUPPORT_REPRODUCED`는 무보정 기본 모델에서 **LLR 0(설계상 중립)** — baseline이 이미 잡은
  신호의 재확인. 코퍼스 피팅으로 소폭 가중을 켤 수 있음.
- 프롬프트 힌트 효과는 미미(거부 수 불변); 결정적 개선은 하이브리드 마커.
- 모델은 3B 파인튜닝이라 novel WAF 우회 창의성은 없음(on-distribution). SQLi는 충분히 동작.

## 리뷰 노트

- **모델 바이너리는 저장소에 포함되지 않음**(게이트 HF `lsk0228/vulnspider-3b_v3`).
  `models/*.gguf|*.whl`는 gitignore; 실행하려면 `models/README.md`대로 받아야 함.
- 본체 코드 변경은 **additive** — deterministic 기본 경로/기존 계약은 그대로.
- (별도 정리 제안) `payload_verifier_v2/`에 커밋된 `__pycache__/*.pyc`는 gitignore/삭제 권장.

## 변경 파일 (로컬-AI 통합분)

```
 src/vulnspider/verification/llm_proposal.py   | +388  (신규 proposer)
 src/vulnspider/cli.py                         | +80   (--verify-proposer / --llm-model)
 src/vulnspider/verification/__init__.py       | +12   (export)
 src/vulnspider/verification/result.py         | +6    (based_on_value / rationale)
 tools/verification_detail_report.py           | +372  (상세 리포트)
 tools/llm_verify_demo.py                      | +89   (모델 sanity)
 tests/unit/test_llm_proposal.py               | +432  (신규 테스트)
 docs/DYNAMIC_TESTING.md / README_DYNAMIC_TESTING.md | +196 각각
 models/README.md                              | +40
 .gitignore                                    | +7    (모델 바이너리/캐시 제외)
```
