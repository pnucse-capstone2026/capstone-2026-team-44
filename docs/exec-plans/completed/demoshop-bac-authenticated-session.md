# DemoShop 인증 세션 + 네이티브 BAC 탐지

## Goal

DemoShop에 로그인 세션(admin / 일반 사용자)과 접근제어 엔드포인트를 추가하고,
VulnSpider의 BAC 파이프라인이 **진짜 취약점(true positive)**과 **정상 접근제어
(true negative)**를 실제 인증 상태에서 구분하도록 한다. 이를 위해 네이티브 정적
크롤러가 **운영자가 제공한 세션 쿠키**를 들고 크롤/재프로브하도록 지원한다.

## Non-Goals

- 로그인 자동화/계정 생성/인증 상태 변경 (AGENTS.md 금지). 쿠키는 운영자가 제공.
- 동적(브라우저) 크롤러의 쿠키 지원. 이번엔 정적 경로만.
- 새 취약점 패밀리·feature. BAC 파이프라인/feature는 그대로 사용.

## Context Read

- `src/vulnspider/access/{planner,features,executor,scoring}.py`
- `src/vulnspider/discovery/{static_crawler,html_extractor}.py`
- `src/vulnspider/domain/models.py` (RequestTemplate — id가 쿠키 포함)
- `src/vulnspider/observation/executor.py` (이미 request.cookies 전송)
- `tools/demo_shop.py`, `docs/DECISION_LOG.md` ADR-014/035

## Current State (왜 지금은 안 되나)

- 크롤러는 4xx 응답을 스킵(`static_crawler.py:502`) → 로그인 없이는 403인 정상
  접근제어 엔드포인트가 발견되지 않음(true negative 불가).
- 크롤러가 쿠키를 안 보내고 RequestTemplate에도 안 실음 → `CREDENTIAL_STRIP`이
  계획 자체가 안 됨. IDOR 참조 요청도 인증이 안 되어 403.
- BAC feature 2개(`access_unauthorized_success`, `access_body_size_similarity_ratio`)는
  **참조 요청이 인증된 2xx**여야 의미가 있음.
- `RequestTemplate.fingerprint/id`가 쿠키를 포함(models.py:325) → 사후 부착은 참조
  무결성을 깨뜨림. 쿠키는 **템플릿 생성 시점(추출기)**에 있어야 함.

## Proposed Changes

### A. 네이티브 세션 쿠키 지원 (정적 경로)
1. `CrawlPolicy.session_cookies: tuple[tuple[str,str],...]` 추가. `to_dict`에는
   **쿠키 이름만** 넣어 값이 fingerprint/직렬화로 새지 않게 함.
2. `StaticCrawlerRequest.cookies` 추가; 크롤 요청 생성(693)에서 정책 쿠키 주입;
   `UrlLibStaticCrawlerTransport.send`가 `Cookie` 헤더 전송.
3. `CanonicalDiscoveryBuilder(session_cookies=...)` → `RequestTemplate(cookies=...)`.
   `extract_static_html` / `..._with_sensitive_form_elision`에 `session_cookies`
   인자 추가(기본 빈값), 크롤러의 추출기 호출(535)에서 정책 쿠키 전달.
4. 크롤 리포트 직렬화에서 **쿠키 값 마스킹**(이름 유지) — 세션 토큰 유출 방지.
5. CLI `--cookie NAME=VALUE`(반복) — analyze + simple(`--static-only` 필수).
   `--dynamic`과 함께 쓰면 명확한 에러.

### B. DemoShop 인증/BAC
6. `/login?as=admin|user` → `demoshop_session` 쿠키 발급(역할·user_id 인코딩).
7. BAC 취약(1~2): IDOR(소유자 미확인 → 식별자 치환이 남의 자원 200),
   기능수준 접근제어 누락(권한 없는 세션도 200).
8. 정상 접근제어(true negative): 쿠키 제거/식별자 치환 시 403.
9. ground truth 라벨 + `/_lab` 갱신.

## Interfaces / Data Changes

- `CrawlPolicy`/`StaticCrawlerRequest`에 필드 추가(하위호환, 기본 빈값).
- `extract_static_html*`에 옵션 인자 추가(기본 빈값 → 기존 호출 불변).
- 크롤 리포트의 template.cookies 값은 마스킹되어 출력.

## Safety / Scope Impact

- **네트워크 동작 변경**: 운영자 지정 쿠키를 loopback 대상에 전송(읽기 전용 GET).
  계정 생성/로그인 자동화/상태 변경 없음. 세션은 운영자가 제공.
- 쿠키 값은 리포트에 마스킹. AGENTS.md "세션 시크릿 커밋 금지" 준수(데모는 가짜 토큰).

## Test Plan

- unit: 쿠키가 템플릿에 실림 / transport가 Cookie 헤더 전송 / CREDENTIAL_STRIP·
  IDENTIFIER_SUBSTITUTION이 인증 참조에서 계획됨 / 정상 엔드포인트 403→안전.
- unit(demo_shop): 로그인 쿠키 발급, BAC 엔드포인트 상태, 정상 엔드포인트 403,
  ground truth 라벨 정합.
- e2e(수동): `analyze --url ... --access-control --cookie ... --ground-truth ...`로
  BAC true positive/negative가 랭킹·평가에 반영되는지.

## Acceptance Criteria

- [x] `--cookie`로 인증 크롤 → 보호 엔드포인트 발견
- [x] BAC 취약이 `access_unauthorized_success=1.0`로 탐지, 정상은 0.0
- [x] 크롤 리포트에 세션 토큰 값이 마스킹됨
- [x] 전체 테스트/정적 검사 통과, 문서 갱신

## Progress Log

- 2026-08-27: 조사 완료(파이프라인/크롤러/템플릿 id 제약). 구현 착수.
- 2026-08-27: 구현 완료. `/portal/` 인증 영역(IDOR 2 + 정상 1) + 네이티브
  `--cookie`. 실측(`analyze --url .../portal/ --access-control --cookie ...`,
  top-10): IDOR 2개 최종 0.953(1~2위), 정상 접근제어 0.524(4위);
  Recall@2 1.000 / MAP@K 1.000 vs random 0.22~0.29. live 평가의 credential-strip
  스킵, 크롤 리포트 쿠키 마스킹 반영. 전체 859 테스트 통과. ADR-037 기록.
  완료 후 이 계획은 completed/로 이동 예정.
