# NO-2 Balanced Same-Scope GET/HEAD fetch/XHR Runtime Transport

## Goal

Allow naturally emitted, exact same-origin `fetch` and XHR GET/HEAD requests in the
default simple CLI dynamic run while preserving the strict low-level browser default,
the existing transport budget, per-hop redirect authorization, and NO-1 passive
observation invariants.

## Scope

- Add one explicit runtime-authority switch with a strict default of `False`.
- Enable it only through the existing simple CLI dynamic wiring.
- Allow primary-page fetch/XHR GET and HEAD only when scheme, host, and effective port
  exactly match the configured root URL.
- Keep exact resource grants authoritative and backward compatible.
- Add a dedicated allow audit reason for this balanced path.
- Preserve `route.fetch(max_redirects=0)` and authorize every redirect hop using the
  request's original method.
- Add unit and real Chromium loopback coverage, including exact server-side counts.

## Non-goals and invariants

- No request creation, replay, retry, or observation-driven transport.
- No POST/PUT/PATCH/DELETE transport.
- No suffix-host, cross-scheme, cross-host, cross-port, non-primary-page, or
  cross-origin redirect allowance.
- No raw Cookie, Authorization, JWT, password, token, body, or header persistence.
- No change to NO-1 observation schema, installation order, retention bounds, budget
  accounting, or observer side effects.
- No change to canonical Endpoint/InputPoint/RequestTemplate conversion, merge,
  feature/scoring/top-k/BAC/LLM, authentication/session, DOM interaction, or browser
  context count.
- `--static-only` remains unchanged.

## Design decisions

1. Add `allow_passive_same_origin_fetch_xhr: bool = False` to
   `DynamicRequestAuthority`. The low-level default remains strict; `_simple_analysis_args`
   reaches `_dynamic_authority_from_args(..., simple_mode=True)`, which enables it
   without a new CLI option.
2. Evaluate GET/HEAD plus fetch/XHR plus exact origin as one narrow balanced allowance.
   Other non-GET methods retain `NON_GET_METHOD`; all existing scope and page checks
   remain in force.
3. Exact `FETCH_XHR` grants continue to allow their existing GET requests and retain
   the existing exact-grant reason.
4. Pass the original request method into redirect-hop authorization. A HEAD redirect
   therefore remains HEAD; `route.fetch(max_redirects=0)` continues to prevent hidden
   browser-library redirect following.
5. Do not include the new transport-policy bit in the canonical discovery
   configuration fingerprint. It is a runtime permission, not a discovered surface;
   toggling it must not structurally change a snapshot when canonical results are
   otherwise identical. Newly reachable page behavior may still change actual
   discovery content in the normal way.
6. NO-1 observations remain passive evidence only. They are neither canonicalized nor
   converted into API endpoints in NO-2; that work is deferred to NO-3.

## Files expected to change

- `src/vulnspider/discovery/dynamic_browser.py`
- `src/vulnspider/cli.py`
- `tests/unit/test_dynamic_browser.py`
- `tests/unit/test_simple_cli.py`
- `tests/unit/test_dynamic_crawler.py` or the closest snapshot-invariance unit module
- `tests/integration/dynamic_loopback_site.py`
- `tests/integration/test_dynamic_browser_loopback.py`
- `tests/integration/test_simple_cli_loopback.py`
- strict browser-loopback manifest in `tools/check_dynamic_gate.py`

## Verification

1. Baseline focused unit tests and the existing strict/simple Chromium cases.
2. Focused authority, route-guard, crawler, simple CLI, and loopback tests.
3. Real Chromium balanced loopback with exact counts: natural GET fetch/XHR and HEAD
   each once; POST and cross-port sentinel zero; redirects manually authorized; no
   doubled transport.
4. Real Chromium strict fixture proving ungranted fetch/XHR remain zero transport.
5. Strict browser-loopback manifest with zero skips.
6. Related CLI/pipeline tests, then the full unit suite.
7. Formatting, lint, types, diff/status, protected JSON hashes, and stash OID checks.
8. Independent fresh review; fix Critical/High and invariant-affecting Medium findings,
   then rerun the affected focused, Chromium, and full gates.

## Progress

- [x] Read repository rules and relevant architecture/contracts/decision material.
- [x] Verify starting branch, HEAD, protected untracked files, staged state, and stash.
- [x] Run focused unit baseline (82 tests, pass).
- [x] Run strict fetch/XHR Chromium baseline (pass).
- [x] Run simple CLI Chromium baseline (pass).
- [x] Implement the narrow runtime policy and simple-mode wiring.
- [x] Add unit and real Chromium loopback tests.
- [x] Run all verification gates.
- [x] Complete independent review and remediation.
- [x] Move this plan to `docs/exec-plans/completed/` for the final explicit commit.

## Outcome

- Added a strict-default runtime authority bit and enabled it only for the existing
  simple dynamic CLI path.
- Balanced primary-page fetch/XHR GET and HEAD use exact origin matching and the stable
  `PASSIVE_SAME_ORIGIN_FETCH_XHR` audit reason.
- Redirect transport remains `max_redirects=0`; every hop is re-authorized with the
  original method. Real Chromium proved same-origin GET redirect hops execute once and
  a different-port next hop executes zero times.
- POST and off-origin attempts remain passively observed but have zero server-side
  transport. Observations remain secret-free, bounded, and excluded from canonical
  endpoint/input conversion.
- Independent review found two invariant-affecting Medium issues: whitespace method
  normalization and explicit port `0` collapsing to the default port. Both were fixed,
  covered by unit regressions, and accepted by a read-only correction review with no
  remaining Critical/High/invariant-Medium findings.
- Final verification: focused units 61/61, unit suite 436/436, browser-loopback
  17/17 with zero skips, repository suite 492/492, and format/lint/type checks pass.
