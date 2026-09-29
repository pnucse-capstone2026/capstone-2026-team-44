# Native Dynamic Discovery MVP Execution Plan

## 1. Purpose and Success Definition

Native Static Discovery is implemented and merged, but it can inspect only the
HTTP response HTML received by `StaticCrawler`. It cannot observe anchors,
forms, inputs, or route state created after JavaScript executes. That leaves a
measurable discovery gap for the bounded loopback applications targeted by the
v0.2 prototype.

Native Dynamic Discovery adds one browser-backed producer that:

- renders an authorized loopback HTTP(S) page in a fresh headless context;
- waits for a bounded, testable DOM stabilization condition;
- collects the rendered main-frame DOM and current client-side route;
- discovers dynamically created anchors, forms, and successful controls;
- passively discovers route candidates and navigates only exact URLs authorized
  by the caller independently of DOM content;
- emits `CanonicalDiscoveryResult` data using the existing domain identities;
- merges its result with the Static Discovery result in one deterministic order.

Successful MVP completion means that a local JavaScript fixture proves all of
the following:

- rendered-only elements enter the same canonical consumer used by Static
  Discovery;
- static and dynamic observations of one semantic surface deduplicate without
  losing either provenance record;
- repeated occurrences, blank values, and raw percent-encoded query tokens
  survive extraction and merge;
- no cross-origin request, cross-origin navigation, POST submission, or
  unapproved same-origin request reaches either test server;
- all browser, page, context, navigation, action, DOM-size, and elapsed-time
  bounds are enforced;
- browser resources are closed on success, timeout, page crash, and exception;
- existing Static Discovery, legacy `--input`, scoring, selection, and reporting
  behavior remains unchanged when dynamic discovery is not requested;
- the complete existing regression and quality suite remains green.

The result remains a discovery producer. It may create `Endpoint`,
`InputPoint`, `RequestTemplate`, `InputPointRequestContext`,
`DiscoveryProvenance`, `ProbeReadiness`, and `DiscoveryWarning` records. It
must not generate payloads, submit forms, execute attacks, score
vulnerabilities, update confidence, or claim that any vulnerability exists.

## 2. Current Repository Baseline

### Confirmed implementation evidence

- `src/vulnspider/discovery/contracts.py`
  - `CONTRACT_VERSION = "canonical-discovery/1.0"`.
  - `CollectorKind` already contains `NATIVE_STATIC`, `NATIVE_DYNAMIC`, and
    `LEGACY_COMPATIBILITY`.
  - `CanonicalDiscoveryResult.create()` canonicalizes the ordering of
    endpoints, inputs, templates, contexts, readiness records, provenance,
    hints, and warnings, then calls `validate()`.
  - `CanonicalDiscoveryResult.validate()` checks stable identities, child
    references, ownership, counts, ordering, provenance, metadata, and probe
    readiness.
  - `CanonicalDiscoveryResult.ready_contexts()` is the existing producer-to-
    consumer handoff.
  - Current provenance validation requires both
    `DiscoveryProvenance.discovery_run_id == result.discovery_run_id` and
    `DiscoveryProvenance.collector_kind ==
    result.discovery_metadata.collector_kind`. This prevents a valid combined
    result from retaining both static and dynamic collector provenance without
    a reviewed contract extension.
  - Existing non-ready reasons cover missing/partial/unknown request context,
    form-boundary and hidden-input uncertainty, untrusted method/action,
    missing or misaligned raw query, and unsupported input location.
- `src/vulnspider/discovery/html_extractor.py`
  - `extract_static_html()` is transport-free and returns
    `StaticExtractionResult`.
  - It resolves relative links, preserves raw query tokens and repeated
    occurrence indexes, applies HTML successful-control behavior, preserves
    hidden controls, and creates canonical forms and query contexts.
  - It currently requires `DiscoveryMetadata.collector_kind` to be
    `NATIVE_STATIC`.
  - Existing semantics include default GET and current-document form behavior,
    POST discovery without submission, disabled/unnamed/unchecked control
    warnings, first/selected option behavior, and deterministic warning/output
    ordering.
- `src/vulnspider/discovery/static_crawler.py`
  - `CrawlPolicy` defaults are 10 pages, depth 2, 20 requests, 3-second request
    timeout, 3 redirects, no delay, 10 seconds total elapsed time, and 512,000
    response bytes.
  - `StaticCrawler.crawl(root_url, policy)` uses a heap queue, same-origin
    checks, bounded redirect handling, GET-only transport, response-size
    bounds, and structured warnings.
  - `canonicalize_crawl_url()` normalizes HTTP(S) identity while preserving
    path/query data and removing fragments.
  - The implemented same-origin definition is scheme, lower-cased hostname,
    and effective port through `_origin()` / `_same_origin()`.
  - `_build_discovery_result()` and `_merge_input_points()` merge per-document
    static observations deterministically, but are private static-crawler
    helpers rather than a reusable cross-producer merge API.
- `src/vulnspider/discovery/__init__.py` exports the canonical contract,
  Static Discovery policy, transport, crawler, result, URL canonicalizer, and
  `extract_static_html`.
- `src/vulnspider/domain/models.py`
  - owns `Endpoint`, `InputPoint`, `RequestTemplate`, and
    `InputPointRequestContext`;
  - includes stable fingerprint helpers and occurrence identity;
  - treats query and form inputs as the implemented locations;
  - validates input/template/context ownership.
- `src/vulnspider/pipeline.py`
  - `analyze_url()` currently runs `StaticCrawler` and passes its
    `CanonicalDiscoveryResult` to `analyze_discovery_result()`;
  - `analyze_discovery_result()` validates the result, consumes only
    `ready_contexts()`, and permits only GET request templates;
  - `AnalysisResult` retains the authoritative discovery result and static
    crawl result;
  - crawler warnings become report warnings, not candidates or findings.
- `src/vulnspider/cli.py`
  - `vulnspider analyze` requires exactly one of `--input` or `--url`;
  - `--url` currently means bounded Native Static Discovery;
  - Static policy flags are `--max-pages`, `--max-depth`, `--max-requests`,
    `--timeout-seconds`, and `--max-redirects`;
  - legacy `--input` rejects native policy options;
  - JSON output is required and HTML output remains optional.

### Existing tests and checks

- Canonical contract:
  `tests/unit/test_discovery_contract.py` and
  `tests/unit/test_discovery_contract_adversarial.py`.
- Static extraction:
  `tests/unit/test_html_extractor.py` and
  `tests/unit/test_html_extractor_adversarial.py`.
- Static crawler:
  `tests/unit/test_static_crawler.py`,
  `tests/unit/test_static_crawler_adversarial.py`, and
  `tests/integration/test_static_crawler_loopback.py`.
- Pipeline/CLI:
  `tests/unit/test_native_pipeline_cli.py`.
- End to end:
  `tests/integration/test_native_static_discovery_e2e.py` and the unchanged
  `tests/integration/test_v01_smoke.py`.
- The current full suite has 266 passing tests at this plan baseline.
- Repository checks are:
  `python -B -m unittest discover -s tests`,
  `python -B tools/check_format.py`,
  `python -B tools/check_lint.py`,
  `python -B tools/check_types.py`, and `git diff --check`, with
  `$env:PYTHONPATH='src'` documented for this source layout.
- No repository secret-scanning command exists. Secret review is therefore a
  required diff-review item, not an invented command.

### Dependencies and documentation

- `pyproject.toml` uses `setuptools.build_meta`, requires Python 3.11 or newer,
  declares `dependencies = []`, has no optional dependency groups, and has no
  project lockfile.
- Neither Playwright nor Selenium is a declared project dependency, lockfile
  entry, production import, test import, or currently importable package in the
  audited environment.
- `tools/check_lint.py` currently forbids any Playwright import under `src/`.
  A browser adapter cannot be added until that rule is narrowed deliberately;
  removing the safety rule wholesale is not acceptable.
- `reference/whspider_legacy/` contains historical Playwright code, but
  `AGENTS.md` makes it read-only reference material. It is not a reusable
  contract or implementation base.
- `README_START_HERE.md`, `AGENTS.md`, `docs/ARCHITECTURE.md`, and
  `docs/PROTOTYPE_V0_2.md` still describe Native Static Discovery or direct URL
  input as planned/unimplemented even though merge commit
  `7598fdee9fabd1372b1c9e5810792aed26b1c45c` implements it. This is a known
  documentation-alignment issue. This planning task records it but does not
  modify those documents.

## 3. Producer and Consumer Boundary

### Boundary definition

- Producer input: one canonicalized, explicitly authorized loopback root URL;
  a validated `DynamicCrawlPolicy`; a proposed immutable
  `DynamicRequestAuthority`; and a browser lifecycle implementation.
- Producer output: one validated `CanonicalDiscoveryResult` whose
  `DiscoveryMetadata` identifies native dynamic collection, plus a
  `DynamicCrawlResult` containing `COMPLETE`/`DEGRADED` completion state,
  bounded operational/audit summaries, and no duplicated canonical ownership.
- Aggregate input: Static and Dynamic producer results whose extraction paths
  have already applied the proposed Sensitive Form Pre-Canonical Elision policy
  and independently validated their canonical output.
- Aggregate boundary: only when Dynamic aggregation is requested, use the
  opt-in eliding Static extractor and the rendered-DOM eliding extractor before
  either producer creates canonical form artifacts. The merger receives only
  already-safe producer results and performs no sensitive-form filtering,
  reconstruction, splitting, repair, or cross-producer secret matching.
- Aggregate output: one validated combined `CanonicalDiscoveryResult`.
- Canonical consumer: existing
  `vulnspider.pipeline.analyze_discovery_result()`.

```text
Root URL
  -> StaticCrawler(policy-bound extractor) --\
                                            -> deterministic canonical merge
  -> DynamicCrawler(rendered pre-elision) --/     -> CanonicalDiscoveryResult
       -> fresh headless browser              -> ready_contexts()
       -> rendered DOM snapshots              -> existing analysis pipeline
       -> authority-filtered route navigation
```

Data crossing the producer boundary is limited to canonical domain records,
scope metadata, bounded crawl statistics, structured warnings, probe readiness,
redacted provenance, and a secret-free `BrowserAuditSummary` carried by
`DynamicCrawlResult`. Browser objects, Playwright handles, DOM nodes, network
request objects, response bodies, JavaScript exceptions, cookies, headers,
storage state, and credentials must not cross it.

Static-only compatibility is explicit: if Dynamic mode is not requested, the
existing Static result and its current extraction/readiness behavior are not
rewritten by this MVP. Sensitive Form Pre-Canonical Elision is enabled only by
the explicit Dynamic aggregation path through a backward-compatible extraction
policy; default `extract_static_html()` and `StaticCrawler` behavior remain
unchanged. Legacy `--input` behavior is also unchanged.

Discovery eligibility and request authority are separate. DOM extraction may
record a canonical URL, but only the caller can place that exact URL in
`DynamicRequestAuthority`. The explicitly supplied root URL is the sole
implicit navigation authorization. Rendered anchors, History API state, form
actions, redirects, frames, popups, and page script never mutate or expand the
authority object.

Enumerated operational browser failures become typed internal errors and may
produce a validated partial result with `DYNAMIC_INCOMPLETE`. Canonical
integrity failures, including invalid references, ownership, provenance,
statistics, or merge invariants, are typed hard failures and never become a
normal Static-only success. Section 21 defines the exact CLI behavior.

Crawler warnings describe collection limits or rejected observations. They
must never become `FeatureVector`, `VulnerabilityCandidate`, `ScoreEvidence`,
rank, confidence, or finding records. Existing pipeline behavior already
forwards discovery warnings separately from candidate creation and must remain
the consumer rule.

## 4. Proposed Module Boundaries

The smallest layout that keeps browser I/O, DOM preprocessing, crawl policy,
and merge ownership separate is four production modules plus narrow edits at
existing public boundaries.

| Proposed file/API | Responsibility, inputs, and outputs | Dependencies | Prohibited responsibilities |
|---|---|---|---|
| `src/vulnspider/discovery/dynamic_browser.py` | Define the proposed immutable `DynamicRequestAuthority`, immutable browser navigation/snapshot records, a narrow `DynamicBrowser`/session protocol, typed lifecycle errors, proposed secret-free `BrowserAuditSummary`, and the synchronous `PlaywrightDynamicBrowser` adapter. Input is an exact URL admitted by caller-owned request authority plus per-navigation bounds; output is a redacted `RenderedDomSnapshot`, audit summary, or typed error. | Standard library plus Playwright only inside the concrete adapter. | Canonical model creation, merge, scoring, form submission, arbitrary clicking, deriving authority from DOM, persistent profiles, secret logging. |
| `src/vulnspider/discovery/rendered_dom.py` | Define `extract_rendered_dom(snapshot, metadata, scope, authority)` and the extraction-relevant stabilization projection. Detect rendered `input[type=password]` structurally before reading form-control values, omit the entire form from canonical projection, emit one `SENSITIVE_FORM_ELIDED` warning, then reuse Static HTML extraction semantics for non-sensitive surfaces. The sensitive form contributes no Endpoint or other canonical artifact. | Canonical contracts, domain models, request-authority type, elision policy, and the transport-free HTML extractor. No Playwright import. | Browser launch/navigation, network I/O, route actions, scoring, building any password form artifact, storing live password values, expanding authority. |
| `src/vulnspider/discovery/dynamic_crawler.py` | Own `DynamicCrawlPolicy`, deterministic discovery ordering, application of immutable request authority, network/action/page/time budgets, stabilization orchestration, partial-result warnings, and `DynamicCrawler.crawl(root_url, policy, authority) -> DynamicCrawlResult`. | Browser protocol and request-authority type, rendered DOM extractor, URL canonicalization, canonical contracts. | Playwright-specific calls, deriving authority from discovered content, static transport changes, probe execution, form submission, reporting. |
| `src/vulnspider/discovery/discovery_merge.py` | Own `merge_discovery_results(static_result, dynamic_result, policy) -> CanonicalDiscoveryResult`. Require each producer to validate and satisfy the pre-canonical-elision contract, then merge surviving identities in Static-first order, preserve producer-local sensitive-form warnings without cross-producer deduplication, rebuild counts, and validate output. | Canonical contracts and domain identity helpers. | Sensitive-form detection/filtering, post-coalescing reconstruction, crawling, parsing, browser lifecycle, scoring, value placeholders, cross-producer secret matching, synthetic merged warnings, catching canonical integrity failures. |
| `src/vulnspider/discovery/contracts.py` | Minimal additive aggregate-contract extension: an aggregate collector discriminator, allowed contributing provenance kinds for aggregate results, proposed request-not-authorized non-ready reason, `SENSITIVE_FORM_ELIDED` warning code policy, Static-before-Dynamic aggregate warning ordering without changing warning identity, and a reviewed contract-version update if required. Existing domain binding identity is unchanged. | Existing canonical/domain code only. | Browser imports, dynamic execution policy, optional request values, revised warning identity, or revised input/template binding semantics. |
| `src/vulnspider/discovery/html_extractor.py` | Add the proposed keyword-only `sensitive_form_policy` seam to `extract_static_html()`, defaulting to current behavior. When enabled, perform a value-blind structural form pass, then prevent marked form occurrences from reaching `_Builder.add_form()` in the canonical pass. Provide a policy-bound extractor callable compatible with the existing `StaticCrawler.extractor` protocol. | Standard library and canonical/domain code. | Browser/network behavior, post-canonical repair, reading password values, or dynamic navigation policy. |
| `src/vulnspider/discovery/__init__.py` | Export only the reviewed public dynamic policy, browser protocol, result, extractor, crawler, and merge APIs. | Discovery modules. | Runtime side effects or eager Playwright import that breaks Static-only use. |
| `src/vulnspider/pipeline.py` and `src/vulnspider/cli.py` | Later opt-in orchestration only. Validate explicit navigation/resource authority, bind the elision policy into the injected Static extractor only for `--dynamic`, run Static and Dynamic, enforce Section 21 failure categories, merge, and pass exactly one canonical result to the existing consumer. | Public discovery APIs. | DOM parsing, browser implementation, scoring changes, automatic browser installation, treating capability or integrity failure as success. |
| `tests/integration/dynamic_loopback_site.py` | Shared deterministic `ThreadingHTTPServer` harness with primary/sentinel counters, authorized and unauthorized paths, JavaScript safety cases, and secret-free browser-audit assertions. | Standard library only. | Production imports that execute crawling or any external target. |

`DynamicCrawlPolicy` remains in `dynamic_crawler.py`; a separate policy package
would add abstraction without a second consumer. Authority-filtered route
scheduling also remains in `DynamicCrawler`; the browser adapter receives only
exact caller-approved URLs. The loopback harness is test-only and never ships
as application code.

## 5. Browser Lifecycle

### Chosen API style

Use Playwright's synchronous Python API for this MVP. The repository is
synchronous end to end: `StaticCrawler.crawl()`, `urllib` transports,
`pipeline.analyze_url()`, `cli.main()`, standard `unittest`, and
`ThreadingHTTPServer` fixtures. A synchronous adapter avoids introducing an
event-loop ownership contract, async CLI boundary, or mixed sync/async test
stack for a bounded single-browser prototype. The async API is not an Open
Decision for this MVP.

### Required lifecycle

1. Resolve the optional Playwright import only when dynamic discovery is
   explicitly invoked. Static and legacy imports must continue to work without
   Playwright installed. An explicit Dynamic CLI request performs capability
   preflight and fails with the Section 21 configuration status if the Python
   package or matching Chromium executable is unavailable.
2. Start Playwright and launch one supported headless Chromium process with no
   persistent user-data directory.
3. Create a new incognito-like browser context for one dynamic crawl. Supply no
   storage state, cookies, authorization headers, client certificates, proxy
   credentials, or user browser profile.
4. Immediately after context creation, configure both mandatory context-wide
   transport guards before creating the first page: default-deny HTTP(S)
   request interception and a WebSocket denial hook. The HTTP(S) guard admits
   only GET requests whose exact canonical URL and resource category are
   present in caller-owned `DynamicRequestAuthority`; cross-origin, non-GET,
   popup/frame, EventSource, and all other requests are aborted before
   transmission. The proposed Playwright dependency is
   `BrowserContext.route_web_socket()`, introduced in Playwright 1.48, with a
   proposed supported constraint of `playwright>=1.48,<2`. Milestone 2 must
   verify that lower bound and API behavior against official Playwright Python
   documentation before implementation. Strict capability preflight must fail
   if the installed package lacks the context-wide hook; WebSocket protection
   is mandatory and cannot be disabled or downgraded.
5. Create one primary page. Attach crash, popup/new-page, console/JavaScript
   error, and request accounting hooks before navigation.
6. Navigate first to the explicitly authorized root. Additional navigation
   occurs only when the exact canonical URL is in the caller-supplied
   navigation set; being same-origin or discovered in the DOM is insufficient.
   Wait for `DOMContentLoaded`, then run the bounded stabilization procedure.
7. Collect only the redacted rendered snapshot/projection, discovered route
   candidates, and secret-free audit evidence. Release element handles
   immediately; no live handle crosses the adapter boundary.
8. Reuse the isolated context/page only within the same bounded crawl so
   passive same-page route behavior can be observed, but reset only to an exact
   caller-approved URL for each scheduled navigation. Never reuse it across
   analyses.
9. Close page, then context, then browser, then Playwright in nested
   `finally` cleanup. Cleanup is attempted exactly once for every successfully
   created resource.

This ordering is invariant: context creation, then HTTP(S) routing and the
context-wide WebSocket denial hook, then page creation, navigation, and any
authorized page script. A page must never exist in a context during a window in
which either guard is absent.

Browser launch failure, missing executable, page crash, navigation timeout,
stabilization timeout, and JavaScript error have typed codes. A JavaScript
error alone is a warning if a valid bounded snapshot remains available. Launch
failure, page crash before snapshot, or navigation failure yields no dynamic
records for that page. Cleanup errors retain the primary error, add a safe
cleanup code, and force the Section 21 degraded exit rather than a successful
warning-only result.

Headless mode is mandatory. Persistent contexts, `user_data_dir`, connection
to an installed user's browser, browser extension loading, downloads, tracing
with bodies, screenshots containing secrets, video, HAR recording, and
credential reuse are prohibited.

## 6. Same-Origin and Safety Policy

Dynamic Discovery reuses the Static Discovery origin tuple: lower-cased scheme,
lower-cased hostname, and effective port. The private static helpers must not be
imported directly; Milestone 1 or 4 promotes a reviewed shared origin predicate
beside `canonicalize_crawl_url()` without changing Static behavior. Passing the
origin predicate is necessary for scope, but never grants request authority.

### Discovery eligibility versus request authority

A proposed immutable `DynamicRequestAuthority` is created only from caller
input before browser launch. It contains:

- the exact canonical root URL, which is the sole implicit navigation grant;
- a sorted, duplicate-free set of exact canonical additional navigation URLs;
- a sorted, duplicate-free set of exact canonical resource grants, each paired
  with one category: `script`, `style`, or `fetch_xhr`;
- a stable fingerprint included in the Dynamic configuration fingerprint.

Every entry must be same-origin with the root and HTTP(S); invalid,
cross-origin, credential-bearing, fragment-only, or malformed entries are
configuration errors before browser launch. CLI/API proposals are repeatable
`--dynamic-allow-navigation URL` and
`--dynamic-allow-resource CATEGORY=URL`, backed by an API constructor rather
than parsed inside the browser adapter.

A URL can be eligible for extraction and canonical discovery without being
authorized for transport. Rendered anchors, form actions, History API state,
hash changes, JavaScript-created URLs, redirects, popups, and frames are
untrusted observations. They never add entries to request authority. A
discovered but unauthorized URL is recorded when representable, receives a
safe `DYNAMIC_REQUEST_NOT_AUTHORIZED` warning/audit decision, and is never
requested by the browser. Any input context derived only from that unauthorized
Dynamic surface is also `NOT_READY` with the proposed
`REQUEST_NOT_AUTHORIZED`; this prevents the existing canonical consumer from
turning browser-blocked discovery into a later request. A separately complete
Static context retains its existing independently validated readiness.

Resource authority is separate from navigation authority. Images, fonts,
media, downloads, frame documents, and popup documents are blocked in this MVP.
Scripts and styles are allowed only through an exact category-matched resource
grant. Same-origin fetch/XHR is blocked by default and is allowed only for an
exact `fetch_xhr` grant. Cross-origin requests remain blocked even if a caller
attempts to list them.

**C-01-R1 corrected decision and test ownership:** `ws://` and `wss://` are
never authorized in this MVP. Same-origin, an exact
HTTP navigation/resource grant, DOM content, and page JavaScript cannot grant
or expand WebSocket authority. WebSocket traffic is discovery-irrelevant and
always closed by the mandatory context-wide hook before a handshake reaches a
server; no WebSocket connection may be established.

EventSource remains HTTP(S), but it has an explicit resource classification and
does not implicitly inherit document or `fetch_xhr` authority. The recommended
and required MVP policy is complete denial: there is no EventSource authority
category, and every same-origin or cross-origin EventSource attempt is aborted
by context routing before transmission. Any future allowance would require a
separate exact caller-approved `eventsource` category and a new Gate Review; it
is not part of this plan.

| Surface/event | May appear in DOM/snapshot | May become warning/provenance | May be navigated/requested |
|---|---:|---:|---:|
| Explicit root URL | Yes | Yes | Yes; exact root grant and budgets are required |
| Same-origin anchor/form action | Yes, resolved canonically | Yes | Anchor only when its exact URL is in navigation authority; form action is never submitted |
| Unauthorized same-origin URL | Yes | Yes, `DYNAMIC_REQUEST_NOT_AUTHORIZED` | No |
| Cross-origin anchor/form action | Redacted/fingerprinted only | Yes, `OFF_SCOPE_DYNAMIC_*` | No |
| Redirect target | Sanitized observation | Yes | Follow only an exact same-origin navigation/resource grant; otherwise abort before dispatch |
| Automatic `history.pushState`/`replaceState`/hash route | Yes | Yes | Passive record only; later direct navigation requires an existing exact navigation grant |
| Popup/new page | No DOM extraction | Yes | All popup document requests blocked; page closed immediately |
| iframe | Element may be counted; child DOM ignored | Yes | All child-frame document requests blocked |
| JavaScript location assignment | Attempt/final location may be observed safely | Yes | Request proceeds only for an existing exact navigation grant; page code cannot grant authority |
| Cross-origin resource | Element URL may exist | Yes when blocked | No |
| Same-origin script/style | Not a discovery surface | Count only | Only an exact category-matched resource grant |
| Same-origin fetch/XHR | Not a discovery surface | Count only | Blocked by default; only an exact `fetch_xhr` grant may proceed |
| Same-origin or cross-origin EventSource | Not a discovery surface | Count attempt/block only | Always aborted before transmission; does not inherit document or `fetch_xhr` authority |
| Same-origin or cross-origin WebSocket | Not a discovery surface | Count attempt/block/connection outcome only | Always denied by the pre-page context-wide WebSocket hook; HTTP authority is irrelevant |
| Image/font/media/download | Element URL may exist | Yes when blocked | No, regardless of origin |
| POST/PUT/PATCH/DELETE or any non-GET request | Not stored | Yes, method and sanitized URL shape only | Always aborted regardless of authority |

The initial root and every authority entry are canonicalized before browser
launch. Every redirect, request, rendered URL, form action, route observation,
and main-frame change is canonicalized and checked against both origin and the
immutable authority object. Context routing is the mandatory transport guard,
configured before page creation. Service workers are blocked so they cannot
bypass it.

HTTP(S) routing is not claimed to cover every browser transport. The separate
context-wide WebSocket hook is required for socket handshakes, while
EventSource is classified and denied by HTTP(S) routing. Both guards must be
active before page creation and before authorized scripts can execute.

No form is submitted. No button, submit control, generic `[onclick]` element,
target-blank link, or script-defined arbitrary action is activated. No attack
payload or mutated value is generated. Route names such as `delete`, `reset`,
or `logout` are not interpreted; exact caller authority, not keyword blocking,
controls transport.

### Secret-free browser audit evidence

The proposed immutable `BrowserAuditSummary` contains:

- contexts created and closed;
- pages created and closed;
- popup creation attempts;
- `child_frame_attach_attempt_count`;
- `child_frame_document_request_count`;
- `child_frame_document_blocked_count`;
- `child_frame_commit_count`;
- `child_frame_completion_count`;
- `child_frame_detach_count`;
- `child_frame_authorized_commit_count`,
  `child_frame_unauthorized_commit_count`,
  `child_frame_authorized_completion_count`, and bounded counts classifying
  `about:blank`, browser-error, and replacement-document commits/completions;
- bounded enum-only `child_frame_commit_kinds` and
  `child_frame_completion_kinds`, plus independent overflow counts, so scalar
  totals continue after evidence sampling reaches its policy limit;
- bounded `child_frame_committed_origin_summaries`;
- navigation attempts and approved navigation completions;
- main-frame committed origin tuples;
- `websocket_attempt_count`, `websocket_blocked_count`, and
  `websocket_connected_count`;
- `eventsource_attempt_count`, `eventsource_blocked_count`, and
  `eventsource_allowed_count`;
- allowed request counts by resource category;
- blocked request counts by policy category;
- redirect blocks; and
- cleanup completion count and final cleanup-complete flag.

Bounded sanitized events may contain only decision category, scheme,
lower-cased host, effective port, normalized path, query-name count, and a
redacted query-name structure. They never contain query values, cookies,
headers, authorization data, bodies, storage, DOM, passwords, or provider
exception dumps. Event storage is capped by the browser-request-decision budget;
aggregate counts continue after the event sample cap.

**H-03-R1 corrected audit decision and test ownership:** Milestones 2, 4, and 7
own the schema, strict lifecycle cases, and final E2E evidence respectively.
Child-frame lifecycle counting is ordered and exact:

1. attachment counts when a non-main frame object/element is observed;
2. document-request attempt counts when routing observes its document request;
3. block counts before transport when policy aborts that request;
4. commit counts only when the browser reports a new child-frame document;
5. completion counts only when the browser reports load/completion for that
   committed document; and
6. detach counts when the child frame is detached or cleanup removes it.

A blocked request may cause Chromium to commit an internal error document. That
commit and any completion are classified as browser-error, `about:blank`, or
replacement-document activity, never as an authorized fixture document or an
authorized completion. Authorized and unauthorized fixture commits have
separate counters; an authorized completion must be a subset of an authorized
commit. Each bounded committed-origin summary contains only scheme,
lower-cased hostname, effective port, and a safe normalized path. Separate
scalar counters and a parallel bounded enum-only classification sequence
distinguish authorized, unauthorized, `about:blank`, browser-error, and
replacement commits without adding URL data to that sequence. Neither form
stores query text or values, fragments, credentials, headers, bodies, or DOM.
Both bounded collections have a policy maximum; excess items increment a
structured truncation/overflow counter while the scalar totals continue.

WebSocket counters mean: an attempt was observed by the context-wide hook, a
block was closed before handshake transport, and a connection was established.
For this MVP, blocked must equal attempts and connected must be zero.
EventSource counters mean: an HTTP(S) EventSource request reached routing, was
aborted before transmission, or was allowed. For this MVP, blocked must equal
attempts and allowed must be zero. These counters and their bounded summaries
never contain cookies, authorization/request headers, socket messages,
EventSource response data, query values, bodies, or storage state.

Adapter fakes prove counter arithmetic, ordering, cleanup-state transitions, and
redaction. Real Playwright loopback tests must additionally prove interception
ordering, popup/frame behavior, redirects, JavaScript location attempts,
fetch/XHR and EventSource blocking, WebSocket denial, child-frame
attach/request/block/commit/completion/detach classification, and
committed-origin constraints. Server counters alone are insufficient; the final
E2E asserts server counters and browser audit counters together.

## 7. Navigation, Action, and Time Budgets

The following are proposed MVP defaults. They must be approved before
Milestone 2 and become part of the dynamic configuration fingerprint. Tests
use smaller explicit values to prove each boundary.

| Budget | Proposed default | Reason and relationship to Static Discovery | Exhaustion behavior |
|---|---:|---|---|
| Rendered pages | 5 | Browser rendering is materially heavier than Static's 10-page default; five covers root plus a small loopback route set. | Stop scheduling pages; return partial result with `DYNAMIC_PAGE_BUDGET_EXHAUSTED`. |
| Main-frame navigations | 8 | Allows initial pages plus bounded redirects/routes while remaining below Static's 20-request cap. | Block the next navigation and warn. |
| Client-side route actions | 3 | The MVP demonstrates minimal route discovery, not arbitrary exploration. | Record remaining candidates as skipped fingerprints and warn. |
| Depth | 1 | Stricter than Static's depth 2 because every rendered branch can execute JavaScript and subrequests. | Do not schedule the candidate; warn with depth and URL fingerprint. |
| Per-navigation timeout | 3 seconds | Reuses Static's request-timeout default and keeps cross-suite timing predictable. | Abort navigation, retain earlier valid results, warn. |
| DOM stabilization timeout | 1 second | Bounded loopback JavaScript should settle quickly; this permits a deliberate delayed mutation without adopting production-SPA waits. | Capture the last safe bounded projection if available, mark partial, and warn. |
| Minimum stabilization observation | 250 ms | Prevents immediate false stability before the fixture's delayed mutation. | Included inside the 1-second hard bound. |
| Total dynamic elapsed time | 15 seconds | Adds bounded browser startup/stabilization allowance to Static's 10-second model without permitting an open-ended run. | Abort active page, clean up, return partial result and warning. |
| DOM snapshot bytes | 512,000 UTF-8 bytes | Reuses Static's response bound, avoiding a second unexplained content-size scale. | Do not pass oversized HTML to extraction; warn and continue. |
| Actionable elements | 100 per page | A conservative fixture-scale cap prevents DOM fan-out while allowing normal small forms/link sets. | Process the first deterministic sorted 100; count and warn about the remainder. |
| Browser request decisions | 50 total | Every document/subresource interception, including blocked attempts, must be bounded separately from canonical document crawl statistics. | Abort all subsequent requests, stop the active page, mark partial, and warn. |
| Redirects per navigation | 3 | Reuses Static's redirect default. | Abort before the next redirect request and warn. |

Counters are monotonic and owned by the dynamic crawl state. A browser request
decision counts when context routing receives it, before allow/block
classification; an approved main-frame navigation attempt separately counts
when admitted for dispatch. Blocked requests therefore cannot create an
unbounded hidden workload. Main-frame navigation and passive client-side route
changes have distinct counters, and observing route state does not consume or
grant a navigation action. No budget warning upgrades incomplete data to
probe-ready.

EventSource attempts consume the browser-request-decision budget before their
mandatory block. WebSocket attempts are observed by the separate context hook
and consume the same total browser transport-decision budget before mandatory
closure. Neither transport can consume a navigation action or create discovery
authority. When the shared decision budget is exhausted, subsequent HTTP(S)
requests are aborted and subsequent WebSockets are closed; no unguarded
transport fallback is permitted.

## 8. DOM Stabilization Condition

`networkidle` is not the completion signal. Modern pages may poll forever,
keep sockets open, or become network-idle before a delayed DOM mutation.

The MVP uses a bounded extraction-relevant projection:

1. Navigate with `wait_until="domcontentloaded"` and the remaining
   per-navigation/total timeout.
2. Wait at least 250 ms from `DOMContentLoaded`.
3. At fixed 50 ms intervals, first evaluate a value-blind structural projection
   containing the current main-frame URL, ordered anchor hrefs, form occurrence
   boundaries, form action/method without query values, and descendant control
   tag plus normalized type. Mark any form containing normalized
   `type=password` as sensitive without reading its name or value. Only after
   that classification may a separate projection read successful-control
   state/value for forms proven non-sensitive.
4. Treat the DOM as stable after the projection fingerprint and current URL
   are unchanged for four consecutive polls spanning at least 150 ms after the
   minimum observation interval.
5. Stop unconditionally at the 1-second stabilization timeout or earlier total
   elapsed deadline.
6. Serialize one sanitized clone of the main-frame DOM only after stability.
   Omit every sensitive form occurrence and event-handler state before
   projecting any canonical HTML, add one safe structural elision warning per
   omitted occurrence, then enforce the UTF-8 size bound.

The projection ignores text nodes, style/class animation churn, timestamps,
canvas pixels, and other non-discovery state. This prevents animation/noisy DOM
from holding the crawler open. Repeated relevant mutation reaches the hard
timeout, produces `DOM_STABILIZATION_TIMEOUT`, and may yield the last bounded
snapshot as explicitly partial. A snapshot is deterministic because extraction
operates on canonical content and result ordering, not mutation arrival order.

The loopback fixture's delayed mutation occurs before the minimum observation
window ends. Delays beyond the configured bound are intentionally out of scope
and become partial-result behavior rather than an unbounded wait.

## 9. Dynamic Link, Route, Form, and Input Extraction

### Rendered anchors and routes

- Inspect main-frame `a[href]` elements after stabilization.
- Resolve relative hrefs against the stabilized `page.url`.
- Preserve raw query text before decoding and discard fragments for crawl
  identity, matching `canonicalize_crawl_url()`.
- Create query `InputPoint` occurrences from ordered raw query tokens exactly
  as Static extraction does.
- Preserve duplicate equal-name/equal-value occurrences through occurrence
  index; do not collapse them into a mapping.
- Record malformed, empty, unsupported-scheme, and cross-origin hrefs as
  structured warnings with fingerprints, never raw secret-bearing URLs.
- The exact SPA action model is:
  1. record an automatic same-origin `history.pushState` or `replaceState`
     change, hash change, and current rendered location observed during
     stabilization as passive route provenance;
  2. canonicalize rendered `a[href]` values in deterministic order as
     discovery candidates without granting transport;
  3. intersect those candidates with the immutable caller-supplied navigation
     authority and schedule only exact matches within all budgets;
  4. use direct `page.goto()` only for an exact caller-approved route instead
     of clicking the element;
  5. record unauthorized candidates with safe warning/audit evidence but never
     request them; and
  6. never activate target-blank links, buttons, generic click handlers,
     form controls, or href-less router widgets.
- Hash-only changes may be recorded as observations but do not consume a new
  network navigation or create a distinct canonical endpoint.

### Rendered forms and controls

Rendered DOM extraction reuses the current HTML successful-control rules:

- missing form action means the stabilized current document URL;
- missing form method means GET;
- non-sensitive explicit GET forms create complete request context when all
  existing provenance requirements are met;
- POST forms are discovered canonically but never submitted and remain
  ineligible for the existing GET-only analysis execution;
- for non-sensitive forms, `input`, `hidden`, `textarea`, `select`, selected
  options, checked checkbox, and checked radio controls are preserved;
- blank values remain blank;
- repeated names and repeated identical name/value pairs retain distinct
  occurrence indexes;
- disabled, unnamed, unchecked, unsupported, and malformed controls are
  skipped or marked partial using the same warning semantics as Static
  extraction;
- malformed form boundaries/actions do not stop extraction of the rest of the
  page.

Live DOM properties matter for checkbox/radio checked state, selected options,
and textarea values; therefore the sanitized snapshot must reflect current
property state rather than stale source attributes. The snapshot builder
normalizes those current states into HTML that the existing semantic parser
can consume.

Password controls are an intentional Dynamic aggregation exception to existing
source-HTML behavior. The rendered-DOM preprocessor classifies a form as
sensitive from a descendant control's normalized `type=password` before
reading any control value. It records only safe source/action/method/
control-count/form-occurrence data, omits the entire form element from the
sanitized canonical projection, and emits `SENSITIVE_FORM_ELIDED`. The form
contributes no Endpoint, `InputPoint`, `RequestTemplate`,
`InputPointRequestContext`, readiness, or provenance. The semantic parser never
sees the form and does not fabricate an empty, redacted, hashed, sentinel, or
synthetic successful-control value.

Sensitivity is structural and policy-owned. For this MVP, `type=password` is
the sole mandatory sensitive type. A future fixed crawler-policy revision may
explicitly add another control type, but path names, field names such as
`token` or `secret`, values, page text, and LLM analysis never imply
sensitivity.

Default Static extraction remains unchanged. During explicit Dynamic
aggregation, Section 10 binds an opt-in policy-aware extractor into
`StaticCrawler`. Its structural first pass marks password-form occurrences, and
its canonical pass skips each marked occurrence before `_Builder.add_form()`.
No password-form value or artifact can therefore enter `_remember_point()`,
`_finalize_points()`, crawler-level `_merge_input_points()`, serialization,
merge, `ready_contexts()`, pipeline analysis, or reporting. No password value
may appear in warnings, provenance, diagnostics, browser audit, merge logs,
exceptions, canonical serialization, JSON/HTML reports, or test output.

No extraction path submits a form, clicks a control, creates an attack request,
or generates a payload. Client-side form validation and framework component
introspection are out of scope.

## 10. Canonical Identity and Deterministic Merge

### Contract extension required before merge implementation

The current singular collector validation cannot represent a combined result
with truthful producer provenance. Milestone 1 proposes the smallest compatible
extension:

- add an aggregate `CollectorKind.NATIVE_COMBINED`;
- use it only for `DiscoveryMetadata.collector_kind` on aggregate results;
- permit aggregate provenance records to retain `NATIVE_STATIC` or
  `NATIVE_DYNAMIC`, while single-producer results still require an exact
  metadata/provenance collector match;
- rebuild aggregate provenance IDs under the aggregate `discovery_run_id`;
- bind the aggregate configuration fingerprint to the merge-policy version and
  the ordered component run IDs;
- update the canonical contract version according to the repository's
  compatibility policy and require producer/consumer Gate Review.

This reuses `CanonicalDiscoveryResult`; it does not introduce a parallel
consumer schema.

### Single merge order

The only allowed merge order is:

```text
Static HTML
  -> opt-in value-blind structural form classification
  -> canonicalize only non-sensitive forms
  -> validate Static Discovery result
Rendered DOM
  -> value-blind structural form classification
  -> project/canonicalize only non-sensitive forms
  -> validate Dynamic Discovery result
  then deterministic Static-first merge
  then CanonicalDiscoveryResult.create()
  then CanonicalDiscoveryResult.validate()
```

The order is policy, even when set-like collections are later sorted. Merge is
not "last write wins."

### Sensitive Form Pre-Canonical Elision

**H-01-R2-RESCOPE decision and ownership:** the prior Sensitive Form Atomic
Exclusion design is superseded because canonical `InputPoint` coalescing can
erase password type attribution while retaining its values. Milestone 1 owns
the opt-in extraction-policy contract, value-blind structural classifier,
`SENSITIVE_FORM_ELIDED`, and transport-free helper/extractor tests. Milestone 3
owns equivalent rendered-DOM elision. Milestone 5 accepts only already-safe
producer results and never filters or reconstructs sensitive artifacts.
Milestone 6 enables the policy only for explicit Dynamic aggregation, and
Milestone 7 proves final collision and sentinel behavior. Milestone 4 has no
sensitive-form ownership.

#### Selected extraction seam and detection point

The selected approach is a proposed keyword-only
`sensitive_form_policy: SensitiveFormElisionPolicy | None = None` parameter on
`extract_static_html()`. `None` is the default and preserves current Static-only
output. The enabled policy uses a value-blind structural first pass to assign
stable zero-based raw form-occurrence indexes and classify an occurrence as
sensitive only when a descendant input has normalized `type=password`. It does
not inspect control names, endpoint paths, page text, values, JavaScript
meaning, or LLM output.

The canonical second pass receives only the sensitive occurrence-index set and
safe warning facts. For a marked occurrence, it does not read or collect any
successful-control value and does not call `_Builder.add_form()`. Consequently
the form cannot reach `_add_template_with_points()`, `_remember_point()`,
`_finalize_points()`, or crawler-level `_merge_input_points()`. A proposed
policy-bound extractor factory/callable binds the keyword policy while
preserving the existing `StaticCrawler.extractor` calling protocol; explicit
Dynamic orchestration injects that callable, while default `StaticCrawler`
remains unchanged.

If a structural pass cannot determine or apply a form boundary safely, the
enabled path raises a proposed `SensitiveFormElisionIntegrityError` before
normal form canonicalization. This typed error is not a `TypeError` or
`ValueError`, so it is outside `StaticCrawler`'s existing extractor-warning
catch and reaches the already-defined canonical-integrity failure boundary.
It never falls back to an unfiltered parse, logs/serializes the raw form, or
continues Dynamic aggregation with that producer result. Static-only mode keeps
existing malformed-form behavior.

#### Zero-artifact and Endpoint policy

A sensitive form contributes zero canonical artifacts: no form-derived
Endpoint, InputPoint, RequestTemplate, InputPointRequestContext,
ProbeReadiness, provenance, BAC hint, or form metadata is created. No
password-bound canonical object exists to remove, sanitize, split, repair, or
reconstruct after coalescing.

An Endpoint discovered only through a sensitive form is absent. If the same
Endpoint is independently discovered by an anchor, query URL, client-side
route, or non-sensitive form, that independent canonical subject and its own
provenance remain. The sensitive form contributes no Endpoint provenance. This
is determined by ordinary construction of safe observations, not by subtracting
or rebuilding shared provenance.

#### Dynamic rendered-DOM elision

Before projecting form-control values, the rendered extractor performs the same
value-blind structural classification over main-frame form occurrences. A
marked form is omitted from canonical HTML projection and never reaches the
semantic parser. No password value is read, projected, hashed, replaced, or
stored, and the form creates no route candidate or Endpoint. Non-sensitive
forms continue through existing successful-control semantics.

#### Secret-free warning

Each producer emits exactly one proposed `SENSITIVE_FORM_ELIDED`
`DiscoveryWarning` for each marked raw form occurrence that it independently
observes, in stable document order. Because no form subject or canonical
provenance exists, `subject_id` and `provenance_id` are `None`. Frozen details
are limited to producer kind; source and action
scheme/host/effective-port/path without query; normalized method; depth;
control count; and the stable non-secret form-occurrence index needed to keep
duplicate warnings distinct. The message and details contain no control or
password value, query, header, cookie, storage, authorization data, DOM
serialization, or raw exception text. The warning is discovery safety
information only and never becomes an InputPoint, candidate, feature, score,
confidence, or finding.

Warning identity and exact duplicate suppression remain producer-local. A
genuinely identical duplicate from the same producer may collapse under the
existing exact warning identity; Static and Dynamic warnings never
cross-producer deduplicate and are never replaced with one synthetic warning.
An aggregate has one warning when only one producer observes the sensitive form
and exactly two when both producers observe it: one Static warning followed by
one Dynamic warning. For `NATIVE_COMBINED` results, the reviewed warning order is
producer rank (Static before Dynamic) followed by the existing canonical stable
warning order within each producer. Milestone 1 extends aggregate ordering
validation only as necessary for this rank; `DiscoveryWarning` identity and
single-producer ordering remain unchanged.

No empty string, reserved sentinel, synthetic value, hash, or redacted string
is stored as a password successful-control value. No unsanitized Dynamic-mode
Static canonical result exists: elision precedes all canonical construction,
validation, serialization, diagnostics, merge, `ready_contexts()`, pipeline
analysis, reporting, and captured test output.

#### Deterministic ordering and collision guarantee

Structural classification numbers raw forms in parser document order,
normalizes type with the existing lowercase/trim rule, and creates warnings in
that same occurrence order. The canonical pass processes only unmarked forms
and existing anchors in their existing deterministic order. Producers validate
independently; the merger then uses fixed Static-first ordering and current
canonical sort keys.

For the required `/search?q=safe` anchor plus GET password form targeting
`/search` with `q=PW_SENTINEL`, the form is marked before its value is accessed
or any form artifact is built. The anchor therefore creates the only `q`
InputPoint; its `type_hint`, `baseline_value(s)`, raw-query metadata, template,
context, readiness, and provenance contain only the safe observation. Nothing
from the password form can participate in InputPoint identity or coalescing.
When both producers observe the fixture, the aggregate contains zero password
artifacts, zero `PW_SENTINEL`, one Static warning, and one Dynamic warning in
that order. Repeated runs produce identical warnings and canonical
serialization.

### Identity and conflict rules

- Endpoint: existing method + normalized scheme + normalized host + canonical
  path identity. Static and Dynamic copies with the same fingerprint become
  one endpoint.
- InputPoint: existing endpoint fingerprint + location + canonical name +
  optional auth context + occurrence index. Repeated occurrences are never
  collapsed merely because name/value pairs are equal.
- RequestTemplate: existing full content fingerprint remains authoritative.
  Templates with different raw query, ordered pairs, form values,
  completeness, context key, or provenance remain distinct.
- InputPointRequestContext: existing input/template/role ownership identity
  remains authoritative.
- Stable ordering: use the sort keys already enforced by
  `CanonicalDiscoveryResult.create()`.
- Duplicate suppression: deduplicate only exact stable identity. Preserve all
  unique provenance observations for the retained subject.
- Same item from both producers: retain one canonical subject and at least one
  static plus one dynamic provenance record, ordered by the existing
  provenance sort key.
- Same semantic input with different provenance: retain one InputPoint only if
  the existing identity matches; union non-secret baseline values and
  provenance metadata deterministically.
- Blank values: `""` remains an observed value and is not converted to `None`.
- Raw percent encoding: retain each raw token from the authoritative request
  template/provenance; never regenerate `%20` as `+` or otherwise normalize
  raw query text.
- Conflicting metadata: preserve exact canonical fields from the Static-first
  candidate, union only reviewed multi-value metadata under sorted tuple keys,
  and emit `DISCOVERY_METADATA_CONFLICT` for incompatible non-secret values.
  No arbitrary dictionary overwrite is permitted.
- Conflicting readiness: `READY` is retained only if a complete validated
  context independently satisfies current readiness rules. Sensitive form
  groups do not participate in this conflict rule because producer-local atomic
  exclusion removes their templates, contexts, and form-owned inputs before
  merge; no producer precedence can restore an excluded group.
- BAC static hints: pass through validated static hints; Dynamic Discovery adds
  no BAC hints in this MVP.

The merger must be deterministic for input permutation and repeated execution.
Its intended aggregate operation is associative only for inputs already ordered
by the fixed producer precedence; arbitrary caller order is rejected rather
than silently reinterpreted. All child references and ownership relationships
are rebuilt from authoritative objects and validated at the end.

### Exact CrawlStatistics semantics

The existing `CrawlStatistics` contract has no browser-subresource, route-action,
popup, frame, or cleanup fields. Those browser-specific counters remain in the
proposed `DynamicCrawlResult.browser_audit` and must not be inserted into an
unrelated existing scalar. Existing fields are used only where Static and
Dynamic have an aligned document-crawl meaning:

The current contract already enforces non-negative numeric values, the three
budget inequalities, and the four canonical collection counts. Any additional
aggregate relationship stated in the validation column below is a proposed
Milestone 1/5 merge precondition or contract validation change, not a claim
about current code.

| CrawlStatistics field | Existing Static meaning | Dynamic producer meaning | Aggregate merge rule | Validation invariant |
|---|---|---|---|---|
| `requests_attempted` | Static transport requests admitted for dispatch, including redirect hops | Exact-authorized main-frame document requests admitted for dispatch, including authorized redirect hops; excludes subresources and blocked decisions | Sum | Each producer validates against its own budget first; aggregate value must equal component sum |
| `pages_processed` | Successful HTML extractions retained in `state.extractions` | Sanitized rendered main-frame documents successfully extracted into validated Dynamic data | Sum | Must not exceed the corresponding summed page budget |
| `html_pages` | HTML pages passed to extraction; currently equal to Static extracted pages | Rendered HTML documents passed to rendered extraction | Sum | Non-negative, no greater than aggregate `pages_processed` unless a future reviewed contract changes Static semantics |
| `links_discovered` | Link observations reported by Static extraction before cross-page canonical deduplication | Rendered anchor observations reported by Dynamic extraction, authorized or not | Sum | Activity count only; it need not equal canonical endpoint count |
| `forms_discovered` | Form observations reported by Static extraction | Rendered form observations reported by Dynamic extraction | Sum | Activity count only; it need not equal template count |
| `skipped` | Static crawler/extractor observations explicitly counted as skipped | Dynamic discovery candidates/pages explicitly skipped by extraction, authority, or budget policy; low-level blocked resource attempts remain browser-audit counts | Sum | Every increment maps to a deterministic warning/skip decision; warning records not marked skipped do not increment it |
| `redirects_followed` | Static redirect hops actually admitted and followed | Exact-authorized same-origin main-frame redirect hops actually admitted and followed | Sum | Blocked redirect attempts are audit counters, not followed redirects |
| `max_depth_reached` | Greatest Static crawl depth reached | Greatest Dynamic rendered-document depth reached | Maximum | Each producer first satisfies its own depth budget |
| `request_budget` | Configured Static `max_requests` | Configured Dynamic main-frame navigation-request budget; excludes browser request-decision budget | Sum | Never pair one producer's attempt count with another producer's budget; aggregate attempts must not exceed the summed aligned budget |
| `page_budget` | Configured Static `max_pages` | Configured Dynamic rendered-page budget | Sum | Aggregate pages must not exceed the summed budget after both producers validate independently |
| `depth_budget` | Configured Static `max_depth` | Configured Dynamic depth limit | Maximum | Aggregate maximum depth must not exceed the maximum component depth budget; independent producer validation prevents a larger peer budget from concealing a violation |
| `elapsed_ms` | Measured Static crawl elapsed time | Measured Dynamic crawl elapsed time, including browser startup and cleanup | Sum because the fixed pipeline runs Static then Dynamic sequentially | Both values must be finite/non-negative; no wall-clock maximum or parallel overlap is inferred |
| `endpoint_count` | Number of canonical endpoints in that result | Number of canonical endpoints in that result | Recompute from merged `endpoints` | Must equal `len(aggregate.endpoints)` |
| `input_point_count` | Number of canonical input points in that result | Number of canonical input points in that result | Recompute from merged `input_points` | Must equal `len(aggregate.input_points)` |
| `request_template_count` | Number of canonical request templates in that result | Number of canonical request templates in that result | Recompute from merged `request_templates` | Must equal `len(aggregate.request_templates)` |
| `request_context_count` | Number of canonical input/template contexts in that result | Number of canonical input/template contexts in that result | Recompute from merged `input_point_request_contexts` | Must equal `len(aggregate.input_point_request_contexts)` |

Both component results call `validate()` before any arithmetic. Unequal
request/page budgets use the sums above; unequal depth budgets use maximum;
unequal elapsed times use sequential sum. A Dynamic result with zero
navigations contributes zero attempts/pages and its configured budgets. A
validated partial Dynamic result contributes only activity actually completed
before its structured operational failure. If no valid Dynamic result exists,
the Static-only statistics remain byte/semantically unchanged. Any inconsistent
component or aggregate statistic is a canonical integrity failure under
Section 21, never a warning-only fallback.

Milestones 1 and 5 add tests for unequal budgets, unequal elapsed times,
Static-only identity, zero-navigation Dynamic output, validated partial
Dynamic output, merged canonical count recomputation, subresource-count
exclusion, and rejection of inconsistent statistics.

## 11. Provenance and Ownership

Every canonical subject must retain sufficient provenance to distinguish:

- `NATIVE_STATIC` response-HTML discovery;
- `NATIVE_DYNAMIC` rendered-DOM discovery;
- `NATIVE_DYNAMIC` route/navigation discovery;
- source/stabilized URL;
- parent URL;
- canonical depth;
- aggregate discovery run;
- producer/collector kind;
- a stable, non-secret browser navigation/action identifier where necessary.

Use existing `DiscoveryProvenance` fields whenever possible:
`discovery_run_id`, `subject_kind`, `subject_id`, `collector_kind`,
`source_url`, `parent_url`, `depth`, and `collector_observation_key`.
The observation key should encode a stable kind and ordinal/fingerprint such as
rendered document, rendered form, rendered anchor, automatic history route, or
scheduled route navigation. It must not include DOM text, passwords, cookies,
headers, or storage.

The aggregate merger re-parents provenance to the aggregate run without
reconstructing canonical subject IDs. `CanonicalDiscoveryResult.validate()`
must still prove that every subject has provenance and every reference resolves.

Section 10 pre-canonical elision creates no sensitive-form subject and therefore
no sensitive-form provenance to remove or reconstruct. Independent anchors,
query URLs, routes, and non-sensitive forms retain only their own provenance.
A form-only sensitive action creates no Endpoint and no provenance. The
subject-free `SENSITIVE_FORM_ELIDED` warning contains only bounded safe
structural details.

Future role/session support may add an optional versioned context reference to
metadata/provenance after contract review. The MVP always uses no auth context
and creates a fresh anonymous browser context. It must not pre-create fields
containing cookie jars, storage state, session labels, or role values.

Never store or log secret values, cookies, authorization headers, browser
storage, password values, complete request/response captures, or user profile
paths.

## 12. Probe Readiness

Dynamic discovery reuses `ProbeReadiness`,
`CanonicalDiscoveryResult.ready_contexts()`, and the existing validation rules.
Collector kind alone never makes an input probe-ready.

A dynamic input is `READY` only when:

- it is QUERY or FORM;
- its `RequestTemplate` is complete;
- ordered pairs and occurrence identity are preserved;
- a query has authoritative raw-query provenance aligned with decoded pairs;
- a form has trusted explicit/default method and action provenance;
- the form boundary and complete successful-control set are known;
- hidden-input completeness uses the existing
  `native_all_successful_controls_preserved` evidence;
- input/template/context ownership validates.

An input is `NOT_READY` when context is missing, partial, unknown, malformed,
unsupported, ambiguously grouped, missing raw query, misaligned with raw query,
or when its Dynamic request URL lacks exact caller authority. Reuse existing
`NonProbeReadyReason` values and propose only `REQUEST_NOT_AUTHORIZED`.
Sensitive forms do not need a readiness state: pre-canonical elision prevents
their InputPoints, templates, contexts, and readiness records from existing.
Skipped disabled/unnamed controls in non-sensitive forms need warnings, not
fabricated InputPoints.

GET forms may become ready only when their complete request URL is independently
authorized and every existing readiness rule passes; discovery itself never
submits them. A Dynamic context derived from an unauthorized form/anchor stays
non-ready, so the consumer cannot request it. POST forms remain visible
canonical discovery surfaces; the current pipeline will skip their contexts
because `analyze_discovery_result()` executes GET only.
Password forms are pre-canonically elided in this MVP: no Endpoint, control,
template, context, readiness, or provenance from the form is present in either
producer or aggregate. An independently discovered Endpoint or safe context
remains, but a form-only Endpoint is absent. Unrelated non-password forms retain
their independently validated readiness. Static-only runs do not enable the
elision policy and retain current repository behavior.
Route-only endpoints without inputs require endpoint provenance but no
fabricated InputPoint or readiness record.

## 13. Loopback JavaScript Fixture

Create a deterministic standard-library `ThreadingHTTPServer` harness following
the existing static loopback fixtures. It owns:

- a primary loopback server on an ephemeral port;
- a sentinel loopback server on a distinct port, which is cross-origin because
  effective port differs;
- thread-safe ordered request logs containing only method, normalized path
  without query values, resource category where test-owned, redacted
  query-name structure, and fixture counters;
- the exact navigation/resource authority supplied to each test, kept separate
  from page-generated URLs;
- explicit shutdown, server close, and thread join in `finally`.

The primary root page includes:

- one initial static same-origin anchor;
- the mandatory collision pair in response HTML: an independent
  `/search?q=safe` anchor and a GET form targeting `/search` with
  `<input type="password" name="q" value="PW_SENTINEL">`;
- one same-origin anchor inserted by JavaScript after load;
- one dynamically inserted form and dynamic input;
- one JavaScript-inserted GET form containing username, password, hidden,
  checkbox, and select controls, with a unique password sentinel absent from
  response-HTML form markup;
- query links with repeated names, repeated identical name/value pairs, blank
  value, and raw `%20` encoding;
- a relative route;
- a bounded automatic `history.pushState` route;
- an exact caller-approved rendered anchor route;
- a caller-approved same-origin redirect whose exact final URL is also
  authorized;
- a cross-origin sentinel link;
- a same-origin endpoint that redirects toward the sentinel origin;
- an automatic `window.open()` attempt and an unactivated `target=_blank`
  anchor;
- same-origin and cross-origin iframe elements;
- a JavaScript location assignment toward an unauthorized same-origin path;
- blocked same-origin fetch/XHR toward an unauthorized path and one separately
  authorized fixture fetch resource;
- same-origin and cross-origin WebSocket constructor attempts directed at
  fixture endpoints with explicit HTTP Upgrade handshake and established-
  connection counters;
- same-origin and cross-origin EventSource attempts directed at fixture
  endpoints with explicit request counters;
- a POST form and an autosubmit attempt, both of which must be intercepted;
- a delayed DOM mutation before the 250 ms minimum observation completes;
- an unnamed or malformed control;
- explicit unsafe same-origin links/routes `/delete`, `/reset`, `/logout`, and
  `/state-change`, inserted only by JavaScript after load so the Static response
  HTML cannot cause the existing Static crawler to request them; they are
  discoverable by Dynamic extraction but absent from request authority;
- deterministic JavaScript-error, noisy-mutation, and test-driven page-close
  routes for adversarial tests.

The fixture authority grants only the root, the named approved route/redirect
chain, and exact fixture script/style/fetch resources required by that test.
Unsafe path names are not a denylist; their zero counters demonstrate that
absence from caller authority, rather than keyword matching, controls access.

Server counters and `BrowserAuditSummary` must jointly prove:

- sentinel request log length is zero;
- collision output contains exactly one safe `q` InputPoint whose baseline/raw
  query metadata contains only `safe`; `PW_SENTINEL` request count is zero
  while otherwise-authorized safe-anchor analysis remains observable; when
  both producers observe the form, warning counts are Static one, Dynamic one,
  aggregate two, ordered Static then Dynamic;
- every unsafe same-origin endpoint request counter is zero;
- primary POST log length is zero;
- only expected category-matched resource URLs were allowed;
- browser request decisions are bounded by the configured test policy;
- dynamic main-frame navigations/actions/pages do not exceed their budgets;
- popup attempts are counted, popup requests are blocked, and created popup
  pages close;
- same-origin and cross-origin child-frame attachment and document-request
  attempts are counted; blocked request counts agree with zero fixture endpoint
  requests; authorized commit/completion counts are zero; any Chromium
  `about:blank`, browser-error, or replacement-document commit/completion is
  classified separately; and detach/cleanup counts balance;
- same-origin and cross-origin WebSocket attempt counts match the fixture,
  blocked count equals all attempts, connected count is zero, server handshake
  count is zero, and server established-connection count is zero;
- same-origin and cross-origin EventSource attempt counts match the fixture,
  blocked count equals all attempts, allowed count is zero, and server endpoint
  request count is zero;
- main-frame committed origins contain only the root origin;
- cross-origin and unauthorized same-origin redirect blocks are counted;
- navigation attempts and approved completions match the test authority;
- created/closed page and context counts balance and cleanup is complete;
- each canonical route is requested at most once under deduplication;
- results and warning codes are identical across repeated runs.

The same/cross-origin WebSocket, EventSource, and iframe lifecycle cases are
mandatory members of the deterministic strict `browser-loopback` manifest.
Their browser-audit counters and server counters must be asserted together on
repeated real-Chromium runs; no external-origin request is permitted.

The fixture must not use Internet resources, CDN scripts, authentication,
cookies, storage injection, or real secrets. The password sentinel exists only
as an in-browser fixture value and must be absent from server logs, browser
audit evidence, canonical serialization, reports, exceptions, and test output.

## 14. Normal Test Matrix

| Test ID | Scenario | Expected Result | Narrow Test Location |
|---|---|---|---|
| N-01 | Browser starts, creates one isolated context/page, renders root, and closes | Headless resources close once in page-context-browser-Playwright order | `tests/unit/test_dynamic_browser.py` |
| N-02 | Browser adapter is replaced by a fake | `DynamicCrawler` behavior is testable without Playwright or network | `tests/unit/test_dynamic_crawler.py` |
| N-03 | Anchor is inserted after `DOMContentLoaded` | Stabilization waits, rendered anchor is extracted with dynamic provenance | `tests/unit/test_rendered_dom.py` |
| N-04 | Relative dynamic anchor | URL resolves against stabilized page URL and stays same-origin | `tests/unit/test_rendered_dom.py` |
| N-05 | Dynamic GET form with hidden/input/textarea/select/checkable controls | Successful controls, defaults, current states, and stable form context are preserved | `tests/unit/test_rendered_dom.py` |
| N-06 | Dynamic POST form | Canonical surface is retained, form is never submitted, pipeline later skips execution | `tests/unit/test_rendered_dom.py` |
| N-07 | Blank, repeated, repeated-identical, and percent-encoded query values | Blank string, occurrence indexes, ordered pairs, and raw tokens survive | `tests/unit/test_rendered_dom_adversarial.py` |
| N-08 | Automatic same-origin `history.pushState` | Current route is recorded passively with route provenance and grants no request authority | `tests/integration/test_dynamic_browser_loopback.py` |
| N-09 | Rendered anchor whose exact URL is caller-approved | Canonical route is navigated directly within page/navigation/depth budgets; an otherwise identical unapproved anchor is discovery-only | `tests/integration/test_dynamic_browser_loopback.py` |
| N-10 | Static and Dynamic discover identical endpoint/input/template/context | One canonical subject remains with both producer provenance records | `tests/unit/test_discovery_merge.py` |
| N-11 | Static and Dynamic discover distinct surfaces | Union is canonically ordered, references validate, counts match | `tests/unit/test_discovery_merge.py` |
| N-12 | Page budget or stabilization timeout after one valid page | Valid prior records return with structured partial-result warning | `tests/unit/test_dynamic_crawler.py` |
| N-13 | `analyze_discovery_result()` receives combined result | Only validated READY GET contexts enter unchanged observation/scoring flow | `tests/unit/test_native_pipeline_cli.py` |
| N-14 | CLI legacy `--input` without dynamic flag | Existing behavior and output remain byte/semantically compatible | `tests/integration/test_v01_smoke.py` |
| N-15 | CLI `--url --dynamic` with loopback fixture | Static and rendered surfaces merge; JSON/HTML consume the same authoritative selection | `tests/integration/test_native_dynamic_discovery_e2e.py` |
| N-16 | GET form with username, password, hidden, checkbox, and select siblings | Structural pre-pass elides the form before any control value or canonical artifact is created; one `SENSITIVE_FORM_ELIDED` warning exists and no request executes | `tests/unit/test_rendered_dom.py` and `tests/integration/test_dynamic_browser_loopback.py` |
| N-17 | Unequal Static/Dynamic budgets and elapsed times | Aggregate statistics follow the exact sum/maximum/recompute rules and validate | `tests/unit/test_discovery_merge.py` |
| N-18 | Real browser audit on an authorized route/resource | Server counters and sanitized browser audit counters agree; created/closed resources balance | `tests/integration/test_dynamic_browser_loopback.py` |
| N-19 | Caller-approved same-origin redirect and exact approved destination | Redirect hop is followed once, both request and navigation counters match, and committed origin remains the root origin | `tests/integration/test_dynamic_browser_loopback.py` |
| N-20 | Static GET password form | Opt-in Static structural pass emits one warning and the form contributes zero canonical artifacts or requests | `tests/unit/test_html_extractor.py` and `tests/unit/test_discovery_merge.py` |
| N-21 | Dynamic GET password form | Rendered structural pass reads no value, omits the form before projection, emits one warning, and executes no GET | `tests/unit/test_rendered_dom.py` |
| N-22 | Password POST form | Form contributes zero canonical artifacts and POST remains unsubmitted | `tests/unit/test_html_extractor.py` and `tests/unit/test_rendered_dom.py` |
| N-23 | Password form with hidden sibling | Neither password nor hidden sibling reaches value collection or canonical construction | `tests/unit/test_html_extractor.py` |
| N-24 | Password form with checkbox/radio sibling | No checkable sibling or form artifact survives and no control state/value leaks | `tests/unit/test_html_extractor.py` |
| N-25 | Password form with select sibling | No selected option or form artifact is projected or canonicalized | `tests/unit/test_rendered_dom.py` |
| N-26 | Password form with repeated sibling names | No form-owned occurrence is created; warning/output order is deterministic | `tests/unit/test_html_extractor_adversarial.py` |
| N-27 | Multiple forms where only one contains password | Sensitive occurrence is elided; non-sensitive form remains valid and ready when otherwise eligible | `tests/unit/test_html_extractor_adversarial.py` |
| N-28 | Unrelated non-password form beside a sensitive form | Unrelated form retains its existing canonical artifacts, readiness, and deterministic ordering | `tests/unit/test_discovery_merge_adversarial.py` |
| N-29 | Sensitive action Endpoint independently discovered by an anchor | Independent Endpoint, InputPoint, template, context, and provenance remain; sensitive form adds none | `tests/unit/test_html_extractor_adversarial.py` |
| N-30 | Form-only sensitive action Endpoint | No Endpoint or provenance exists for the form-only action | `tests/unit/test_html_extractor_adversarial.py` |
| N-31 | Malformed password form | Deterministically elided or fail-closed with canonical-integrity error; never falls back to unfiltered canonicalization | `tests/unit/test_html_extractor_adversarial.py` and `tests/unit/test_rendered_dom_adversarial.py` |
| N-32 | Duplicate Static/Dynamic sensitive form | Each producer elides before canonical construction; merge receives no sensitive artifact, preserves one Static plus one Dynamic warning without cross-producer deduplication, and orders them Static then Dynamic | `tests/unit/test_discovery_merge_adversarial.py` |
| N-33 | Permuted input and repeated execution | Safe subjects, warnings, provenance, counts, and serialization are byte/semantically deterministic | `tests/unit/test_discovery_merge_adversarial.py` |
| N-34 | Safe anchor `/search?q=safe` plus GET password form `/search` with `q=PW_SENTINEL` | Form is elided before value collection; anchor creates the only `q` InputPoint with safe-only type/baseline/raw-token metadata; when both producers observe it, aggregate warnings are exactly two—one Static then one Dynamic—with valid ownership and zero sensitive GET | `tests/unit/test_html_extractor_adversarial.py`, `tests/unit/test_discovery_merge_adversarial.py`, and final E2E |

For every applicable N-20–N-34 case, assert that no sensitive-form Endpoint,
InputPoint, RequestTemplate, InputPointRequestContext, readiness, provenance,
or metadata is created; the password sentinel is absent from producer and
aggregate canonical output; unrelated safe discovery remains valid; canonical
validation passes; `SENSITIVE_FORM_ELIDED` count/order/details are exact and
secret-free; no excluded-form GET or POST executes; and repeated or permuted
input preserves deterministic output. N-34 additionally asserts that
`baseline_values` and raw-query metadata contain `safe` only and no password
type contribution. Its two-producer form asserts one Static and one Dynamic
warning, aggregate count two, Static-before-Dynamic order, no cross-producer
deduplication, and producer-local exact-duplicate suppression only. The final
E2E scans serialized JSON, HTML report, captured logs, exceptions, and captured
test output and requires zero `PW_SENTINEL` occurrences.

## 15. Adversarial Test Matrix

| Test ID | Adversarial Case | Required Safety Behavior | Narrow Test Location |
|---|---|---|---|
| A-01 | Cross-origin rendered link | Record fingerprinted warning; never schedule or request | `tests/unit/test_dynamic_crawler_adversarial.py` |
| A-02 | Same-origin URL redirects cross-origin | Context route aborts destination before sentinel request; warn | `tests/integration/test_dynamic_browser_loopback.py` |
| A-03 | Automatic `window.open()` and popup/new tab | Real context-wide interception blocks popup document transport, counts the attempt, closes the page, and performs no extraction | `tests/integration/test_dynamic_browser_loopback.py` plus adapter-fake unit coverage |
| A-04 | Same-origin and cross-origin iframe | Real browser blocks both child-frame document requests, counts attachment/navigation attempts, ignores child DOM, and warns | `tests/integration/test_dynamic_browser_loopback.py` plus adapter-fake unit coverage |
| A-05 | Infinite relevant DOM mutation | Hard stabilization timeout; last bounded snapshot is partial or page is skipped; cleanup | `tests/integration/test_dynamic_browser_loopback.py` |
| A-06 | Infinite client-side history loop | Stabilization/elapsed bound stops passive observation; it grants no navigation authority | `tests/unit/test_dynamic_crawler_adversarial.py` |
| A-07 | HTTP redirect loop | Redirect bound and visited-set stop before repeated transport | `tests/integration/test_dynamic_browser_loopback.py` |
| A-08 | Excessive serialized DOM size | Snapshot is rejected before extraction; warning without raw DOM | `tests/unit/test_rendered_dom_adversarial.py` |
| A-09 | Excessive anchors/actions | Deterministic first bounded set only; remainder skipped and counted | `tests/unit/test_dynamic_crawler_adversarial.py` |
| A-10 | Malformed URL or unsupported scheme | Ignore as navigation input; structured warning; continue | `tests/unit/test_rendered_dom_adversarial.py` |
| A-11 | JavaScript error with stable DOM | Warning only; valid sanitized snapshot may continue | `tests/unit/test_dynamic_browser.py` |
| A-12 | Page crash | No page result; close context/browser; retain earlier valid pages with warning | `tests/unit/test_dynamic_browser.py` |
| A-13 | Navigation timeout | Abort navigation, close resources, retain earlier result, warning | `tests/unit/test_dynamic_browser.py` |
| A-14 | Browser launch failure after preflight | Typed operational failure; only validated partial data may survive; CLI reports Dynamic incomplete with the proposed degraded exit | `tests/unit/test_dynamic_browser.py` |
| A-15 | Duplicate rendered elements/permuted discovery order | Exact identities deduplicate; output and warning order remain deterministic | `tests/unit/test_rendered_dom_adversarial.py` |
| A-16 | Forged canonical child reference | Aggregate validation rejects all output and propagates a hard integrity failure; CLI exits nonzero and writes no success report | `tests/unit/test_discovery_merge_adversarial.py` and `tests/unit/test_native_pipeline_cli.py` |
| A-17 | Input/template/context ownership mismatch | Aggregate validation hard-fails; Static is not mutated and is not returned as successful fulfillment of `--dynamic` | `tests/unit/test_discovery_merge_adversarial.py` |
| A-18 | Password leakage attempt through value, sibling artifact, warning, exception, audit, or log | Sentinel absent everywhere because the raw form is elided before value collection/canonicalization; form-only Endpoint is absent and no request executes | `tests/integration/test_dynamic_browser_loopback.py` |
| A-19 | JavaScript form autosubmit or fetch POST | Context route aborts before server; POST counter remains zero; warning | `tests/integration/test_dynamic_browser_loopback.py` |
| A-20 | Cross-origin script/image/fetch | Request is aborted before sentinel; URL fingerprint warning only | `tests/integration/test_dynamic_browser_loopback.py` |
| A-21 | Missing Playwright package or Chromium | Base mode imports and skips real-browser cases explicitly; explicit Dynamic CLI and strict gate fail capability preflight nonzero | `tests/unit/test_native_pipeline_cli.py` and proposed strict-gate tests |
| A-22 | Aggregate provenance claims wrong producer/run | Contract rejects mismatched collector/run ownership | `tests/unit/test_discovery_merge_adversarial.py` |
| A-23 | `/delete`, `/reset`, `/logout`, `/state-change`, or unauthorized same-origin fetch/XHR | Items remain discoverable where applicable, derived contexts are NOT_READY, no consumer request executes, and all unsafe endpoint counters remain zero | `tests/integration/test_dynamic_browser_loopback.py` and `tests/unit/test_native_pipeline_cli.py` |
| A-24 | `target=_blank` link or JavaScript location assignment | No click occurs; any automatic request is blocked unless its exact URL was pre-authorized; popup/navigation audit records the attempt | `tests/integration/test_dynamic_browser_loopback.py` |
| A-25 | Same-origin redirect target absent from authority | Redirect is blocked before target dispatch; redirect-block counter increments and target server counter remains zero | `tests/integration/test_dynamic_browser_loopback.py` |
| A-26 | Inconsistent aggregate counts, unequal-budget arithmetic error, or browser subresource inserted into `requests_attempted` | Canonical validation/merge rejects with hard integrity failure | `tests/unit/test_discovery_merge_adversarial.py` |
| A-27 | Strict Dynamic gate with missing capability or a skipped required case | Proposed gate exits nonzero before/after suite as applicable and reports that Dynamic safety was not proved | proposed `tests/unit/test_dynamic_gate.py` |
| A-28 | Deterministic test-driven page close while navigation/stabilization is active | Real adapter records page close/crash-equivalent, cleans all resources, and returns only previously validated data | `tests/integration/test_dynamic_browser_loopback.py` |
| A-29 | Same-origin and cross-origin WebSocket constructors | Pre-page context hook counts and blocks every attempt; server handshake/connection and browser connected counts are zero | `tests/integration/test_dynamic_browser_loopback.py` |
| A-30 | Same-origin and cross-origin EventSource constructors | HTTP(S) routing classifies and blocks every attempt before transmission; allowed/server/external counts are zero | `tests/integration/test_dynamic_browser_loopback.py` |
| A-31 | Same-origin and cross-origin iframe documents under Chromium | Audit proves attach/request/block/commit/completion/detach ordering; fixture requests and authorized completions are zero; internal/about:blank/replacement documents are separate | `tests/integration/test_dynamic_browser_loopback.py` |
| A-32 | Static and Dynamic password-form duplicate plus shared-identity safe anchor collision | Both forms are pre-canonically elided, the safe anchor remains uncontaminated, merge sees no sentinel or sensitive artifact, preserves exactly one warning per producer in Static-then-Dynamic order, and GET/POST execution is zero | `tests/unit/test_discovery_merge_adversarial.py` and `tests/unit/test_native_pipeline_cli.py` |

Final-loop test traceability remains explicit: C-01-R1 owns A-29/A-30 and their
strict-manifest cases; H-01-R2-RESCOPE owns N-20 through N-34 plus A-32;
H-03-R1 owns A-31 and its strict child-frame audit assertions; H-04-R1 owns the
Milestone 4 ordered non-skippable gate and manifest-completeness tests.

Active blocking versus warning behavior is explicit:

- actively blocked before transport: unapproved same-origin requests,
  cross-origin requests/navigations, non-GET requests, popups, iframe
  documents, EventSource, all WebSockets through the separate context hook,
  disallowed resources, and actions beyond budget;
- ignored for discovery with warning: malformed/unsupported URLs, disabled or
  unnamed controls, child-frame DOM, arbitrary clickable widgets;
- warning plus validated partial result and proposed degraded CLI exit: timeout,
  page/browser crash after prior success, noisy DOM, JavaScript error, budget
  exhaustion, oversized DOM, or approved route unavailability;
- configuration/capability hard failure: invalid authority, missing Playwright,
  missing matching Chromium, or unsupported runtime;
- canonical integrity hard failure: forged identity/reference/ownership,
  noncanonical order, inconsistent statistics, identity collision, or mixed
  provenance that violates aggregate policy.

## 16. Milestone Plan

Each milestone is one small implementation prompt and produces at most one
focused commit. A milestone may be left uncommitted for correction, but it must
not be bundled with another milestone. Every milestone has a maximum of two
Critical/High correction loops.

### Milestone 1 — Dynamic Discovery Contract and Merge Policy

**Objective**

Approve and implement only the canonical capability needed for truthful
Static-plus-Dynamic aggregation before adding browser code.

**Allowed files to modify**

- `src/vulnspider/discovery/contracts.py`
- `src/vulnspider/discovery/html_extractor.py` (only the keyword-only extraction
  policy, structural classifier/elision seam, warning emission, and default-off
  compatibility path)
- `src/vulnspider/discovery/discovery_merge.py` (new, policy and validation
  boundary only)
- `src/vulnspider/discovery/__init__.py`
- `tests/unit/test_discovery_contract.py`
- `tests/unit/test_discovery_contract_adversarial.py`
- `tests/unit/test_html_extractor.py`
- `tests/unit/test_html_extractor_adversarial.py`
- `tests/integration/test_static_crawler_loopback.py` (only opt-in
  policy-bound extractor integration and the N-34 collision)
- `tests/unit/test_discovery_merge.py` (new)
- `tests/unit/test_discovery_merge_adversarial.py` (new)
- this active execution plan for progress/decision entries

**Files that must not be modified**

- `pyproject.toml`
- `src/vulnspider/discovery/static_crawler.py`
- `src/vulnspider/pipeline.py`
- `src/vulnspider/cli.py`
- observation, features, scoring, selection, and reporting packages

**Public interface added or changed**

- Aggregate collector discriminator and reviewed provenance validation rule.
- Proposed `NonProbeReadyReason.REQUEST_NOT_AUTHORIZED`.
- Immutable/versioned `DiscoveryMergePolicy` defining Static-first order.
- Proposed immutable `SensitiveFormElisionPolicy`, keyword-only
  `extract_static_html(..., sensitive_form_policy=None)` seam, policy-bound
  extractor callable, and `SENSITIVE_FORM_ELIDED` warning code.
- Aggregate warning ordering validation ranks Static before Dynamic, then uses
  the existing stable warning order within each producer; warning identity and
  single-producer ordering are unchanged.
- Exact Section 10 aggregate-statistics policy and validation preconditions;
  no new browser counter is added to `CrawlStatistics`.
- Contract-version change only if compatibility review confirms it is required.

**Narrow implementation unit**

Add the warning/policy contract and the smallest transport-free extractor seam.
When enabled, a value-blind structural first pass marks raw form occurrences
containing normalized `type=password`; the canonical pass skips those
occurrences before `_Builder.add_form()` and emits one subject-free warning per
occurrence. Default behavior remains byte/semantically compatible. Do not
implement browser lifecycle or the full collection merge yet. Prove the N-34
safe-anchor/password-form collision directly: only the safe `q` InputPoint,
safe baseline/raw token, template, context, readiness, Endpoint, and provenance
exist; the form-only Endpoint is absent; `PW_SENTINEL` is absent. Prove that
single-producer results remain valid, mixed provenance is allowed only for an
explicit aggregate, and invalid component/aggregate statistics are rejected.

**Narrow test command**

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_discovery_contract `
  tests.unit.test_discovery_contract_adversarial `
  tests.unit.test_html_extractor `
  tests.unit.test_html_extractor_adversarial `
  tests.integration.test_static_crawler_loopback `
  tests.unit.test_discovery_merge `
  tests.unit.test_discovery_merge_adversarial
```

**Complete regression command**

```powershell
$env:PYTHONPATH='src'
python -B -m unittest discover -s tests
python -B tools/check_format.py
python -B tools/check_lint.py
python -B tools/check_types.py
git diff --check
```

**Safety assertions**

- Legacy/static results still reject mismatched collector provenance.
- Aggregate provenance accepts only reviewed static/dynamic producer kinds.
- All run IDs, child references, ownership, counts, and ordering still validate.
- An enabled sensitive raw form creates no Endpoint, InputPoint, template,
  context, readiness, provenance, or successful-control value; exactly one
  producer-local `SENSITIVE_FORM_ELIDED` warning is safe and deterministic.
- The N-34 shared-identity collision proves the safe anchor is the only
  contributor before `_finalize_points()` and crawler coalescing; no
  reconstruction or value scrubbing occurs.
- Static-only/default extractor fixtures remain unchanged, unrelated forms are
  not elided, and form-only sensitive Endpoints are absent only in the opt-in
  path.
- Unequal budget/elapsed, zero-navigation, partial, and Static-only statistics
  follow Section 10 without changing existing Static fixtures.
- No browser or network import is added.

**Independent Gate Review checklist**

- Contract change is minimal and versioned consistently.
- Producer and existing pipeline consumer owners review the boundary.
- Static and legacy contract fixtures remain valid.
- Every actual `CrawlStatistics` field has an encoded/tested aggregate rule.
- No display-string reconstruction or silent provenance loss exists.

**Critical/High issues that block commit**

- Static/legacy contract incompatibility; ambiguous merge order; mixed
  provenance accepted outside aggregate mode; unresolved ownership/reference
  validation; classification reads a password value; a sensitive form reaches
  `add_form()`/canonical construction/coalescing; the safe-anchor collision
  contains a password type/value/raw token; a form-only sensitive Endpoint
  survives; warning collision/leak; unfiltered fallback; unrelated-form elision;
  inconsistent statistics; incorrect contract versioning.

**Non-blocking Medium/Low issues to defer**

- Naming preferences for policy fields; optional serializer convenience;
  generalized N-producer aggregation beyond Static plus Dynamic.

**Focused commit boundary**

Canonical aggregate contract and merge-policy foundation only.

**Proposed focused commit message**

`feat(discovery): define dynamic aggregate contract policy`

**Maximum correction loops:** 2

### Milestone 2 — Browser Lifecycle and Loopback Harness

**Objective**

Introduce the optional synchronous Playwright lifecycle behind a narrow
protocol and prove deterministic cleanup/request interception on loopback.

**2026-07-30 focused implementation unit**

The first Milestone 2 commit is limited to strict optional-runtime capability
preflight. It declares the `dynamic` optional dependency, preserves import-safe
Static/legacy mode, verifies the supported Playwright release, requires a
callable context-wide `BrowserContext.route_web_socket()`, verifies the
matching Chromium executable, performs one headless launch, and closes every
created resource exactly once. Failures expose stable secret-free codes and
setup hints without provider exception text.

This unit does not create a browser context or page, install routing hooks,
navigate, extract DOM, add the loopback harness/strict gate, or claim Milestone
2 complete. Those responsibilities remain in the next coherent lifecycle
unit. The Playwright Python API and v1.48 release notes were rechecked before
dependency metadata changed; both identify `route_web_socket()` as introduced
in v1.48 and direct callers to register it before page creation.

**Allowed files to modify**

- `pyproject.toml`
- `tools/check_lint.py`
- `tools/check_dynamic_gate.py` (new proposed strict-gate runner)
- `src/vulnspider/discovery/dynamic_browser.py` (new)
- `src/vulnspider/discovery/__init__.py`
- `tests/unit/test_dynamic_browser.py` (new)
- `tests/unit/test_dynamic_gate.py` (new proposed runner tests)
- `tests/integration/dynamic_loopback_site.py` (new)
- `tests/integration/test_dynamic_browser_loopback.py` (new)
- this active plan

**Files that must not be modified**

- Static crawler/extractor implementation
- canonical domain models
- pipeline and CLI
- observation, scoring, selection, and reporting
- legacy reference code

**Public interface added or changed**

- `DynamicBrowser` and session protocol.
- Proposed immutable `DynamicRequestAuthority`.
- Immutable rendered navigation/snapshot record types.
- Proposed immutable secret-free `BrowserAuditSummary`.
- Proposed `BrowserContext.route_web_socket()` dependency with verified
  Playwright 1.48 minimum and mandatory callable capability preflight.
- `PlaywrightDynamicBrowser`.
- Proposed base-capability test helper and strict-gate runner; neither exists at
  the current repository baseline.
- Typed lifecycle error codes that contain no secret data.

**Narrow implementation unit**

Resolve the approved optional dependency strategy, narrow lint so Playwright is
allowed only in `dynamic_browser.py`, implement capability preflight,
launch/context/pre-page HTTP(S)-plus-WebSocket guards/page/navigation/cleanup,
default-deny exact request authority, and secret-free audit accounting. Define
the exact WebSocket/EventSource counters and child-frame
attach/request/block/commit/completion/detach classifications. Create the
deterministic explicit `browser-loopback` manifest in the proposed strict
runner and the shared loopback harness with same/cross-origin WebSocket and
EventSource attempts,
automatic popup, same/cross-origin iframe, redirect, JavaScript location,
blocked fetch/XHR, unsafe same-origin GET, autosubmit, and deterministic
test-driven page-close cases. Do not extract canonical models yet.

**Narrow test command**

Base-capable command; real-browser cases may explicitly skip when the optional
runtime is unavailable and therefore this command alone is not Dynamic safety
proof:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_dynamic_browser `
  tests.integration.test_dynamic_browser_loopback
```

Proposed strict command after this milestone implements the runner:

```powershell
$env:PYTHONPATH='src'
python -B tools/check_dynamic_gate.py --suite browser-loopback
```

**Complete regression command**

```powershell
$env:PYTHONPATH='src'
python -B -m unittest discover -s tests
python -B tools/check_format.py
python -B tools/check_lint.py
python -B tools/check_types.py
git diff --check
```

**Safety assertions**

- Headless, ephemeral context only; no persistent profile or storage state.
- HTTP(S) routing and mandatory context-wide WebSocket denial exist after
  context creation and before page creation, navigation, or page script.
- `ws://`/`wss://` are never authorized; browser blocked equals attempted,
  connected is zero, and server handshake/connection counters are zero.
- EventSource is explicitly classified under HTTP(S), never inherits another
  grant, and browser allowed/server request counters are zero.
- Cross-origin, non-GET, and unauthorized same-origin server counters remain
  zero.
- Popup/frame/redirect/location/fetch behavior is asserted in a real browser
  using server and audit evidence together. Frame assertions cover
  attach/request/block/commit/completion/detach and separately classify
  internal/error/about:blank/replacement documents.
- Browser/page/context close on success, timeout, launch partial failure, and
  exception.
- Missing dependency does not break Static/legacy imports.
- The strict gate fails on missing package/browser, launch failure, or any
  required real-browser skip; it also fails if the WebSocket hook is absent,
  the manifest is incomplete, no required test executes, or expected/executed
  counts differ, and prints expected, executed, and skipped counts.

**Independent Gate Review checklist**

- Dependency strategy and browser-install instructions are approved.
- Official Playwright Python documentation confirms the proposed
  `playwright>=1.48,<2` lower bound provides context-wide
  `route_web_socket()`; strict preflight proves it callable.
- Concrete adapter is the only production Playwright import.
- Request routing cannot be bypassed by popups, frames, redirects, page script,
  or service workers.
- Request authority is immutable, caller-owned, exact, and never expanded from
  DOM observations.
- Logs/errors contain no cookies, headers, storage, DOM, or passwords.

**Critical/High issues that block commit**

- Resource leak; persistent user data; cross-origin, POST, or unauthorized
  same-origin request reaches a server; popup/frame policy is proved only by a
  fake; any WebSocket handshake/connection or EventSource request reaches a
  server; WebSocket protection is absent/silently disabled; child-frame
  commit/completion cannot be classified; eager optional import breaks existing
  CLI; strict gate can pass by skipping or an incomplete/empty manifest;
  unbounded navigation; secret-bearing diagnostics.

**Non-blocking Medium/Low issues to defer**

- Support for Firefox/WebKit; richer console diagnostics; reusable browser
  pools; async API; performance tuning.

**Focused commit boundary**

Optional browser lifecycle, safety interception, and loopback harness only.

**Proposed focused commit message**

`feat(discovery): add bounded browser lifecycle`

**Maximum correction loops:** 2

### Milestone 3 — Rendered DOM Extraction

**Objective**

Convert one bounded sanitized rendered snapshot into canonical dynamic
discovery data while preserving Static extraction semantics.

**Allowed files to modify**

- `src/vulnspider/discovery/rendered_dom.py` (new)
- minimal behavior-preserving changes in
  `src/vulnspider/discovery/html_extractor.py`
- `src/vulnspider/discovery/__init__.py`
- `tests/unit/test_rendered_dom.py` (new)
- `tests/unit/test_rendered_dom_adversarial.py` (new)
- existing static extractor tests only when needed to lock unchanged behavior
- this active plan

**Files that must not be modified**

- browser navigation implementation beyond interface corrections
- Static crawler
- pipeline/CLI
- domain/scoring/selection/reporting
- dependency declarations

**Public interface added or changed**

- `RenderedDomSnapshot` redaction/size invariant if not finalized in
  Milestone 2.
- `extract_rendered_dom(..., authority)`.
- Structural, value-free rendered-form occurrence classification needed for
  pre-canonical elision; it is not a canonical model or cross-producer
  fingerprint.
- Static extractor compatibility extension for explicit
  `CollectorKind.NATIVE_DYNAMIC` metadata without changing
  `extract_static_html()` defaults/output.

**Narrow implementation unit**

Implement stabilization projection helpers, live-control state normalization,
value-blind structural sensitive-form detection before any form-control value
projection, whole-form omission before semantic parsing, size enforcement,
dynamic metadata/provenance, and rendered anchor/non-sensitive form/query
extraction. Emit one subject-free `SENSITIVE_FORM_ELIDED` warning per sensitive
rendered occurrence; never build its Endpoint, InputPoint, RequestTemplate,
context, readiness, or provenance. Mark contexts
derived from URLs absent from exact
authority `NOT_READY` with `REQUEST_NOT_AUTHORIZED`; no route navigation or
authority expansion.

**Narrow test command**

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_rendered_dom `
  tests.unit.test_rendered_dom_adversarial `
  tests.unit.test_html_extractor `
  tests.unit.test_html_extractor_adversarial
```

**Complete regression command**

```powershell
$env:PYTHONPATH='src'
python -B -m unittest discover -s tests
python -B tools/check_format.py
python -B tools/check_lint.py
python -B tools/check_types.py
git diff --check
```

**Safety assertions**

- Password values are never read, and no sentinel leaves the browser fixture.
- Structural evidence contains only safe source/action/method/occurrence/
  control-type facts; marked forms are omitted before the semantic parser and
  never used for cross-producer matching.
- Any normalized `type=password` descendant causes zero form-derived canonical
  artifacts and exactly one producer-local `SENSITIVE_FORM_ELIDED` warning.
- No password-form Endpoint, InputPoint, template, context, readiness, or
  provenance exists; no request can be produced.
- Unauthorized Dynamic surfaces remain discoverable but their contexts do not
  enter `ready_contexts()`.
- No browser/network import in rendered DOM module.
- Disabled/unnamed/malformed controls fail closed.
- Repeated occurrences, blank values, and raw encoded tokens remain exact.
- Static extractor fixtures remain unchanged and passing.

**Independent Gate Review checklist**

- Static and rendered paths use one semantic rule set.
- Dynamic collector provenance is truthful.
- Sanitization occurs before size checks, logs, and exceptions.
- A username-plus-password GET form proves zero form-derived canonical
  artifacts, one Dynamic warning, no value read/projected, and no fabricated
  sibling.
- Authorized and unauthorized otherwise-identical anchors/forms prove that
  authority changes readiness, not discovery visibility or identity.
- Output is immutable, canonical, deterministic, and validated.

**Critical/High issues that block commit**

- Password value access/leakage; any password-form canonical artifact survives;
  form-only Endpoint survives; duplicate/missing warnings; unfiltered fallback;
  static semantic regression; occurrence collapse; raw-query rewrite;
  dynamic output claiming static provenance; extraction performs I/O.

**Non-blocking Medium/Low issues to defer**

- More HTML5 controls; shadow DOM; iframe DOM; framework component metadata;
  cosmetic warning wording.

**Focused commit boundary**

Sanitized rendered DOM preprocessing and canonical extraction only.

**Proposed focused commit message**

`feat(discovery): extract bounded rendered DOM`

**Maximum correction loops:** 2

### Milestone 4 — Bounded Same-Origin Navigation

**Objective**

Orchestrate rendered pages and the exact minimal passive SPA route model under
deterministic caller authority, same-origin, navigation, action, network, DOM,
and time budgets.

**H-04-R1 corrected gate decision and test ownership:** Milestone 2 creates the
proposed strict runner and initial explicit manifest, Milestone 4 may add only
its owned mandatory cases and cannot commit without an actual non-skipped
`browser-loopback` pass, and Milestone 7 retains that evidence in the final
gate.

**Allowed files to modify**

- `src/vulnspider/discovery/dynamic_crawler.py` (new)
- `src/vulnspider/discovery/dynamic_browser.py`
- `src/vulnspider/discovery/rendered_dom.py`
- shared public URL/origin helper location chosen by Gate Review
- `src/vulnspider/discovery/__init__.py`
- `tests/unit/test_dynamic_crawler.py` (new)
- `tests/unit/test_dynamic_crawler_adversarial.py` (new)
- `tools/check_dynamic_gate.py`, only to add deterministic explicit
  `browser-loopback` manifest entries for Milestone 4-owned cases
- `tests/unit/test_dynamic_gate.py`, only when needed to lock those manifest
  completeness/failure rules
- `tests/integration/dynamic_loopback_site.py`
- `tests/integration/test_dynamic_browser_loopback.py`
- this active plan

**Files that must not be modified**

- canonical domain identity semantics
- pipeline and CLI
- observation/scoring/selection/reporting
- legacy adapter/reference

**Public interface added or changed**

- `DynamicCrawlPolicy`.
- `DynamicCrawler.crawl(root_url, policy, authority) -> DynamicCrawlResult`.
- Reviewed shared canonical same-origin predicate used without changing Static
  behavior.

**Narrow implementation unit**

Implement deterministic candidate ordering, passive automatic-history/hash
recording, exact intersection with caller navigation authority, direct
`page.goto()` only for authorized matches, stabilization orchestration, all
budgets, audit aggregation, warnings, and partial Dynamic result creation.
Unauthorized same-origin candidates remain discoverable but never enter the
request queue. Preserve the mandatory pre-page WebSocket denial, HTTP(S)
EventSource denial, and exact child-frame lifecycle audit. Update only
Milestone 4-owned entries in the explicit strict `browser-loopback` manifest;
that manifest must include all mandatory Milestone 2 and Milestone 4 real-
browser cases: WebSocket, EventSource, iframe lifecycle, redirect, popup,
JavaScript navigation, unsafe GET, fetch/XHR, and autosubmit. No
Static-plus-Dynamic merge yet.

**Narrow test command**

Milestone 4 uses this fixed order. First run its unit tests:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_dynamic_crawler `
  tests.unit.test_dynamic_crawler_adversarial
```

Second run the real-browser loopback tests directly:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest tests.integration.test_dynamic_browser_loopback -v
```

Third run the non-skippable strict gate:

```powershell
$env:PYTHONPATH='src'
python -B tools/check_dynamic_gate.py --suite browser-loopback
```

This proposed command does not exist at the current repository baseline; it is
created by owning Milestone 2. It must fail for a missing Playwright package,
matching Chromium, launch capability, or context-wide WebSocket hook; any
required skip; zero executed required tests; unequal expected/executed counts;
nonzero skipped count; or any absent mandatory manifest case. It prints
expected, executed, and skipped counts.

**Complete regression command**

Fourth run full base regression, then fifth run format/lint/type/diff checks:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest discover -s tests
python -B tools/check_format.py
python -B tools/check_lint.py
python -B tools/check_types.py
git diff --check
```

Sixth, request Independent Gate Review. The focused commit is blocked unless
all six ordered stages complete and the strict gate actually runs and passes.
A Mode A skip is never sufficient for this milestone.

**Safety assertions**

- Same-origin uses scheme/hostname/effective port.
- Same-origin never grants authority; root and every additional request match an
  immutable exact caller grant.
- WebSocket remains always denied by the pre-page context hook; EventSource
  remains always denied by HTTP(S) routing; all browser/server counters are
  asserted by the strict real-browser manifest.
- Strict iframe cases assert
  `child_frame_attach_attempt_count`,
  `child_frame_document_request_count`,
  `child_frame_document_blocked_count`, commit/completion classifications,
  `child_frame_detach_count`, and bounded committed-origin summaries together
  with zero unauthorized fixture endpoint requests and zero authorized child-
  frame completions.
- `/delete`, `/reset`, `/logout`, and `/state-change` request counters remain
  zero while their eligible links remain discoverable.
- No arbitrary click, form submit, target-blank activation, popup request,
  iframe DOM, or state-changing method.
- Unauthorized Dynamic input contexts are non-ready and cannot be requested by
  the downstream canonical consumer.
- Every counter is at or below its configured budget.
- Budget/timeout exhaustion returns partial validated records and warnings.
- Input permutation and repeated run produce equal canonical output.

**Independent Gate Review checklist**

- Scope and exact authority checks occur before every scheduled navigation and
  resource request.
- Context route remains the final transport guard.
- The separate WebSocket hook remains registered before every page and the
  explicit strict manifest contains every Milestone 2/4 mandatory case.
- The strict runner reports equal nonzero expected/executed counts, zero skips,
  and an actual successful Chromium run before review.
- Queue ordering and duplicate rules are deterministic.
- Elapsed deadline bounds launch, navigation, stabilization, and cleanup.

**Critical/High issues that block commit**

- Scope/authority bypass; DOM-derived authorization; unauthorized same-origin
  GET; POST/unsafe method; any WebSocket handshake/connection or EventSource
  server request; incomplete child-frame commit/completion evidence; missing
  mandatory manifest case; package/browser/launch/WebSocket-capability
  preflight failure; any required skip, zero executed tests, count mismatch, or
  strict-gate failure; unbounded loop/action/mutation; queue nondeterminism;
  cleanup failure that leaves browser running; invalid partial contract.

**Non-blocking Medium/Low issues to defer**

- Rich router instrumentation; href-less widgets; deeper routes; parallel
  pages; retry strategy; performance.

**Focused commit boundary**

Bounded same-origin dynamic crawl orchestration plus its Milestone 4-owned
strict browser-loopback manifest evidence only.

**Proposed focused commit message**

`feat(discovery): crawl bounded rendered routes`

**Maximum correction loops:** 2

### Milestone 5 — Combined Native Discovery Orchestration

**Objective**

Run the existing Native Static and Native Dynamic crawlers through one strict
Static-first public entry point, validate both components, and hand them to the
existing reviewed merge core. Prove canonical identity, provenance, readiness,
ordering, ownership, and explicit degraded completion across producers.

**Allowed files to modify**

- `src/vulnspider/discovery/combined.py`
- minimal compatible-scope correction in `src/vulnspider/discovery/merge.py`
- minimal Static aggregate safety-marker propagation in
  `src/vulnspider/discovery/static_crawler.py`
- `src/vulnspider/discovery/__init__.py`
- `tests/unit/test_combined_discovery.py`
- narrow existing merge/Gate tests
- `tests/integration/test_combined_discovery_loopback.py`
- minimal shared loopback fixture and strict Gate manifest additions
- this active plan

**Files that must not be modified**

- Static crawler transport/extraction behavior beyond propagating an explicitly
  declared, already-enforced safety invariant
- browser lifecycle/navigation behavior
- pipeline/CLI
- observation/scoring/selection/reporting
- dependencies

**Public interface added or changed**

- `NativeDiscoveryOrchestrator.discover(...) -> CombinedDiscoveryResult`.
- `discover_native_combined(...) -> CombinedDiscoveryResult` convenience entry.
- `CombinedDiscoveryResult.discovery` is the validated
  `NATIVE_COMBINED CanonicalDiscoveryResult` accepted by the existing consumer;
  producer crawl results and Dynamic `COMPLETE`/`DEGRADED` state remain visible.
- Existing `merge_discovery_results(static, dynamic, policy)` remains the only
  canonical identity/conflict/statistics merge implementation.

**Narrow implementation unit**

Validate immutable caller authority before transport. Bind the reviewed
pre-canonical sensitive-form elision policy to the default Static producer, run
Static then Dynamic, validate each canonical component, and call the existing
merge core unchanged for identity/conflict/statistics rules. Producer or
canonical-integrity exceptions propagate without a Static-only fallback.
Validated partial Dynamic output may merge, but `CombinedDiscoveryResult`
retains and serializes `DEGRADED`; it cannot present partial execution as
complete. Compatible producer-local scope-decision references are preserved as
a canonical union while root, target-scope identity, and policy version must
match exactly. No producer object is mutated, no sensitive-form comparison or
post-canonical filtering occurs, and no Probe/CLI/Feature/Scoring work is added.

**Narrow test command**

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_combined_discovery `
  tests.unit.test_discovery_merge `
  tests.unit.test_dynamic_gate `
  tests.integration.test_combined_discovery_loopback
python -B tools/check_dynamic_gate.py --suite combined-discovery
```

**Complete regression command**

```powershell
$env:PYTHONPATH='src'
python -B -m unittest discover -s tests
python -B tools/check_format.py
python -B tools/check_lint.py
python -B tools/check_types.py
git diff --check
```

**Safety assertions**

- Static input remains equal before/after failure or success.
- Forged/missing/mismatched dynamic records never enter aggregate output.
- Canonical/ownership/provenance/statistics failures propagate as hard errors;
  they do not return Static as successful Dynamic fulfillment.
- Producer provenance survives exact deduplication.
- Blank/raw/repeated occurrence identity survives.
- Neither producer input contains a sensitive-form Endpoint, InputPoint,
  template, context, readiness, provenance, value, raw token, or type
  contribution; merge never creates or reconstructs one.
- N-34 proves the safe anchor's InputPoint, `baseline_values`, raw token,
  template/context/readiness, and provenance remain uncontaminated and valid;
  form-only sensitive Endpoint is absent; when both producers observe the form,
  the aggregate preserves exactly two secret-free warnings—one Static then one
  Dynamic.
- Warning identity semantics are unchanged; no cross-producer warning
  deduplication or synthetic merged-provenance warning exists.
- Aggregate statistics satisfy the field table for unequal budgets, partial
  results, zero navigations, and canonical counts.
- Static-first order is invariant under input collection permutation.

**Independent Gate Review checklist**

- Every conflict rule is encoded and tested.
- The 15 pre-canonical-elision cases prove zero sentinel occurrences in all
  canonical/provenance/warning/diagnostic/audit/report/log/exception surfaces,
  no sensitive GET execution, no POST submission, independent safe discovery
  preservation, form-only Endpoint absence, and no cross-producer form
  matching. N-32/N-34 prove producer-local exact warning suppression, both
  producer warnings preserved, and Static-before-Dynamic aggregate order.
- No canonical ID is reconstructed from display text.
- Aggregate activity/count statistics, ownership, readiness, and provenance
  validate.
- Operational failure can leave Static usable, while canonical integrity
  failure aborts the requested Dynamic analysis.

**Critical/High issues that block commit**

- Static mutation/loss; provenance loss or false producer claim; occurrence
  collapse; non-associative behavior under fixed policy; unresolved references;
  merge receives or reconstructs any sensitive-form artifact; a secret reaches
  any aggregate surface; safe independent Endpoint/InputPoint is lost;
  form-only sensitive Endpoint survives; sensitive GET/POST executes; incorrect statistics arithmetic;
  integrity failure downgraded to Static-only success; dynamic invalidity
  corrupting static output.

**Non-blocking Medium/Low issues to defer**

- Generic multi-producer API; metadata conveniences; performance on large
  result sets beyond MVP bounds.

**Focused commit boundary**

Strict Static-plus-Dynamic orchestration, direct seam corrections, and its
five-case real-Chromium Gate only.

**Proposed focused commit message**

`feat(discovery): orchestrate combined native discovery`

**Maximum correction loops:** 2

### Milestone 6 — CLI and Pipeline Integration

**Objective**

Add backward-compatible opt-in Dynamic Discovery to `--url`, preserve legacy
and Static-only defaults, and send exactly one merged canonical result to the
existing consumer.

**Allowed files to modify**

- `src/vulnspider/pipeline.py`
- `src/vulnspider/cli.py`
- `src/vulnspider/discovery/__init__.py`
- `tests/unit/test_native_pipeline_cli.py`
- new focused pipeline tests if the existing file becomes unwieldy
- `README_START_HERE.md`
- `docs/ARCHITECTURE.md`
- `docs/PROTOTYPE_V0_2.md`
- `docs/DECISION_LOG.md` when a reviewed ADR is required
- this active plan

**Files that must not be modified**

- scoring, selection, reporting semantics
- legacy adapter behavior
- Static crawler/extractor behavior
- browser/merge internals except narrow interface corrections
- domain identity models

**Public interface added or changed**

- `analyze_url()` optional dynamic crawler/policy arguments with default off.
- `AnalysisResult` retains aggregate discovery plus optional static/dynamic
  crawl results without changing existing properties; proposed Dynamic result
  completion state is `COMPLETE` or `DEGRADED`.
- CLI `--dynamic` opt-in and separately named bounded dynamic-policy options.
- Proposed repeatable `--dynamic-allow-navigation URL` and
  `--dynamic-allow-resource CATEGORY=URL` options construct immutable request
  authority before browser launch.
- Dynamic options are invalid with `--input` or without `--dynamic`.
- Proposed typed capability and merge-integrity errors plus explicit exit
  statuses from Section 21.

**Narrow implementation unit**

Run Static first. When `--dynamic` is present, validate exact request authority,
perform lazy capability preflight, construct the policy-bound Static extractor
callable from Milestone 1, inject it into `StaticCrawler`, run Dynamic Discovery
with rendered pre-canonical elision, and merge only validated complete/partial
safe output before calling unchanged `analyze_discovery_result()`. No
password-bearing Static canonical intermediate is created or retained in
`AnalysisResult`. Assert zero sensitive-form canonical artifacts before
`ready_contexts()` and `_analyze_contexts()`, including N-34. Without
`--dynamic`, use the default extractor/crawler path with no elision policy and
preserve current Static-only behavior.
Operational degradation produces explicit `DYNAMIC_INCOMPLETE` status/warning
and the proposed degraded exit. Capability and canonical integrity failures
take their distinct nonzero hard-failure paths and do not write a success
report. Update stale documentation to describe Static as implemented and
Dynamic accurately by status.

**Narrow test command**

```powershell
$env:PYTHONPATH='src'
python -B -m unittest `
  tests.unit.test_native_pipeline_cli `
  tests.integration.test_v01_smoke
```

**Complete regression command**

```powershell
$env:PYTHONPATH='src'
python -B -m unittest discover -s tests
python -B tools/check_format.py
python -B tools/check_lint.py
python -B tools/check_types.py
git diff --check
```

**Safety assertions**

- No flag means current Static-only behavior.
- `--input` legacy behavior is unchanged and cannot activate browser code.
- Explicit Dynamic capability failure exits nonzero without pretending Static
  fulfilled the request.
- Enumerated Dynamic operational failure retains only validated data, marks
  `DEGRADED`, and returns the proposed degraded nonzero exit.
- Canonical integrity failure returns the proposed internal-error exit and no
  report.
- Invalid merged contract is never consumed.
- Sensitive forms contribute no Endpoint, InputPoint, template, context,
  readiness, or provenance; the sentinel is absent from output/diagnostics,
  neither GET nor POST executes, independently safe discoveries remain, and
  form-only sensitive Endpoints are absent.
- Unauthorized Dynamic discoveries never appear in `ready_contexts()`.
- Warnings never enter candidate/scoring data.
- `SENSITIVE_FORM_ELIDED` remains visible only as discovery safety/degradation
  information and is never converted into a vulnerability finding.

**Independent Gate Review checklist**

- CLI combinations and errors are deterministic and tested.
- Optional import remains lazy.
- Existing `DiscoveryContractError` is caught before the current broad
  `ValueError` handler; the broad handler is not silently expanded.
- Exact navigation/resource options are rejected if malformed, cross-origin,
  credential-bearing, or supplied outside `--dynamic`.
- Existing public call sites remain source-compatible.
- Documentation reflects implemented/planned status without overclaim.

**Critical/High issues that block commit**

- Dynamic runs implicitly; DOM content expands authority; legacy/static
  regression; missing capability is reported as success; integrity error is
  downgraded; elision policy is omitted/bypassed/falls back; a secret-bearing
  result reaches probes/storage/logs; N-34 safe anchor is contaminated;
  sensitive Static GET or any POST executes; unrelated form is elided; scoring/Top-K
  changes; warning becomes finding; stale or misleading safety documentation.

**Non-blocking Medium/Low issues to defer**

- CLI flag naming preferences; configuration file support; richer progress
  output; consolidating policy flags.

**Focused commit boundary**

Opt-in pipeline/CLI integration and directly required status documentation.

**Proposed focused commit message**

`feat(pipeline): integrate opt-in dynamic discovery`

**Maximum correction loops:** 2

### Milestone 7 — Final Loopback E2E

**Objective**

Prove the complete Static-plus-Dynamic loopback CLI flow, safety counters,
canonical/report consistency, cleanup, and unchanged regression baseline.

**Allowed files to modify**

- `tests/integration/dynamic_loopback_site.py`
- `tests/integration/test_native_dynamic_discovery_e2e.py` (new)
- `tools/check_dynamic_gate.py` only to add the final required-test manifest
- narrow corrections to dynamic production modules only when a failing
  acceptance test demonstrates a Critical/High defect
- this active plan for final evidence/progress

**Files that must not be modified**

- scoring weights or Top-K policy
- legacy behavior
- unrelated docs/refactors
- reference legacy code
- dependency strategy except a proven blocking correction

**Public interface added or changed**

None expected. Any required public change returns to the owning earlier
milestone and its Gate Review rather than being hidden in E2E work.

**Narrow implementation unit**

Complete the deterministic fixture and one end-to-end test that invokes
`cli.main()` with `--url --dynamic` plus exact authority options, asserts server
and browser-audit counters, canonical surfaces/provenance/statistics, password
form pre-canonical elision, N-34 safe-anchor preservation, form-only Endpoint
absence, completion status, report
consistency, and cleanup. The final strict gate must exercise real Chromium,
include the strict `browser-loopback` WebSocket/EventSource/iframe lifecycle/
redirect/popup/location/unsafe-GET/fetch/autosubmit manifest coverage, and
reject any skip or absent mandatory case. Add focused
adversarial E2E only when it verifies a listed safety boundary not covered
narrowly. The final fixture invocation uses existing Static `--max-depth 0` so
the Static producer fetches only the authorized root; unsafe links are
JavaScript-only and test Dynamic authority rather than changing Static
semantics.

**Narrow test command**

Proposed strict command; it must preflight package/browser availability, fail
on any required skip, and print the executed required-test count:

```powershell
$env:PYTHONPATH='src'
python -B tools/check_dynamic_gate.py --suite final
```

**Complete regression command**

```powershell
$env:PYTHONPATH='src'
python -B -m unittest discover -s tests
python -B -m unittest tests.integration.test_v01_smoke -v
python -B -m unittest tests.integration.test_native_static_discovery_e2e -v
python -B tools/check_dynamic_gate.py --suite final
python -B tools/check_format.py
python -B tools/check_lint.py
python -B tools/check_types.py
git diff --check
```

**Safety assertions**

- Sentinel requests, cross-origin navigations, POST submissions, and
  unauthorized same-origin endpoint requests are all exactly zero.
- WebSocket server handshake/connection counts are zero; browser attempts equal
  blocks and connected is zero. EventSource server/allowed counts are zero and
  browser attempts equal blocks.
- Popup, frame, redirect, JavaScript-location, fetch/XHR, navigation-commit,
  and cleanup audit counters agree with server counters. Child-frame audit
  specifically proves attach/request/block/commit/completion/detach,
  zero authorized completion, separate internal/error/about:blank/replacement
  classifications, and bounded safe committed-origin summaries.
- Browser request/page/navigation/action/depth/time counts are bounded.
- `PW_SENTINEL` is absent from producer/aggregate results, warnings, diagnostics,
  exceptions, browser audit, reports, logs, and captured test output.
- Serialized JSON, rendered HTML report, captured logs/exceptions/test output
  each contain zero sentinel occurrences.
- Static and Dynamic sensitive forms are independently elided before canonical
  construction; all form-derived artifacts are absent, form-only Endpoints are
  absent, independently safe discoveries remain, one warning exists per
  producer observation, and no derived GET/POST executes.
- N-34 proves the safe anchor creates the only `q` InputPoint with safe-only
  `type_hint`, `baseline_values`, raw-query metadata, context, and provenance.
  When Static and Dynamic both observe the sensitive form, final output has
  exactly two warnings—one Static then one Dynamic—with zero secret values in
  either warning. Each retains its own producer-kind attribution without a
  canonical subject/provenance reference; neither warning becomes a candidate,
  feature, score, or finding.
- Aggregate statistics satisfy Section 10.
- Static and Dynamic provenance both survive merge.
- Browser processes and server threads close.

**Independent Gate Review checklist**

- All acceptance criteria map to assertions.
- The strict runner reports a nonzero required-test count, zero required skips,
  equal expected/executed counts, complete deterministic manifests, mandatory
  WebSocket capability, and a successful real Chromium preflight.
- JSON and HTML consume the same authoritative selection.
- Dynamic warnings are absent from candidate evidence.
- Full branch diff contains no secrets, captures, screenshots, profiles,
  browser binaries, or generated reports.
- Gate result is `PASS` or `PASS WITH MINOR`.

**Critical/High issues that block commit**

- Any external/POST/unauthorized same-origin/EventSource request or WebSocket
  handshake/connection; browser-audit/server mismatch; incomplete child-frame
  classification; missing manifest case; required real-browser skip; resource
  leak; nondeterministic result; password leak, any form-derived sensitive
  artifact, surviving form-only Endpoint, contaminated/missing safe anchor, or
  unrelated-form elision; incorrect aggregate statistics;
  integrity fallback; report/canonical mismatch; existing regression failure;
  unreviewed production interface change.

**Non-blocking Medium/Low issues to defer**

- Fixture organization preferences; extra framework examples; performance
  improvements; nonessential report presentation.

**Focused commit boundary**

Final loopback acceptance harness and E2E evidence only.

**Proposed focused commit message**

`test(discovery): verify dynamic discovery end to end`

**Maximum correction loops:** 2

## 17. Quality and Gate Workflow

Every milestone follows exactly:

```text
Plan
-> Small Implementation Unit
-> Narrow Test
-> Complete Regression Test
-> Independent Gate Review
-> Fix Critical/High Only
-> Focused Commit
-> Next Milestone
```

Rules:

- Maximum two correction loops per milestone.
- A Critical or High correctness, safety, scope, contract, ownership,
  provenance, cleanup, or regression issue blocks that milestone's commit.
- Medium/Low naming preferences, speculative generalization, optional future
  refactors, and performance preferences do not block; record and defer them.
- Do not commit directly to `main`.
- Do not push directly to `main`.
- Do not force-push any shared branch.
- Do not commit secrets, cookies, session state, authorization data, `.env`
  contents, browser profiles, storage state, screenshots, videos, traces,
  HAR files, browser binaries, or generated reports.
- Open a PR only after all milestones, full regression, final E2E, and final
  Gate Review pass.
- Obtain at least one teammate review before merge. Because this work changes
  network scope/interception and a shared canonical contract, request affected
  producer/consumer review and a second safety reviewer when practical.
- A milestone with a failing required check remains uncommitted.
- Milestone 4 is a stricter ordered case: narrow unit tests, direct real-browser
  loopback tests, non-skippable `--suite browser-loopback`, full base
  regression, format/lint/type/diff checks, then Independent Gate Review. Its
  commit cannot rely on a Mode A skip.
- If correction loop two still has a Critical/High issue, stop and escalate
  rather than broadening scope.

Current repository commands at this plan baseline:

```powershell
$env:PYTHONPATH='src'

python -B -m unittest discover -s tests

python -B -m unittest tests.integration.test_v01_smoke -v
python -B -m unittest tests.integration.test_native_static_discovery_e2e -v

python -B tools/check_format.py
python -B tools/check_lint.py
python -B tools/check_types.py
git diff --check
```

`tests.integration.test_native_dynamic_discovery_e2e` and
`tools/check_dynamic_gate.py` do not exist at the baseline and are not current
commands.

### Mode A — Base regression

The existing `python -B -m unittest discover -s tests` command remains the base
mode. Dynamic production modules and test support resolve Playwright lazily so
module import succeeds when the optional package is absent. Real-browser cases
perform a capability check after import and may use `unittest` skip with an
explicit package-missing, executable-missing, or launch-unavailable reason.
Static, legacy, fake-adapter, contract, and non-browser Dynamic tests still run.
A skip is reported as unavailable evidence and never recorded as a Dynamic
safety pass.

Installing the Python package and installing its matching Chromium executable
are separate environment actions. Base mode requires neither. Application code
and ordinary tests never download a browser automatically.

### Mode B — Proposed strict Dynamic gate

Milestone 2 proposes `tools/check_dynamic_gate.py`; it is not a current
repository command. The runner:

1. imports the approved Playwright package lazily;
2. verifies the matching Chromium executable and performs a launch/close
   preflight, and verifies the required context-wide WebSocket hook exists and
   is callable;
3. loads a fixed named manifest for `--suite browser-loopback` or
   `--suite final`;
4. runs the real-browser tests;
5. fails if preflight fails, any required test is skipped, a manifest test is
   missing, zero required tests execute, expected/executed counts differ,
   skipped count is nonzero, or any failure/error occurs; and
6. prints the expected, executed, and skipped required-test counts; expected
   and executed must be equal and greater than zero, and skipped must be zero.

The manifests are deterministic explicit test identifiers, not discovery
patterns. Milestone 2 creates `browser-loopback` with its owned mandatory
WebSocket, EventSource, iframe lifecycle, popup, and base interception cases.
Milestone 4 may add only its owned redirect, JavaScript navigation, unsafe GET,
fetch/XHR, autosubmit, and bounded-navigation cases, while retaining every
Milestone 2 entry. `--suite browser-loopback` fails when any required
Milestone 2/4 case is absent. Milestone 7 may add the final E2E manifest; it
does not defer or replace the earlier strict browser-loopback gate.

Proposed commands after their owning milestones implement them:

```powershell
$env:PYTHONPATH='src'
python -B tools/check_dynamic_gate.py --suite browser-loopback
python -B tools/check_dynamic_gate.py --suite final
```

Milestone 4 must run and pass Mode B `--suite browser-loopback` before its
focused commit. The final branch gate runs Mode A plus `--suite final`.
Successful final
acceptance is impossible without the optional Python package, the matching
Chromium binary, a successful launch preflight, zero required skips, and actual
execution of the final loopback E2E.

There is no repository-provided secret-scan command, CI workflow, tox, nox,
Makefile, or dependency lock command. Do not invent one as a gate. Independent
review must inspect the changed-file list and diff for secret/cookie/session/
authorization/profile/capture artifacts.

The current lint rule forbids Playwright in all `src` modules. Milestone 2 must
intentionally narrow it to permit only the concrete browser adapter; it must
not remove Playwright from the forbidden set globally. Playwright remains
forbidden from contracts, domain, extractor, merge, pipeline, scoring, and
reporting modules. Test/tool imports are allowed only in the capability helper
and proposed strict runner needed for the two explicit modes.

## 18. Acceptance Criteria

- [ ] AC-01: A loopback page element inserted only after JavaScript execution
  is present in the dynamic canonical result.
- [ ] AC-02: A dynamically inserted anchor resolves relative to the stabilized
  page URL and has `NATIVE_DYNAMIC` rendered-DOM provenance.
- [ ] AC-03: A dynamically inserted form and input produce canonical
  `Endpoint`, `InputPoint`, `RequestTemplate`, context, readiness, and
  provenance records.
- [ ] AC-04: History/hash/current-location state and rendered anchors are
  recorded passively; direct navigation occurs only for an exact URL already
  present in caller-owned navigation authority.
- [ ] AC-05: Same-origin is enforced by exact scheme, hostname, and effective
  port, but never substitutes for exact request authority.
- [ ] AC-06: External-origin sentinel request count is exactly zero.
- [ ] AC-07: Successful cross-origin main-frame navigation count is exactly
  zero.
- [ ] AC-08: POST submission/request count is exactly zero, including
  JavaScript autosubmit and fetch attempts.
- [ ] AC-09: Rendered pages, navigations, route actions, depth, network
  requests, DOM bytes, actionable elements, redirects, per-navigation time,
  stabilization time, and total elapsed time never exceed policy.
- [ ] AC-10: Budget exhaustion retains only validated prior records, marks
  Dynamic `DEGRADED`, emits a structured warning, and uses the proposed
  degraded exit rather than hanging or fabricating completeness.
- [ ] AC-11: Identical inputs and permuted collection order produce identical
  canonical ordering, stable IDs, warning order, and serialized result.
- [ ] AC-12: Static and Dynamic observation of one stable identity yields one
  canonical subject with both producer provenance records.
- [ ] AC-13: Repeated parameter names and repeated identical name/value
  occurrences remain distinct by occurrence index after merge.
- [ ] AC-14: Blank query/form values remain observed empty strings.
- [ ] AC-15: Raw percent-encoded query tokens remain byte-equivalent in
  authoritative template/provenance fields.
- [ ] AC-16: Conflicting metadata follows the documented Static-first union/
  warning policy and never uses arbitrary last-write-wins behavior.
- [ ] AC-17: Every aggregate reference, ownership relationship, Section 10
  statistic, run ID, producer provenance, readiness record, and ordering rule
  passes `CanonicalDiscoveryResult.validate()`.
- [ ] AC-18: Missing package/browser is a typed capability hard failure;
  canonical corruption is a typed integrity hard failure; only enumerated
  browser-runtime failures may produce validated degraded output and warnings.
- [ ] AC-19: Page, context, browser, Playwright, loopback servers, and threads
  are closed on success and every tested failure path.
- [ ] AC-20: Password sentinel values are absent from snapshots, canonical
  Endpoint/RequestTemplate/InputPoint/context data, provenance, warnings, merge
  diagnostics, browser audit, exceptions, logs, JSON, HTML, and test output.
- [ ] AC-21: During explicit Dynamic aggregation, each producer structurally
  elides every password form before successful-control value collection,
  Endpoint/InputPoint/template/context construction, coalescing, serialization,
  merge, readiness, analysis, or reporting. Form-only Endpoints are absent,
  independent safe discoveries remain, exactly one secret-free warning exists
  per producer observation, and no derived sensitive GET/POST executes. One
  observing producer yields one warning; both producers yield exactly two,
  ordered Static then Dynamic without cross-producer deduplication.
- [ ] AC-22: Dynamic warnings remain report warnings and never appear in
  candidate evidence, vulnerability type, score, rank, confidence, or finding.
- [ ] AC-23: `analyze_discovery_result()` remains the canonical consumer and
  receives one validated result only on complete or explicitly degraded
  operational paths; integrity failures never reach it.
- [ ] AC-24: CLI dynamic behavior is explicit opt-in; plain `--url` retains
  Static-only behavior.
- [ ] AC-25: Legacy `--input` behavior, validation, JSON output, and optional
  HTML output remain backward compatible.
- [ ] AC-26: Existing Static Discovery request counts, scope behavior,
  extraction semantics, warnings, identities, readiness, and E2E remain
  unchanged when Dynamic aggregation is not requested.
- [ ] AC-27: Mode A full regression, static E2E, v0.1 smoke, new Dynamic narrow
  suites, proposed strict Mode B final Dynamic E2E, format, lint, type, and diff
  checks pass.
- [ ] AC-28: No browser profile, browser binary, secret, session artifact,
  cookie, storage state, capture, screenshot, video, or generated report is
  tracked.
- [ ] AC-29: Missing optional Dynamic runtime leaves Static and legacy imports
  and base analysis usable, while explicit `--dynamic` and strict Mode B fail
  capability preflight nonzero.
- [ ] AC-30: Documentation status accurately distinguishes implemented Static
  Discovery, implemented bounded Dynamic MVP after completion, and deferred
  session/role/general SPA work.
- [ ] AC-31: The root is the only implicit request grant; additional
  navigation/resource grants are exact, immutable, caller-owned, same-origin,
  and never expanded by DOM or page script. Contexts derived from unauthorized
  Dynamic surfaces are `NOT_READY` with `REQUEST_NOT_AUTHORIZED`.
- [ ] AC-32: `/delete`, `/reset`, `/logout`, `/state-change`, unauthorized
  fetch/XHR, EventSource, popup documents, and frame documents all have zero
  server requests.
- [ ] AC-33: Server counters and secret-free browser audit counters jointly
  prove popup/redirect/location/request/cleanup and child-frame
  attach/request/block/commit/completion/detach behavior in real Chromium;
  authorized child-frame completion is zero and internal/error/about:blank/
  replacement documents are separate.
- [ ] AC-34: Unequal budgets/times, zero navigation, Static-only, validated
  partial Dynamic, subresource exclusion, and canonical-count recomputation
  follow the Section 10 statistics table.
- [ ] AC-35: Proposed strict Dynamic gate preflight succeeds, no required test
  skips, expected and executed counts match and are nonzero, skipped count is
  zero, every mandatory manifest case exists, and real loopback E2E ran.
- [ ] AC-36: Explicit Dynamic capability/configuration failure writes no success
  report and returns proposed exit code 2.
- [ ] AC-37: Canonical integrity failure writes no report, is not converted to
  Static-only success, and returns proposed exit code 3.
- [ ] AC-38: Enumerated operational degradation retains only validated data,
  states `DYNAMIC_INCOMPLETE`, and returns proposed exit code 4.
- [ ] AC-39: Before any page or script exists, the context-wide WebSocket hook
  is active; same/cross-origin attempts equal blocks, connected is zero, and
  server handshake/established-connection counters are zero.
- [ ] AC-40: EventSource is classified under HTTP(S) routing without inherited
  fetch/document authority; same/cross-origin attempts equal blocks,
  allowed/server/external request counts are zero.
- [ ] AC-41: The proposed Playwright lower bound is
  `playwright>=1.48,<2`, official Python documentation verification and
  callable-hook preflight pass, and strict execution fails if protection is
  unavailable.
- [ ] AC-42: All 15 Sensitive Form Pre-Canonical Elision cases N-20 through N-34
  pass with zero sentinel occurrences, zero sensitive form-derived canonical
  artifacts, no sensitive GET/POST execution, form-only Endpoint absence,
  preserved independent safe discoveries, valid deterministic ownership/
  references/counts/warnings/order, and no post-coalescing reconstruction.
- [ ] AC-43: Milestone 4 runs unit tests, direct real-browser tests, strict
  `browser-loopback`, full regression, format/lint/type/diff, then Independent
  Gate Review; Mode A skips cannot authorize its commit.

## 19. Explicit Non-Goals

This MVP does not include:

- login-form inference or generalized login automation;
- username/password entry or browser credential use;
- value-absent or optional-value request binding, sentinel substitution,
  synthetic password templates, hashed/redacted password pairs, or any domain
  redesign to preserve sensitive forms as canonical probe candidates;
- creation of any password-form InputPoint, post-coalescing shared-InputPoint
  reconstruction/splitting/repair, or storage of blank/hash/redacted password
  values;
- account creation, registration, password reset, or privilege changes;
- MFA handling, CAPTCHA handling, or authentication bypass;
- cookie injection, storage-state injection, authorization-header injection,
  client certificate setup, or persisted sessions;
- role-aware/session-aware crawling, role comparison, or account switching;
- BAC feature extraction, BAC scoring, BAC verification, or access-control
  conclusions;
- LLM context construction, GPT/Gemini calls, payload mutation, or model output;
- `PayloadValidator`, payload generation, attack payload execution, exploit
  chaining, or destructive requests;
- focused verification, `VerificationEvidence`, confidence rules,
  `VerificationConfidence`, or vulnerability confirmation;
- scoring-weight, feature, selection-priority, global Top-K, or reporting
  semantic changes;
- form submission of any method, button activation, generic `onclick`
  execution, or arbitrary DOM actions;
- DOM-derived, redirect-derived, or page-script-derived request authorization;
- same-origin fetch/XHR or route navigation without an exact caller grant;
- unrestricted crawling, Internet targets, suffix-based scope expansion,
  unlimited clicking, unlimited routes, or unlimited waits;
- popup, child-frame, shadow-DOM, web-component, or browser-extension
  discovery;
- complete support for React, Vue, Angular, Svelte, Next.js, or every SPA/router
  framework;
- interception/storage of complete browser traffic, HAR, video, tracing,
  screenshots, response bodies, or secrets;
- user browser profile reuse, persistent browser contexts, downloads, or
  connection to an existing signed-in browser;
- asynchronous high-performance crawling, concurrency, browser pooling,
  distributed crawling, retries, caching, or performance optimization;
- Firefox/WebKit parity in this MVP;
- production-scale resilience or general-purpose browser automation.

The Native Dynamic Discovery MVP does not preserve password-bearing forms as
canonical probe candidates and does not retain a password-form Endpoint unless
that Endpoint is independently discovered elsewhere. It creates no password
InputPoint, value-absent password binding, or shared InputPoint reconstruction
after coalescing, and it does not change the domain binding invariant. A future
Session-aware / Sensitive Form Discovery phase may introduce a first-class
value-state model or revise the domain binding invariant, but that work is not
part of this MVP.

Session-aware and role-aware contexts are future versioned provenance/interface
work only. No placeholder session implementation belongs in these milestones.

## 20. Open Decisions

Repository evidence resolves the following and they are not open: use
Playwright rather than Selenium for the required rendered fixture; use the
synchronous API; keep Dynamic Discovery opt-in; retain Static-first merge
precedence; separate discovery eligibility from immutable exact caller request
authority; observe History/hash state passively; use `page.goto()` only for
already-authorized exact routes; use the resolved keyword-only extraction policy
seam to pre-canonically elide password forms and omit form-only Endpoints;
aggregate every existing `CrawlStatistics` field by Section 10; separate base
and strict Dynamic test modes; and hard-fail capability and canonical integrity
errors.

These decisions remained at the plan baseline; resolutions are recorded below:

| Question | Available options | Recommended MVP default | Reason | Resolve by | Consequence of deferring |
|---|---|---|---|---|---|
| How should the Playwright Python dependency be declared without a lockfile? | Core `dependencies`; optional `[project.optional-dependencies]` extra; developer-only undocumented install | Add a named optional `dynamic` extra with proposed `playwright>=1.48,<2`; keep base dependencies empty | Static/legacy operation must not require the heavy browser runtime; 1.48 is the proposed pinned lower bound because the required context-wide WebSocket interception was introduced there | Before Milestone 2 edits, after verification against official Playwright Python documentation | Milestone 2 cannot commit; strict preflight must fail if `route_web_socket()` is unavailable or not callable |
| How should the Chromium binary be installed and version-aligned? | Automatic runtime download; repository helper; explicit documented manual Playwright install command | Chromium only, installed explicitly by the developer/CI setup step matching the approved Playwright package; never download during application execution/tests | Package installation and browser installation are separate; automatic downloads violate predictable/offline-safe runtime | Before Milestone 2 real-browser test | Base mode may skip with explicit reason, but strict Dynamic gate and Milestone 2 commit remain blocked |
| Are the proposed dynamic default budgets accepted as policy? | Accept Section 7; choose stricter reviewed values; require every caller to pass values | Approve the Section 7 defaults and use smaller explicit test policies | Defaults must be reasoned, fingerprinted, documented, and consistent across CLI/API | Before Milestone 2 policy finalization | Identity/configuration fingerprint and CLI defaults remain unstable, blocking contract/E2E acceptance |

The minimum supported Playwright line is resolved for planning as
`playwright>=1.48,<2`; Milestone 2 must verify from official Playwright Python
documentation that 1.48 introduces the required context-wide
`BrowserContext.route_web_socket()` behavior before editing dependency
metadata. The reviewed compatible release within that range and its matching
Chromium must then be selected from project compatibility evidence. If the
installed API is absent, incompatible, or not callable, strict capability
preflight fails; running without WebSocket protection is forbidden. This
was the planning-task baseline before Milestone 2 implementation began.

2026-07-30 resolution for the focused capability-preflight unit: use the
recommended named optional `dynamic` extra with `playwright>=1.48,<2`; keep
base dependencies empty; and keep Chromium installation as an explicit
developer/CI command (`playwright install chromium`) that application code and
tests never invoke. The Section 7 default-budget decision remains for the
subsequent lifecycle/policy unit. A missing package or browser remains a
reported capability failure, never a Static-only success for explicit Dynamic
mode.

2026-08-01 Milestone 2 policy resolution: approve every Section 7 default as
the reviewed Dynamic MVP policy. Milestone 2 directly implements the lifecycle
subset (`3` second navigation timeout and `50` shared HTTP/WebSocket transport
decisions); later crawler-owned milestones must use the remaining approved
defaults rather than reopening or silently changing them. Boundary tests may
continue to pass smaller explicit values. Any default change requires a plan
decision update, configuration-fingerprint review, and the owning strict gate.

## 21. Rollback and Failure Containment

### Independent rollback boundaries

- Milestone 1 can be reverted without browser code because it changes only the
  aggregate contract/policy and tests.
- Milestone 2 can be reverted to remove the optional dependency, lint exception,
  browser adapter, and harness without touching Static Discovery.
- Milestone 3 can be reverted to remove rendered extraction while leaving the
  unused browser adapter isolated.
- Milestone 4 can be reverted to remove route orchestration while leaving
  lower-level browser/extraction units testable.
- Milestone 5 can be reverted to remove aggregation while preserving separate
  producer results.
- Milestone 6 can be reverted to restore the exact current CLI/pipeline;
  earlier dynamic modules remain unreachable and cannot affect users.
- Milestone 7 is test-only and can be reverted independently.

Use normal `git revert <focused-commit>` through the reviewed workflow when a
merged commit must be rolled back. Do not reset or rewrite shared history.

### Runtime containment policy

Failure handling has three non-overlapping categories. A handler for a later
category must never catch an exception from an earlier category.

#### Category 1 — Canonical integrity failure

This includes existing `DiscoveryContractError`, ownership mismatch, missing or
forged references, invalid provenance ownership, deterministic identity
collision, inconsistent `CrawlStatistics`, merge invariant failure, and any
canonical validation failure. A proposed typed `DynamicIntegrityError` covers
merge invariants not already represented by `DiscoveryContractError`.

Required behavior:

- reject the entire aggregate attempt and discard all unvalidated Dynamic data;
- preserve the Static object internally without returning it as successful
  fulfillment of the explicit Dynamic request;
- propagate the typed failure to the CLI;
- write no JSON/HTML success report;
- return proposed exit code 3;
- expose only stable safe diagnostic codes/identifiers; and
- classify the result as an internal correctness failure.

No warning augmentation or operational fallback catches
`DiscoveryContractError` or `DynamicIntegrityError`. Milestone 6 adds specific
CLI handlers before the existing broad `(OSError, ValueError)` handler, because
`DiscoveryContractError` currently subclasses `ValueError`.

#### Category 2 — Configuration or capability failure

This includes malformed/cross-origin request-authority input, missing
Playwright package, missing matching Chromium executable, unsupported runtime
configuration, and failed strict capability preflight. A proposed typed
`DynamicCapabilityError` carries a safe code and setup hint.

Plain Static/legacy Mode A remains usable without the optional runtime. When
the user explicitly requests `--dynamic`, however, capability/configuration
failure:

- occurs before Dynamic crawling;
- writes no report claiming the requested mode ran;
- returns proposed exit code 2, matching the current CLI convention for
  user-facing configuration errors; and
- never silently substitutes a successful Static-only run.

Python package installation and Chromium installation remain separate
preconditions. Application execution and tests never download either.

#### Category 3 — Enumerated operational browser failure

Only failures after successful authority/capability validation enter this
category:

| Failure | Dynamic data retained | Output/status | Proposed CLI exit |
|---|---|---|---:|
| Navigation timeout | Only previously validated pages; current page discarded unless its last bounded snapshot independently validates as partial | Validated aggregate or Static-only report with `DYNAMIC_INCOMPLETE` and `DEGRADED` | 4 |
| DOM stabilization timeout/noisy DOM | Last bounded snapshot only if it validates as partial; otherwise previously validated pages | Same | 4 |
| Page crash or deterministic page-close equivalent | Previously validated pages only | Same | 4 |
| Browser crash after preflight | Previously validated pages only; otherwise no Dynamic contribution | Same | 4 |
| Approved route unavailable/HTTP navigation failure | Previously validated pages only | Same | 4 |
| Browser launch failure after a previously successful capability preflight | No Dynamic contribution; cleanup partial resources | Static-only report with `DYNAMIC_INCOMPLETE` and `DEGRADED` | 4 |
| Cleanup error | Retain only data already validated before cleanup; record safe cleanup code | Report is degraded and strict gate fails | 4 |

Before merge, any retained partial Dynamic result must independently pass
canonical ownership, reference, provenance, readiness, statistics, and ordering
validation. Otherwise the event is Category 1, not Category 3. No operational
handler catches or relabels a canonical exception.

Exit code 0 is reserved for existing Static/legacy success when Dynamic was not
requested, or for complete requested Dynamic success. Exit code 4 may accompany
a safely written validated report, but its structured warning and
`DynamicCrawlResult` completion state explicitly say Dynamic did not complete.

The complete analysis still aborts under existing behavior when the root URL
or Static Discovery itself is invalid. Dynamic handling must not conceal a
Static failure or erase/corrupt the validated Static object.

- Loopback fixture or strict-gate failure blocks the milestone; do not weaken
  counters, scope, authority, audit, or assertions and do not commit.
- Pipeline integration failure withholds/reverts Milestone 6; unreachable
  Dynamic modules cannot alter existing CLI behavior.

Warnings include stable error codes and safe fingerprints, never raw DOM,
passwords, query values, cookies, headers, storage, or provider exception
dumps.

## 22. Completion Checklist

- [x] Plan approved.
- [x] Aggregate contract and merge policy approved by producer and consumer.
- [x] Dependency declaration strategy approved.
- [x] Browser binary installation strategy approved.
- [x] Dynamic default budgets approved.
- [x] Milestone 1 implemented and focused narrow tests passed.
- [x] Milestone 2 implemented and focused narrow tests passed.
- [x] Milestone 3 implemented and focused narrow tests passed.
- [x] Milestone 4 implemented and focused narrow tests passed.
- [x] Milestone 5 implemented and focused narrow tests passed.
- [x] Milestone 6 implemented and focused narrow tests passed.
- [x] Milestone 7 implemented and focused narrow tests passed.
- [x] Full regression passed after every milestone.
- [x] Format, lint, type-hint, and `git diff --check` passed after every
  milestone.
- [x] Independent Gate Review passed after every milestone.
- [x] Maximum two correction loops was respected for each milestone.
- [x] All Critical/High findings were resolved.
- [x] Medium/Low deferrals were recorded without prolonging the milestone.
- [x] Each milestone produced at most one focused commit.
- [x] Final loopback E2E passed.
- [x] External-origin request count is zero.
- [x] Cross-origin navigation count is zero.
- [x] POST submission count is zero.
- [x] Unauthorized same-origin unsafe endpoint request counts are zero.
- [x] WebSocket denial hook was installed before every page; attempt/block
  counts match and browser connected/server handshake/server connection counts
  are zero.
- [x] EventSource attempt/block counts match and browser allowed/server request
  counts are zero.
- [x] Server and browser audit counters agree for popup, frame, redirect,
  location, fetch/XHR, navigation, and cleanup behavior.
- [x] Child-frame attach/request/block/commit/completion/detach evidence,
  internal-document classifications, safe bounded origin summaries, and server
  counters jointly prove zero authorized child completion.
- [x] Every sensitive raw form is elided before value collection and canonical
  construction; it contributes no Endpoint/InputPoint/template/context/
  readiness/provenance, no GET/POST executes, form-only Endpoints are absent,
  and independent safe discoveries remain unaffected.
- [x] The N-34 safe-anchor/password-form collision contains only the safe
  `q` InputPoint, safe `baseline_values`/raw-query metadata, zero password
  artifacts, valid ownership, and zero `PW_SENTINEL`. When both producers
  observe the form, it contains exactly two `SENSITIVE_FORM_ELIDED` warnings:
  one Static then one Dynamic, both secret-free and neither converted into a
  finding.
- [x] Aggregate statistics satisfy every Section 10 rule.
- [x] Strict Dynamic gate executed real Chromium with zero required skips.
- [x] Milestone 4 strict `bounded-navigation` manifest executed all seven owned
  real-Chromium cases while the retained `browser-loopback` 15-case and
  `rendered-dom` six-case manifests remained green; every suite matched
  expected/executed counts with zero skipped, failed, or missing cases.
- [x] Capability, integrity, and degraded operational exit paths match Section
  21.
- [x] Password/secret scan by diff review found no leaked value/artifact.
- [x] Existing Static Discovery and v0.1 smoke suites remain green.
- [x] Documentation is aligned with actual Static/Dynamic implementation
  status.
- [x] Active plan progress and decisions are current.
- [ ] Completed plan is moved from `active/` to `completed/` only after final
  acceptance.
- [ ] Feature branch pushed only after all local gates pass.
- [ ] PR opened only after all milestones and final Gate Review pass.
- [ ] At least one teammate review completed before merge.

### Plan record

- Status: Milestones 1 through 7 and the Native Dynamic Discovery MVP are
  COMPLETE locally. The feature-branch push, PR, teammate review, and merge
  remain separate follow-up actions.
- Baseline: `origin/main` and branch base
  `7598fdee9fabd1372b1c9e5810792aed26b1c45c`.
- 2026-07-27: Initial repository-grounded plan drafted. No runtime code, test,
  dependency, architecture document, branch, stash, commit, push, or PR change
  was made by the planning task.
- 2026-07-27: Correction Loop 1 addressed C-01 and H-01 through H-05 in this
  plan only. No implementation, test, dependency, browser, branch, stash,
  commit, push, or PR action was performed.
- 2026-07-27: Final Correction Loop 2 addressed C-01-R1, H-01-R1, H-03-R1,
  and H-04-R1 in this plan only. No implementation, test, dependency, tool,
  browser, branch, stash, commit, push, or PR action was performed.
- 2026-07-27 (historical; superseded): H-01-R2 was initially resolved by the
  approved MVP rescope to Sensitive Form Atomic Exclusion. This was a scope
  decision, not a third correction loop. Only this plan changed; no
  implementation, test, dependency, tool, browser, branch, stash, commit, push,
  or PR action was performed.
- 2026-07-27: H-01-R2-RESCOPE superseded the historical Atomic Exclusion design
  with Sensitive Form Pre-Canonical Elision because Static `InputPoint`
  coalescing can occur before post-processing. This was a final architectural
  rescope, not a correction loop. Only this plan changed; no implementation,
  test, dependency, tool, browser, branch, stash, commit, push, or PR action was
  performed.
- 2026-07-27: H-01-R2-RESCOPE-GATE-01 resolved the final focused-gate warning
  cardinality inconsistency by preserving one secret-free warning per producer
  observation in Static-before-Dynamic aggregate order. No implementation,
  test, dependency, tool, browser, branch, stash, push, or PR action was
  performed.
- 2026-07-30: Milestone 2 began with the focused optional-runtime capability
  preflight unit. Official Playwright Python API/release documentation
  confirmed the v1.48 context-wide WebSocket routing lower bound. The unit
  declares only the optional `dynamic` extra, adds lazy import/version/hook/
  Chromium/headless-launch checks with deterministic cleanup and secret-free
  typed failures, and leaves context/page/routing/navigation/loopback work for
  the next unit. Milestone 2 remains in progress.
- 2026-07-31: Implemented the next coherent Milestone 2 unit: one managed
  synchronous Playwright/Chromium/context/page lifecycle, pre-page HTTP and
  WebSocket guards, exact loopback-only caller authority, GET-only resource
  grants, bounded secret-free audit evidence, reverse-order idempotent cleanup,
  and an ephemeral dual-server loopback harness. Real Chromium executed the
  authorized JavaScript marker while the external HTTP sentinel and WebSocket
  handshake counts stayed zero; the timeout case retained its typed primary
  error and complete cleanup audit. Focused related regression passed 121
  tests, the full repository passed 324 tests, Native Static E2E passed 1 test,
  and the unchanged v0.1 smoke suite passed 7 tests. This unit does not
  implement rendered-DOM extraction, crawler orchestration, strict Dynamic
  gate/manifest, or the remaining popup/frame/EventSource/redirect cases, so
  Milestone 2 is not complete.
- 2026-07-31: The independent lifecycle Gate Review initially blocked on
  M2-LIFECYCLE-H-01 because WebSocket attempts did not consume the shared
  browser transport-decision budget. Correction Loop 1 added one atomic
  HTTP/WebSocket budget, one active-page stop request on first overflow,
  bounded post-overflow handling, a typed exhaustion error, and a final
  post-cleanup latch check. Unit mixed-transport evidence and a real Chromium
  1,000-WebSocket flood fixture passed with processed decisions capped at
  budget plus one, zero sentinel handshakes, and complete cleanup. Focused
  re-review passed with zero remaining Critical/High findings.
- 2026-07-31: Gate Review Medium/Low items are deferred to their owning
  follow-up units: bounded path/query-name audit representation, `text_content`
  timeout/public seam hardening, adversarial partial harness construction
  cleanup, and generated Chromium log containment. None is included in this
  Critical/High-only correction loop.
- 2026-07-31: Added the explicit ten-case `browser-loopback` manifest and
  strict gate. The gate performs capability preflight before loading the exact
  named tests and fails on a missing/renamed link, zero or mismatched execution,
  any required skip/failure, or failed real-browser invariant. Its verified
  result was Playwright 1.61.0, expected/executed 10/10, skipped 0, failed 0,
  and `FINAL=PASS`.
- 2026-07-31: Extended the loopback fixture and real Chromium evidence for
  same/cross-authority EventSource, blocked child frames with lifecycle audit,
  popup ownership/cleanup, same-authority and two-hop cross-authority HTTP
  redirects, and same/cross-authority JavaScript location. Document redirect
  hops are fetched without automatic following, authorized before their next
  transport, and converted into a bounded trusted `location.replace`
  navigation so every hop re-enters the context guard and the real browser URL
  commits. The same-authority case also proves relative-resource resolution
  from the final URL; the cross-authority chain leaves the sentinel at zero.
- 2026-07-31: Strict-gate Chromium logging is contained in owned temporary
  working directories. The repository root has no `debug.log`; no ignore rule,
  wildcard cleanup, private Playwright API, browser cache, or user artifact was
  added or removed.
- 2026-07-31: Independent Gate Review found M2-STRICT-H-01 because the first
  redirect implementation returned a synthetic effective URL without committing
  the browser location. Correction Loop 1 replaced that behavior with guarded
  one-hop relocation navigations and added final-URL, relative-resource, and
  multi-hop cross-authority evidence. Focused re-review passed with Critical 0
  and High 0. Medium items remain recorded: gate output does not itself state
  the broader milestone status, and internal child-frame document subtypes need
  finer evidence in the remaining Milestone 2 work.
- 2026-07-31: Milestone 2 decision is PARTIAL, not BLOCKED and not COMPLETE.
  Before Milestone 3 starts, the active plan still requires at least the
  same-authority WebSocket denial case, blocked fetch/XHR, unauthorized
  same-origin unsafe GET, autosubmit, deterministic test-driven page-close,
  finer about:blank/error/replacement child-frame classification evidence, and
  resolution/recording of the remaining Milestone 2 policy approvals. These
  cases must be added to and pass the strict manifest without required skips.
- 2026-08-01: Closure triage classified same/cross-authority WebSocket denial,
  blocked fetch and XHR, unauthorized same-origin unsafe GET, autosubmit POST,
  deterministic DOM-driven page close, and fine-grained child-frame document
  classification as category A completion requirements. Section 7 default
  budget approval is category B documentation/policy work. Previously recorded
  bounded-path audit representation, DOM-read timeout seam hardening, partial
  fixture-construction cleanup, and other Medium/Low refinements are category C
  follow-up items and do not block Milestone 2 COMPLETE.
- 2026-08-01: Implemented all category A evidence without Milestone 3 DOM
  extraction. The managed session exposes one idempotent owner-mediated page
  close. Child-frame commits and completions now retain bounded enum-only
  `authorized`, `unauthorized`, `about_blank`, `browser_error`, and
  `replacement` classifications with subtype and overflow counters. The
  loopback fixture executes same/cross-authority WebSocket constructors, fetch,
  XHR, a same-origin unsafe navigation GET, autosubmit POST, DOM-driven page
  close, and internal iframe variants without credentials or sensitive values.
- 2026-08-01: Expanded the explicit required manifest from 10 to 15 linked
  cases while retaining all original entries. Playwright 1.62.0 plus matching
  Chromium executed 15/15 required cases with skipped 0, failed 0, missing 0,
  and `FINAL=PASS`.
- 2026-08-01: Milestone 2 closure verification passed: focused Dynamic/Gate/
  harness tests 36, related Discovery regression 135, full repository 347,
  Native Static E2E 1, v0.1 smoke 7, format, lint, type-hint, and
  `git diff --check`. The repository root retained no `debug.log`, generated
  browser artifact, or untracked file. Independent Gate Review separately
  reproduced strict Chromium 15/15 and focused unit 33/33, found Critical 0,
  High 0, Medium 0, Low 0, and returned `PASS`. Milestone 2 is therefore
  COMPLETE; this plan stays active because Milestones 3 onward remain pending.
- 2026-08-01: Implemented Milestone 3 as a single-page, main-frame rendered DOM
  unit. Chromium captures a deterministic bounded projection in a fresh CDP
  isolated world, omits physical password-form descendants before any value
  projection, and host-validates the minimal allowlisted structure and active
  policy limits before canonical extraction. Dynamic artifacts carry truthful
  `NATIVE_DYNAMIC` provenance; exact-authority mismatches remain discoverable
  but `NOT_READY`; iframe DOM, clicks, submissions, navigation frontier, and
  orchestration remain outside this milestone.
- 2026-08-01: Final Milestone 3 verification passed focused unit 69/69, strict
  rendered-DOM Chromium 6/6, retained browser safety Chromium 15/15, full
  repository 369, Native Static E2E 1, v0.1 smoke 7, format, lint, type-hint,
  and `git diff --check`. Both strict gates reported skipped 0, failed 0, and
  missing 0. Password sentinels had zero serialized or server-request
  occurrences, cleanup completed, and generated `debug.log`/bytecode artifacts
  were removed before commit.
- 2026-08-01: Independent Gate Review initially found two Critical, one High,
  and two Medium issues: main-world prototype poisoning, an unfiltered direct
  Native Dynamic fallback, associated-control rather than physical-descendant
  classification, synthetic occurrence indices, and query values in the
  stabilization key. Correction Loop 1 moved capture to an isolated world,
  required elision policy for Native Dynamic metadata, used physical DOM
  descendants, preserved exact occurrences, removed query values, and added
  host revalidation of caller-lowered limits. Focused re-review reproduced the
  adversarial Chromium cases and returned `PASS` with Critical 0, High 0,
  Medium 0, and Low 0. Milestone 3 is therefore COMPLETE; this plan stays active
  for Milestones 4 onward.
- 2026-08-02: Implemented Milestone 4 bounded same-origin navigation. One
  managed Chromium crawl performs deterministic canonical BFS over rendered
  anchors, intersects every candidate and redirect with immutable exact caller
  authority, never clicks/submits/traverses frames or popups, and emits one
  validated Native Dynamic component per successful page plus a Dynamic-only
  aggregate for Milestone 5. Static orchestration and Static/Dynamic merge remain
  unimplemented.
- 2026-08-02: Final Milestone 4 verification passed strict real-Chromium gates
  `browser-loopback` 15/15, `rendered-dom` 6/6, and `bounded-navigation` 7/7,
  each with skipped 0, failed 0, and missing 0. Full repository regression
  passed 389 tests, Native Static E2E passed 1, v0.1 smoke passed 7, and format,
  lint, type-hint, and `git diff --check` passed. The designated Python runtime
  was restored to Playwright 1.62.0 plus matching Chromium after its optional
  package disappeared; no alternate Python was used.
- 2026-08-02: Independent Gate Review initially found five High issues covering
  total lifecycle deadline enforcement, redirect-follow accounting, canonical
  exception relabeling, public handoff topology validation, and post-transport
  redirect deduplication. The single permitted correction loop added a
  supervised single-worker hard deadline with exact process-tree termination,
  actual main-frame-follow accounting, cleanup-preserved integrity exceptions,
  topology/provenance/completion validation, and pre-target duplicate redirect
  blocking. Re-review passed with Critical 0, High 0, Medium 0, and Low 0 and
  independently confirmed zero worker, temporary directory, or Chromium leak.
- 2026-08-03: Implemented Milestone 5 combined orchestration. The new strict
  public handoff runs Native Static before Native Dynamic, validates both
  components, preserves producer-local scope-decision references, and delegates
  all canonical identity/conflict/statistics behavior to the existing merge
  core. `CombinedDiscoveryResult` retains both producer results and exposes
  Dynamic `COMPLETE`/`DEGRADED` state while its `discovery` member is directly
  consumable by the existing canonical analysis boundary. No CLI, Probe,
  Feature, Scoring, Top-K, or generalized pipeline work was added.
- 2026-08-03: Milestone 5 pre-review verification passed real-Chromium
  `combined-discovery` 5/5, retained `browser-loopback` 15/15, `rendered-dom`
  6/6, and `bounded-navigation` 7/7, all with skipped 0, failed 0, missing 0,
  and `FINAL=PASS`. Full repository regression passed 399 tests, Native Static
  E2E passed 1, v0.1 smoke passed 7, and format, lint, type-hint, and
  `git diff --check` passed.
- 2026-08-03: The one requested Independent Gate Review returned `BLOCK` with
  Critical 0, High 4, Medium 1, and Low 0. High findings covered a caller-
  asserted Static safety marker, missing crawl-wrapper revalidation, an
  uncorrelated public combined handoff, and a mock-only fifth strict-Gate case.
  The single permitted correction loop removed the caller marker, revalidated
  both complete crawl wrappers, required the handoff to equal a fresh pure
  merge of its retained producers, and replaced the mock-only manifest link
  with an actual Chromium operational-failure case.
- 2026-08-03: Post-correction verification passed focused orchestration/merge/
  Gate unit tests 36/36, actual-Chromium `combined-discovery` 5/5 with skipped
  0, failed 0, missing 0 and `FINAL=PASS`, and full repository regression
  402/402. The correction audit leaves Critical 0 and High 0. One non-blocking
  Medium remains recorded: the shared fixture redacts query strings before
  storing `LoopbackRequest.path`, so the sensitive test's path-level sentinel
  assertion is weaker than a dedicated secret-free forbidden-query counter.
  Canonical serialization, producer warning cardinality, zero POST, safe-anchor
  preservation, and the actual Gate remain green. Per the requested single
  independent review limit, no second independent review was run; Milestone 5
  is `COMPLETE` with this recorded Medium follow-up.
- 2026-08-03: Implemented Milestone 6 opt-in CLI/pipeline integration. Plain
  `--url` remains Static-only and `--input` remains legacy-only; explicit
  `--dynamic` constructs exact immutable navigation/resource authority and a
  bounded Dynamic policy, retains the validated `CombinedDiscoveryResult`,
  and hands only its canonical `discovery` member to the unchanged
  `analyze_discovery_result()` READY-context consumer. Complete, capability/
  configuration, integrity, and validated degraded outcomes map to exits 0,
  2, 3, and 4 without raw DOM or secret-bearing diagnostics.
- 2026-08-03: Milestone 6 final verification passed focused pipeline/CLI/v0.1
  tests 22/22, actual-Chromium `combined-discovery` 5/5, retained
  `browser-loopback` 15/15 after the narrow capability-error worker-boundary
  correction, full repository regression 410/410 twice, Native Static E2E 1/1,
  v0.1 smoke 7/7, and format, lint, type-hint, and `git diff --check`. Two
  Independent Gate Reviews initially found the same High issue: duplicated
  preflight before Static-first orchestration. Correction Loop 1 removed that
  preflight and made `DynamicCapabilityError` pickle-safe across the existing
  supervised worker seam; both re-reviews returned `PASS` with Critical 0,
  High 0, and no Medium/Low deferrals. Milestone 6 is `COMPLETE`; Milestone 7
  remains unimplemented.
- 2026-08-03: Implemented the Milestone 7 final loopback scenario and strict
  seven-case `final` manifest. Two independent public `cli.main()` executions
  used real Chromium and the real loopback probe transport, retained 11
  canonical input points with READY/NOT_READY counts 9/2, executed nine paired
  baseline/probe plans, emitted 18 selected findings consistently to JSON and
  HTML, preserved N-34's safe-only `q` metadata and Static-then-Dynamic warning
  pair, and recorded zero sentinel, cross-authority, POST, process, temporary-
  directory, or `debug.log` residue. A failing cleanup assertion exposed a
  Chromium log in the caller working directory; the narrow correction isolated
  the supervised Dynamic worker in its owned temporary directory and directed
  Chromium logging to the null device without changing crawl semantics.
- 2026-08-03: Milestone 7 pre-review verification passed focused E2E 7/7 and
  strict real-Chromium gates `final` 7/7, `browser-loopback` 15/15,
  `rendered-dom` 6/6, `bounded-navigation` 7/7, and `combined-discovery` 5/5;
  every gate reported skipped 0, failed 0, missing 0, and `FINAL=PASS`. Full
  repository regression passed 417/417; Native Static E2E passed 1/1 and v0.1
  smoke passed 7/7. Format, lint, type-hint, and `git diff --check` passed before
  the single Independent Gate Review.
- 2026-08-03: The one Independent Gate Reviewer initially returned `BLOCK`
  with Critical 0, High 1, Medium 0, and Low 0 because the deterministic report
  comparison sorted candidate identities and could miss cross-run result-order
  drift. The single permitted correction compares scoring-result order,
  authoritative selection order, and JSON candidate identity order directly.
  Focused E2E 7/7, strict `final` 7/7 with skipped/failed/missing 0 and
  `FINAL=PASS`, plus format, lint, type-hint, and `git diff --check` passed after
  the correction. The same reviewer returned `PASS` with Critical/High/Medium/
  Low all 0. Milestone 7 and the Native Dynamic Discovery MVP are `COMPLETE`.

### Gate Review Correction Record

| Finding ID | Correction Summary | Affected Sections | Status |
|---|---|---|---|
| M7-E2E-H-01 | Replaced sorted cross-run candidate comparison with direct scoring-result, authoritative selection, and JSON candidate identity order checks | 17; Milestone 7 | Addressed in the single correction; same-reviewer re-review passed |
| M2-STRICT-H-01 | Replaced synthetic effective redirect URLs with guarded one-hop `location.replace` navigations; added actual final-URL, final-path relative-resource, and same-origin-intermediate-to-cross-authority sentinel evidence | 13, 14, 17; Milestone 2 | Addressed in Correction Loop 1; focused re-review passed |
| M2-LIFECYCLE-H-01 | Made HTTP and WebSocket share one atomic transport-decision budget, requested one active-page stop on first overflow, bounded post-overflow accounting, and added unit plus sustained real-Chromium evidence | 7, 13, 14; Milestone 2 | Addressed in Correction Loop 1; focused re-review passed |
| M3-RENDERED-C-01 | Moved snapshot evaluation from the target page main world to a fresh main-frame CDP isolated world with a fixed one-second evaluation timeout; added prototype-poisoning and cleanup evidence | 6, 14, 17; Milestone 3 | Addressed in Correction Loop 1; focused re-review passed |
| M3-RENDERED-C-02 | Required a sensitive-form elision policy for every explicit `NATIVE_DYNAMIC` Static-extractor compatibility call, closing the direct unfiltered fallback | 9, 14, 17; Milestone 3 | Addressed in Correction Loop 1; focused re-review passed |
| M3-RENDERED-H-01 | Classified sensitive forms from physical descendant inputs rather than form-associated controls and proved associated password controls cannot leave a surviving form artifact | 9, 14, 17; Milestone 3 | Addressed in Correction Loop 1; focused re-review passed |
| M3-RENDERED-M-01 | Preserved exact sensitive-form occurrence indices and excluded action query values from structural stabilization keys | 9, 14, 17; Milestone 3 | Addressed in Correction Loop 1; focused re-review passed |
| M3-RENDERED-M-02 | Re-applied caller-lowered attribute-count, attribute-length, and text-length policy limits in the host validator before accepting browser payloads | 7, 14, 17; Milestone 3 | Addressed in Correction Loop 1; focused re-review passed |
| M4-NAV-H-01 | Propagated the crawl deadline through browser lifecycle, redirect transport, and DOM capture, then supervised the complete concrete-browser crawl in one synchronous child process with exact process-tree termination on timeout | 7, 14, 17; Milestone 4 | Addressed in Correction Loop 1; focused re-review passed |
| M4-NAV-H-02 | Counted redirects followed only after a successful main-frame target dispatch and excluded blocked targets plus subresource redirects from canonical document statistics | 10, 14, 17; Milestone 4 | Addressed in Correction Loop 1; focused re-review passed |
| M4-NAV-H-03 | Preserved crawler canonical and authority exceptions across the managed operation boundary and re-raised them after browser cleanup | 15, 17, 21; Milestone 4 | Addressed in Correction Loop 1; focused re-review passed |
| M4-NAV-H-04 | Enforced visited/root/origin/order, parent-depth, page provenance, depth-budget, and completion/termination invariants in the public Dynamic handoff | 3, 10, 17; Milestone 4 | Addressed in Correction Loop 1; focused re-review passed |
| M4-NAV-H-05 | Blocked previously dispatched redirect targets at the Location decision before target transport and added reverse-order real-Chromium evidence | 5, 14, 17; Milestone 4 | Addressed in Correction Loop 1; focused re-review passed |
| M5-ORCH-H-01 | Removed caller-asserted Static safety markers; aggregate safety evidence now comes only from the policy-bound extractor output | 9, 17, 22; Milestone 5 | Addressed in the single correction loop; focused adversarial tests passed |
| M5-ORCH-H-02 | Reconstructed both frozen crawl wrappers through their validators before merge and handoff construction | 10, 15, 17; Milestone 5 | Addressed in the single correction loop; mutated completion/termination proof now fails closed |
| M5-ORCH-H-03 | Required every public combined handoff to equal a fresh existing-core merge of its retained producer components and policy | 3, 10, 17; Milestone 5 | Addressed in the single correction loop; unrelated valid aggregate proof now fails closed |
| M5-ORCH-H-04 | Replaced the mock-only fifth strict-Gate link with a concrete Chromium operational-failure/degraded-result case | 14, 17, 20, 22; Milestone 5 | Addressed in the single correction loop; strict Gate passed 5/5 actual Chromium |
| M5-ORCH-M-01 | Shared fixture request records omit query strings, weakening one path-level sentinel assertion; canonical/server-count safety evidence remains green | 14, 17, 22; Milestone 5 | Recorded non-blocking follow-up; not changed in the Critical/High-only correction loop |
| C-01 | Separated discovery eligibility from immutable exact caller navigation/resource authority; unauthorized same-origin GET remains discovery-only and is tested with zero server counters | 1, 3–9, 13–18, 20–22; Milestones 2, 4, 6, 7 | Addressed in Correction Loop 1 |
| H-01 | Made every context sharing a sensitive-redacted form template PARTIAL/NOT_READY and prohibited execution or sibling upgrade | 9, 10, 12–18, 22; Milestones 1, 3, 5, 6 | Addressed in Correction Loop 1 |
| H-02 | Defined every existing `CrawlStatistics` field, aggregate arithmetic, component validation, partial behavior, and adversarial tests | 10, 14–18, 21–22; Milestones 1, 5, 7 | Addressed in Correction Loop 1 |
| H-03 | Added real-browser popup/frame/redirect/location/fetch/page-close cases and secret-free audit evidence asserted with server counters | 5–7, 13–18, 22; Milestones 2, 4, 7 | Addressed in Correction Loop 1 |
| H-04 | Defined import-safe Base Mode A and proposed non-skippable strict Dynamic Mode B with package/browser preflight and executed-test counts | 2, 5, 14–18, 20–22; Milestones 2, 6, 7 | Addressed in Correction Loop 1 |
| H-05 | Split capability, canonical-integrity, and operational failures with proposed exit codes 2/3/4 and no integrity fallback | 3–4, 10, 15–18, 20–22; Milestones 5, 6, 7 | Addressed in Correction Loop 1 |
| C-01-R1 | Added mandatory pre-page context-wide WebSocket denial, explicit EventSource HTTP(S) denial, lower-bound capability preflight, bounded counters, and strict real-browser cases | 5–7, 13–18, 20, 22; Milestones 2, 4, 7 | Addressed in Final Correction Loop 2 |
| H-01-R1 | Added value-free cross-producer sensitive-form matching and mandatory aggregate quarantine before canonical consumption while preserving Static-only behavior | 3, 9–12, 14–18, 22; Milestones 1, 3, 5, 6, 7 | Addressed in Final Correction Loop 2; sensitive-form solution superseded by H-01-R2-RESCOPE |
| H-03-R1 | Defined bounded child-frame attach/request/block/commit/completion/detach audit evidence and real-Chromium server-plus-browser assertions | 6, 13–18, 22; Milestones 2, 4, 7 | Addressed in Final Correction Loop 2 |
| H-04-R1 | Made Milestone 4 run and update the deterministic non-skippable browser-loopback manifest before regression and review | 16–18, 22; Milestones 2, 4, 7 | Addressed in Final Correction Loop 2 |

| H-01-R2 | Introduced Sensitive Form Atomic Exclusion after canonical construction | Historical MVP rescope record below | Superseded by H-01-R2-RESCOPE |
| H-01-R2-RESCOPE | Moved sensitive-form classification/elision before canonical form construction, value collection, and `InputPoint` coalescing | 3, 4, 8–20, 22; Milestones 1, 3, 5, 6, 7 | Rescoped before implementation |
| H-01-R2-RESCOPE-GATE-01 | Resolved aggregate sensitive-form warning cardinality by preserving one warning per observing producer in Static-before-Dynamic order | 4, 10, 13–18, 22; Milestones 1, 5, 7 | Resolved before plan commit |

### Historical MVP Rescope Decision — Sensitive Form Atomic Exclusion (Superseded)

- Blocker: H-01-R2.
- Decision: Sensitive Form Atomic Exclusion.
- Reason: the existing value-bearing `RequestTemplate`/
  `InputPointRequestContext` binding cannot represent a value-absent sensitive
  occurrence without domain redesign.
- Static-only impact: none; Static-only discovery, the Static extractor, and
  legacy `--input` remain unchanged.
- Dynamic aggregation impact: Static and Dynamic producer results are filtered
  independently before serialization, logging, validation, merge, readiness,
  analysis, or reporting. The complete sensitive form-owned closure is
  excluded; the safe action Endpoint/provenance remains; one
  `SENSITIVE_FORM_EXCLUDED` warning is emitted per producer-local group.
- Deferred work: a first-class sensitive value-state/domain-contract extension
  in a future Session-aware / Sensitive Form Discovery phase.
- Status: Historical and superseded by H-01-R2-RESCOPE before implementation.
  This is not Correction Loop 3 and does not reopen C-01-R1, H-02, H-03-R1,
  H-04-R1, or H-05.

### MVP Rescope Decision — Pre-Canonical Sensitive Form Elision

- Blocker: H-01-R2-RESCOPE.
- Root cause: Static `InputPoint` coalescing occurs before the previous
  exclusion policy and can erase password type attribution while retaining
  secret values.
- Superseded policy: Sensitive Form Atomic Exclusion.
- Active policy: Sensitive Form Pre-Canonical Elision.
- Key decision: sensitive forms contribute zero canonical artifacts.
- Endpoint policy: form-only sensitive endpoints are absent; an Endpoint
  remains only when independently discovered elsewhere.
- Static-only impact: none.
- Status: Rescoped before implementation.

### Final Gate Resolution — Per-Producer Warning Cardinality

- Finding: H-01-R2-RESCOPE-GATE-01.
- Decision: preserve one warning per producer observation.
- Aggregate cardinality:
  - one observing producer -> one warning;
  - two observing producers -> two warnings.
- Ordering: Static before Dynamic.
- Cross-producer deduplication: none.
- Reason: preserve meaningful producer provenance and avoid unnecessary merge
  semantics.
- Status: Resolved before plan commit.

### Decision record

- Decision: Use Playwright synchronous API behind one optional concrete
  adapter.
  Reason: existing crawler, pipeline, CLI, and unittest architecture is
  synchronous.
- Decision: Dynamic Discovery is explicit opt-in; plain `--url` remains
  Static-only.
  Reason: backward compatibility, optional dependency containment, and browser
  side-effect visibility.
- Decision: Merge order is validated Static first, validated Dynamic second,
  followed by canonical creation and validation.
  Reason: deterministic conflict handling and preservation of the authoritative
  existing producer.
- Decision: Discovery eligibility never grants transport. The root is the only
  implicit grant; exact same-origin navigation/resource URLs come only from
  immutable caller authority.
  Reason: same-origin GET and DOM content do not prove action authorization.
- Decision: WebSocket is always denied by a context-wide hook registered before
  page creation; EventSource is always denied by explicitly classified HTTP(S)
  routing. Proposed Playwright support begins at 1.48 and strict preflight fails
  without the WebSocket capability.
  Reason: same-origin and HTTP authority do not cover or authorize these
  transports.
- Decision: Minimal SPA behavior observes History/hash/current location
  passively and directly navigates only exact pre-authorized routes; no
  arbitrary click.
  Reason: route discovery remains useful without allowing page content to
  expand request authority.
- Decision: Explicit Dynamic aggregation applies Sensitive Form Pre-Canonical
  Elision independently while extracting its Static snapshot and rendered DOM.
  A structurally sensitive form is skipped before value collection and before
  any form-derived Endpoint, InputPoint, template, context, readiness, or
  provenance is constructed. Form-only sensitive Endpoints are absent; an
  independently discovered safe Endpoint remains. Default Static-only and
  legacy `--input` behavior are unchanged.
  Reason: pre-canonical elision prevents a password observation from entering
  `InputPoint` coalescing, so there is no shared canonical object to reconstruct,
  sanitize, split, or repair and no domain binding invariant must change.
- Decision: Child-frame audit records attach, document request, pre-transport
  block, classified commit/completion, detach, and bounded safe origin evidence.
  Reason: server counters alone cannot prove whether Chromium committed an
  authorized fixture document or an internal replacement/error document.
- Decision: Primary document HTTP redirects are fetched one hop at a time with
  automatic following disabled. An authorized hop becomes a trusted
  `location.replace` navigation so it re-enters the context guard and commits
  the real browser URL; a denied hop is aborted before its server transport.
  Reason: normal route continuation bypasses interception of redirected
  requests, while proxying the final body into the first URL preserves network
  safety but breaks browser URL, history, and relative-resource semantics.
- Decision: Existing aligned document-crawl statistics use the exact Section 10
  rules; browser-specific activity remains in `BrowserAuditSummary`.
  Reason: browser subresources must not be mislabeled as Static-style document
  requests.
- Decision: Approve the Section 7 Dynamic MVP default budgets; lifecycle owns
  the implemented 3-second navigation timeout and 50-decision shared transport
  budget, while later crawler milestones own the remaining approved limits.
  Reason: stable reviewed defaults are required before the Dynamic policy and
  configuration fingerprint can be treated as fixed.
- Decision: Base Mode A may explicitly skip unavailable real-browser evidence;
  proposed strict Mode B fails on unavailable capability or any required skip.
  Reason: optional runtime must not break base regression or create a false
  Dynamic pass.
- Decision: Milestone 4 owns a separate explicit seven-case
  `bounded-navigation` manifest and must pass it together with the retained
  `browser-loopback` and `rendered-dom` strict gates before commit; Milestone 7
  cannot defer that evidence.
  Reason: browser navigation and request-safety changes require non-skippable
  real-Chromium proof at their owning milestone.
- Decision: Capability failures exit 2, canonical integrity failures exit 3,
  and validated operational degradation exits 4; only complete success exits 0
  when Dynamic was requested.
  Reason: canonical corruption and missing requested capability cannot be
  hidden by a normal Static-only success.
