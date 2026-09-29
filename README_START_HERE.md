# VulnSpider - Start Here

## Repository status

This repository retains the **Completed and Frozen v0.1 checkpoint** and now
also contains the in-progress v0.2 Native Discovery implementation.

- **Implemented:** the `prototype/v0.1` legacy-record analysis path, JSON
  report, optional HTML report, Native Static Discovery, bounded combined
  Native Static plus Native Dynamic Discovery, final loopback E2E acceptance,
  observed GET/blocked POST JSON canonicalization, and the simple Dynamic-first
  CLI adapter.
- **Also implemented (opt-in):** LLM-assisted focused verification with a
  provider-neutral payload proposer, a mandatory deterministic
  `PayloadValidator`, loopback re-probing, and rule-based confidence updates
  (`vulnspider ... --verify`, ADR-032).
- **Still planned for v0.2:** BAC prioritization and a real GPT/Gemini
  proposer behind the existing validator gate.
- **Historical:** the Prompt 01-07 sequence that produced and reviewed v0.1.

Planning documents do not imply that later v0.2 milestones are implemented.

## Read first

New contributors should read these documents in order:

1. [AGENTS.md](AGENTS.md) - frozen scope, authorized v0.2 scope, safety, and
   Git rules.
2. [Architecture](docs/ARCHITECTURE.md) - implemented v0.1, target v0.2, and
   legacy path.
3. [Prototype v0.1](docs/PROTOTYPE_V0_1.md) - the completed v0.1 checkpoint.
4. [Prototype v0.2](docs/PROTOTYPE_V0_2.md) - the authorized v0.2 plan.
5. [Interface Contract v1](docs/INTERFACE_CONTRACT_V1.md) - implemented
   Probe/Feature, selected-candidate, and canonical-artifact handoff contract.
6. [Team Interfaces v0.2](docs/TEAM_INTERFACES_V0_2.md) - broader proposed
   cross-owner contracts.
7. [Git Workflow](docs/GIT_WORKFLOW.md) - branch, PR, review, and
   secret-handling policy.
8. [Decision Log](docs/DECISION_LOG.md) - accepted and superseded decisions.

Use `docs/DOMAIN_MODEL.md`, `docs/FEATURE_SCHEMA.md`, and
`docs/EVALUATION_PROTOCOL.md` when changing their respective boundaries.

## Implemented analysis entry points

The default user command runs the existing combined discovery and Light Probe
pipeline and atomically writes two reports in the current directory:

- `vulnspider-crawl.json`: the validated Combined Discovery result, including
  Static/Dynamic provenance, READY/NOT_READY contexts, crawl statistics, and
  completion state.
- `vulnspider-analysis.json`: executed ProbePlan/response identities, retained
  observations and features, scoring evidence, and the existing Top-K fields,
  linked by stable InputPoint IDs to the crawl report.

```powershell
vulnspider -u http://127.0.0.1:8080/
vulnspider -u http://127.0.0.1:8080/ --crawl-output crawl.json -o analysis.json
vulnspider -u http://127.0.0.1:8080/ --static-only
```

Simple Dynamic mode automatically admits only rendered GET anchors on the
exact root origin and GET script/style resources on that same origin. Existing
page, depth, elapsed-time, navigation, and request-decision budgets remain in
force; the simple adapter permits at most two link depths while the advanced
Dynamic policy default remains unchanged. The simple adapter also permits only
naturally emitted same-origin GET/HEAD fetch/XHR; POST, form submission,
WebSocket, EventSource, popup, child-frame traversal, cross-origin, and
different-port traffic remain blocked. Existing `--dynamic-allow-navigation` and
`--dynamic-allow-resource` flags add explicit advanced grants.

Dynamic browser audit evidence passively records bounded fetch/XHR request
attempt projections separately from Guard transport decisions. It never
replays a request and retains no raw URL, path, query value, header, cookie, or
body. These observations remain audit-only under
`dynamic_crawl.browser_audit` and do not affect discovery snapshot IDs.
Separately, an already-allowed exact-origin GET fetch/XHR is projected directly
from the Guard's original request into canonical discovery without another
request. Credential-free query values produce ordinary READY GET contexts;
credential-bearing requests retain at most Endpoint and ordered query-name
InputPoints, with no values/template/context and explicit NOT_READY status.
Separately, an exact-origin primary-page POST fetch/XHR with `application/json`
may retain only a POST Endpoint and top-level `JSON_BODY` member names at the
same Guard decision seam. The POST remains blocked before transport and is
always NOT_READY, with no template/context or value. HEAD, other methods,
non-JSON, malformed, sensitive, non-primary, and off-scope attempts do not
produce this structure.

Each JSON report is rendered completely into a same-directory temporary file
and replaces its requested destination only after validation, flush, and
`fsync`. Invalid discovery publishes neither new file. If validated crawl
publication succeeds but probe/analysis later fails, the crawl report remains
available and the analysis report is not published. Degraded Dynamic discovery
publishes only a crawl report explicitly marked `DEGRADED` and exits with code
4. Successful simple scans print only a bounded summary and the two resolved
output paths; reports and diagnostics do not print raw DOM or sensitive form
values.

The frozen compatibility path consumes legacy crawl records, then performs
authorized localhost/loopback Light Probes:

```text
Legacy record JSON
  -> LegacyCrawlerAdapter
  -> Endpoint / InputPoint / RequestTemplate / InputPointRequestContext
  -> baseline + one-at-a-time probe
  -> minimal differential / reflection / SQL features
  -> SQLi and Reflected XSS scoring
  -> deterministic global Top-K by selection_priority
  -> JSON report
  -> optional HTML report
```

```powershell
vulnspider analyze `
  --input legacy-records.json `
  --top-k 10 `
  --output result.json `
  --html-output result.html
```

`--html-output` is optional. The HTML renderer displays the same validated
`SelectionOutcome`, `ScoreEvidence`, and executed baseline/probe provenance as
the JSON path. It does not recompute scores or confirm vulnerabilities.
Equivalent JSON and HTML output paths are rejected before either report is
written.

An authorized loopback URL uses Native Static Discovery by default. Bounded
Native Dynamic Discovery is explicit opt-in and merges its validated result
with the policy-bound Static result before the unchanged canonical analysis
consumer runs:

```powershell
vulnspider analyze `
  --url http://127.0.0.1:8080/ `
  --dynamic `
  --dynamic-allow-navigation http://127.0.0.1:8080/search `
  --dynamic-allow-resource script=http://127.0.0.1:8080/app.js `
  --top-k 10 `
  --output result.json
```

Without `--dynamic`, `--url` remains Static-only and never requires
Playwright. Dynamic authority and policy options are invalid without the
opt-in flag and with `--input`. Explicit Dynamic capability/configuration,
integrity, and validated degradation paths use exit codes 2, 3, and 4
respectively.

Simple `-u` mode produces `vulnspider-report.html` — the single end-to-end web
dashboard — by default, alongside the machine-readable crawl/analysis JSON.
The v0.2 dashboard now opens on a Korean overview with discovery counts, a
candidate ownership map, and a type distribution. Its sidebar leads to a
searchable/filterable candidate list and a guide for non-specialist readers.
Selecting a node or row opens a dedicated candidate screen with initial
observations, actual additional payload records, before/after confidence,
conditional defensive guidance, and criteria for checking a fix. All screens
travel in one offline HTML file using fragment links; browser back/forward and
direct detail links work without companion assets. The map represents
endpoint/input-point ownership, not discovered navigation or attack paths.
The displayed representative count remains distinct from the selected
type-specific candidate count. Missing, rejected, unexecuted, and BAC aggregate
records are labeled explicitly. A fixed CSP-hashed script supplies navigation,
search, filters and current-screen printing; modern browsers can still navigate
the fragment screens using CSS when JavaScript is disabled. Existing generated
reports must be regenerated to receive this UI (ADR-041).
The projector update (`decision-html-v5`) adds larger high-contrast text,
**화면 크게** with persistent navigation, a **발표 스토리** screen, verification
status cards and final-confidence bars. Candidate detail compares retained,
escaped Baseline/Probe response excerpts and explains the recorded clues and
their limits in plain Korean. It remains an offline report with no manual
target-execution feature. Presentation guidance and the fresh K=20 run command:
[Projector demo guide](docs/PROJECTOR_DEMO_GUIDE.md).
With `--verify` it leads with the post-verification confidence. Adding
`--verify` (on `analyze` or simple `-u` mode) runs focused verification
after ranking: for each Top-K candidate it proposes same-family variant
payloads (SQL metacharacters, wider HTML sentinels, out-of-range integers),
gates every one through a mandatory deterministic `PayloadValidator`, re-sends
the accepted payloads against the loopback target, re-collects a feature
vector, and updates the candidate's confidence by a reviewed rule set. A small
feature difference keeps the confidence; a reproduced or newly revealed
type-specific signal confirms or raises it; a safely encoded reflection lowers
it; a large change with no type-specific signal is reported as an inconclusive
error. Results are written to `vulnspider-verification.json` (default) as
`VerificationResult` records; the existing analysis report is unchanged. An
LLM never sets the confidence and no proposal executes before the validator
accepts it.

```powershell
vulnspider -u http://127.0.0.1:8080/ --verify
vulnspider analyze --url http://127.0.0.1:8080/ --top-k 10 `
  --output result.json --html-output result.html `
  --verify --verify-output verification.json
```

With `--html-output`, `--verify` makes the report lead with the
post-verification confidence instead of the pre-verification probability. The
amount each verification signal moves the confidence is bounded and, once a
labeled verification corpus exists, learned from it rather than hand-picked:

```powershell
vulnspider corpus verify-collect --url http://127.0.0.1:8080/ `
  --application-id app1 --ground-truth gt.json -o verify-corpus.jsonl --append
vulnspider corpus verify-fit --corpus verify-corpus.jsonl `
  -o confidence-model.json --report arm.json
vulnspider analyze --url http://127.0.0.1:8080/ --top-k 10 --output result.json `
  --verify --verification-model confidence-model.json
```

`verify-fit --report` writes the out-of-fold evaluation arm: the Brier score of
the pre-verification prior versus the post-verification confidence. Without
`--verification-model`, the update uses a conservative built-in model.

A fitted model is committed at `data/corpus/verification-model.json`, built by
`tools/build_verification_corpus.py`, which serves the labeled loopback
applications from `tools/corpus_target_site.py` (they reproduce the same signal
families a target like DVWA exposes — error-based SQLi, blind SQLi, raw
reflected XSS, safely escaped reflection, and safe endpoints), runs real
verification against them, and fits the model. On that corpus (146 samples, 14
applications) the out-of-fold Brier score improves from 0.136 to 0.102, and the
model learns that a reproduced signal is strongly vulnerable (LLR capped at
+1.0) while a safely-encoded reflection is safe (−1.0). Rebuild and use it with:

```powershell
python tools/build_verification_corpus.py --applications 14
vulnspider analyze --url http://127.0.0.1:8080/ --top-k 10 --output result.json `
  --verify --verification-model data/corpus/verification-model.json
```

Running against a real DVWA instance additionally needs an authenticated crawl
(login, session, and the security-level cookie), which the current crawler does
not perform; the loopback fixtures stand in for it while exercising the same
verification signals.

## Implemented and not implemented

### Implemented

- Legacy crawl-record JSON input.
- Direct authorized URL input through bounded Native Static Discovery.
- Explicit `--dynamic` combined Native Discovery with exact, immutable
  navigation/resource authority and lazy Playwright capability checking.
- Dynamic-first `vulnspider -u URL` adapter with rendered same-origin GET
  anchor navigation, same-origin script/style loading, separately atomic crawl
  and analysis JSON reports, and `--static-only` compatibility.
- Combined canonical handoff to the existing READY-context analysis consumer;
  NOT_READY contexts remain non-executable.
- Guard-owned, transport-free observed GET and blocked POST JSON canonical
  discovery with bounded credential elision.
- `LegacyCrawlerAdapter` normalization into canonical v0.1 domain models.
- Deterministic probe planning and loopback-only baseline/probe execution.
- Minimal differential, reflection, and SQL signal extraction.
- Independent SQLi and Reflected XSS scoring with `ScoreEvidence`.
- Deterministic global Top-K using `selection_priority`.
- JSON report and optional escaped HTML report.
- Opt-in focused verification (`--verify`): provider-neutral payload mutation
  with a deterministic default proposer, a mandatory deterministic
  `PayloadValidator`, loopback re-probing that reuses the v0.1 executor and
  feature extractor, a baseline-vs-reprobe feature delta, rule-based
  `VerificationConfidence`, and a separate `vulnspider-verification.json`
  `VerificationResult` report (ADR-032).
- Corpus-calibrated confidence: a per-(family, verification-signal)
  log-likelihood-ratio model with a bounded, gentle update
  (`verification/calibration.py`), the verification corpus label/protocol
  (`corpus/verification_collection.py`), and an out-of-fold Brier evaluation
  arm (`corpus/verification_fitting.py`), reachable through
  `corpus verify-collect` and `corpus verify-fit` (ADR-033).
- One end-to-end HTML dashboard report as the primary output: simple `-u` mode
  writes `vulnspider-report.html` by default, leading with the
  **post-verification** confidence and showing each candidate's verdict and
  prior→final change; the decision JSON carries the same final confidence so
  both artifacts agree (ADR-033, ADR-034). `--no-html` skips it.
- `INCONCLUSIVE_ERROR` is reserved for a genuine error (transport failure or a
  payload-induced 5xx); a benign length/status difference stays `UNCHANGED`
  (ADR-034).
- Unit and integration coverage for the implemented path.

### Planned for v0.2, not implemented

- BAC role/session orchestration and CREDENTIAL_STRIP-specific verification.
  (BAC observation — credential-strip / identifier-substitution GET re-probes —
  scoring, calibrated-probability ranking alongside SQLi/XSS, dashboard
  rendering, and identifier-substitution re-verification are implemented;
  ADR-035.)
- Feature cache and automated quantitative ranking evaluation.
- GPT/Gemini comparison harness and a real model proposer behind the existing
  `PayloadValidator` gate.
- A real labeled verification corpus and live `verify-collect` loopback
  integration; folding the updated confidence into the decision JSON report.

Fine-tuning is **Deferred** unless the v0.2 API comparison and failure analysis
meet the decision gate in [Prototype v0.2](docs/PROTOTYPE_V0_2.md).

## Historical v0.1 build process

The Prompt 01-07 flow is retained as project history, not as the current
onboarding workflow:

1. `prompts/01_LEGACY_AUDIT.md`
2. `prompts/02_REPOSITORY_SCAFFOLD.md`
3. `prompts/03_DOMAIN_MODEL.md`
4. `prompts/04_LEGACY_ADAPTER.md`
5. `prompts/05_PROBE_FEATURE_SCORING.md`
6. `prompts/06_INDEPENDENT_REVIEW.md`
7. `prompts/07_FIX_REVIEW_LOOP.md`

These files document how v0.1 was built and reviewed. New v0.2 work starts from
the current code and the v0.2 documents, not by replaying the prompts.

## DemoShop storefront presentation

Run `python demo_target_server.py` and open `http://127.0.0.1:8899/` for the
responsive lifestyle storefront: twelve products (four locally bundled photos
plus eight recoloured variants of them), category browsing, product details,
a cart/checkout simulation and a service page for every route. No real order or payment is
created. All 100 canonical GET input points, labels and probe response
behaviors remain available. Photography and asset provenance:
[DemoShop assets](tools/demo_shop_assets/README.md).

Every route's canonical GET form *is* the page's UI: the catalog and search
render it as the filter bar above the grid (category, brand, colour, size,
sort, page), the product page as its option panel (`id`, `variant`, `tab`,
`qty`), the cart and checkout as their order forms, and each service route
(orders, tickets, seller tools, admin lookups, …) as its own form with a
contextual submit label. The page reacts to what was submitted — the grid is
filtered, sorted and paged from the URL query, the product/cart/checkout
totals follow `qty`, `coupon`, `shipping` — and the server's per-parameter
response cards (rows, echoes, database errors, validation warnings) are shown
in a visible results section. Quick-pick chips and the pager are unnamed
`type="button"` controls; names, seeds, form actions, response behaviors and
ground truth are unchanged, and the public evaluation surface retains its 100
input points. The parameter-free member login entries add pages without adding
input points. Product data (names, prices, per-product option chips) is served
as its own script, `/assets/products.js`, not embedded in the page: editing the
catalog never changes a route's response bytes, so it never moves a scan's
response-size features or the ranking a dashboard is built from.

Each canonical input has a small `⊙` marker: hover over the field or focus the
marker to see its display number `#001`–`#100`, parameter name and request
shape (`GET /search?q=…`). The page's input-point shortcut expands the existing
form. Hidden inputs have a separate annotation. Numbers follow the authored
target order and are display identifiers, distinct from scanner-generated
InputPoint IDs.

The fixed **⊙ 입력점 표시** pill (bottom right) switches on reveal mode for the
demo: every canonical control gets a solid green outline with its number, and
the storefront controls that feed a canonical parameter — the header search
box (`/search q`), category tabs (`category`), the product grid
(`/product id`), the product tab bar (`tab`) and the catalog pager (`page`) —
get a dashed outline and a `⊙ #001 검색어 q` tag; quick-pick chips and pager
buttons turn green as well. The choice is kept in `localStorage`, so it
survives navigation; click again to return to the plain storefront.

The header search box is a real search: Enter or the magnifier opens
`/search?q=<term>`, the term narrows the product grid on the client and the
route echoes it as input point #001. The box has no `name` and no `<form>`, so
the crawl surface is still the canonical `/search` GET form.

The v0.2 dashboard calls the overview list **상위 취약점 후보** and every
candidate's displayed probability **최종 신뢰도**. Without focused verification,
that value is the unchanged pre-verification probability, explicitly explained
in the report; no verification record is invented and scores are not recomputed.

Storefront HTML sizes have changed. Regenerate reports and ranking evaluations
against the current target revision rather than treating historical metrics as
measurements of the same response bytes.

The header's **마이페이지** now opens `/login`, with a single **한수훈으로 로그인**
button. It creates the existing demo `user` session (uid 1042) through an explicit
POST and redirects to `/portal/`. Returning to My Page keeps that session;
**로그아웃** clears the browser cookie. No password, email link or destination
fields are needed for this fixed demo profile.

For the manual BAC example, open **주문 상세** from My Page. Order `4100` belongs
to `한수훈` (uid 1042). Change the **주문번호** field to `4101` and select **조회**:
the same signed-in user can now see `전상현`'s order (uid 1043), including a
different product and amount. The intentional flaw is the missing ownership
check; requests without a valid session still receive 403. The payment-card
route remains the safe comparison: `5001` succeeds and `5002` is denied.
These are synthetic fixtures; non-seed order identifiers continue to return a
synthetic other-member record for the existing BAC probe behavior.

The header's **주문조회** and footer's **주문 및 배송 조회** open that same protected
order screen through `/login/orders`. If needed, the one-button login returns
directly to the order lookup. Existing signed-in `/orders?order_id=...` URLs also
redirect to `/portal/order?ref=...`, preserving the entered number; older demo
numbers `20240517` and `20240518` map to `4100` and `4101`. An anonymous `/orders`
visit retains the four public evaluation inputs and offers a member-order login
link. Thus real order data and its BAC label remain on the protected endpoint.

The older `/account/login` GET form remains an evaluation fixture with its three
canonical inputs; it does not authenticate. `/login?as=admin|user` remains an
explicit lab helper for the existing scanner runbook. Anonymous GET navigation
never submits the shopper login form. Session cookies are demo-only signed
tokens, marked HttpOnly and SameSite=Lax; logout clears the browser cookie rather
than revoking this deterministic lab token. Responses use `Cache-Control:
no-store` so a logged-out browser revalidates protected pages.

## Development checks

```text
python -B -m unittest discover -s tests
python tools/check_format.py
python tools/check_lint.py
python tools/check_types.py
git diff --check
```

Windows and Codex setup details remain in `docs/CODEX_SETUP.md`.

### Direct member lookup demo

DemoShop uses three member fixtures: 한수훈 (1042, existing contacts),
전상현 (1043, sanghyun.jeon@demoshop.test, 010-1234-5678), and
이석현 (1044, seokhyun.lee@demoshop.test, 010-2345-6789).
At `/admin/users`, leave the search empty or at its default `soohoon` to
look up the entered member ID. Unknown IDs return no rows. A different search
term searches Korean names or English usernames independently of the ID.
Entering `1' OR '1'='1` returns all three members without `vs_confirm`.
This one fixture uses a disposable, read-only SQLite SELECT with an instruction
budget; malformed quotes return SQL errors and multiple statements are rejected.
The Response section shows one member table and no redundant search-term card.
The confirmation overlay for this lookup describes the actual result, not a
fabricated member dump. Other legacy SQL demo overlays remain illustrative.

Protected order and message screens compare the returned owner's UID to the
current session UID and show an amber notice with both names and IDs on mismatch.
This works without dashboard navigation. Login requirements and the protected
payment-card comparison remain unchanged. The fixture response bytes changed;
regenerate demo reports/ranking measurements against this revision.
