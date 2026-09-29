# Legacy WHSPIDER Audit

## 1. Executive Summary

The legacy WHSPIDER project is a CLI-oriented crawler and analysis tool that combines static crawling, dynamic Playwright crawling, SQLite persistence, export, graph visualization, and local LLM/RAG analysis. Its useful v0.1 asset is the existing page discovery and HTML input extraction knowledge, but the current implementation is page-centric and tightly coupled to a SQLite table, CLI options, graph export, and LLM analysis (`reference/whspider_legacy/cli.py::webspider`, `reference/whspider_legacy/modules/static_crawler.py::fetch_page`, `reference/whspider_legacy/modules/db.py::create_table`, `reference/whspider_legacy/modules/local_llm.py::run_llm_analysis`).

Recommended reuse decision: do not import the legacy package as the new VulnSpider architecture. Reuse only selected static crawling outputs through a `LegacyCrawlerAdapter` boundary that converts legacy `crawl_links` rows into the v0.1 `Endpoint`, `InputPoint`, and `RequestTemplate` concepts described in `docs/DOMAIN_MODEL.md`. The old LLM/RAG, dynamic crawler, visualization, export format, and SQLite schema should not become v0.1 domain architecture because v0.1 explicitly excludes LLM payload generation, browser crawling, dashboards, and old schema reuse (`AGENTS.md` Legacy Code Policy; `docs/DECISION_LOG.md` ADR-005, ADR-006; `docs/PROTOTYPE_V0_1.md` Out of Scope).

Top reuse path:

1. Use legacy data only as `RawDiscoveredSurface` input.
2. Normalize query parameters and form fields into separate `InputPoint`s.
3. Add a new safety/scope layer outside legacy behavior.
4. Keep Probe, FeatureVector, Candidate, Scoring, Top-K, and JSON report as new VulnSpider code.

## 2. Repository Module Map

Top-level files:

- `reference/whspider_legacy/cli.py`: Click CLI entrypoint. It validates URL scheme, initializes SQLite, dispatches static/dynamic crawling, optional JSON/CSV export, graph generation, and LLM/RAG analysis (`cli.py` lines 5-21, 31-96).
- `reference/whspider_legacy/setup.py`: package metadata and dependencies. It installs `modules`, `cli`, and dependencies including Playwright, sentence-transformers, FAISS, PyYAML, requests, BeautifulSoup, and rapidfuzz (`setup.py` lines 6-26).
- `reference/whspider_legacy/README.md`: user-facing guide for CLI options and result location. It describes static/dynamic crawling, graph, cookies, LLM, and data output under `data/` (`README.md` lines 5, 57-76, 145-163).
- `reference/whspider_legacy/data/`: committed RAG files `kb.index` and `kb_chunks.pkl` plus `.gitkeep`.
- `reference/whspider_legacy/lib/`: vendored browser/graph UI assets for visualization.

Crawler and extraction modules:

- `modules/static_crawler.py`: requests/BeautifulSoup crawler with DFS/BFS traversal, robots.txt handling, cookie parsing, include/exclude filters, query/form extraction, similar-URL filtering, and direct DB insertion (`static_crawler.py::run_static_crawl_entry`, `fetch_page`, `save_filtered_urls`).
- `modules/dynamic_crawler.py`: Playwright-based crawler with similar output shape, resource blocking, context cookies, DFS/BFS, and direct DB insertion (`dynamic_crawler.py::run_dynamic_crawl_entry`, `fetch_page`, `save_filtered_urls`).
- `modules/parser.py`: extracts `input`, `textarea`, and `select` tags, attaches form method/action, and discards hidden inputs (`parser.py::extract_inputs_with_form_context` lines 4-33).
- `modules/params.py`: extracts query parameters using a regex gate plus `urllib.parse.parse_qs` (`params.py::has_query_params`, `extract_params_from_url`, `flatten_query_dict`).
- `modules/url_filter.py`: include/exclude regex filtering plus Levenshtein-based similar URL reduction (`url_filter.py::compile_patterns`, `is_url_allowed`, `filter_similar_urls`).
- `modules/config.py`: allowed HTML attributes for input extraction (`config.py::TARGET_ATTRIBUTES`).
- `modules/utils.py`: terminal spinner only (`utils.py::DotsSpinner`).

Persistence, output, and analysis modules:

- `modules/db.py`: SQLite database path derivation, table creation, row insertion, and old-row cleanup (`db.py::get_db_path`, `create_table`, `insert_link`, `cleanup_by_age`).
- `modules/export.py`: dumps every `crawl_links` row to JSON or CSV (`export.py::export_json`, `export_csv`).
- `modules/visualize.py`: reads `crawl_links`, builds a PyVis graph, and injects an info panel into generated HTML (`visualize.py::generate_interactive_graph`, `inject_info_panel`).
- `modules/local_llm.py`: reads crawl rows, builds LLM prompts, optionally uses RAG, calls Ollama with `subprocess.run`, and reports model-generated vulnerability-style analysis (`local_llm.py::build_prompt`, `query_local_llm`, `run_llm_analysis`).
- `modules/rag.py`: loads sentence-transformer embeddings, FAISS index, and pickled chunks; also writes default config under the user home path (`rag.py::RAGPipeline`, `create_default_config`, `get_rag_pipeline`).
- `modules/tempCodeRunnerFile.py`: stray temporary file containing only `fr`; not part of the meaningful module graph.

## 3. Actual Execution Flow

CLI flow:

1. User invokes `whspider`, which maps to `cli:webspider` (`setup.py` lines 25-28).
2. `webspider` receives URL, depth, crawl mode, export flags, graph flag, cookie, LLM flags, include/exclude filters, traversal mode, and robots override (`cli.py` lines 5-21).
3. It validates only that the URL scheme is `http` or `https`; there is no localhost-only allowlist at this layer (`cli.py` lines 31-36).
4. It derives a SQLite path from the target netloc, creates the `crawl_links` table, and deletes old rows while preserving the latest old row per URL (`cli.py` lines 38-43; `db.py::get_db_path`, `create_table`, `cleanup_by_age`).
5. It imports `get_last_id` from `modules.local_llm` before crawling so it can later analyze only newly inserted rows (`cli.py` lines 49-50).
6. If neither `--static` nor `--dynamic` is set, it defaults to static crawling (`cli.py` lines 53-56; README says the same at lines 74 and 162).
7. Static mode calls `run_static_crawl_entry`; dynamic mode calls `run_dynamic_crawl_entry` (`cli.py` lines 58-67).
8. Optional exports and graph generation read the same SQLite table after crawling (`cli.py` lines 70-83; `export.py::export_json`, `export_csv`; `visualize.py::generate_interactive_graph`).
9. Optional LLM/deep analysis reads new rows from `crawl_links` and sends prompt text to Ollama, with RAG enabled for `--deep` (`cli.py` lines 86-97; `local_llm.py::run_llm_analysis`, `build_prompt`, `query_local_llm`).

Static crawler flow:

1. `run_static_crawl_entry` derives `base_netloc` from the start URL, creates a `RobotFileParser`, initializes a `requests.Session`, applies User-Agent and optional cookies, compiles include/exclude filters, and dispatches DFS or BFS (`static_crawler.py` lines 31-60).
2. DFS/BFS stores `(url, depth, parent)` in a stack or queue and calls `fetch_page` until exhausted (`static_crawler.py:: _run_static_dfs`, `_run_static_bfs`).
3. `fetch_page` skips visited URLs and over-depth URLs, checks robots.txt, performs `session.get(url, timeout=5)`, forces `res.encoding = "utf-8"`, and calls `res.raise_for_status()` (`static_crawler.py` lines 69-82).
4. It extracts `query_params` from the URL and `input_fields` from the HTML body, JSON-encodes both, and appends the page record to a module-level `parent_url_groups` dictionary (`static_crawler.py` lines 88-95).
5. It parses links with BeautifulSoup, resolves relative links with `urljoin`, removes fragments with `urldefrag`, strips trailing slashes, keeps only suffix-matching internal URLs, applies include/exclude filters, and pushes the next URL (`static_crawler.py` lines 100-112).
6. After traversal, `save_filtered_urls` groups URLs by parent, applies `filter_similar_urls`, and inserts surviving rows into SQLite (`static_crawler.py` lines 131-145).

Dynamic crawler flow:

1. `run_dynamic_crawl_entry` mirrors static setup but uses `asyncio.run` and Playwright (`dynamic_crawler.py` lines 48-69).
2. `fetch_page` opens a new page, calls `page.goto(url, timeout=7000, wait_until="networkidle")`, reads `page.content()`, extracts query/form data, records the original URL, and parses links (`dynamic_crawler.py` lines 80-128).
3. Browser contexts are launched with `ignore_https_errors=True`, optional cookies are added to the browser context, and image/font/stylesheet requests are blocked (`dynamic_crawler.py` lines 140-148 and 164-172).
4. Dynamic BFS schedules up to 20 concurrent `fetch_page` calls from the queue (`dynamic_crawler.py` lines 173-181).

## 4. Data Flow and Persistence

The persistence schema is a single page-centric SQLite table:

```sql
CREATE TABLE IF NOT EXISTS crawl_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    link TEXT,
    parent TEXT,
    depth INTEGER,
    host TEXT,
    query_params TEXT,
    input_fields TEXT,
    collected_time TEXT
);
```

Evidence: `reference/whspider_legacy/modules/db.py::create_table` lines 14-29.

Inserted record shape:

- `link`: discovered page URL.
- `parent`: referring page URL, or `None`.
- `depth`: crawl depth.
- `host`: `urlparse(url).netloc`.
- `query_params`: JSON string from `extract_params_from_url`.
- `input_fields`: JSON string from `extract_inputs_with_form_context`.
- `collected_time`: KST timestamp string.

Evidence: `db.py::insert_link` lines 32-41; `static_crawler.py` lines 88-95 and 139-142; `dynamic_crawler.py` lines 96-105 and 193-196.

This schema is not the new VulnSpider domain schema. It has no first-class `Endpoint`, `InputPoint`, `RequestTemplate`, `ResponseSnapshot`, `FeatureVector`, `VulnerabilityCandidate`, `ScoreEvidence`, or scorer version. It stores query/form observations as JSON strings nested inside a page row. This conflicts with the v0.1 domain rule that `FeatureVector` belongs to one `InputPoint` and ranking is `InputPoint x VulnerabilityType` (`docs/DOMAIN_MODEL.md` sections 9-11; `docs/DECISION_LOG.md` ADR-001 and ADR-002).

Exports preserve the old table shape exactly: `export_json` and `export_csv` run `SELECT * FROM crawl_links` and dump the rows (`export.py` lines 18-49). Graphing also reads directly from `crawl_links` (`visualize.py` lines 16-24). LLM analysis selects `link`, `input_fields`, and `query_params` from `crawl_links` (`local_llm.py` lines 547-556).

## 5. Crawler Output Examples

A typical static or dynamic stored row looks like this conceptually:

```json
{
  "link": "http://127.0.0.1/search?q=book&page=1",
  "parent": "http://127.0.0.1/",
  "depth": 1,
  "host": "127.0.0.1",
  "query_params": "{\"q\":\"book\",\"page\":\"1\"}",
  "input_fields": "[{\"name\":\"username\",\"type\":\"text\",\"form_method\":\"POST\",\"form_action\":\"/login\"}]",
  "collected_time": "2026-07-07 12:00:00"
}
```

The query portion comes from `extract_params_from_url`, which returns a dictionary where a single value becomes a string and repeated values become a list (`params.py` lines 9-18). The form portion comes from `extract_inputs_with_form_context`, which attaches `form_method` and `form_action` to each non-hidden field inside a form (`parser.py` lines 8-23).

Mapping to VulnSpider v0.1 should produce at least:

- Endpoint from `link`: method plus normalized scheme/host/path.
- Query `InputPoint`s from every key in `query_params`.
- Form `InputPoint`s from every named item in `input_fields`, using resolved `form_action` and method where available.
- `RequestTemplate` candidates from the original URL and form metadata.

The legacy row itself is not enough to create complete probe-ready templates for every form because it does not preserve all baseline form values reliably, discards hidden fields, and does not resolve form action against the page URL (`parser.py` lines 13-22 and 28-33).

## 6. Coupling Points

Major coupling points:

- CLI couples crawl, persistence, export, graph, LLM, and RAG orchestration in one function (`cli.py::webspider` lines 21-97).
- Crawler modules write directly to SQLite through `insert_link` instead of returning structured discovery records (`static_crawler.py` lines 10 and 139-142; `dynamic_crawler.py` lines 10 and 193-196).
- Crawler output is grouped in module-level mutable `parent_url_groups`, then filtered and inserted after traversal (`static_crawler.py` lines 18 and 131-145; `dynamic_crawler.py` lines 19 and 184-199). This makes repeated in-process runs and tests sensitive to global state.
- Export, visualization, and LLM all depend on the old `crawl_links` table shape (`export.py` lines 18-49; `visualize.py` lines 16-24; `local_llm.py` lines 547-556).
- LLM analysis is coupled to Ollama subprocess execution (`local_llm.py::query_local_llm` lines 510-536).
- RAG is coupled to local FAISS and pickled data files under `data/kb.index` and `data/kb_chunks.pkl` (`rag.py` lines 43-44 and 79-95).
- Packaging pulls in heavy and out-of-scope dependencies such as Playwright, sentence-transformers, and FAISS (`setup.py` lines 14, 17-19).

For v0.1, the adapter must break these couplings by treating legacy output as external/raw input, not as the new architecture.

## 7. Reuse Matrix

### reuse as-is

- None of the core legacy modules should be reused as-is in the v0.1 runtime path. The crawler, parser, URL filtering, and DB modules each contain assumptions that need either tests or adapter containment before use.
- `modules/config.py::TARGET_ATTRIBUTES` can be copied as a reference list for form extraction tests, but direct dependency is not recommended because it includes event-handler attributes such as `onclick`, `onfocus`, and `onblur` that are not obviously required for v0.1 `InputPoint` identity.
- `modules/utils.py::DotsSpinner` is harmless UI utility code, but it is not needed for the v0.1 research core.

### reuse behind adapter

- `modules/static_crawler.py`: useful for legacy static discovery, but only behind a `LegacyCrawlerAdapter` and only after scope guards and tests. It can discover links, query params, and form fields (`static_crawler.py::fetch_page` lines 88-112), but it forces UTF-8, drops 4xx/5xx, follows redirects without scope recheck, and writes SQLite directly.
- `modules/parser.py::extract_inputs_with_form_context`: useful as a starting point for form extraction because it records `form_method` and `form_action` (`parser.py` lines 21-22). It must be wrapped because it discards hidden inputs and only preserves selected attributes (`parser.py` lines 13-18 and 28-33).
- `modules/params.py::extract_params_from_url`: useful as a starting point for query parsing (`params.py` lines 9-18), but the adapter should decide how to preserve blank values, repeated values, and exact baseline values.
- `modules/url_filter.py`: include/exclude filtering and similarity reduction may be useful for crawl de-duplication (`url_filter.py::is_url_allowed`, `filter_similar_urls`), but deterministic ordering and test coverage are needed because `filter_similar_urls` starts from a `set` (`url_filter.py` line 23).
- `modules/db.py`: useful only as a reader/writer for legacy crawl records during migration. Its table is not the new VulnSpider schema (`db.py::create_table` lines 14-29).

### refactor later

- Static crawler traversal could later be refactored to return `RawDiscoveredSurface[]` instead of writing SQLite, but prompt01 does not modify code.
- Parser logic could later become a new `discovery` or `surface` component that preserves hidden/default values and normalizes forms according to `docs/DOMAIN_MODEL.md`.
- URL scope logic should be replaced by a v0.1 `ScopeGuard`, then legacy link discovery can call that interface instead of `netloc.endswith`.
- Similar URL filtering can be retained only if it is made deterministic and does not hide distinct `InputPoint`s.

### do not reuse

- `modules/local_llm.py`: v0.1 explicitly excludes delegating vulnerability judgment to an LLM. The prompt text asks the model to judge "vulnerability probability" and emit `confidence_score` (`local_llm.py` lines 501-502), which conflicts with `RankScore` as verification priority, not vulnerability probability (`AGENTS.md` Non-Negotiable Domain Rules; `docs/DECISION_LOG.md` ADR-003).
- `modules/rag.py` and committed RAG assets under `data/`: v0.1 excludes LLM/RAG and should not require FAISS/sentence-transformers (`rag.py::RAGPipeline`; `setup.py` lines 17-19).
- `modules/dynamic_crawler.py`: Playwright dynamic crawling is out of v0.1 scope (`docs/PROTOTYPE_V0_1.md` Out of Scope). It also adds browser behavior, concurrency, and resource blocking that are unnecessary for the first prototype.
- `modules/visualize.py` and `lib/`: dashboard/graph visualization is out of v0.1 scope.
- `modules/export.py`: old JSON/CSV exports mirror old DB rows and do not satisfy v0.1 JSON report requirements for candidates, rank scores, and score evidence.
- `setup.py` dependency set: too broad for v0.1 and includes out-of-scope components.
- `modules/tempCodeRunnerFile.py`: stray temporary file.

## 8. Architecture Mismatches

Legacy model vs VulnSpider domain:

- Legacy stores page rows. VulnSpider separates `Page`, `Endpoint`, `InputPoint`, and `VulnerabilityCandidate` (`docs/DOMAIN_MODEL.md` section 1; legacy `db.py::create_table`).
- Legacy nests all query params of a URL into one JSON cell. VulnSpider must split each query parameter into a separate `InputPoint` (`docs/PROTOTYPE_V0_1.md` AC-01; legacy `params.py::extract_params_from_url`).
- Legacy nests all visible form fields into one page row. VulnSpider must split each form field into a separate `InputPoint` and normalize the form action/method into an endpoint/request template (`docs/PROTOTYPE_V0_1.md` AC-02; legacy `parser.py::extract_inputs_with_form_context`).
- Legacy has no one-at-a-time probe representation. VulnSpider requires `ProbePlan.changed_fields` length 1 and one target `InputPoint` per probe (`docs/DOMAIN_MODEL.md` section 5; `docs/PROTOTYPE_V0_1.md` AC-03).
- Legacy does not keep `ResponseSnapshot` status code, elapsed time, headers, body hash, body length, encoding, or redirect location. VulnSpider needs these for observation and feature extraction (`docs/DOMAIN_MODEL.md` section 6).
- Legacy discards or ignores HTTP status semantics. Static `fetch_page` calls `raise_for_status()` and returns on exceptions (`static_crawler.py` lines 79-83), while v0.1 requires preserving 4xx/5xx as observation data (`docs/PROTOTYPE_V0_1.md` AC-04; `docs/DOMAIN_MODEL.md` section 6).
- Legacy forces static response encoding to UTF-8 (`static_crawler.py` line 80). VulnSpider response snapshots should preserve encoding and not blindly force it (`docs/DOMAIN_MODEL.md` section 6; `CODE_REVIEW.md` HTTP Semantics).
- Legacy LLM analysis emits `confidence_score` as vulnerability probability (`local_llm.py` lines 501-502). VulnSpider v0.1 uses `RankScore` only as verification priority (`docs/DECISION_LOG.md` ADR-003).
- Legacy has no feature observation missing-vs-zero semantics. VulnSpider requires `observed=false, value=null` to differ from `observed=true, value=0` (`docs/FEATURE_SCHEMA.md` section 2; `docs/PROTOTYPE_V0_1.md` AC-05).
- Legacy old graph/export/LLM outputs do not produce candidate-level `ScoreEvidence`, type-specific ranking, or Top-K per vulnerability type (`docs/PROTOTYPE_V0_1.md` AC-06 and AC-07).

## 9. Safety and Correctness Risks

1. Scope bypass by suffix matching. Both static and dynamic `is_internal_url` return `urlparse(url).netloc.endswith(base_netloc)` (`static_crawler.py` lines 20-21; `dynamic_crawler.py` lines 25-26). v0.1 forbids suffix-based scope expansion (`AGENTS.md` Safety and Scope Rules).
2. Redirect scope is not rechecked. Static `requests.Session.get` follows redirects by default and the code does not inspect `res.url` before parsing/storing (`static_crawler.py` lines 79-95). Dynamic `page.goto` may navigate through redirects and the code records the original URL without final scope validation (`dynamic_crawler.py` lines 90-105). v0.1 requires redirect scope revalidation (`docs/ARCHITECTURE.md` scope module).
3. 4xx/5xx are discarded in static crawling. `raise_for_status()` prevents those responses from becoming observation data (`static_crawler.py` line 81), conflicting with v0.1 acceptance criteria.
4. Encoding is forced to UTF-8 in static crawling (`static_crawler.py` line 80), which can corrupt evidence and conflicts with response snapshot requirements.
5. Hidden form inputs are discarded (`parser.py` lines 13-14 and 28-29). That loses baseline fields needed to reconstruct safe one-at-a-time probe requests.
6. Form action is not resolved. `form_action` is stored raw from the HTML attribute (`parser.py` line 22); adapter must resolve it against the source page URL.
7. Missing form method becomes an empty string, not an HTML default (`GET`) (`parser.py` line 9). Adapter must define a deterministic default.
8. Similar URL filtering can hide distinct attack surfaces. It reduces URLs per parent using string similarity and keeps at most three from a group (`static_crawler.py` lines 134-142; `url_filter.py::filter_similar_urls`). This may drop parameters or form pages that differ in security-relevant ways.
9. Global `parent_url_groups` is not cleared between runs (`static_crawler.py` line 18; `dynamic_crawler.py` line 19), which can pollute repeated adapter calls in one process.
10. No v0.1 request budget or delay control exists in legacy crawler beyond depth and timeout. README documents `--depth`, but not max requests or delay (`README.md` lines 57-68).
11. Dynamic crawler catches broad exceptions and may leave pages unclosed if an exception occurs after page creation (`dynamic_crawler.py` lines 70 and 130-132).
12. RAG config helper writes to the user's home directory (`rag.py::create_default_config` lines 317-335), which should not be part of v0.1 core behavior.
13. Old CLI can crawl arbitrary Internet hosts as long as the URL has `http` or `https` scheme (`cli.py` lines 31-36), conflicting with v0.1 default local-only scope.

## 10. Proposed LegacyCrawlerAdapter Boundary

Smallest safe boundary:

```text
Legacy crawl source
  -> RawLegacyCrawlRecord[]
  -> LegacyCrawlerAdapter
  -> RawDiscoveredSurface[]
  -> AttackSurfaceNormalizer
  -> Endpoint[] + InputPoint[] + RequestTemplate[]
```

Adapter input options:

- Preferred for tests: read legacy `crawl_links` rows from a fixture SQLite DB or JSON export without running network I/O.
- Optional for local smoke only: invoke legacy static crawler under an explicit VulnSpider `ScopeGuard`, using local authorized targets only.

Raw legacy record shape:

```text
link: str
parent: str | None
depth: int
host: str
query_params: JSON object string
input_fields: JSON array string
collected_time: str | None
source: "legacy_static" | "legacy_dynamic" | "legacy_fixture"
```

Adapter responsibilities:

1. Parse `query_params` and `input_fields` JSON safely.
2. Resolve page URL into canonical scheme, host, path.
3. For each query key, create one raw query input record with baseline value.
4. For each form field with a `name`, resolve `form_action` against the page URL, normalize method, and create one raw form input record.
5. Preserve source page and legacy row ID for traceability.
6. Emit warnings/details when legacy data is incomplete, for example hidden inputs were omitted or form method/action is missing.
7. Never compute features, scores, vulnerability probabilities, or LLM analysis.
8. Never rely on legacy suffix scope checks; scope validation belongs to VulnSpider `scope/`.

Adapter non-goals:

- Do not reuse old SQLite schema as VulnSpider domain schema.
- Do not import `local_llm`, `rag`, `visualize`, or dynamic crawler for v0.1 core.
- Do not let legacy crawler decide final in-scope hosts.
- Do not treat legacy LLM confidence as `RankScore` or `VerificationConfidence`.

## 11. Migration Plan for v0.1

1. Keep `reference/whspider_legacy/` read-only.
2. Build the VulnSpider scaffold separately under `src/vulnspider/`.
3. Define new typed domain models from `docs/DOMAIN_MODEL.md`.
4. Add fixtures that mimic legacy `crawl_links` rows, including query params, visible form fields, hidden-field loss, repeated query params, blank query values, relative form actions, and missing methods.
5. Implement a `LegacyCrawlerAdapter` that consumes legacy rows or export-like dictionaries and outputs normalized raw discovery records.
6. Implement `AttackSurfaceNormalizer` to split records into `Endpoint`, `InputPoint`, and `RequestTemplate`.
7. Add tests proving `/search?q=book&page=1` becomes separate `query.q` and `query.page` input points.
8. Add tests proving forms create separate `form.username` and `form.password` input points.
9. Add tests ensuring legacy hidden-field loss is flagged or handled before probe planning.
10. Keep observation/probe execution new and separate from legacy crawler HTTP behavior.
11. Add scope tests that reject suffix-domain bypass and redirect expansion.
12. Only after adapter tests pass, consider local smoke use of the legacy static crawler to populate fixture rows.

## 12. Open Questions

- Should hidden inputs be included for `RequestTemplate` baseline reconstruction, even if they are not ranked as independent v0.1 `InputPoint`s? Legacy currently discards them (`parser.py` lines 13-14 and 28-29).
- Should blank query values be preserved as empty strings or `None`? Legacy `parse_qs` default behavior may drop blank values (`params.py::extract_params_from_url`).
- Should repeated query values become one `InputPoint` with list baseline, multiple indexed `InputPoint`s, or unsupported/missing detail? Legacy returns lists only when `parse_qs` sees multiple values (`params.py` lines 14-18).
- Should form method default to `GET` when missing, matching HTML behavior, or be treated as missing? Legacy stores an empty string (`parser.py` line 9).
- Should dynamic crawling be completely postponed, or kept as audit-only reference for future versions? v0.1 excludes Playwright dynamic crawler.
- What is the exact local allowlist policy for running legacy static crawl during smoke tests: only `localhost`/`127.0.0.1`, configured Docker hostnames, or fixture-only?
- Should similar URL filtering be disabled for v0.1 experiments to avoid losing candidate-level ground truth?
- Should legacy committed RAG assets remain in the repository reference folder, or be replaced by a documented external artifact pointer to keep the starter lightweight?

## 13. File-level Evidence

Files inspected:

- `reference/whspider_legacy/README.md`
- `reference/whspider_legacy/setup.py`
- `reference/whspider_legacy/cli.py`
- `reference/whspider_legacy/.gitignore`
- `reference/whspider_legacy/data/.gitkeep`
- `reference/whspider_legacy/data/kb.index`
- `reference/whspider_legacy/data/kb_chunks.pkl`
- `reference/whspider_legacy/modules/config.py`
- `reference/whspider_legacy/modules/db.py`
- `reference/whspider_legacy/modules/dynamic_crawler.py`
- `reference/whspider_legacy/modules/export.py`
- `reference/whspider_legacy/modules/local_llm.py`
- `reference/whspider_legacy/modules/params.py`
- `reference/whspider_legacy/modules/parser.py`
- `reference/whspider_legacy/modules/rag.py`
- `reference/whspider_legacy/modules/static_crawler.py`
- `reference/whspider_legacy/modules/tempCodeRunnerFile.py`
- `reference/whspider_legacy/modules/url_filter.py`
- `reference/whspider_legacy/modules/utils.py`
- `reference/whspider_legacy/modules/visualize.py`
- `reference/whspider_legacy/lib/bindings/utils.js`
- `reference/whspider_legacy/lib/tom-select/tom-select.css`
- `reference/whspider_legacy/lib/tom-select/tom-select.complete.min.js`
- `reference/whspider_legacy/lib/vis-9.1.2/vis-network.css`
- `reference/whspider_legacy/lib/vis-9.1.2/vis-network.min.js`

Key evidence by question:

- Current module map: `cli.py`, `setup.py`, `modules/*.py`, `data/`, and `lib/` listed above.
- Execution flow: `cli.py::webspider` lines 21-97.
- Crawler inputs: CLI options in `cli.py` lines 5-19 and README option tables at lines 57-68 and 145-156.
- Crawler outputs: `db.py::create_table` lines 14-29 and `insert_link` lines 32-41.
- Query parameters: `params.py::extract_params_from_url` lines 9-18; used by static crawler lines 88-89 and dynamic crawler lines 101-102.
- Forms and input fields: `parser.py::extract_inputs_with_form_context` lines 4-33; used by static crawler lines 91-92 and dynamic crawler lines 96-97.
- Form method/action: `parser.py` lines 9, 21-22.
- Hidden inputs discarded: `parser.py` lines 13-14 and 28-29.
- Internal URL scope check: `static_crawler.py::is_internal_url` lines 20-21 and `dynamic_crawler.py::is_internal_url` lines 25-26.
- Redirect handling: no explicit final URL/scope check after `session.get` in `static_crawler.py` lines 79-95; no final URL/scope check after `page.goto` in `dynamic_crawler.py` lines 90-105.
- Cookies/sessions: static `parse_cookie_string` and `requests.Session` in `static_crawler.py` lines 23-46; dynamic cookie conversion and `context.add_cookies` in `dynamic_crawler.py` lines 28-41 and 145-146/169-170.
- HTTP 4xx/5xx: static `res.raise_for_status()` in `static_crawler.py` line 81; dynamic does not store status code.
- Encoding: static `res.encoding = "utf-8"` in `static_crawler.py` line 80; dynamic uses rendered browser content without storing response encoding.
- Coupling to DB/CLI/LLM/RAG/graph/export: `cli.py` lines 38-97; `static_crawler.py` line 10 and lines 139-142; `dynamic_crawler.py` line 10 and lines 193-196; `export.py`; `visualize.py`; `local_llm.py`; `rag.py`.
- Safe to reuse behind adapter: static discovery, parser, params, URL filter, legacy DB reader, with caveats documented above.
- Do not reuse in v0.1: `local_llm.py`, `rag.py`, `dynamic_crawler.py`, `visualize.py`, `export.py`, old DB schema, broad dependency set.
- Architecture mismatches: page-centric `crawl_links` vs `Endpoint`, `InputPoint`, `FeatureVector`, `VulnerabilityCandidate` in `docs/DOMAIN_MODEL.md`.
- Security/scope risks: suffix scope check, redirect scope gap, forced UTF-8, 4xx/5xx discard, hidden input loss, arbitrary Internet target acceptance.
- Smallest adapter boundary: legacy row reader -> raw discovered surface -> new normalizer; do not import old LLM/RAG or DB schema into v0.1.

---

## 14. Adapter implementation policy for Probe readiness

The v0.1 `LegacyCrawlerAdapter` treats legacy crawl rows as lossy discovery
evidence, not as complete HTTP request reconstructions.

Request contexts:

- `RequestTemplate.id` is context-sensitive and includes ordered query/form
  pairs, a context key, and request-context provenance.
- `InputPointRequestContext` explicitly links an InputPoint to every
  RequestTemplate variant that can carry it.
- `InputPointRequestContext` associations are validated against endpoint,
  location, target name, and occurrence index before adapter output is created.
  Probe-consumable associations are produced through validated construction,
  not arbitrary raw id construction.
- If one logical InputPoint appears in multiple baseline variants, the adapter
  preserves those variants and reports that no canonical baseline was selected.
  Conflicting context-specific values leave the logical `InputPoint` with no
  single baseline value.

Repeated parameters:

- Repeated query names are preserved as ordered pairs in `RequestTemplate.query`.
- Repeated query names with ordered URL evidence become occurrence-level
  InputPoints, such as `tag` occurrence `0` and `tag` occurrence `1`.
  When a context-specific baseline value is known, validation checks that it
  matches the exact indexed occurrence in the associated RequestTemplate.
- URL query ordering is authoritative for request reconstruction. Legacy JSON
  query metadata is supplemental, and conflicts produce deterministic warnings.
- Duplicate same-name form controls are likewise preserved in ordered form
  pairs. They become occurrence-level targets only when stable form-boundary and
  ordering evidence exists.

Form metadata:

- Present `form_method` and `form_action` are recorded as explicit provenance.
- Missing method/action are treated as unknown legacy metadata. The adapter may
  retain standards-compatible convenience defaults, but it records them as
  assumptions and emits warnings.
- Identical resolved method/action values with different provenance remain
  distinct request contexts.
- Same source page, method, and action do not prove that fields belong to the
  same form. Without stable form-boundary evidence, fields are preserved as
  separate partial/ambiguous contexts annotated with
  `form-boundary-unavailable`.
- Ambiguous form context identity is derived from semantic field evidence such
  as source page, resolved method/action, provenance, field name/type/value, and
  ambiguity state. It does not use collector list position as a fabricated form
  instance. Indistinguishable duplicate field records may deduplicate
  deterministically while remaining non-probe-ready.

Hidden inputs:

- Legacy static parsing may omit hidden inputs.
- Every legacy-derived form RequestTemplate is marked `PARTIAL` unless a future
  collector can prove complete form preservation.
- The adapter does not fabricate hidden inputs and does not treat their absence
  as evidence that no hidden inputs existed.

Feature details:

- Feature observation details are accepted only as JSON-like mappings with
  string keys and JSON-like nested values.
- Details are deep-frozen before `FeatureVector.id` is computed, and unsupported
  mutable values such as sets are rejected.
