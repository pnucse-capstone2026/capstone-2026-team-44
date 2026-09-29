"""Canonical crawl evidence reporting for the public simple CLI."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from vulnspider.discovery import (
    CombinedDiscoveryResult,
    DynamicCrawlCompletion,
    StaticCrawlResult,
)
from vulnspider.reporting.json_report import (
    REPORT_SCHEMA_VERSION,
    ReportingError,
    render_json_document,
    write_json_document,
)


def build_crawl_report(
    crawl: StaticCrawlResult | CombinedDiscoveryResult,
) -> dict[str, Any]:
    """Wrap a revalidated producer-owned canonical serialization."""

    try:
        if type(crawl) is CombinedDiscoveryResult:
            validated = replace(crawl)
            mode = "combined"
            completion = validated.completion.value
            degraded = validated.degraded
        elif type(crawl) is StaticCrawlResult:
            validated = replace(crawl)
            mode = "static_only"
            completion = DynamicCrawlCompletion.COMPLETE.value
            degraded = False
        else:
            raise ReportingError(
                "crawl must be a StaticCrawlResult or CombinedDiscoveryResult"
            )
    except (TypeError, ValueError) as exc:
        raise ReportingError("crawl result failed revalidation") from exc

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_kind": "crawl",
        "crawl_mode": mode,
        "completion": completion,
        "degraded": degraded,
        "crawl": _redact_cookie_values(validated.to_dict()),
    }


_REDACTED_COOKIE_VALUE = "<redacted>"


def _redact_cookie_values(value: Any) -> Any:
    """Mask session-cookie *values* in the serialized crawl report.

    An authenticated Broken Access Control scan (``--cookie``) attaches the
    operator's session cookie to every request template, and the crawl report
    is a shareable artifact. The cookie names are kept (they are useful
    provenance and not secret) but the values are redacted so a session token is
    never written to disk (AGENTS.md: never commit session secrets). The
    in-memory templates the pipeline executes are untouched.
    """

    if isinstance(value, dict):
        return {
            key: (
                {name: _REDACTED_COOKIE_VALUE for name in sorted(inner)}
                if key == "cookies" and isinstance(inner, dict)
                else _redact_cookie_values(inner)
            )
            for key, inner in value.items()
        }
    if isinstance(value, list):
        return [_redact_cookie_values(item) for item in value]
    return value


def render_crawl_report(
    crawl: StaticCrawlResult | CombinedDiscoveryResult,
) -> str:
    return render_json_document(build_crawl_report(crawl))


def write_crawl_report(
    crawl: StaticCrawlResult | CombinedDiscoveryResult,
    destination: str | Path,
) -> None:
    write_json_document(render_crawl_report(crawl), destination)
