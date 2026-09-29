"""The per-input-point detail report: crawl join, warning collapse, escaping."""

from __future__ import annotations

import unittest

from vulnspider.reporting.html_report import _render_warnings
from vulnspider.reporting.verification_detail_report import (
    build_verification_detail_html,
    crawl_index_from_report,
)

_VERIFY_REPORT = {
    "target": "http://127.0.0.1:8899/",
    "counts": {
        "candidates_verified": 1,
        "proposals": 2,
        "accepted": 2,
        "rejected": 0,
        "supported": 1,
        "weakened": 0,
    },
    "candidates": [
        {
            "candidate_id": "cand_1",
            "input_point_id": "inp_1",
            "vulnerability_type": "SQLI",
            "selection_rank": 1,
            "prior_probability": 0.88,
            "final_confidence": 0.95,
            "confidence_delta": 0.07,
            "final_outcome": "SUPPORTED",
            "final_signal": "SUPPORT_REPRODUCED",
            "results": [
                {
                    "provider": "deterministic-baseline",
                    "mutation_family": "SQL_META",
                    "mutated_value": "1'",
                    "based_on_value": "101",
                    "rationale": "Append a SQL metacharacter.",
                    "outcome_status": "SUPPORTED",
                    "execution": {"probe_plan_id": "probe_1"},
                    "validator": {"decision": "ACCEPTED", "rejection_reasons": []},
                    "confidence": {
                        "signal": "SUPPORT_REPRODUCED",
                        "confidence_delta": 0.07,
                        "evidence": [
                            {
                                "feature_name": "sql_error_pattern",
                                "baseline_value": 1.0,
                                "verification_value": 1.0,
                                "direction": "flat",
                                "reason": "reproduced",
                            }
                        ],
                    },
                    "feature_delta": {"observability_flips": ["marker_reflected"]},
                }
            ],
        }
    ],
}

# The dict shape build_crawl_report produces: endpoints/input_points nested
# under "crawl", which the index builder finds by recursive key search.
_CRAWL_REPORT = {
    "report_kind": "crawl",
    "crawl": {
        "discovery": {
            "endpoints": [
                {
                    "id": "ep_1",
                    "method": "GET",
                    "scheme": "http",
                    "host": "127.0.0.1:8899",
                    "path": "/product",
                }
            ],
            "input_points": [
                {
                    "id": "inp_1",
                    "endpoint_id": "ep_1",
                    "name": "id",
                    "location": "QUERY",
                    "baseline_value": "101",
                }
            ],
        }
    },
}


class CrawlIndexTests(unittest.TestCase):
    def test_index_is_built_from_nested_crawl_report(self) -> None:
        index = crawl_index_from_report(_CRAWL_REPORT)
        self.assertIn("inp_1", index)
        self.assertEqual(index["inp_1"]["base_url"], "http://127.0.0.1:8899/product")
        self.assertEqual(index["inp_1"]["name"], "id")

    def test_none_crawl_report_yields_an_empty_index(self) -> None:
        self.assertEqual(crawl_index_from_report(None), {})


class DetailReportTests(unittest.TestCase):
    def test_with_crawl_report_renders_the_full_request_url(self) -> None:
        html = build_verification_detail_html(_VERIFY_REPORT, _CRAWL_REPORT)
        self.assertIn("http://127.0.0.1:8899/product?", html)
        self.assertIn("id=101", html)  # baseline value from the crawl join
        self.assertIn("SUPPORTED", html)
        self.assertIn("prior 0.880", html)
        self.assertIn("final 0.950", html)

    def test_without_crawl_report_falls_back_to_bare_value(self) -> None:
        html = build_verification_detail_html(_VERIFY_REPORT, None)
        self.assertIn("파라미터 원본값만 표시", html)
        self.assertNotIn("http://127.0.0.1:8899/product?", html)

    def test_attacker_shaped_payload_is_escaped(self) -> None:
        report = {
            **_VERIFY_REPORT,
            "candidates": [
                {
                    **_VERIFY_REPORT["candidates"][0],
                    "results": [
                        {
                            **_VERIFY_REPORT["candidates"][0]["results"][0],
                            "mutated_value": "<script>alert(1)</script>",
                        }
                    ],
                }
            ],
        }
        html = build_verification_detail_html(report, None)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)


class WarningCollapseTests(unittest.TestCase):
    def test_identical_warnings_collapse_with_a_count(self) -> None:
        html = _render_warnings(["dup"] * 8 + ["once"])
        self.assertIn("(&times;8)", html)
        self.assertIn("2 distinct, 9 total", html)
        # The distinct message appears once, not eight times.
        self.assertEqual(html.count("<li>dup"), 1)

    def test_distinct_list_is_capped_with_an_overflow_line(self) -> None:
        warnings = [f"warning-{i}" for i in range(20)]
        html = _render_warnings(warnings)
        self.assertIn("more distinct warning(s)", html)

    def test_empty_warnings_render_nothing(self) -> None:
        self.assertEqual(_render_warnings([]), "")


if __name__ == "__main__":
    unittest.main()
