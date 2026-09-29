"""Report-ready table renderers: evaluation comparison and input-point map."""

from __future__ import annotations

import unittest

from vulnspider.corpus.ground_truth import (
    GroundTruthKey,
    GroundTruthStore,
    ground_truth_from_entries,
)
from vulnspider.evaluation.live import ScoredCandidate, evaluate_live_run
from vulnspider.reporting.report_tables import (
    render_evaluation_html,
    render_evaluation_markdown,
    render_ground_truth_html,
    render_ground_truth_markdown,
)

APP = "demoshop"


def _key(path: str, name: str, family: str, *, method: str = "GET") -> GroundTruthKey:
    return GroundTruthKey(
        application_id=APP,
        method=method,
        canonical_path=path,
        parameter_location="QUERY",
        parameter_name=name,
        vulnerability_type=family,
    )


def _eval_report():
    pool = (
        ScoredCandidate("c1", _key("/a", "id", "SQLI"), 0.8, 0.95, True, True),
        ScoredCandidate("c2", _key("/a", "id", "REFLECTED_XSS"), 0.3, 0.18, True, False),
        ScoredCandidate("c3", _key("/b", "q", "SQLI"), 0.4, 0.40, False, False),
    )
    return evaluate_live_run(
        pool,
        application_id=APP,
        target="http://127.0.0.1:8899/",
        top_k=10,
        cutoffs=(1, 3),
    )


def _store() -> GroundTruthStore:
    return ground_truth_from_entries(
        (
            (_key("/sqli", "id", "SQLI"), True),
            (_key("/sqli", "id", "REFLECTED_XSS"), False),
            (_key("/safe", "q", "SQLI"), False),
            (_key("/safe", "q", "REFLECTED_XSS"), False),
            (_key("/bac", "uid", "BROKEN_ACCESS_CONTROL"), True),
        )
    )


class EvaluationMarkdownTests(unittest.TestCase):
    def test_has_a_section_per_metric_and_a_row_per_arm(self) -> None:
        md = render_evaluation_markdown(_eval_report())
        self.assertIn("# 랭킹 평가 지표 — demoshop", md)
        for heading in ("## Recall@K", "## Precision@K", "## MAP@K", "## NDCG@K"):
            self.assertIn(heading, md)
        self.assertIn("| Arm | K=1 | K=3 |", md)
        self.assertIn("Random predictor", md)
        # The shipped product row is emphasised.
        self.assertIn("**VulnSpider (full pipeline)**", md)

    def test_values_are_three_decimals(self) -> None:
        md = render_evaluation_markdown(_eval_report())
        self.assertIn("1.000", md)


class EvaluationHtmlTests(unittest.TestCase):
    def test_is_a_standalone_document_with_highlighted_product_row(self) -> None:
        html = render_evaluation_html(_eval_report())
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("<table>", html)
        self.assertIn("class='full'", html)
        self.assertIn("VulnSpider (full pipeline)", html)
        self.assertIn("후보 3개", html)


class GroundTruthMarkdownTests(unittest.TestCase):
    def test_one_row_per_input_point_with_its_family(self) -> None:
        md = render_ground_truth_markdown(_store(), APP)
        self.assertIn("# 입력점별 취약 유형 — demoshop", md)
        self.assertIn("입력점 3개 · 취약 2개", md)
        self.assertIn("SQLi 1", md)
        self.assertIn("BAC 1", md)
        self.assertIn("| `/sqli` | `id` | QUERY | **SQLi** |", md)
        self.assertIn("| `/bac` | `uid` | QUERY | **BAC** |", md)
        self.assertIn("| `/safe` | `q` | QUERY | 안전 |", md)

    def test_safe_input_point_is_not_bolded(self) -> None:
        md = render_ground_truth_markdown(_store(), APP)
        self.assertNotIn("**안전**", md)


class GroundTruthHtmlTests(unittest.TestCase):
    def test_family_badges_and_counts(self) -> None:
        html = render_ground_truth_html(_store(), APP)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("tag sqli", html)
        self.assertIn("tag bac", html)
        self.assertIn("tag safe", html)
        self.assertIn("입력점 3개", html)

    def test_only_the_scanned_application_is_included(self) -> None:
        store = ground_truth_from_entries(
            (
                (_key("/sqli", "id", "SQLI"), True),
                (
                    GroundTruthKey("other", "GET", "/x", "QUERY", "p", "SQLI"),
                    True,
                ),
            )
        )
        md = render_ground_truth_markdown(store, APP)
        self.assertIn("입력점 1개", md)
        self.assertNotIn("/x", md)


if __name__ == "__main__":
    unittest.main()
