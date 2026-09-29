"""The BAC dashboard folds into the injection dashboard without id collisions."""

from __future__ import annotations

import collections
import re
import unittest

from tools import merge_dashboard
from vulnspider.decision.candidate import DecisionCandidate
from vulnspider.decision.policy import run_decision_layer
from vulnspider.reporting.decision_html_report import render_decision_html_report


def _candidate(cid: str, subject: str, family: str, probability: float) -> DecisionCandidate:
    return DecisionCandidate(
        candidate_id=cid, subject_ref=subject, family=family,
        probability=probability, selection_rank=1,
    )


def _dashboard(candidates: tuple[DecisionCandidate, ...], target: str) -> str:
    return render_decision_html_report(run_decision_layer(candidates, top_k=3), target=target)


def _ids(html: str) -> list[str]:
    return re.findall(r'\bid="([^"]+)"', html)


class MergeDashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.injection = _dashboard(
            (_candidate("s1", "i1", "SQLI", 0.9), _candidate("s2", "i2", "REFLECTED_XSS", 0.7)),
            "http://target/",
        )
        self.bac = _dashboard(
            (_candidate("a1", "j1", "BROKEN_ACCESS_CONTROL", 0.95),
             _candidate("a2", "j2", "BROKEN_ACCESS_CONTROL", 0.6)),
            "http://target/portal/",
        )

    def test_folds_in_a_namespaced_access_control_page(self) -> None:
        merged = merge_dashboard.merge(self.injection, self.bac)
        self.assertIn('id="ac-candidates"', merged)
        self.assertIn('href="#ac-candidates"', merged)  # sidebar nav item
        self.assertIn("접근제어 (BAC)", merged)
        # both candidate sets survive, in their own namespaces
        self.assertTrue(re.search(r'id="candidate-\d+"', merged))
        self.assertTrue(re.search(r'id="ac-candidate-\d+"', merged))

    def test_the_merge_never_collides_ids_and_every_link_resolves(self) -> None:
        merged = merge_dashboard.merge(self.injection, self.bac)
        duplicates = [i for i, n in collections.Counter(_ids(merged)).items() if n > 1]
        self.assertEqual(duplicates, [])
        targets = set(_ids(merged))
        hrefs = {h for h in re.findall(r'href="#([^"]+)"', merged) if h}
        self.assertEqual(sorted(h for h in hrefs if h not in targets), [])

    def test_the_bac_page_drops_its_own_filter_controls(self) -> None:
        merged = merge_dashboard.merge(self.injection, self.bac)
        # the injection filter stays; the BAC page must not duplicate it
        self.assertIn('id="candidate-search"', merged)
        self.assertNotIn('id="ac-candidate-search"', merged)

    def test_without_a_bac_scan_the_page_shows_a_notice(self) -> None:
        merged = merge_dashboard.merge(self.injection, None)
        self.assertIn('id="ac-candidates"', merged)
        self.assertIn("포함되지 않았습니다", merged)
        self.assertIsNone(re.search(r'id="ac-candidate-\d+"', merged))
        self.assertEqual(
            [i for i, n in collections.Counter(_ids(merged)).items() if n > 1], []
        )

    def test_a_non_dashboard_base_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            merge_dashboard.merge("<html><body>not a dashboard</body></html>", self.bac)


if __name__ == "__main__":
    unittest.main()
