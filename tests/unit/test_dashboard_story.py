from __future__ import annotations

import html
import unittest
from dataclasses import replace
from types import SimpleNamespace

from tools import demo_shop
from tests.unit.test_dashboard_experience import _candidate
from tests.unit.test_verification import ScriptedTransport, _target
from vulnspider.decision.policy import run_decision_layer
from vulnspider.domain import Endpoint, HttpMethod, InputLocation, InputPoint
from vulnspider.reporting.dashboard_story import candidate_caption, source_caption
from vulnspider.reporting.decision_html_report import _dashboard_rows, render_decision_html_report
from vulnspider.verification import VerificationConfig, verify_target


def _source(page, item, body=None):
    endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1:8899", page.path)
    point = InputPoint(endpoint_id=endpoint.id, endpoint_fingerprint=endpoint.fingerprint,
                       location=InputLocation.QUERY, name=item.name)
    request = SimpleNamespace(id="request", method=HttpMethod.GET,
                              url=f"http://127.0.0.1:8899{page.path}?{item.name}=seed")
    plan = SimpleNamespace(input_point_id=point.id, baseline_request=request)
    baseline = SimpleNamespace(request_id="request", execution_error=None, redirect_location=None,
                               status_code=200, decoded_text=body or demo_shop.render_route(page, {})[1].decode())
    return point, endpoint, (plan, baseline, None)


class DashboardStoryTests(unittest.TestCase):
    def test_all_authored_markers_and_labels_match_the_site(self) -> None:
        seen = set()
        for page in demo_shop.PAGES:
            for item in page.inputs:
                caption = source_caption(*_source(page, item))
                number = f"{demo_shop.INPUT_POINT_NUMBERS[page.path, item.name]:03d}"
                self.assertEqual(caption, {"friendly_path": page.title,
                    "friendly_parameter": item.label, "input_number": number})
                seen.add(number)
        self.assertEqual(len(seen), 100)

    def test_missing_repeated_or_wrong_provenance_has_no_demo_annotation(self) -> None:
        page = demo_shop.PAGES[0]
        point, endpoint, run = _source(page, page.inputs[0])
        self.assertEqual(source_caption(point, endpoint, None), {})
        self.assertEqual(source_caption(replace(point, occurrence_index=0), endpoint, run), {})
        self.assertEqual(source_caption(replace(point, name="unknown"), endpoint, run), {})
        for owner, key, value in ((run[0], "input_point_id", "other"),
                                  (run[1], "request_id", "other"),
                                  (run[1], "decoded_text", None),
                                  (run[1], "status_code", 302)):
            old = getattr(owner, key)
            setattr(owner, key, value)
            self.assertEqual(source_caption(point, endpoint, run), {})
            setattr(owner, key, old)

    def test_ambiguous_number_wrong_form_and_non_demo_stay_unknown(self) -> None:
        page = demo_shop.PAGES[0]
        source = demo_shop.render_route(page, {})[1].decode()
        alterations = (
            source.replace(f'action="{page.path}"', 'action="http://["'),
            source.replace(f'action="{page.path}"', 'action="http://other.test/search"'),
            source.replace('method="get"', 'method="post"'),
            source.replace(' · DemoShop</title>', '</title>'),
            source.replace('data-input-point="002"', 'data-input-point="001"'),
            source.replace('id="input-point-001"', 'id="other"'),
        )
        for altered in alterations:
            self.assertEqual(source_caption(*_source(page, page.inputs[0], altered)), {})

    def test_source_captions_are_escaped_and_never_become_navigation(self) -> None:
        page = demo_shop.PAGES[0]
        source = demo_shop.render_route(page, {})[1].decode()
        attack = '<img src=x onerror="alert(1)">'
        source = source.replace(page.title + " · DemoShop", html.escape(attack) + " · DemoShop")
        row = {"path": page.path, "parameter": "q", **source_caption(*_source(page, page.inputs[0], source))}
        rendered = candidate_caption(row)
        self.assertIn(html.escape(attack), rendered)
        self.assertNotIn(attack, rendered)

    def test_prior_final_and_signal_are_read_from_verification_without_recalculation(self) -> None:
        target = _target("quote_error", "SQLI")
        verified = verify_target(target, config=VerificationConfig(transport=ScriptedTransport("quote_error")))
        candidate = _candidate(target.candidate_id, target.input_point.id, 0.99)
        for prior, final in ((0.312, 0.953), (0.81, 0.31), (0.6, 0.6), (0.0, 1.0)):
            record = replace(verified, prior_probability=prior, final_confidence=final)
            rows = _dashboard_rows((candidate,), {}, {}, {candidate.candidate_id: record}, {})
            self.assertEqual((rows[0]["prior"], rows[0]["score"]), (prior, final))
        rendered = render_decision_html_report(run_decision_layer((candidate,), top_k=1),
            verification={candidate.candidate_id: replace(verified, prior_probability=0.81, final_confidence=0.31)})
        self.assertIn('-50.0%p', rendered)
        self.assertIn('left:31.0000%;width:50.0000%', rendered)

    def test_unverified_and_empty_reports_do_not_claim_a_verification_gain(self) -> None:
        rendered = render_decision_html_report(run_decision_layer((_candidate(),), top_k=1))
        self.assertIn('검증 전 확률을 최종 신뢰도로 그대로 표시합니다', rendered)
        self.assertNotIn('+0.0%p', rendered)
        empty = render_decision_html_report(run_decision_layer((), top_k=1))
        self.assertIn('비교할 상위 후보가 없습니다', empty)

    def test_journey_distinguishes_selected_candidates_from_collapsed_representatives(self) -> None:
        candidates = (_candidate(), replace(_candidate("c2", "i1", 0.6), family="REFLECTED_XSS"))
        rendered = render_decision_html_report(run_decision_layer(candidates, top_k=2),
            endpoint_count=33, input_point_count=100)
        overview = rendered.split('id="overview"', 1)[1].split('id="candidates"', 1)[0]
        self.assertIn('33<small>개', overview)
        self.assertIn('100<small>개', overview)
        self.assertIn('대표 1개 표시', overview)
        self.assertIn('후보 수는 확정된 취약점 수가 아닙니다', overview)
        self.assertEqual(overview.count('class="comparison-card"'), 1)


if __name__ == "__main__":
    unittest.main()
