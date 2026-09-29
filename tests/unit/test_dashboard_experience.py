from __future__ import annotations

import base64
import hashlib
import html
import unittest
from dataclasses import replace
from html.parser import HTMLParser

from tests.unit import test_verification as verification_fixture
from tests.unit.test_verification import ScriptedTransport, _target
from vulnspider.decision.candidate import DecisionCandidate
from vulnspider.decision.policy import run_decision_layer
from vulnspider.domain import Endpoint, HttpMethod
from vulnspider.observation.executor import RequestExecutionError
from vulnspider.reporting.dashboard_assets import SCRIPT
from vulnspider.reporting.dashboard_evidence import explain_candidate, payload_records
from vulnspider.reporting.decision_html_report import render_decision_html_report
from vulnspider.scoring.calibration import CalibratedProbability, CalibrationEvidence
from vulnspider.verification import (
    DeterministicMutationProposer, MutationSubject, PayloadValidator,
    VerificationConfig, VerificationResult, update_confidence, verify_target,
)
from vulnspider.verification.access_verify import AccessCandidateVerification


class DocumentLinks(HTMLParser):
    def __init__(self, source: str) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.links: list[str] = []
        self.scripts: list[dict[str, str | None]] = []
        self.csp = ""
        self.feed(source)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"] or "")
        if tag == "a":
            self.links.append(values.get("href") or "")
        if tag == "script":
            self.scripts.append(values)
        if values.get("http-equiv") == "Content-Security-Policy":
            self.csp = values.get("content") or ""


def _candidate(candidate_id: str = "c1", subject: str = "i1", probability: float = 0.7) -> DecisionCandidate:
    return DecisionCandidate(candidate_id=candidate_id, subject_ref=subject,
                             family="SQLI", probability=probability, selection_rank=1)


class DashboardExperienceTests(unittest.TestCase):
    def test_every_link_resolves_to_a_unique_local_screen_and_data_never_enters_script(self) -> None:
        outcome = run_decision_layer((_candidate(), _candidate("c2", "i2", 0.6)), top_k=2)
        attack = '</script><img src="http://invalid.test" onerror="alert(1)">'
        rendered = render_decision_html_report(outcome, target=attack, warnings=(attack,))
        parsed = DocumentLinks(rendered)
        self.assertEqual(len(parsed.ids), len(set(parsed.ids)))
        self.assertTrue({"overview", "candidates", "methodology", "candidate-1", "candidate-2"}.issubset(parsed.ids))
        self.assertTrue(all(link.startswith("#") and link[1:] in parsed.ids for link in parsed.links))
        self.assertEqual(parsed.scripts, [{}])
        self.assertIn(f"<script>{SCRIPT}</script>", rendered)
        digest = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
        self.assertIn(f"script-src 'sha256-{digest}'", parsed.csp)
        self.assertIn("default-src 'none'", parsed.csp)
        self.assertNotIn(attack, rendered)
        self.assertIn(html.escape(attack), rendered)
        self.assertNotIn("/_lab/verify", rendered)
        self.assertNotIn("직접 실증", rendered)

    def test_empty_report_keeps_overview_and_does_not_invent_a_candidate_screen(self) -> None:
        rendered = render_decision_html_report(run_decision_layer((), top_k=5))
        parsed = DocumentLinks(rendered)
        self.assertNotIn("candidate-1", parsed.ids)
        self.assertIn("표시할 상위 후보가 없습니다", rendered)
        self.assertIn("0 / 0개", rendered)

    def test_unknown_location_stays_unknown_and_mixed_scores_are_labeled(self) -> None:
        target = _target("quote_error", "SQLI")
        verified = verify_target(target, config=VerificationConfig(transport=ScriptedTransport("quote_error")))
        candidates = (_candidate(target.candidate_id, target.input_point.id or "", target.prior_probability), _candidate("c2", "other", 0.2))
        rendered = render_decision_html_report(run_decision_layer(candidates, top_k=2), verification={target.candidate_id: verified})
        self.assertIn("엔드포인트 정보 미제공", rendered)
        self.assertIn("추가 검증 전", rendered)
        self.assertIn("추가 검증 기록이 없습니다", rendered)
        self.assertIn("최종 신뢰도", rendered)
        self.assertIn("상위 취약점 후보", rendered)
        self.assertNotIn("먼저 확인할 후보", rendered)
        self.assertNotIn('class="location-sub">검증 전 확률</div>', rendered)
        self.assertIn('class="location-sub">최종 신뢰도</div>', rendered)
        self.assertIn('class="prio low">20%', rendered)
        self.assertNotIn("[None]", rendered)
        self.assertIn("추가 페이로드 01", rendered)

    def test_canonical_endpoint_names_are_escaped_not_used_as_routes(self) -> None:
        target = _target("raw_reflect", "REFLECTED_XSS")
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", '/search"><script>bad()</script>')
        point = replace(target.input_point, endpoint_id=endpoint.id, endpoint_fingerprint=endpoint.fingerprint)
        rendered = render_decision_html_report(run_decision_layer((_candidate(subject=point.id or ""),), top_k=1),
                                              endpoints={endpoint.id or "": endpoint}, input_points={point.id or "": point})
        self.assertIn(html.escape(endpoint.path), rendered)
        self.assertNotIn('<script>bad()', rendered)
        self.assertIn('href="#candidate-1"', rendered)
        self.assertNotIn('[None]', rendered)

    def test_verify_links_open_the_target_verify_endpoint_only_when_enabled(self) -> None:
        # The verify button is shown only on the DemoShop demo input points
        # (here the SQLi demo point /admin/users), and only when verify links
        # are enabled -- never on other candidates or with links disabled.
        target = _target("raw_reflect", "REFLECTED_XSS")
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1:8899", "/admin/users")
        point = replace(target.input_point, endpoint_id=endpoint.id, endpoint_fingerprint=endpoint.fingerprint)
        outcome = run_decision_layer((_candidate(subject=point.id or ""),), top_k=1)
        maps = dict(endpoints={endpoint.id or "": endpoint}, input_points={point.id or "": point},
                    target="http://127.0.0.1:8899/")
        enabled = render_decision_html_report(outcome, verify_links=True, **maps)
        disabled = render_decision_html_report(outcome, verify_links=False, **maps)
        self.assertIn("/_verify?path=", enabled)
        self.assertIn("verify-live", enabled)
        self.assertNotIn("/_verify", disabled)

        # A candidate that is not one of the three demo points never gets the
        # button, even with verify links enabled.
        other_endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1:8899", "/search")
        other_point = replace(target.input_point, endpoint_id=other_endpoint.id, endpoint_fingerprint=other_endpoint.fingerprint)
        other_outcome = run_decision_layer((_candidate(subject=other_point.id or ""),), top_k=1)
        other = render_decision_html_report(
            other_outcome, verify_links=True,
            endpoints={other_endpoint.id or "": other_endpoint},
            input_points={other_point.id or "": other_point},
            target="http://127.0.0.1:8899/",
        )
        self.assertNotIn("/_verify", other)

    def test_missing_feature_is_not_explained_as_zero_or_positive_evidence(self) -> None:
        calibrated = CalibratedProbability._from_parts(
            family="SQLI", model_version="unit", probability=0.5,
            logit_mean=0.0, logit_variance=0.0, observed_feature_count=0,
            evidence=(CalibrationEvidence(feature_name="sql_error_pattern", feature_value=None,
                      weight=1.0, logit_contribution=None, deciban_contribution=None,
                      observed=False, reason="not observed"),),
        )
        rendered = explain_candidate("SQLI", calibrated)
        self.assertIn("관측값 미관측", rendered)
        self.assertNotIn("확률을 높이는 방향", rendered)
        self.assertNotIn("관측값 0", rendered)

    def test_payload_display_uses_real_execution_refs_and_escaped_values(self) -> None:
        target = _target("raw_reflect", "REFLECTED_XSS")
        verified = verify_target(target, config=VerificationConfig(transport=ScriptedTransport("raw_reflect")))
        rendered = payload_records(verified)
        self.assertIn("실행 기록 있음", rendered)
        for result in verified.results:
            self.assertIn(html.escape(result.mutated_value), rendered)
            self.assertIn(result.proposal_id, rendered)
            if result.execution_refs:
                self.assertIn(result.execution_refs.probe_response_id, rendered)
            self.assertIn(f'{result.verification_confidence.confidence * 100:.1f}%', rendered)
        self.assertIn("차례로 누적하지 않으며", rendered)

    def test_rejected_proposal_does_not_appear_as_executed(self) -> None:
        target = _target("quote_error", "SQLI")
        transport = ScriptedTransport("quote_error")
        verified = verify_target(target, config=VerificationConfig(
            transport=transport, proposer=verification_fixture.MaliciousProposerTests.DestructiveProposer()))
        rendered = payload_records(verified)
        self.assertEqual(transport.calls, [])
        self.assertIn("검증기 거부 · 실행되지 않음", rendered)
        self.assertIn("제안된 변형 입력값", rendered)
        self.assertNotIn("실행 기록 있음", rendered)
        self.assertIn("실행 참조 없음", rendered)

    def test_bac_summary_does_not_invent_individual_payloads(self) -> None:
        verified = verify_target(_target("quote_error", "SQLI"), config=VerificationConfig(transport=ScriptedTransport("quote_error")))
        bac = AccessCandidateVerification(candidate_id="bac", input_point_id="relation", selection_rank=1,
            prior_probability=verified.prior_probability, final_outcome=verified.final_outcome,
            final_signal=verified.final_signal, final_confidence=verified.final_confidence, attempted=3, reproduced=2)
        rendered = payload_records(bac)
        self.assertIn("다른 식별자 3개 중 2개", rendered)
        self.assertIn("개별 식별자 값", rendered)
        self.assertNotIn("추가 페이로드 01", rendered)

    def test_accepted_but_unexecuted_is_not_labeled_as_an_executed_payload(self) -> None:
        target = _target("quote_error", "SQLI")
        subject = MutationSubject(candidate_id=target.candidate_id,
            input_point_id=target.input_point.id or "", vulnerability_type=target.vulnerability_type,
            baseline_value="7", parameter_name=target.input_point.name,
            parameter_location=target.input_point.location)
        proposal = DeterministicMutationProposer().propose(subject)[0]
        validator = PayloadValidator().validate(proposal)
        self.assertTrue(validator.accepted)
        confidence = update_confidence(vulnerability_type=target.vulnerability_type,
            prior_probability=target.prior_probability, delta=None, executed=False)
        result = VerificationResult.from_objects(proposal=proposal, validator_result=validator,
            confidence=confidence, baseline_feature_vector_id=target.baseline_feature_vector.id or "",
            selection_rank=1)
        aggregate = verify_target(target, config=VerificationConfig(transport=ScriptedTransport("quote_error")))
        rendered = payload_records(replace(aggregate, results=(result,)))
        self.assertIn("검증기 승인 · 실행되지 않음", rendered)
        self.assertNotIn("실행 기록 있음", rendered)
        self.assertIn("실행 참조 없음", rendered)

    def test_execution_errors_are_escaped_and_not_hidden_as_success(self) -> None:
        class FailingTransport:
            def send(self, request, *, timeout_seconds):
                raise RequestExecutionError('test <error>')

        target = _target("quote_error", "SQLI")
        verified = verify_target(target, config=VerificationConfig(transport=FailingTransport()))
        rendered = payload_records(verified)
        self.assertIn("실행 오류", rendered)
        self.assertIn("&lt;error&gt;", rendered)
        self.assertNotIn("test <error>", rendered)
        self.assertIn("오류로 판단 보류", rendered)


if __name__ == "__main__":
    unittest.main()
