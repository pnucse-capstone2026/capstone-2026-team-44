from __future__ import annotations

import unittest
from dataclasses import replace
from html import escape
from urllib.parse import urlencode

from tests.unit.test_verification import ScriptedTransport, _endpoint, _query_input_point
from vulnspider.domain import HttpMethod, InputPointRequestContext, RequestContextCompleteness, RequestTemplate
from vulnspider.features import extract_minimal_features
from vulnspider.observation import ProbePlanner
from vulnspider.observation.executor import RequestExecutor
from vulnspider.reporting.dashboard_comparison import response_comparison
from vulnspider.reporting.dashboard_presentation import evidence_summary
from vulnspider.scoring.calibration import CalibratedScorer, heuristic_prior_for_family


def _pair(mode: str, family: str, baseline_value: str = "7"):
    point = _query_input_point(baseline_value)
    endpoint = _endpoint()
    template = RequestTemplate(endpoint_id=endpoint.id, endpoint_fingerprint=endpoint.fingerprint,
                               method=HttpMethod.GET,
                               url="http://127.0.0.1/search?" + urlencode({"q": baseline_value}),
                               query=(("q", baseline_value),),
                               completeness=RequestContextCompleteness.COMPLETE, context_key="test")
    context = InputPointRequestContext.from_objects(point, template)
    plan = ProbePlanner().plan(point, template, context)
    execution = RequestExecutor(transport=ScriptedTransport(mode)).execute_plan(plan)
    run = (plan, execution.baseline_response, execution.probe_response)
    vector = extract_minimal_features(point, plan, execution.response_pair, run[1], run[2])
    calibrated = CalibratedScorer.from_prior(heuristic_prior_for_family(family)).probability(vector.features)
    return point, run, calibrated


class ResponseComparisonTests(unittest.TestCase):
    def test_actual_values_body_ids_and_explanation_are_present(self) -> None:
        point, run, calibrated = _pair("quote_error", "SQLI")
        rendered = response_comparison(point, run, "SQLI", calibrated)
        self.assertIn('HTTP 200', rendered)
        self.assertIn('HTTP 500', rendered)
        self.assertIn(escape(run[1].decoded_text), rendered)
        self.assertIn('SQL syntax', rendered)
        self.assertIn(run[1].id, rendered)
        self.assertIn(run[2].id, rendered)
        self.assertIn("새 데이터베이스 오류 패턴", rendered)
        self.assertIn("형 변환 오류", rendered)

    def test_payload_cannot_execute_and_excerpts_are_bounded(self) -> None:
        point, run, calibrated = _pair("raw_reflect", "REFLECTED_XSS")
        attack = '<script>alert(1)</script>'
        response = replace(run[2], decoded_text=attack + "x" * 50000)
        rendered = response_comparison(point, (run[0], run[1], response), "REFLECTED_XSS", calibrated)
        self.assertNotIn(attack, rendered)
        self.assertIn(escape(attack), rendered)
        self.assertLess(len(rendered), 6500)
        self.assertIn("반사만으로 XSS 실행을 입증하지는", rendered)

    def test_wrong_owner_or_role_is_not_presented(self) -> None:
        point, run, calibrated = _pair("quote_error", "SQLI")
        for response in (replace(run[2], request_id="wrong"), replace(run[2], probe_plan_id="wrong"),
                         replace(run[2], request_role="baseline")):
            rendered = response_comparison(point, (run[0], run[1], response), "SQLI", calibrated)
            self.assertIn("소속이 일치하지 않아", rendered)
            self.assertNotIn('class="response-card', rendered)

    def test_missing_and_error_are_explicit(self) -> None:
        point, run, calibrated = _pair("quote_error", "SQLI")
        absent = replace(run[2], decoded_text=None)
        rendered = response_comparison(point, (run[0], run[1], absent), "SQLI", None)
        self.assertIn("응답 본문이 보관되지", rendered)
        self.assertIn("긍정 신호가 제공되지", rendered)
        error = replace(absent, execution_error="failed <timeout>")
        rendered = response_comparison(point, (run[0], run[1], error), "SQLI", calibrated)
        self.assertIn("실행 오류로 응답 비교", rendered)
        self.assertNotIn("새 데이터베이스 오류 패턴", rendered)
        self.assertIn("failed &lt;timeout&gt;", rendered)

    def test_encoded_reflection_is_not_explained_as_raw_execution(self) -> None:
        point, run, calibrated = _pair("safe_encode", "REFLECTED_XSS")
        rendered = response_comparison(point, run, "REFLECTED_XSS", calibrated)
        self.assertIn("안전 인코딩 신호", rendered)
        self.assertIn("가능성을 낮추는", rendered)

    def test_identical_responses_do_not_claim_a_change(self) -> None:
        point, run, calibrated = _pair("static", "SQLI")
        rendered = response_comparison(point, run, "SQLI", calibrated)
        self.assertIn("상태·크기·응답 내용 동일", rendered)
        self.assertNotIn("응답 크기·본문 변화", rendered)
        self.assertIn("기록된 sql_error_pattern=0", rendered)
        self.assertNotIn("새 오류 등장", rendered)

    def test_error_already_in_baseline_is_not_called_new(self) -> None:
        point, run, calibrated = _pair("quote_error", "SQLI", "'")
        rendered = response_comparison(point, run, "SQLI", calibrated)
        self.assertIn("SQL syntax", rendered)
        self.assertIn("새 SQL 오류 패턴은 관찰되지", rendered)
        self.assertNotIn("새 데이터베이스 오류 패턴이 기록", rendered)
        self.assertNotIn("변형 입력에서만", rendered)

    def test_raw_text_does_not_reconstruct_missing_features(self) -> None:
        for mode, family in (("quote_error", "SQLI"), ("raw_reflect", "REFLECTED_XSS")):
            with self.subTest(family=family):
                point, run, _ = _pair(mode, family)
                rendered = response_comparison(point, run, family, None)
                self.assertIn("긍정 신호가 제공되지", rendered)
                self.assertIn("미관측", rendered)
                self.assertNotIn("핵심 단서", rendered)
                self.assertNotIn("새 오류 등장", rendered)

    def test_aggregate_evidence_is_not_attributed_to_the_displayed_pair(self) -> None:
        point, run, _ = _pair("static", "SQLI")
        _, _, positive_evidence = _pair("quote_error", "SQLI")
        rendered = response_comparison(point, run, "SQLI", positive_evidence)
        self.assertIn("이 후보에는 새 데이터베이스 오류 패턴이 기록", rendered)
        self.assertIn("상태·크기·응답 내용 동일", rendered)
        self.assertIn("이 한 쌍이 모든 근거의 출처라는 뜻은 아닙니다", rendered)
        self.assertNotIn("입력을 바꾸자", rendered)

    def test_other_family_evidence_is_not_used(self) -> None:
        point, run, calibrated = _pair("quote_error", "SQLI")
        rendered = response_comparison(point, run, "REFLECTED_XSS", calibrated)
        self.assertIn("반사에 관한 긍정 신호가 제공되지", rendered)

    def test_baseline_excerpt_uses_nearby_shared_html_context(self) -> None:
        point, run, calibrated = _pair("quote_error", "SQLI")
        heading = '<h3>판매자 코드</h3>'
        before = '<form>EARLY_FORM_VALUE</form>' + 'a' * 2000 + '<section class="result">' + heading
        before += '<table><tr><td>NORMAL_ROWS</td></tr></table></section>' + 'a' * 700
        after = '<form>CHANGED_FORM_VALUE</form>' + 'b' * 2200 + '<section class="danger">' + heading
        after += '<p class="error">Database error: SQL syntax</p></section>' + 'b' * 700
        baseline = replace(run[1], decoded_text=before)
        probe = replace(run[2], decoded_text=after)
        rendered = response_comparison(point, (run[0], baseline, probe), "SQLI", calibrated)
        baseline_card, probe_card = rendered.split('<article class="response-card probe">')
        self.assertIn(escape(heading), baseline_card)
        self.assertIn('NORMAL_ROWS', baseline_card)
        self.assertNotIn('EARLY_FORM_VALUE', baseline_card)
        self.assertIn(escape(heading), probe_card)
        self.assertIn('Database error:', probe_card)
        self.assertNotIn(heading, rendered)
        self.assertIn(run[1].id, baseline_card)
        self.assertIn(run[2].id, probe_card)

    def test_short_or_ambiguous_context_preserves_fallback(self) -> None:
        point, run, calibrated = _pair("quote_error", "SQLI")
        for context in ('<p>', '<section><h3>Shared result heading</h3></section>'):
            with self.subTest(context=context):
                before = 'BASELINE_START' + 'a' * 2000 + context + 'a' * 200 + context + 'a' * 700
                after = 'PROBE_START' + 'b' * 2200 + context + 'SQL syntax' + 'b' * 700
                rendered = response_comparison(
                    point, (run[0], replace(run[1], decoded_text=before), replace(run[2], decoded_text=after)),
                    "SQLI", calibrated,
                )
                baseline_card = rendered.split('<article class="response-card probe">')[0]
                self.assertIn('BASELINE_START', baseline_card)

    def test_change_summary_remains_accessible(self) -> None:
        point, run, calibrated = _pair("quote_error", "SQLI")
        rendered = response_comparison(point, run, "SQLI", calibrated)
        self.assertIn('<div class="cmp-arrow hot">', rendered)
        self.assertIn('<span class="cmp-arrow-mark" aria-hidden="true">', rendered)
        self.assertIn('<em>상태 코드 변화</em>', rendered)

    def test_status_summary_groups_only_representatives(self) -> None:
        rows = [{"state": state} for state in ("SUPPORTED", "WEAKENED", "UNCHANGED", "UNVERIFIED", "REJECTED")]
        rendered = evidence_summary(rows)
        self.assertIn("대표 후보 5개", rendered)
        self.assertIn("3<small>개", rendered)
        self.assertIn("확정 취약점 수가 아닙니다", rendered)


if __name__ == "__main__":
    unittest.main()
