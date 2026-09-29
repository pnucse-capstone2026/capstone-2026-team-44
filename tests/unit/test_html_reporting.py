from __future__ import annotations

import unittest

from vulnspider.domain import (
    Endpoint,
    FeatureObservation,
    FeatureVector,
    HttpMethod,
    InputLocation,
    InputPoint,
    ProbeFamily,
    ProbePlan,
    RequestInstance,
    ResponseSnapshot,
)
from vulnspider.features import (
    MARKER_REFLECTED,
    RESPONSE_LENGTH_DIFF_RATIO,
    SQL_ERROR_PATTERN,
    STATUS_CODE_CHANGED,
)
from vulnspider.reporting import (
    ReportingError,
    build_html_report_context,
    render_html_report,
)
from vulnspider.scoring import SQLiScorer, XSSScorer
from vulnspider.selection import select_top_k


class HtmlReportingTests(unittest.TestCase):
    def _endpoint(self, *, path: str = "/product") -> Endpoint:
        return Endpoint(
            method=HttpMethod.GET,
            scheme="http",
            host="127.0.0.1:8899",
            path=path,
            discovered_by="unit-test",
        )

    def _input_point(self, endpoint: Endpoint, *, name: str = "id") -> InputPoint:
        return InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name=name,
            baseline_value="1",
        )

    def _vector(
        self,
        input_point_id: str,
        *,
        status_code_changed: float = 0.0,
        response_length_diff_ratio: float = 0.0,
        marker_reflected: float = 0.0,
        sql_error_pattern: float = 0.0,
        probe_run_id: str = "pair_html",
    ) -> FeatureVector:
        values = {
            STATUS_CODE_CHANGED: status_code_changed,
            RESPONSE_LENGTH_DIFF_RATIO: response_length_diff_ratio,
            MARKER_REFLECTED: marker_reflected,
            SQL_ERROR_PATTERN: sql_error_pattern,
        }
        return FeatureVector(
            input_point_id=input_point_id,
            probe_run_ids=(probe_run_id,),
            features={
                name: FeatureObservation(
                    name=name,
                    value=value,
                    observed=True,
                    source="html-report-test",
                    extractor_version="unit-v1",
                )
                for name, value in values.items()
            },
        )

    def _probe_run(
        self,
        input_point: InputPoint,
        *,
        marker: str = "VULNSPIDER_TESTMARKER0000",
    ) -> tuple[ProbePlan, ResponseSnapshot, ResponseSnapshot]:
        baseline_request = RequestInstance(
            method=HttpMethod.GET,
            url="http://127.0.0.1:8899/product?id=1",
            query=((input_point.name, "1"),),
        )
        probe_request = RequestInstance(
            method=HttpMethod.GET,
            url=f"http://127.0.0.1:8899/product?id={marker}",
            query=((input_point.name, marker),),
        )
        probe_plan = ProbePlan(
            input_point_id=input_point.id or "",
            probe_family=ProbeFamily.REFLECTION_MARKER,
            baseline_request=baseline_request,
            probe_request=probe_request,
            changed_fields=(f"query.{input_point.name}",),
            probe_marker=marker,
            marker_strategy="neutral-reflection-marker-v1",
        )
        baseline_response = ResponseSnapshot(
            request_id=baseline_request.id or "",
            status_code=200,
            elapsed_ms=12.0,
            body_bytes_hash="a" * 64,
            body_length_bytes=100,
            probe_plan_id=probe_plan.id,
            request_role="baseline",
        )
        probe_response = ResponseSnapshot(
            request_id=probe_request.id or "",
            status_code=500,
            elapsed_ms=34.0,
            body_bytes_hash="b" * 64,
            body_length_bytes=222,
            probe_plan_id=probe_plan.id,
            request_role="probe",
        )
        return probe_plan, baseline_response, probe_response

    def _full_context_kwargs(
        self,
        endpoint: Endpoint,
        input_point: InputPoint,
        vector: FeatureVector,
    ) -> dict:
        return {
            "input_points": {input_point.id or "": input_point},
            "endpoints": {endpoint.id or "": endpoint},
            "probe_runs": {vector.id or "": self._probe_run(input_point)},
            "target": "http://127.0.0.1:8899/",
            "elapsed_seconds": 0.5,
        }

    # -- determinism ---------------------------------------------------

    def test_deterministic_output_regardless_of_input_order(self) -> None:
        endpoint = self._endpoint()
        input_point = self._input_point(endpoint)
        vector = self._vector(
            input_point.id or "",
            status_code_changed=1.0,
            response_length_diff_ratio=0.5,
            marker_reflected=1.0,
            sql_error_pattern=1.0,
        )
        results = (SQLiScorer().score(vector), XSSScorer().score(vector))
        kwargs = self._full_context_kwargs(endpoint, input_point, vector)

        first = render_html_report(
            select_top_k(results, k=2),
            warnings=("z", "a", "z"),
            **kwargs,
        )
        second = render_html_report(
            select_top_k(tuple(reversed(results)), k=2),
            warnings=("a", "z"),
            **kwargs,
        )
        self.assertEqual(first, second)

    # -- escaping --------------------------------------------------------

    def test_escapes_untrusted_crawled_and_observed_text(self) -> None:
        endpoint = self._endpoint(path="/product\"><script>alert('path')</script>")
        input_point = self._input_point(
            endpoint, name="id\"><script>alert('param')</script>"
        )
        vector = FeatureVector(
            input_point_id=input_point.id or "",
            probe_run_ids=("pair_escape",),
            features={
                MARKER_REFLECTED: FeatureObservation.missing(
                    MARKER_REFLECTED,
                    source="reflection_marker_probe",
                    extractor_version="unit-v1",
                    details={"reason": "<script>alert('reason')</script>"},
                ),
                RESPONSE_LENGTH_DIFF_RATIO: FeatureObservation(
                    name=RESPONSE_LENGTH_DIFF_RATIO,
                    value=0.1,
                    observed=True,
                    source="html-report-test",
                    extractor_version="unit-v1",
                ),
            },
        )
        result = XSSScorer().score(vector)
        outcome = select_top_k((result,), k=1)

        html_text = render_html_report(
            outcome,
            warnings=("<script>alert('warning')</script>",),
            input_points={input_point.id or "": input_point},
            endpoints={endpoint.id or "": endpoint},
        )

        self.assertNotIn("<script>alert('path')</script>", html_text)
        self.assertNotIn("<script>alert('param')</script>", html_text)
        self.assertNotIn("<script>alert('reason')</script>", html_text)
        self.assertNotIn("<script>alert('warning')</script>", html_text)
        self.assertIn("&lt;script&gt;alert(&#x27;path&#x27;)&lt;/script&gt;", html_text)
        self.assertIn("&lt;script&gt;alert(&#x27;warning&#x27;)&lt;/script&gt;", html_text)

    def test_escapes_untrusted_text_in_executed_requests_section(self) -> None:
        endpoint = self._endpoint()
        input_point = self._input_point(endpoint)
        vector = self._vector(input_point.id or "", marker_reflected=1.0)
        result = XSSScorer().score(vector)
        outcome = select_top_k((result,), k=1)
        marker = "VULNSPIDER_<script>alert('marker')</script>"

        html_text = render_html_report(
            outcome,
            input_points={input_point.id or "": input_point},
            endpoints={endpoint.id or "": endpoint},
            probe_runs={vector.id or "": self._probe_run(input_point, marker=marker)},
        )

        self.assertNotIn("<script>alert('marker')</script>", html_text)
        self.assertIn("&lt;script&gt;alert(&#x27;marker&#x27;)&lt;/script&gt;", html_text)

    # -- truthfulness invariant (shared with the JSON reporter) ---------

    def test_never_labels_priority_as_confidence_probability_or_confirmed(
        self,
    ) -> None:
        endpoint = self._endpoint()
        input_point = self._input_point(endpoint)
        vector = self._vector(
            input_point.id or "",
            status_code_changed=1.0,
            response_length_diff_ratio=1.0,
            marker_reflected=1.0,
            sql_error_pattern=1.0,
        )
        results = (SQLiScorer().score(vector), XSSScorer().score(vector))
        outcome = select_top_k(results, k=2)

        html_text = render_html_report(
            outcome, **self._full_context_kwargs(endpoint, input_point, vector)
        )

        lowered = html_text.lower()
        for misleading_name in ("confidence", "probability", "confirmed"):
            self.assertNotIn(misleading_name, lowered)

    # -- graceful degradation --------------------------------------------

    def test_renders_without_optional_display_maps(self) -> None:
        vector = self._vector("inp_bare", marker_reflected=1.0)
        outcome = select_top_k((XSSScorer().score(vector),), k=1)

        html_text = render_html_report(outcome)

        self.assertIn("endpoint not supplied to report builder", html_text)
        self.assertIn(
            "No executed-request detail was supplied to the report builder",
            html_text,
        )

    def test_renders_empty_state_with_no_selected_candidates(self) -> None:
        outcome = select_top_k((), k=1)
        html_text = render_html_report(outcome)
        self.assertIn("No rankable candidates were selected.", html_text)

    # -- truthful revalidation at the reporting boundary ------------------

    def test_rejects_non_selection_outcome(self) -> None:
        with self.assertRaisesRegex(ReportingError, "SelectionOutcome"):
            build_html_report_context(object())  # type: ignore[arg-type]

    def test_revalidates_outcome_and_rejects_corruption(self) -> None:
        vector = self._vector("inp_corrupt", marker_reflected=1.0)
        outcome = select_top_k((XSSScorer().score(vector),), k=1)
        object.__setattr__(outcome.summary, "selected_results", 0)
        with self.assertRaisesRegex(ReportingError, "internally inconsistent"):
            render_html_report(outcome)

    # -- context content ---------------------------------------------------

    def test_context_joins_endpoint_and_computes_priority_band(self) -> None:
        endpoint = self._endpoint()
        input_point = self._input_point(endpoint)
        vector = self._vector(
            input_point.id or "",
            marker_reflected=1.0,
            response_length_diff_ratio=1.0,
        )
        outcome = select_top_k((XSSScorer().score(vector),), k=1)

        context = build_html_report_context(
            outcome,
            input_points={input_point.id or "": input_point},
            endpoints={endpoint.id or "": endpoint},
        )

        self.assertEqual(len(context["candidates"]), 1)
        candidate = context["candidates"][0]
        self.assertEqual(candidate["rank"], 1)
        self.assertEqual(candidate["vulnerability_type"], "REFLECTED_XSS")
        self.assertEqual(candidate["priority_band"], "high")
        self.assertEqual(candidate["selection_priority"], 1.0)
        self.assertEqual(
            candidate["endpoint"],
            {
                "method": "GET",
                "url": "http://127.0.0.1:8899/product",
                "location": "QUERY",
                "name": "id",
                "occurrence_index": None,
            },
        )
        self.assertEqual(candidate["requests"], [])
        self.assertEqual(context["summary"]["selected_results"], 1)
        self.assertEqual(context["priority_bands"], {"high": 1, "medium": 0, "low": 0})

    def test_context_includes_executed_requests_only_when_supplied(self) -> None:
        endpoint = self._endpoint()
        input_point = self._input_point(endpoint)
        vector = self._vector(input_point.id or "", marker_reflected=1.0)
        outcome = select_top_k((XSSScorer().score(vector),), k=1)
        probe_plan, baseline_response, probe_response = self._probe_run(input_point)

        with_requests = build_html_report_context(
            outcome, probe_runs={vector.id or "": (probe_plan, baseline_response, probe_response)}
        )
        without_requests = build_html_report_context(outcome)

        self.assertEqual(len(with_requests["candidates"][0]["requests"]), 2)
        self.assertEqual(without_requests["candidates"][0]["requests"], [])
        roles = [item["role"] for item in with_requests["candidates"][0]["requests"]]
        self.assertEqual(roles, ["baseline", "probe"])
        self.assertEqual(
            with_requests["candidates"][0]["requests"][1]["injected_value"],
            probe_plan.probe_marker,
        )

    def test_context_lists_unrankable_reasons(self) -> None:
        missing_vector = FeatureVector(
            input_point_id="inp_missing",
            probe_run_ids=("pair_missing",),
            features={
                name: FeatureObservation.missing(
                    name,
                    source="execution-error",
                    extractor_version="unit-v1",
                    details={"reason": "execution-error"},
                )
                for name in (
                    STATUS_CODE_CHANGED,
                    RESPONSE_LENGTH_DIFF_RATIO,
                    MARKER_REFLECTED,
                    SQL_ERROR_PATTERN,
                )
            },
        )
        outcome = select_top_k(
            (SQLiScorer().score(missing_vector), XSSScorer().score(missing_vector)),
            k=5,
        )
        context = build_html_report_context(outcome)
        self.assertEqual(context["summary"]["unrankable_results"], 2)
        self.assertEqual(len(context["unrankable"]), 2)
        for item in context["unrankable"]:
            self.assertTrue(item["reasons"])

        html_text = render_html_report(outcome)
        self.assertIn("Unrankable", html_text)
        self.assertNotIn(">safe<", html_text.lower())


if __name__ == "__main__":
    unittest.main()
