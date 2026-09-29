from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import unittest

from vulnspider.domain import (
    Endpoint,
    HttpMethod,
    InputLocation,
    InputPoint,
    InputPointRequestContext,
    ParamPairs,
    ProbePlan,
    RequestContextCompleteness,
    RequestInstance,
    RequestTemplate,
    ResponsePair,
    ResponseSnapshot,
)
from vulnspider.features import (
    MARKER_REFLECTED,
    RESPONSE_LENGTH_DIFF_RATIO,
    SQL_ERROR_PATTERN,
    STATUS_CODE_CHANGED,
    FeatureExtractionError,
    extract_minimal_features,
)
from vulnspider.observation import (
    ProbePlanner,
    RequestExecutionError,
    TransportResponse,
    UrlLibTransport,
    execute_probe_plan,
    execute_request,
    pair_probe_responses,
)


@dataclass
class FakeTransport:
    responses: dict[str, TransportResponse]
    calls: list[RequestInstance] = field(default_factory=list)
    failures: dict[str, str] = field(default_factory=dict)

    def send(
        self,
        request: RequestInstance,
        *,
        timeout_seconds: float,
    ) -> TransportResponse:
        self.calls.append(request)
        if request.id in self.failures:
            raise RequestExecutionError(self.failures[request.id])
        return self.responses[request.id or ""]


class ObservationPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.planner = ProbePlanner()

    def _query_plan(
        self,
        pairs: ParamPairs = (("q", "book"),),
        *,
        target: str = "q",
        occurrence_index: int | None = None,
        baseline_value: str | None = None,
        url: str = "http://127.0.0.1/search?q=book",
    ) -> tuple[InputPoint, RequestTemplate, InputPointRequestContext, ProbePlan]:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        if baseline_value is None:
            matches = [value for name, value in pairs if name == target]
            baseline_value = matches[0 if occurrence_index is None else occurrence_index]
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name=target,
            occurrence_index=occurrence_index,
            baseline_value=baseline_value,
        )
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url=url,
            query=pairs,
            headers={"X-Test": "one"},
            cookies={"sid": "abc"},
            completeness=RequestContextCompleteness.COMPLETE,
            context_key=f"query:{url}:{pairs}",
        )
        context = InputPointRequestContext.from_objects(input_point, template)
        return input_point, template, context, self.planner.plan(
            input_point,
            template,
            context,
        )

    def _form_plan(
        self,
    ) -> tuple[InputPoint, RequestTemplate, InputPointRequestContext, ProbePlan]:
        endpoint = Endpoint(HttpMethod.POST, "http", "127.0.0.1", "/login")
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.FORM,
            name="username",
            baseline_value="alice",
        )
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.POST,
            url="http://127.0.0.1/login",
            form=(("username", "alice"), ("password", "secret")),
            headers={"X-Test": "form"},
            cookies={"session": "cookie"},
            completeness=RequestContextCompleteness.COMPLETE,
            context_key="form:login",
        )
        context = InputPointRequestContext.from_objects(input_point, template)
        return input_point, template, context, self.planner.plan(
            input_point,
            template,
            context,
        )

    def _snapshot(
        self,
        request: RequestInstance,
        *,
        status_code: int = 200,
        text: str = "",
        execution_error: str | None = None,
        headers: dict[str, str] | None = None,
        redirect_location: str | None = None,
        probe_plan_id: str | None = None,
        request_role: str | None = None,
    ) -> ResponseSnapshot:
        body = text.encode("utf-8")
        return ResponseSnapshot(
            request_id=request.id or "",
            status_code=status_code,
            elapsed_ms=10.0,
            body_bytes_hash=sha256(body).hexdigest(),
            body_length_bytes=len(body),
            headers=headers or {"Content-Type": "text/plain"},
            decoded_text=text,
            encoding="utf-8",
            redirect_location=redirect_location,
            execution_error=execution_error,
            probe_plan_id=probe_plan_id,
            request_role=request_role,
        )

    def _plan_snapshot(
        self,
        plan: ProbePlan,
        request_role: str,
        *,
        status_code: int = 200,
        text: str = "",
        execution_error: str | None = None,
        headers: dict[str, str] | None = None,
        redirect_location: str | None = None,
    ) -> ResponseSnapshot:
        if request_role == "baseline":
            request = plan.baseline_request
        elif request_role == "probe":
            request = plan.probe_request
        else:
            raise ValueError("request_role must be baseline or probe")
        return self._snapshot(
            request,
            status_code=status_code,
            text=text,
            execution_error=execution_error,
            headers=headers,
            redirect_location=redirect_location,
            probe_plan_id=plan.id,
            request_role=request_role,
        )

    def _pair_and_extract(
        self,
        input_point: InputPoint,
        plan: ProbePlan,
        baseline: ResponseSnapshot,
        probe: ResponseSnapshot,
    ):
        pair = pair_probe_responses(plan, baseline, probe)
        return pair, extract_minimal_features(input_point, plan, pair, baseline, probe)

    def _overlapping_context_plans(self) -> tuple[InputPoint, ProbePlan, ProbePlan]:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
            baseline_value=None,
        )
        first_template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?q=book",
            query=(("q", "book"),),
            completeness=RequestContextCompleteness.COMPLETE,
            context_key="same-request-context-a",
        )
        second_template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?q=book",
            query=(("q", "book"),),
            completeness=RequestContextCompleteness.COMPLETE,
            context_key="same-request-context-b",
        )
        first_plan = self.planner.plan(
            input_point,
            first_template,
            InputPointRequestContext.from_objects(input_point, first_template),
        )
        second_plan = self.planner.plan(
            input_point,
            second_template,
            InputPointRequestContext.from_objects(input_point, second_template),
        )
        return input_point, first_plan, second_plan

    def _same_request_plan_alias(self, plan: ProbePlan) -> ProbePlan:
        return ProbePlan(
            input_point_id=plan.input_point_id,
            probe_family=plan.probe_family,
            baseline_request=plan.baseline_request,
            probe_request=plan.probe_request,
            changed_fields=plan.changed_fields,
            request_template_id=f"{plan.request_template_id}:alias",
            request_context_id=f"{plan.request_context_id}:alias",
            probe_marker=plan.probe_marker,
            marker_strategy=plan.marker_strategy,
        )

    def _start_http_server(
        self,
        handler_type: type[BaseHTTPRequestHandler],
    ) -> str:
        server = HTTPServer(("127.0.0.1", 0), handler_type)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def cleanup() -> None:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1.0)

        self.addCleanup(cleanup)
        host, port = server.server_address[:2]
        return f"http://{host}:{port}"

    def test_executes_exact_baseline_and_probe_requests_once(self) -> None:
        _input_point, _template, _context, plan = self._query_plan(
            (("q", "book"), ("page", "1")),
            url="http://127.0.0.1/search?q=book&page=1",
        )
        transport = FakeTransport(
            {
                plan.baseline_request.id or "": TransportResponse(200, b"base"),
                plan.probe_request.id or "": TransportResponse(200, b"probe"),
            }
        )
        result = execute_probe_plan(plan, transport=transport)
        self.assertEqual(transport.calls, [plan.baseline_request, plan.probe_request])
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(result.baseline_response.request_id, plan.baseline_request.id)
        self.assertEqual(result.probe_response.request_id, plan.probe_request.id)
        self.assertEqual(result.baseline_response.probe_plan_id, plan.id)
        self.assertEqual(result.baseline_response.request_role, "baseline")
        self.assertEqual(result.probe_response.probe_plan_id, plan.id)
        self.assertEqual(result.probe_response.request_role, "probe")
        self.assertEqual(result.response_pair.probe_plan_id, plan.id)

    def test_preserves_method_url_query_form_headers_and_cookies(self) -> None:
        _input_point, _template, _context, plan = self._form_plan()
        transport = FakeTransport(
            {
                plan.baseline_request.id or "": TransportResponse(200, b"base"),
                plan.probe_request.id or "": TransportResponse(200, b"probe"),
            }
        )
        execute_probe_plan(plan, transport=transport)
        baseline_call, probe_call = transport.calls
        self.assertEqual(baseline_call.method, HttpMethod.POST)
        self.assertEqual(baseline_call.url, "http://127.0.0.1/login")
        self.assertEqual(baseline_call.query, ())
        self.assertEqual(
            baseline_call.form,
            (("username", "alice"), ("password", "secret")),
        )
        self.assertEqual(baseline_call.headers, {"X-Test": "form"})
        self.assertEqual(baseline_call.cookies, {"session": "cookie"})
        self.assertEqual(probe_call.method, HttpMethod.POST)
        self.assertEqual(probe_call.url, "http://127.0.0.1/login")
        self.assertEqual(
            probe_call.form,
            (("username", plan.probe_marker or ""), ("password", "secret")),
        )

    def test_timeout_error_creates_explicit_error_snapshot(self) -> None:
        _input_point, _template, _context, plan = self._query_plan()
        transport = FakeTransport(
            {plan.probe_request.id or "": TransportResponse(200, b"probe")},
            failures={plan.baseline_request.id or "": "timeout"},
        )
        result = execute_probe_plan(plan, transport=transport)
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(result.baseline_response.status_code, 0)
        self.assertEqual(result.baseline_response.execution_error, "timeout")
        self.assertIsNone(result.baseline_response.decoded_text)
        self.assertEqual(result.baseline_response.probe_plan_id, plan.id)
        self.assertEqual(result.baseline_response.request_role, "baseline")
        self.assertIsNone(result.probe_response.execution_error)

    def test_body_capture_limit_is_explicit_error_state(self) -> None:
        _input_point, _template, _context, plan = self._query_plan()
        transport = FakeTransport(
            {
                plan.baseline_request.id or "": TransportResponse(200, b"abcdef"),
            }
        )
        snapshot = execute_request(
            plan.baseline_request,
            transport=transport,
            max_body_bytes=3,
        )
        self.assertEqual(snapshot.body_length_bytes, 6)
        self.assertEqual(snapshot.decoded_text, "abc")
        self.assertEqual(snapshot.execution_error, "body-capture-limit-reached")
        self.assertIsNone(snapshot.probe_plan_id)
        self.assertIsNone(snapshot.request_role)

    def test_redirect_response_is_captured_without_following(self) -> None:
        _input_point, _template, _context, plan = self._query_plan()
        redirect_target = "http://127.0.0.1/next"
        transport = FakeTransport(
            {
                plan.baseline_request.id or "": TransportResponse(
                    302,
                    b"",
                    headers={"Location": redirect_target},
                    redirect_location=redirect_target,
                ),
                plan.probe_request.id or "": TransportResponse(200, b"probe"),
            }
        )
        result = execute_probe_plan(plan, transport=transport)
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(result.baseline_response.status_code, 302)
        self.assertEqual(result.baseline_response.redirect_location, redirect_target)
        self.assertEqual(result.baseline_response.headers["Location"], redirect_target)

    def test_http_4xx_and_5xx_are_normal_observations(self) -> None:
        _input_point, _template, _context, plan = self._query_plan()
        transport = FakeTransport(
            {
                plan.baseline_request.id or "": TransportResponse(404, b"missing"),
                plan.probe_request.id or "": TransportResponse(500, b"server"),
            }
        )
        result = execute_probe_plan(plan, transport=transport)
        self.assertEqual(result.baseline_response.status_code, 404)
        self.assertEqual(result.probe_response.status_code, 500)
        self.assertIsNone(result.baseline_response.execution_error)
        self.assertIsNone(result.probe_response.execution_error)

    def test_url_lib_transport_does_not_follow_redirect(self) -> None:
        class RedirectHandler(BaseHTTPRequestHandler):
            seen: list[str] = []

            def do_GET(self) -> None:
                type(self).seen.append(self.path)
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/target")
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"followed")

            def log_message(self, format: str, *args: object) -> None:
                return None

        base_url = self._start_http_server(RedirectHandler)
        request = RequestInstance(HttpMethod.GET, f"{base_url}/redirect")
        snapshot = execute_request(request, transport=UrlLibTransport())

        self.assertEqual(snapshot.status_code, 302)
        self.assertEqual(snapshot.redirect_location, "/target")
        self.assertEqual(RedirectHandler.seen, ["/redirect"])

    def test_url_lib_transport_captures_direct_4xx_and_5xx(self) -> None:
        class ErrorHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/missing":
                    status_code = 404
                    body = b"missing"
                else:
                    status_code = 500
                    body = b"server"
                self.send_response(status_code)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return None

        base_url = self._start_http_server(ErrorHandler)
        missing = execute_request(
            RequestInstance(HttpMethod.GET, f"{base_url}/missing"),
            transport=UrlLibTransport(),
        )
        server_error = execute_request(
            RequestInstance(HttpMethod.GET, f"{base_url}/error"),
            transport=UrlLibTransport(),
        )

        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.decoded_text, "missing")
        self.assertIsNone(missing.execution_error)
        self.assertEqual(server_error.status_code, 500)
        self.assertEqual(server_error.decoded_text, "server")
        self.assertIsNone(server_error.execution_error)

    def test_connection_failure_creates_explicit_error_snapshot(self) -> None:
        _input_point, _template, _context, plan = self._query_plan()
        baseline_request_id = plan.baseline_request.id or ""
        transport = FakeTransport(
            {plan.probe_request.id or "": TransportResponse(200, b"probe")},
            failures={
                baseline_request_id: "transport-error:ConnectionRefusedError"
            },
        )
        result = execute_probe_plan(plan, transport=transport)
        self.assertEqual(result.baseline_response.status_code, 0)
        self.assertEqual(
            result.baseline_response.execution_error,
            "transport-error:ConnectionRefusedError",
        )
        self.assertEqual(result.baseline_response.probe_plan_id, plan.id)
        self.assertEqual(result.baseline_response.request_role, "baseline")

    def test_pair_validation_accepts_valid_and_deterministic_pair(self) -> None:
        input_point, _template, _context, plan = self._query_plan()
        baseline = self._plan_snapshot(plan, "baseline", text="base")
        probe = self._plan_snapshot(plan, "probe", text="probe")
        first = pair_probe_responses(plan, baseline, probe)
        second = pair_probe_responses(plan, baseline, probe)
        self.assertEqual(first.input_point_id, input_point.id)
        self.assertEqual(first.probe_plan_id, plan.id)
        self.assertEqual(first.id, second.id)

    def test_pair_validation_rejects_mismatched_and_swapped_responses(self) -> None:
        _input_point, _template, _context, plan = self._query_plan()
        baseline = self._plan_snapshot(plan, "baseline", text="base")
        probe = self._plan_snapshot(plan, "probe", text="probe")
        wrong_baseline = ResponseSnapshot(
            request_id="req_other",
            status_code=200,
            elapsed_ms=1.0,
            body_bytes_hash=sha256(b"other").hexdigest(),
            body_length_bytes=5,
            probe_plan_id=plan.id,
            request_role="baseline",
        )
        with self.assertRaisesRegex(RequestExecutionError, "baseline"):
            pair_probe_responses(plan, wrong_baseline, probe)
        with self.assertRaisesRegex(RequestExecutionError, "baseline"):
            pair_probe_responses(plan, probe, baseline)

    def test_pair_validation_rejects_missing_plan_provenance(self) -> None:
        _input_point, _template, _context, plan = self._query_plan()
        direct_baseline = self._snapshot(plan.baseline_request, text="base")
        direct_probe = self._snapshot(plan.probe_request, text="probe")
        with self.assertRaisesRegex(RequestExecutionError, "ProbePlan"):
            pair_probe_responses(plan, direct_baseline, direct_probe)

        transport = FakeTransport(
            {plan.baseline_request.id or "": TransportResponse(200, b"base")}
        )
        unowned_baseline = execute_request(plan.baseline_request, transport=transport)
        self.assertIsNone(unowned_baseline.probe_plan_id)
        self.assertIsNone(unowned_baseline.request_role)
        with self.assertRaisesRegex(RequestExecutionError, "ProbePlan"):
            pair_probe_responses(
                plan,
                unowned_baseline,
                self._plan_snapshot(plan, "probe", text="probe"),
            )

    def test_pair_validation_rejects_wrong_roles(self) -> None:
        _input_point, _template, _context, plan = self._query_plan()
        baseline_marked_probe = self._snapshot(
            plan.baseline_request,
            text="base",
            probe_plan_id=plan.id,
            request_role="probe",
        )
        with self.assertRaisesRegex(RequestExecutionError, "role"):
            pair_probe_responses(
                plan,
                baseline_marked_probe,
                self._plan_snapshot(plan, "probe", text="probe"),
            )

        probe_marked_baseline = self._snapshot(
            plan.probe_request,
            text="probe",
            probe_plan_id=plan.id,
            request_role="baseline",
        )
        with self.assertRaisesRegex(RequestExecutionError, "role"):
            pair_probe_responses(
                plan,
                self._plan_snapshot(plan, "baseline", text="base"),
                probe_marked_baseline,
            )

    def test_same_request_different_plan_baseline_mixing_is_rejected(self) -> None:
        _input_point, first_plan, second_plan = self._overlapping_context_plans()
        self.assertNotEqual(first_plan.id, second_plan.id)
        self.assertNotEqual(
            first_plan.request_context_id,
            second_plan.request_context_id,
        )
        self.assertEqual(first_plan.baseline_request.id, second_plan.baseline_request.id)
        with self.assertRaisesRegex(RequestExecutionError, "baseline"):
            pair_probe_responses(
                first_plan,
                self._plan_snapshot(second_plan, "baseline", text="foreign"),
                self._plan_snapshot(first_plan, "probe", text="own"),
            )

    def test_same_request_different_plan_probe_mixing_is_rejected(self) -> None:
        _input_point, _template, _context, plan = self._query_plan()
        alias_plan = self._same_request_plan_alias(plan)
        self.assertNotEqual(plan.id, alias_plan.id)
        self.assertEqual(plan.baseline_request.id, alias_plan.baseline_request.id)
        self.assertEqual(plan.probe_request.id, alias_plan.probe_request.id)
        with self.assertRaisesRegex(RequestExecutionError, "probe"):
            pair_probe_responses(
                plan,
                self._plan_snapshot(plan, "baseline", text="base"),
                self._plan_snapshot(alias_plan, "probe", text="foreign"),
            )

    def test_same_request_bytes_remain_legal_across_distinct_plans(self) -> None:
        _input_point, _template, _context, plan = self._query_plan()
        alias_plan = self._same_request_plan_alias(plan)
        self.assertEqual(plan.baseline_request.id, alias_plan.baseline_request.id)
        self.assertEqual(plan.probe_request.id, alias_plan.probe_request.id)

        first_baseline = self._plan_snapshot(plan, "baseline", text="same")
        first_probe = self._plan_snapshot(plan, "probe", text="same")
        second_baseline = self._plan_snapshot(alias_plan, "baseline", text="same")
        second_probe = self._plan_snapshot(alias_plan, "probe", text="same")
        first_pair = pair_probe_responses(plan, first_baseline, first_probe)
        second_pair = pair_probe_responses(alias_plan, second_baseline, second_probe)

        self.assertNotEqual(first_baseline.id, second_baseline.id)
        self.assertNotEqual(first_probe.id, second_probe.id)
        self.assertNotEqual(first_pair.id, second_pair.id)

    def test_cross_plan_marker_reflection_corruption_is_rejected(self) -> None:
        input_point, first_plan, second_plan = self._overlapping_context_plans()
        correct_baseline = self._plan_snapshot(
            first_plan,
            "baseline",
            text=f"already {first_plan.probe_marker}",
        )
        correct_probe = self._plan_snapshot(
            first_plan,
            "probe",
            text=f"again {first_plan.probe_marker}",
        )
        _pair, vector = self._pair_and_extract(
            input_point,
            first_plan,
            correct_baseline,
            correct_probe,
        )
        self.assertEqual(vector.features[MARKER_REFLECTED].value, 0.0)

        self.assertEqual(first_plan.baseline_request.id, second_plan.baseline_request.id)
        mixed_baseline = self._plan_snapshot(second_plan, "baseline", text="")
        with self.assertRaisesRegex(RequestExecutionError, "baseline"):
            pair_probe_responses(first_plan, mixed_baseline, correct_probe)

    def test_status_and_length_features(self) -> None:
        input_point, _template, _context, plan = self._query_plan()
        baseline = self._plan_snapshot(
            plan,
            "baseline",
            status_code=200,
            text="abcd",
        )
        probe_equal = self._plan_snapshot(
            plan,
            "probe",
            status_code=200,
            text="wxyz",
        )
        _pair, vector = self._pair_and_extract(input_point, plan, baseline, probe_equal)
        self.assertEqual(vector.features[STATUS_CODE_CHANGED].value, 0.0)
        self.assertEqual(vector.features[RESPONSE_LENGTH_DIFF_RATIO].value, 0.0)

        probe_changed = self._plan_snapshot(
            plan,
            "probe",
            status_code=404,
            text="abcdef",
        )
        _pair, changed = self._pair_and_extract(
            input_point,
            plan,
            baseline,
            probe_changed,
        )
        self.assertEqual(changed.features[STATUS_CODE_CHANGED].value, 1.0)
        self.assertEqual(changed.features[RESPONSE_LENGTH_DIFF_RATIO].value, 0.5)

    def test_zero_length_baseline_ratio(self) -> None:
        input_point, _template, _context, plan = self._query_plan()
        baseline = self._plan_snapshot(plan, "baseline", text="")
        probe = self._plan_snapshot(plan, "probe", text="abc")
        _pair, vector = self._pair_and_extract(input_point, plan, baseline, probe)
        feature = vector.features[RESPONSE_LENGTH_DIFF_RATIO]
        self.assertEqual(feature.value, 1.0)
        self.assertEqual(feature.details["raw_ratio"], 3.0)

    def test_marker_reflection_absent_new_and_preexisting(self) -> None:
        input_point, _template, _context, plan = self._query_plan()
        baseline = self._plan_snapshot(plan, "baseline", text="baseline")
        absent = self._plan_snapshot(plan, "probe", text="probe")
        _pair, absent_vector = self._pair_and_extract(input_point, plan, baseline, absent)
        self.assertEqual(absent_vector.features[MARKER_REFLECTED].value, 0.0)

        reflected = self._plan_snapshot(
            plan,
            "probe",
            text=f"hello {plan.probe_marker}",
        )
        _pair, reflected_vector = self._pair_and_extract(
            input_point,
            plan,
            baseline,
            reflected,
        )
        self.assertEqual(reflected_vector.features[MARKER_REFLECTED].value, 1.0)

        preexisting_baseline = self._plan_snapshot(
            plan,
            "baseline",
            text=f"already {plan.probe_marker}",
        )
        _pair, preexisting_vector = self._pair_and_extract(
            input_point,
            plan,
            preexisting_baseline,
            reflected,
        )
        feature = preexisting_vector.features[MARKER_REFLECTED]
        self.assertEqual(feature.value, 0.0)
        self.assertTrue(feature.details["baseline_contains_marker"])

    def test_sql_error_absent_new_baseline_existing_and_generic_500(self) -> None:
        input_point, _template, _context, plan = self._query_plan()
        baseline = self._plan_snapshot(plan, "baseline", text="ok")
        absent = self._plan_snapshot(plan, "probe", text="still ok")
        _pair, absent_vector = self._pair_and_extract(input_point, plan, baseline, absent)
        self.assertEqual(absent_vector.features[SQL_ERROR_PATTERN].value, 0.0)

        sql_error = self._plan_snapshot(
            plan,
            "probe",
            text="You have an error in your SQL syntax near quote",
        )
        _pair, sql_vector = self._pair_and_extract(input_point, plan, baseline, sql_error)
        sql_feature = sql_vector.features[SQL_ERROR_PATTERN]
        self.assertEqual(sql_feature.value, 1.0)
        self.assertEqual(sql_feature.details["new_patterns"], ("sql_syntax",))

        existing_baseline = self._plan_snapshot(
            plan,
            "baseline",
            text="You have an error in your SQL syntax",
        )
        _pair, existing_vector = self._pair_and_extract(
            input_point,
            plan,
            existing_baseline,
            sql_error,
        )
        self.assertEqual(existing_vector.features[SQL_ERROR_PATTERN].value, 0.0)

        generic_500 = self._plan_snapshot(
            plan,
            "probe",
            status_code=500,
            text="oops",
        )
        _pair, generic_vector = self._pair_and_extract(
            input_point,
            plan,
            baseline,
            generic_500,
        )
        self.assertEqual(generic_vector.features[SQL_ERROR_PATTERN].value, 0.0)

    def test_execution_failure_features_are_missing_not_positive(self) -> None:
        input_point, _template, _context, plan = self._query_plan()
        baseline = self._plan_snapshot(
            plan,
            "baseline",
            text="",
            execution_error="timeout",
        )
        probe = self._plan_snapshot(
            plan,
            "probe",
            text=f"{plan.probe_marker} SQL syntax",
            status_code=500,
        )
        _pair, vector = self._pair_and_extract(input_point, plan, baseline, probe)
        for feature in vector.features.values():
            self.assertFalse(feature.observed)
            self.assertIsNone(feature.value)
            self.assertEqual(feature.details["reason"], "execution-error")

    def test_body_limit_execution_error_features_are_missing_not_positive(self) -> None:
        input_point, _template, _context, plan = self._query_plan()
        transport = FakeTransport(
            {
                plan.baseline_request.id or "": TransportResponse(200, b"abcdef"),
                plan.probe_request.id or "": TransportResponse(
                    200,
                    f"{plan.probe_marker} SQL syntax".encode("utf-8"),
                ),
            }
        )
        result = execute_probe_plan(plan, transport=transport, max_body_bytes=3)
        self.assertEqual(
            result.baseline_response.execution_error,
            "body-capture-limit-reached",
        )
        self.assertEqual(
            result.probe_response.execution_error,
            "body-capture-limit-reached",
        )

        vector = extract_minimal_features(
            input_point,
            plan,
            result.response_pair,
            result.baseline_response,
            result.probe_response,
        )
        for feature in vector.features.values():
            self.assertFalse(feature.observed)
            self.assertIsNone(feature.value)
            self.assertEqual(feature.details["reason"], "execution-error")

    def test_feature_extraction_rejects_mismatched_pair(self) -> None:
        input_point, _template, _context, plan = self._query_plan()
        baseline = self._plan_snapshot(plan, "baseline", text="base")
        probe = self._plan_snapshot(plan, "probe", text="probe")
        pair = ResponsePair(
            input_point_id=input_point.id or "",
            probe_plan_id="probe_other",
            baseline_response_id=baseline.id or "",
            probe_response_id=probe.id or "",
        )
        with self.assertRaisesRegex(FeatureExtractionError, "ProbePlan"):
            extract_minimal_features(input_point, plan, pair, baseline, probe)

    def test_feature_vector_owns_exact_input_point_and_occurrence(self) -> None:
        first_input, _template, _context, first_plan = self._query_plan(
            (("tag", "a"), ("tag", "a")),
            target="tag",
            occurrence_index=0,
            url="http://127.0.0.1/search?tag=a&tag=a",
        )
        second_input, _template, _context, second_plan = self._query_plan(
            (("tag", "a"), ("tag", "a")),
            target="tag",
            occurrence_index=1,
            url="http://127.0.0.1/search?tag=a&tag=a",
        )
        first_pair, first_vector = self._pair_and_extract(
            first_input,
            first_plan,
            self._plan_snapshot(first_plan, "baseline", text="base"),
            self._plan_snapshot(first_plan, "probe", text="probe"),
        )
        second_pair, second_vector = self._pair_and_extract(
            second_input,
            second_plan,
            self._plan_snapshot(second_plan, "baseline", text="base"),
            self._plan_snapshot(second_plan, "probe", text="probe"),
        )
        self.assertNotEqual(first_input.id, second_input.id)
        self.assertNotEqual(first_plan.id, second_plan.id)
        self.assertEqual(first_plan.baseline_request.id, second_plan.baseline_request.id)
        self.assertEqual(first_pair.probe_plan_id, first_plan.id)
        self.assertEqual(second_pair.probe_plan_id, second_plan.id)
        self.assertEqual(first_vector.input_point_id, first_input.id)
        self.assertEqual(second_vector.input_point_id, second_input.id)
        self.assertEqual(first_vector.probe_run_ids, (first_pair.id,))
        self.assertEqual(second_vector.probe_run_ids, (second_pair.id,))
        self.assertNotEqual(first_vector.id, second_vector.id)

    def test_different_request_contexts_remain_traceable(self) -> None:
        input_point, first_plan, second_plan = self._overlapping_context_plans()
        first_baseline = self._plan_snapshot(first_plan, "baseline", text="base")
        first_probe = self._plan_snapshot(first_plan, "probe", text="probe")
        second_baseline = self._plan_snapshot(second_plan, "baseline", text="base")
        second_probe = self._plan_snapshot(second_plan, "probe", text="probe")
        first_pair, first_vector = self._pair_and_extract(
            input_point,
            first_plan,
            first_baseline,
            first_probe,
        )
        second_pair, second_vector = self._pair_and_extract(
            input_point,
            second_plan,
            second_baseline,
            second_probe,
        )
        self.assertNotEqual(first_plan.request_context_id, second_plan.request_context_id)
        self.assertEqual(first_plan.baseline_request.id, second_plan.baseline_request.id)
        self.assertEqual(first_baseline.probe_plan_id, first_plan.id)
        self.assertEqual(second_baseline.probe_plan_id, second_plan.id)
        self.assertNotEqual(first_pair.id, second_pair.id)
        self.assertNotEqual(first_vector.id, second_vector.id)
        with self.assertRaisesRegex(RequestExecutionError, "baseline"):
            pair_probe_responses(first_plan, second_baseline, first_probe)

    def test_source_probe_plan_remains_immutable(self) -> None:
        _input_point, _template, _context, plan = self._query_plan()
        original = (
            plan.id,
            plan.baseline_request.id,
            plan.probe_request.id,
            plan.probe_marker,
            plan.changed_fields,
        )
        transport = FakeTransport(
            {
                plan.baseline_request.id or "": TransportResponse(200, b"base"),
                plan.probe_request.id or "": TransportResponse(200, b"probe"),
            }
        )
        execute_probe_plan(plan, transport=transport)
        self.assertEqual(
            (
                plan.id,
                plan.baseline_request.id,
                plan.probe_request.id,
                plan.probe_marker,
                plan.changed_fields,
            ),
            original,
        )

    def test_in_memory_end_to_end_observation_path(self) -> None:
        input_point, template, context, plan = self._query_plan(
            (("q", "book"), ("page", "1")),
            url="http://127.0.0.1/search?q=book&page=1",
        )
        transport = FakeTransport(
            {
                plan.baseline_request.id or "": TransportResponse(
                    200,
                    b"baseline body",
                ),
                plan.probe_request.id or "": TransportResponse(
                    200,
                    f"reflected {plan.probe_marker}".encode("utf-8"),
                ),
            }
        )
        result = execute_probe_plan(plan, transport=transport)
        feature_vector = extract_minimal_features(
            input_point,
            plan,
            result.response_pair,
            result.baseline_response,
            result.probe_response,
        )
        self.assertEqual(context.input_point_id, input_point.id)
        self.assertEqual(template.id, plan.request_template_id)
        self.assertEqual(result.response_pair.input_point_id, input_point.id)
        self.assertEqual(feature_vector.input_point_id, input_point.id)
        self.assertEqual(feature_vector.features[MARKER_REFLECTED].value, 1.0)


if __name__ == "__main__":
    unittest.main()
