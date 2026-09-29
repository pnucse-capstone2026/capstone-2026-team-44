from __future__ import annotations

import json
import unittest
from urllib.parse import quote

import vulnspider.observation.planner as planner_module
from vulnspider.discovery import LegacyCrawlerAdapter
from vulnspider.domain import (
    Endpoint,
    HttpMethod,
    InputLocation,
    InputPoint,
    InputPointRequestContext,
    ParamPairs,
    ProbeFamily,
    RequestContextCompleteness,
    RequestTemplate,
)
from vulnspider.observation import (
    MARKER_PREFIX,
    ProbePlanner,
    ProbePlanningError,
)


class ProbePlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.planner = ProbePlanner()

    def _query_case(
        self,
        pairs: ParamPairs,
        *,
        target: str,
        occurrence_index: int | None = None,
        baseline_value: str | None = None,
        url: str | None = None,
    ) -> tuple[InputPoint, RequestTemplate, InputPointRequestContext]:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        if baseline_value is None:
            baseline_value = self._baseline_value(pairs, target, occurrence_index)
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
            url=url or "http://127.0.0.1/search",
            query=pairs,
            headers={"X-Test": "one"},
            cookies={"session": "abc"},
            completeness=RequestContextCompleteness.COMPLETE,
            context_key=f"query:{url or pairs}",
        )
        context = InputPointRequestContext.from_objects(input_point, template)
        return input_point, template, context

    def _form_case(
        self,
        pairs: ParamPairs,
        *,
        target: str,
        occurrence_index: int | None = None,
        baseline_value: str | None = None,
        completeness: RequestContextCompleteness = RequestContextCompleteness.COMPLETE,
        metadata: dict[str, object] | None = None,
    ) -> tuple[InputPoint, RequestTemplate, InputPointRequestContext]:
        endpoint = Endpoint(HttpMethod.POST, "http", "127.0.0.1", "/login")
        if baseline_value is None:
            baseline_value = self._baseline_value(pairs, target, occurrence_index)
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.FORM,
            name=target,
            occurrence_index=occurrence_index,
            baseline_value=baseline_value,
        )
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.POST,
            url="http://127.0.0.1/login",
            form=pairs,
            completeness=completeness,
            context_key=f"form:{pairs}",
            metadata=metadata or {},
        )
        context = InputPointRequestContext.from_objects(input_point, template)
        return input_point, template, context

    def _baseline_value(
        self,
        pairs: ParamPairs,
        target: str,
        occurrence_index: int | None,
    ) -> str:
        matches = [value for name, value in pairs if name == target]
        if occurrence_index is None:
            return matches[0]
        return matches[occurrence_index]

    def _unsafe_context(
        self,
        input_point: InputPoint,
        request_template: RequestTemplate,
    ) -> InputPointRequestContext:
        context = object.__new__(InputPointRequestContext)
        object.__setattr__(context, "input_point_id", input_point.id or "")
        object.__setattr__(
            context,
            "request_template_id",
            request_template.id or "",
        )
        object.__setattr__(context, "role", "baseline")
        object.__setattr__(context, "id", "ipctx_unsafe")
        return context

    def test_baseline_query_preserves_selected_context(self) -> None:
        input_point, template, context = self._query_case(
            (("q", "book"), ("page", "2")),
            target="q",
            url="http://127.0.0.1/search?q=book&page=2",
        )
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(plan.baseline_request.method, HttpMethod.GET)
        self.assertEqual(
            plan.baseline_request.url,
            "http://127.0.0.1/search?q=book&page=2",
        )
        self.assertEqual(plan.baseline_request.query, (("q", "book"), ("page", "2")))
        self.assertEqual(plan.baseline_request.form, ())
        self.assertEqual(plan.baseline_request.headers, {"X-Test": "one"})
        self.assertEqual(plan.baseline_request.cookies, {"session": "abc"})

    def test_one_at_a_time_query_mutation(self) -> None:
        input_point, template, context = self._query_case(
            (("q", "book"), ("page", "2")),
            target="q",
            url="http://127.0.0.1/search?q=book&page=2",
        )
        plan = self.planner.plan(input_point, template, context)
        marker = plan.probe_marker or ""
        self.assertEqual(plan.changed_fields, ("query.q",))
        self.assertEqual(plan.probe_request.query, (("q", marker), ("page", "2")))
        self.assertEqual(
            plan.probe_request.url,
            f"http://127.0.0.1/search?q={quote(marker, safe='')}&page=2",
        )

    def test_non_target_query_preservation(self) -> None:
        input_point, template, context = self._query_case(
            (("q", "book"), ("page", "2"), ("sort", "asc")),
            target="q",
        )
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(
            plan.probe_request.query,
            (("q", plan.probe_marker or ""), ("page", "2"), ("sort", "asc")),
        )

    def test_probe_url_preserves_raw_percent_space_and_bare_flag(self) -> None:
        input_point, template, context = self._query_case(
            (("q", "book"), ("page", "a b"), ("flag", "")),
            target="q",
            url="http://127.0.0.1/search?q=book&page=a%20b&flag",
        )
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(
            plan.probe_request.url,
            f"http://127.0.0.1/search?q={quote(plan.probe_marker, safe='')}&page=a%20b&flag",
        )

    def test_probe_url_rejects_raw_query_order_alignment_failure(self) -> None:
        input_point, template, context = self._query_case(
            (("q", "book"), ("flag", ""), ("page", "a b")),
            target="q",
            url="http://127.0.0.1/search?q=book&page=a%20b&flag",
        )
        with self.assertRaisesRegex(
            ProbePlanningError,
            planner_module.RAW_QUERY_ALIGNMENT_FAILED,
        ):
            self.planner.plan(input_point, template, context)

    def test_probe_url_rejects_raw_query_missing_structured_token(self) -> None:
        input_point, template, context = self._query_case(
            (("q", "book"), ("page", "a b")),
            target="q",
            url="http://127.0.0.1/search?q=book&page=a%20b&flag",
        )
        with self.assertRaisesRegex(
            ProbePlanningError,
            planner_module.RAW_QUERY_ALIGNMENT_FAILED,
        ):
            self.planner.plan(input_point, template, context)

    def test_probe_url_rejects_raw_query_extra_structured_token(self) -> None:
        input_point, template, context = self._query_case(
            (("q", "book"), ("page", "a b"), ("flag", "")),
            target="q",
            url="http://127.0.0.1/search?q=book&page=a%20b",
        )
        with self.assertRaisesRegex(
            ProbePlanningError,
            planner_module.RAW_QUERY_ALIGNMENT_FAILED,
        ):
            self.planner.plan(input_point, template, context)

    def test_probe_url_preserves_raw_plus_and_empty_flag(self) -> None:
        input_point, template, context = self._query_case(
            (("q", "book"), ("page", "a b"), ("flag", "")),
            target="q",
            url="http://127.0.0.1/search?q=book&page=a+b&flag=",
        )
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(
            plan.probe_request.url,
            f"http://127.0.0.1/search?q={quote(plan.probe_marker, safe='')}&page=a+b&flag=",
        )

    def test_probe_url_preserves_cross_name_order_for_second_repeated_target(
        self,
    ) -> None:
        first_input, first_template, first_context = self._query_case(
            (("tag", "a"), ("q", "x"), ("tag", "b")),
            target="tag",
            occurrence_index=0,
            url="http://127.0.0.1/search?tag=a&q=x&tag=b",
        )
        input_point, template, context = self._query_case(
            (("tag", "a"), ("q", "x"), ("tag", "b")),
            target="tag",
            occurrence_index=1,
            url="http://127.0.0.1/search?tag=a&q=x&tag=b",
        )
        first_plan = self.planner.plan(first_input, first_template, first_context)
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(
            first_plan.probe_request.url,
            f"http://127.0.0.1/search?tag={quote(first_plan.probe_marker, safe='')}&q=x&tag=b",
        )
        self.assertEqual(
            plan.probe_request.url,
            f"http://127.0.0.1/search?tag=a&q=x&tag={quote(plan.probe_marker, safe='')}",
        )

    def test_probe_url_mutates_equal_repeated_occurrences_separately(self) -> None:
        first_input, first_template, first_context = self._query_case(
            (("tag", "a"), ("tag", "a")),
            target="tag",
            occurrence_index=0,
            url="http://127.0.0.1/search?tag=a&tag=a",
        )
        second_input, second_template, second_context = self._query_case(
            (("tag", "a"), ("tag", "a")),
            target="tag",
            occurrence_index=1,
            url="http://127.0.0.1/search?tag=a&tag=a",
        )
        first = self.planner.plan(first_input, first_template, first_context)
        second = self.planner.plan(second_input, second_template, second_context)
        self.assertEqual(
            first.probe_request.url,
            f"http://127.0.0.1/search?tag={quote(first.probe_marker, safe='')}&tag=a",
        )
        self.assertEqual(
            second.probe_request.url,
            f"http://127.0.0.1/search?tag=a&tag={quote(second.probe_marker, safe='')}",
        )
        self.assertNotEqual(first.id, second.id)

    def test_probe_url_preserves_empty_value_and_bare_token_distinction(self) -> None:
        input_point, template, context = self._query_case(
            (("q", ""), ("flag", "")),
            target="q",
            url="http://127.0.0.1/search?q=&flag",
        )
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(
            plan.probe_request.url,
            f"http://127.0.0.1/search?q={quote(plan.probe_marker, safe='')}&flag",
        )

        flag_input, flag_template, flag_context = self._query_case(
            (("q", ""), ("flag", "")),
            target="flag",
            url="http://127.0.0.1/search?q=&flag",
        )
        flag_plan = self.planner.plan(flag_input, flag_template, flag_context)
        self.assertEqual(
            flag_plan.probe_request.url,
            f"http://127.0.0.1/search?q=&flag={quote(flag_plan.probe_marker, safe='')}",
        )

    def test_probe_url_preserves_percent_encoded_non_target_value(self) -> None:
        input_point, template, context = self._query_case(
            (("q", "book"), ("path", "/admin/index")),
            target="q",
            url="http://127.0.0.1/search?q=book&path=%2fadmin%2findex",
        )
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(
            plan.probe_request.url,
            f"http://127.0.0.1/search?q={quote(plan.probe_marker, safe='')}&path=%2fadmin%2findex",
        )

    def test_probe_url_reconstructs_structured_only_query_context(self) -> None:
        input_point, template, context = self._query_case(
            (("q", "book"), ("page", "a b"), ("flag", "")),
            target="q",
            url="http://127.0.0.1/search",
        )
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(
            plan.probe_request.url,
            f"http://127.0.0.1/search?q={quote(plan.probe_marker, safe='')}&page=a+b&flag=",
        )

    def test_baseline_form_preservation(self) -> None:
        input_point, template, context = self._form_case(
            (("username", "alice"), ("password", "secret")),
            target="username",
        )
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(plan.baseline_request.method, HttpMethod.POST)
        self.assertEqual(plan.baseline_request.url, "http://127.0.0.1/login")
        self.assertEqual(
            plan.baseline_request.form,
            (("username", "alice"), ("password", "secret")),
        )
        self.assertEqual(plan.baseline_request.query, ())

    def test_one_at_a_time_form_mutation(self) -> None:
        input_point, template, context = self._form_case(
            (("username", "alice"), ("password", "secret")),
            target="username",
        )
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(plan.changed_fields, ("form.username",))
        self.assertEqual(
            plan.probe_request.form,
            (("username", plan.probe_marker or ""), ("password", "secret")),
        )
        self.assertEqual(plan.probe_request.url, "http://127.0.0.1/login")

    def test_non_target_form_preservation(self) -> None:
        input_point, template, context = self._form_case(
            (("username", "alice"), ("password", "secret"), ("remember", "yes")),
            target="password",
        )
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(
            plan.probe_request.form,
            (
                ("username", "alice"),
                ("password", plan.probe_marker or ""),
                ("remember", "yes"),
            ),
        )

    def test_repeated_occurrence_zero_mutation(self) -> None:
        input_point, template, context = self._query_case(
            (("tag", "a"), ("tag", "b"), ("q", "x")),
            target="tag",
            occurrence_index=0,
        )
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(plan.changed_fields, ("query.tag[0]",))
        self.assertEqual(
            plan.probe_request.query,
            (("tag", plan.probe_marker or ""), ("tag", "b"), ("q", "x")),
        )

    def test_repeated_occurrence_one_mutation(self) -> None:
        input_point, template, context = self._query_case(
            (("tag", "a"), ("tag", "b"), ("q", "x")),
            target="tag",
            occurrence_index=1,
        )
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(plan.changed_fields, ("query.tag[1]",))
        self.assertEqual(
            plan.probe_request.query,
            (("tag", "a"), ("tag", plan.probe_marker or ""), ("q", "x")),
        )

    def test_equal_repeated_values_remain_distinct_targets(self) -> None:
        first_input, first_template, first_context = self._query_case(
            (("tag", "a"), ("tag", "a")),
            target="tag",
            occurrence_index=0,
        )
        second_input, second_template, second_context = self._query_case(
            (("tag", "a"), ("tag", "a")),
            target="tag",
            occurrence_index=1,
        )
        first_plan = self.planner.plan(first_input, first_template, first_context)
        second_plan = self.planner.plan(second_input, second_template, second_context)
        self.assertEqual(
            first_plan.probe_request.query,
            (("tag", first_plan.probe_marker or ""), ("tag", "a")),
        )
        self.assertEqual(
            second_plan.probe_request.query,
            (("tag", "a"), ("tag", second_plan.probe_marker or "")),
        )
        self.assertNotEqual(first_plan.id, second_plan.id)

    def test_cross_name_query_ordering_preserved(self) -> None:
        input_point, template, context = self._query_case(
            (("tag", "a"), ("q", "x"), ("tag", "b")),
            target="q",
        )
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(
            plan.probe_request.query,
            (("tag", "a"), ("q", plan.probe_marker or ""), ("tag", "b")),
        )

    def test_empty_values_preserved(self) -> None:
        input_point, template, context = self._query_case(
            (("q", ""), ("tag", "a")),
            target="tag",
        )
        plan = self.planner.plan(input_point, template, context)
        self.assertEqual(
            plan.probe_request.query,
            (("q", ""), ("tag", plan.probe_marker or "")),
        )

    def test_multiple_baseline_contexts_remain_distinct(self) -> None:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
            baseline_value=None,
        )
        first = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?q=book",
            query=(("q", "book"),),
            completeness=RequestContextCompleteness.COMPLETE,
            context_key="q=book",
        )
        second = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?q=chair",
            query=(("q", "chair"),),
            completeness=RequestContextCompleteness.COMPLETE,
            context_key="q=chair",
        )
        first_context = InputPointRequestContext.from_objects(input_point, first)
        second_context = InputPointRequestContext.from_objects(input_point, second)
        first_plan = self.planner.plan(input_point, first, first_context)
        second_plan = self.planner.plan(input_point, second, second_context)
        self.assertEqual(first_plan.baseline_request.query, (("q", "book"),))
        self.assertEqual(second_plan.baseline_request.query, (("q", "chair"),))
        self.assertNotEqual(first_plan.id, second_plan.id)

    def test_no_arbitrary_context_selection(self) -> None:
        input_point, template, _context = self._query_case((("q", "book"),), target="q")
        with self.assertRaisesRegex(ProbePlanningError, "request_context"):
            self.planner.plan(input_point, template, None)  # type: ignore[arg-type]

    def test_partial_context_rejection(self) -> None:
        input_point, template, context = self._form_case(
            (("username", "alice"),),
            target="username",
            completeness=RequestContextCompleteness.PARTIAL,
            metadata={"non_probe_ready_reasons": ("legacy-hidden-inputs-may-be-omitted",)},
        )
        with self.assertRaisesRegex(ProbePlanningError, "not probe-ready"):
            self.planner.plan(input_point, template, context)

    def test_ambiguous_context_rejection(self) -> None:
        input_point, template, context = self._form_case(
            (("username", "alice"),),
            target="username",
            metadata={
                "reconstruction_status": "ambiguous",
                "form_boundary_status": "unavailable",
            },
        )
        with self.assertRaisesRegex(ProbePlanningError, "ambiguous"):
            self.planner.plan(input_point, template, context)

    def test_missing_target_rejection(self) -> None:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
        )
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?page=1",
            query=(("page", "1"),),
            completeness=RequestContextCompleteness.COMPLETE,
        )
        context = self._unsafe_context(input_point, template)
        with self.assertRaisesRegex(ProbePlanningError, "missing"):
            self.planner.plan(input_point, template, context)

    def test_wrong_association_rejection(self) -> None:
        input_point, first_template, first_context = self._query_case(
            (("q", "book"),),
            target="q",
            url="http://127.0.0.1/search?q=book",
        )
        _other_input, second_template, _second_context = self._query_case(
            (("q", "chair"),),
            target="q",
            url="http://127.0.0.1/search?q=chair",
        )
        self.assertNotEqual(first_template.id, second_template.id)
        with self.assertRaisesRegex(ProbePlanningError, "RequestTemplate"):
            self.planner.plan(input_point, second_template, first_context)

    def test_deterministic_plan_identity(self) -> None:
        input_point, template, context = self._query_case((("q", "book"),), target="q")
        first = self.planner.plan(input_point, template, context)
        second = self.planner.plan(input_point, template, context)
        self.assertEqual(first.id, second.id)
        self.assertEqual(first.probe_marker, second.probe_marker)
        self.assertEqual(first.baseline_request.id, second.baseline_request.id)
        self.assertEqual(first.probe_request.id, second.probe_request.id)

    def test_different_occurrence_non_collision(self) -> None:
        first_input, first_template, first_context = self._query_case(
            (("tag", "a"), ("tag", "b")),
            target="tag",
            occurrence_index=0,
        )
        second_input, second_template, second_context = self._query_case(
            (("tag", "a"), ("tag", "b")),
            target="tag",
            occurrence_index=1,
        )
        first = self.planner.plan(first_input, first_template, first_context)
        second = self.planner.plan(second_input, second_template, second_context)
        self.assertNotEqual(first.id, second.id)
        self.assertNotEqual(first.probe_request.query, second.probe_request.query)

    def test_different_context_non_collision(self) -> None:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
        )
        first_template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?q=book",
            query=(("q", "book"),),
            completeness=RequestContextCompleteness.COMPLETE,
        )
        second_template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?q=chair",
            query=(("q", "chair"),),
            completeness=RequestContextCompleteness.COMPLETE,
        )
        first = self.planner.plan(
            input_point,
            first_template,
            InputPointRequestContext.from_objects(input_point, first_template),
        )
        second = self.planner.plan(
            input_point,
            second_template,
            InputPointRequestContext.from_objects(input_point, second_template),
        )
        self.assertNotEqual(first.id, second.id)
        self.assertNotEqual(first.request_context_id, second.request_context_id)

    def test_source_request_template_not_mutated(self) -> None:
        input_point, template, context = self._query_case(
            (("q", "book"), ("page", "2")),
            target="q",
        )
        original_query = template.query
        original_headers = dict(template.headers)
        plan = self.planner.plan(input_point, template, context)
        plan.baseline_request.headers["X-Test"] = "changed"
        self.assertEqual(template.query, original_query)
        self.assertEqual(template.headers, original_headers)
        self.assertEqual(plan.probe_request.query[1], ("page", "2"))

    def test_source_input_point_not_mutated(self) -> None:
        input_point, template, context = self._query_case((("q", "book"),), target="q")
        original = (
            input_point.id,
            input_point.fingerprint,
            input_point.baseline_value,
            dict(input_point.metadata),
        )
        self.planner.plan(input_point, template, context)
        self.assertEqual(
            (
                input_point.id,
                input_point.fingerprint,
                input_point.baseline_value,
                dict(input_point.metadata),
            ),
            original,
        )

    def test_adapter_produced_validated_query_context_integrates(self) -> None:
        result = LegacyCrawlerAdapter().convert(
            [
                {
                    "link": "http://127.0.0.1/search?q=book&page=2",
                    "query_params": json.dumps({"q": "book", "page": "2"}),
                    "input_fields": "[]",
                }
            ]
        )
        input_points = {point.id: point for point in result.input_points}
        templates = {template.id: template for template in result.request_templates}
        q_point = next(point for point in result.input_points if point.name == "q")
        context = next(
            binding
            for binding in result.input_point_request_contexts
            if binding.input_point_id == q_point.id
        )
        plan = self.planner.plan(
            input_points[context.input_point_id],
            templates[context.request_template_id],
            context,
        )
        self.assertEqual(plan.baseline_request.query, (("q", "book"), ("page", "2")))
        self.assertEqual(
            plan.probe_request.query,
            (("q", plan.probe_marker or ""), ("page", "2")),
        )

    def test_marker_is_deterministic_bounded_and_carries_sentinel(self) -> None:
        input_point, template, context = self._query_case((("q", "book"),), target="q")
        plan = self.planner.plan(input_point, template, context)
        marker = plan.probe_marker or ""
        identifier = planner_module.marker_identifier(marker)
        # The identifier stays bounded and alphanumeric; the default strategy
        # appends the reflection sentinel after it (ADR-031).
        self.assertTrue(identifier.startswith(MARKER_PREFIX))
        self.assertTrue(identifier[len(MARKER_PREFIX):].isalnum())
        self.assertLessEqual(len(identifier), 32)
        self.assertTrue(marker.endswith(planner_module.PROBE_SENTINEL))
        self.assertNotEqual(marker, "book")
        self.assertEqual(marker, self.planner.plan(input_point, template, context).probe_marker)

    def test_marker_collision_uses_deterministic_non_noop_fallback(self) -> None:
        collision_marker = "VULNSPIDER_AAAAAAAAAAAAAAAA"
        input_point, template, context = self._query_case(
            (("q", collision_marker),),
            target="q",
            url=f"http://127.0.0.1/search?q={collision_marker}",
        )
        original_stable_fingerprint = planner_module.stable_fingerprint

        def fake_fingerprint_with(token: str) -> object:
            def fake_stable_fingerprint(*parts: object) -> str:
                if parts[-1] == 0:
                    return "a" * 64
                if parts[-1] == 1:
                    return token * 64
                return original_stable_fingerprint(*parts)

            return fake_stable_fingerprint

        try:
            planner_module.stable_fingerprint = fake_fingerprint_with("b")  # type: ignore[method-assign]
            first = self.planner.plan(input_point, template, context)
            equivalent = self.planner.plan(input_point, template, context)
            planner_module.stable_fingerprint = fake_fingerprint_with("c")  # type: ignore[method-assign]
            different_marker = self.planner.plan(input_point, template, context)
        finally:
            planner_module.stable_fingerprint = original_stable_fingerprint  # type: ignore[method-assign]

        expected_marker = "VULNSPIDER_BBBBBBBBBBBBBBBB" + planner_module.PROBE_SENTINEL
        self.assertEqual(first.probe_marker, expected_marker)
        self.assertNotEqual(first.probe_marker, collision_marker)
        self.assertEqual(first.probe_marker, equivalent.probe_marker)
        self.assertEqual(first.id, equivalent.id)
        self.assertEqual(
            first.probe_request.query,
            (("q", expected_marker),),
        )
        self.assertIn("VULNSPIDER_BBBBBBBBBBBBBBBB", first.probe_request.url)
        self.assertNotEqual(first.probe_marker, different_marker.probe_marker)
        self.assertNotEqual(first.id, different_marker.id)

    def test_different_marker_strategy_changes_plan_identity(self) -> None:
        input_point, template, context = self._query_case((("q", "book"),), target="q")
        default_plan = self.planner.plan(input_point, template, context)
        other_plan = ProbePlanner(
            probe_family=ProbeFamily.REFLECTION_MARKER,
            marker_strategy="neutral-reflection-marker-v2",
        ).plan(input_point, template, context)
        self.assertNotEqual(default_plan.probe_marker, other_plan.probe_marker)
        self.assertNotEqual(default_plan.id, other_plan.id)

    def test_request_mapping_insertion_order_does_not_affect_plan_identity(self) -> None:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
            baseline_value="book",
        )
        first_template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search",
            query={"q": "book", "page": "2"},
            headers={"A": "1", "B": "2"},
            cookies={"sid": "abc", "theme": "light"},
            completeness=RequestContextCompleteness.COMPLETE,
            context_key="mapping",
        )
        second_template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search",
            query={"page": "2", "q": "book"},
            headers={"B": "2", "A": "1"},
            cookies={"theme": "light", "sid": "abc"},
            completeness=RequestContextCompleteness.COMPLETE,
            context_key="mapping",
        )
        first = self.planner.plan(
            input_point,
            first_template,
            InputPointRequestContext.from_objects(input_point, first_template),
        )
        second = self.planner.plan(
            input_point,
            second_template,
            InputPointRequestContext.from_objects(input_point, second_template),
        )
        self.assertEqual(first.id, second.id)


if __name__ == "__main__":
    unittest.main()
