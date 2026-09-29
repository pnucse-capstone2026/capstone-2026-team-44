from __future__ import annotations

from types import SimpleNamespace
from typing import Any
import unittest

from vulnspider.domain import (
    Endpoint,
    EphemeralRequestMaterial,
    FeatureObservation,
    FeatureVector,
    HttpMethod,
    InputLocation,
    InputPoint,
    InputPointRequestContext,
    ProbeFamily,
    ProbePlan,
    RequestContextCompleteness,
    RequestInstance,
    RequestTemplate,
    VulnerabilityCandidate,
    VulnerabilityType,
    validate_input_point_request_context,
)


class DomainModelTests(unittest.TestCase):
    def _valid_query_binding(self) -> tuple[InputPoint, RequestTemplate]:
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
            url="http://127.0.0.1/search?q=book",
            query=(("q", "book"),),
            completeness=RequestContextCompleteness.COMPLETE,
        )
        return input_point, template

    def _fake_input_point_like(self, input_point: InputPoint) -> Any:
        return SimpleNamespace(
            id="inp_fake",
            endpoint_id=input_point.endpoint_id,
            endpoint_fingerprint=input_point.endpoint_fingerprint,
            location=input_point.location,
            name=input_point.name,
            occurrence_index=input_point.occurrence_index,
            baseline_value=input_point.baseline_value,
        )

    def _fake_request_template_like(self, template: RequestTemplate) -> Any:
        return SimpleNamespace(
            id="rt_fake",
            endpoint_id=template.endpoint_id,
            endpoint_fingerprint=template.endpoint_fingerprint,
            method=template.method,
            url=template.url,
            headers=template.headers,
            query=template.query,
            form=template.form,
            cookies=template.cookies,
            completeness=template.completeness,
            context_key=template.context_key,
            provenance=template.provenance,
        )

    def test_endpoint_identity_ignores_query_values(self) -> None:
        first = Endpoint(
            method=HttpMethod.GET,
            scheme="HTTP",
            host="Example.test",
            path="/search?q=book",
        )
        second = Endpoint(
            method=HttpMethod.GET,
            scheme="http",
            host="example.test",
            path="/search?q=chair&page=2",
        )
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.path, "/search")

    def test_two_parameters_on_same_endpoint_are_distinct_inputs(self) -> None:
        endpoint = Endpoint(
            method=HttpMethod.GET,
            scheme="http",
            host="127.0.0.1",
            path="/search",
        )
        q_input = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
            baseline_value="book",
        )
        page_input = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="page",
            baseline_value="1",
        )
        self.assertNotEqual(q_input.fingerprint, page_input.fingerprint)

    def test_same_normalized_input_point_produces_same_fingerprint(self) -> None:
        first = InputPoint(
            endpoint_id="ep",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.QUERY,
            name=" Q ",
            baseline_value="book",
        )
        second = InputPoint(
            endpoint_id="ep",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.QUERY,
            name="q",
            baseline_value="other",
        )
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_occurrence_index_participates_in_input_point_identity(self) -> None:
        first = InputPoint(
            endpoint_id="ep",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.QUERY,
            name="tag",
            occurrence_index=0,
            baseline_value="a",
        )
        second = InputPoint(
            endpoint_id="ep",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.QUERY,
            name="tag",
            occurrence_index=1,
            baseline_value="a",
        )
        ordinary = InputPoint(
            endpoint_id="ep",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.QUERY,
            name="tag",
            baseline_value="a",
        )
        self.assertNotEqual(first.fingerprint, second.fingerprint)
        self.assertNotEqual(first.fingerprint, ordinary.fingerprint)

    def test_query_and_form_parameters_with_same_name_are_distinct(self) -> None:
        query = InputPoint(
            endpoint_id="ep",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.QUERY,
            name="id",
        )
        form = InputPoint(
            endpoint_id="ep",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.FORM,
            name="id",
        )
        self.assertNotEqual(query.fingerprint, form.fingerprint)

    def test_same_parameter_name_on_different_endpoints_is_distinct(self) -> None:
        first = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        second = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/items")
        first_input = InputPoint(
            endpoint_id=first.id or "",
            endpoint_fingerprint=first.fingerprint,
            location=InputLocation.QUERY,
            name="q",
        )
        second_input = InputPoint(
            endpoint_id=second.id or "",
            endpoint_fingerprint=second.fingerprint,
            location=InputLocation.QUERY,
            name="q",
        )
        self.assertNotEqual(first_input.fingerprint, second_input.fingerprint)

    def test_same_parameter_name_under_different_methods_is_distinct(self) -> None:
        get_endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        post_endpoint = Endpoint(HttpMethod.POST, "http", "127.0.0.1", "/search")
        get_input = InputPoint(
            endpoint_id=get_endpoint.id or "",
            endpoint_fingerprint=get_endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
        )
        post_input = InputPoint(
            endpoint_id=post_endpoint.id or "",
            endpoint_fingerprint=post_endpoint.fingerprint,
            location=InputLocation.FORM,
            name="q",
        )
        self.assertNotEqual(get_input.fingerprint, post_input.fingerprint)

    def test_missing_feature_is_distinct_from_observed_zero(self) -> None:
        missing = FeatureObservation.missing(
            "marker_reflected",
            source="not_run",
            extractor_version="reflection-v1",
        )
        observed_zero = FeatureObservation(
            name="marker_reflected",
            value=0.0,
            observed=True,
            source="reflection_marker_probe",
            extractor_version="reflection-v1",
        )
        self.assertFalse(missing.observed)
        self.assertIsNone(missing.value)
        self.assertTrue(observed_zero.observed)
        self.assertEqual(observed_zero.value, 0.0)

    def test_candidate_identity_differs_by_vulnerability_type(self) -> None:
        sqli = VulnerabilityCandidate(
            input_point_id="inp",
            vulnerability_type=VulnerabilityType.SQLI,
        )
        xss = VulnerabilityCandidate(
            input_point_id="inp",
            vulnerability_type=VulnerabilityType.REFLECTED_XSS,
        )
        self.assertNotEqual(sqli.id, xss.id)

    def test_probe_plan_rejects_multi_field_mutation(self) -> None:
        baseline = RequestInstance(method=HttpMethod.GET, url="http://example.test/search")
        probe = RequestInstance(method=HttpMethod.GET, url="http://example.test/search")
        with self.assertRaises(ValueError):
            ProbePlan(
                input_point_id="inp",
                probe_family=ProbeFamily.REFLECTION_MARKER,
                baseline_request=baseline,
                probe_request=probe,
                changed_fields=("query.q", "query.page"),
            )

    def test_request_template_identity_is_deterministic_and_context_sensitive(self) -> None:
        endpoint = Endpoint(HttpMethod.POST, "http", "127.0.0.1", "/update")
        first = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.POST,
            url="http://127.0.0.1/update",
            form=(("email", "a@example.test"),),
            completeness=RequestContextCompleteness.PARTIAL,
            context_key="legacy-form:http://127.0.0.1/profile:POST:/update",
        )
        equivalent = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.POST,
            url="http://127.0.0.1/update",
            form=(("email", "a@example.test"),),
            completeness=RequestContextCompleteness.PARTIAL,
            context_key="legacy-form:http://127.0.0.1/profile:POST:/update",
        )
        different_context = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.POST,
            url="http://127.0.0.1/update",
            form=(("password", "secret"),),
            completeness=RequestContextCompleteness.PARTIAL,
            context_key="legacy-form:http://127.0.0.1/security:POST:/update",
        )
        self.assertEqual(first.id, equivalent.id)
        self.assertNotEqual(first.id, different_context.id)

    def test_ephemeral_request_material_does_not_change_template_identity_or_repr(
        self,
    ) -> None:
        endpoint = Endpoint(HttpMethod.POST, "http", "127.0.0.1", "/api/search")
        common = {
            "endpoint_id": endpoint.id or "",
            "endpoint_fingerprint": endpoint.fingerprint,
            "method": HttpMethod.POST,
            "url": "http://127.0.0.1/api/search?category=",
            "query": (("category", ""),),
            "json_body": (("keyword", "null"),),
            "completeness": RequestContextCompleteness.COMPLETE,
            "context_key": "network-post-structure",
        }
        first = RequestTemplate(
            **common,
            ephemeral_material=EphemeralRequestMaterial(
                url="http://127.0.0.1/api/search?category=book",
                query=(("category", "book"),),
                json_body=(("keyword", '"phone"'),),
            ),
        )
        second = RequestTemplate(
            **common,
            ephemeral_material=EphemeralRequestMaterial(
                url="http://127.0.0.1/api/search?category=other",
                query=(("category", "other"),),
                json_body=(("keyword", '"different"'),),
            ),
        )

        self.assertEqual(first, second)
        self.assertEqual(first.id, second.id)
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertNotIn("phone", repr(first))
        self.assertNotIn("different", repr(second))
        self.assertNotEqual(first.execution_json_body, second.execution_json_body)

    def test_ephemeral_request_material_must_match_structural_owner(self) -> None:
        endpoint = Endpoint(HttpMethod.POST, "http", "127.0.0.1", "/api/search")
        common = {
            "endpoint_id": endpoint.id or "",
            "endpoint_fingerprint": endpoint.fingerprint,
            "method": HttpMethod.POST,
            "url": "http://127.0.0.1:8080/api/search?category=",
            "query": (("category", ""),),
            "json_body": (("keyword", "null"),),
            "completeness": RequestContextCompleteness.COMPLETE,
            "context_key": "network-post-structure",
        }
        invalid_materials = (
            EphemeralRequestMaterial(
                url="http://example.com/api/search?category=book",
                query=(("category", "book"),),
                json_body=(("keyword", '"phone"'),),
            ),
            EphemeralRequestMaterial(
                url="http://127.0.0.1:8080/other?category=book",
                query=(("category", "book"),),
                json_body=(("keyword", '"phone"'),),
            ),
            EphemeralRequestMaterial(
                url="http://127.0.0.1:8080/api/search?other=book",
                query=(("other", "book"),),
                json_body=(("keyword", '"phone"'),),
            ),
            EphemeralRequestMaterial(
                url="http://127.0.0.1:8080/api/search?category=book",
                query=(("category", "different"),),
                json_body=(("keyword", '"phone"'),),
            ),
            EphemeralRequestMaterial(
                url="http://127.0.0.1:8080/api/search?category=book",
                query=(("category", "book"),),
                json_body=(("other", '"phone"'),),
            ),
        )

        for material in invalid_materials:
            with self.subTest(material=material), self.assertRaises(ValueError):
                RequestTemplate(**common, ephemeral_material=material)

    def test_request_template_mapping_input_order_is_canonical(self) -> None:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        first = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search",
            query={"q": "book", "page": "1"},
            completeness=RequestContextCompleteness.COMPLETE,
            context_key="query",
        )
        second = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search",
            query={"page": "1", "q": "book"},
            completeness=RequestContextCompleteness.COMPLETE,
            context_key="query",
        )
        self.assertEqual(first.query, second.query)
        self.assertEqual(first.id, second.id)

    def test_request_template_identity_includes_provenance(self) -> None:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        explicit = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search",
            form=(("term", ""),),
            completeness=RequestContextCompleteness.PARTIAL,
            context_key="legacy-form:http://127.0.0.1/search",
            provenance={
                "form_method": "explicit",
                "form_action": "explicit",
            },
        )
        assumed = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search",
            form=(("term", ""),),
            completeness=RequestContextCompleteness.PARTIAL,
            context_key="legacy-form:http://127.0.0.1/search",
            provenance={
                "form_method": "unknown_assumed_get",
                "form_action": "unknown_assumed_current_page",
            },
        )
        self.assertNotEqual(explicit.id, assumed.id)

    def test_input_point_request_context_direct_construction_is_unavailable(self) -> None:
        with self.assertRaises(TypeError):
            InputPointRequestContext("inp_1", "rt_1")

    def test_input_point_request_context_has_no_id_only_trusted_factory(self) -> None:
        self.assertFalse(
            hasattr(InputPointRequestContext, "_from_validated_ids"),
            "arbitrary IDs must not mint trusted request-context associations",
        )

    def test_input_point_request_context_rejects_duck_typed_input_point(self) -> None:
        input_point, template = self._valid_query_binding()
        fake_input_point = self._fake_input_point_like(input_point)
        with self.assertRaisesRegex(TypeError, "input_point"):
            InputPointRequestContext.from_objects(fake_input_point, template)

    def test_input_point_request_context_rejects_duck_typed_request_template(self) -> None:
        input_point, template = self._valid_query_binding()
        fake_template = self._fake_request_template_like(template)
        with self.assertRaisesRegex(TypeError, "request_template"):
            InputPointRequestContext.from_objects(input_point, fake_template)

    def test_input_point_request_context_rejects_duck_typed_objects(self) -> None:
        input_point, template = self._valid_query_binding()
        fake_input_point = self._fake_input_point_like(input_point)
        fake_template = self._fake_request_template_like(template)
        with self.assertRaisesRegex(TypeError, "input_point"):
            InputPointRequestContext.from_objects(fake_input_point, fake_template)

    def test_input_point_request_context_rejects_fake_ids_through_factories(self) -> None:
        input_point, template = self._valid_query_binding()
        fake_input_point = self._fake_input_point_like(input_point)
        fake_template = self._fake_request_template_like(template)
        with self.assertRaises(TypeError):
            InputPointRequestContext("inp_fake", "rt_fake")
        self.assertFalse(hasattr(InputPointRequestContext, "_from_validated_ids"))
        with self.assertRaises(TypeError):
            InputPointRequestContext.from_objects(fake_input_point, fake_template)

    def test_input_point_request_context_factory_accepts_valid_binding(self) -> None:
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
            url="http://127.0.0.1/search?q=book",
            query=(("q", "book"),),
            completeness=RequestContextCompleteness.COMPLETE,
        )
        binding = InputPointRequestContext.from_objects(input_point, template)
        self.assertEqual(binding.input_point_id, input_point.id)
        self.assertEqual(binding.request_template_id, template.id)

    def test_input_point_request_context_validates_single_query_baseline(self) -> None:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?q=book",
            query=(("q", "book"),),
        )
        correct = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
            baseline_value="book",
        )
        wrong = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
            baseline_value="WRONG",
        )
        InputPointRequestContext.from_objects(correct, template)
        with self.assertRaises(ValueError):
            InputPointRequestContext.from_objects(wrong, template)

    def test_input_point_request_context_validates_single_form_baseline(self) -> None:
        endpoint = Endpoint(HttpMethod.POST, "http", "127.0.0.1", "/login")
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.POST,
            url="http://127.0.0.1/login",
            form=(("username", "alice"),),
        )
        correct = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.FORM,
            name="username",
            baseline_value="alice",
        )
        wrong = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.FORM,
            name="username",
            baseline_value="WRONG",
        )
        InputPointRequestContext.from_objects(correct, template)
        with self.assertRaises(ValueError):
            InputPointRequestContext.from_objects(wrong, template)

    def test_input_point_request_context_factory_identity_is_deterministic(self) -> None:
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
        first = InputPointRequestContext.from_objects(input_point, first_template)
        equivalent = InputPointRequestContext.from_objects(input_point, first_template)
        different = InputPointRequestContext.from_objects(input_point, second_template)
        self.assertEqual(first.id, equivalent.id)
        self.assertNotEqual(first.id, different.id)

    def test_input_point_request_context_rejects_endpoint_mismatch(self) -> None:
        first = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        second = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/items")
        input_point = InputPoint(
            endpoint_id=first.id or "",
            endpoint_fingerprint=first.fingerprint,
            location=InputLocation.QUERY,
            name="q",
        )
        template = RequestTemplate(
            endpoint_id=second.id or "",
            endpoint_fingerprint=second.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/items?q=book",
            query=(("q", "book"),),
        )
        with self.assertRaises(ValueError):
            InputPointRequestContext.from_objects(input_point, template)

    def test_input_point_request_context_rejects_location_mismatch(self) -> None:
        endpoint = Endpoint(HttpMethod.POST, "http", "127.0.0.1", "/submit")
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
        )
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.POST,
            url="http://127.0.0.1/submit",
            form=(("q", "book"),),
        )
        with self.assertRaises(ValueError):
            InputPointRequestContext.from_objects(input_point, template)

    def test_input_point_request_context_rejects_missing_target(self) -> None:
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
        )
        with self.assertRaises(ValueError):
            InputPointRequestContext.from_objects(input_point, template)

    def test_input_point_request_context_rejects_out_of_range_occurrence(self) -> None:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="tag",
            occurrence_index=2,
        )
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?tag=a&tag=b",
            query=(("tag", "a"), ("tag", "b")),
        )
        with self.assertRaises(ValueError):
            InputPointRequestContext.from_objects(input_point, template)

    def test_input_point_request_context_requires_occurrence_for_repeated_target(self) -> None:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="tag",
        )
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?tag=a&tag=b",
            query=(("tag", "a"), ("tag", "b")),
        )
        with self.assertRaises(ValueError):
            InputPointRequestContext.from_objects(input_point, template)

    def test_input_point_request_context_validates_exact_occurrence_value(self) -> None:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?tag=a&tag=b",
            query=(("tag", "a"), ("tag", "b")),
        )
        valid_cases = ((0, "a"), (1, "b"))
        invalid_cases = ((0, "b"), (1, "a"))
        for occurrence_index, baseline_value in valid_cases:
            with self.subTest(occurrence_index=occurrence_index, value=baseline_value):
                input_point = InputPoint(
                    endpoint_id=endpoint.id or "",
                    endpoint_fingerprint=endpoint.fingerprint,
                    location=InputLocation.QUERY,
                    name="tag",
                    occurrence_index=occurrence_index,
                    baseline_value=baseline_value,
                )
                binding = InputPointRequestContext.from_objects(input_point, template)
                self.assertEqual(binding.input_point_id, input_point.id)
        for occurrence_index, baseline_value in invalid_cases:
            with self.subTest(occurrence_index=occurrence_index, value=baseline_value):
                input_point = InputPoint(
                    endpoint_id=endpoint.id or "",
                    endpoint_fingerprint=endpoint.fingerprint,
                    location=InputLocation.QUERY,
                    name="tag",
                    occurrence_index=occurrence_index,
                    baseline_value=baseline_value,
                )
                with self.assertRaises(ValueError):
                    InputPointRequestContext.from_objects(input_point, template)

    def test_equal_repeated_values_keep_distinct_valid_occurrences(self) -> None:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?tag=a&tag=a",
            query=(("tag", "a"), ("tag", "a")),
        )
        first = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="tag",
            occurrence_index=0,
            baseline_value="a",
        )
        second = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="tag",
            occurrence_index=1,
            baseline_value="a",
        )
        first_binding = InputPointRequestContext.from_objects(first, template)
        second_binding = InputPointRequestContext.from_objects(second, template)
        self.assertNotEqual(first.id, second.id)
        self.assertNotEqual(first_binding.id, second_binding.id)

    def test_occurrence_binding_allows_no_single_logical_baseline(self) -> None:
        endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
        template = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?tag=a&tag=b",
            query=(("tag", "a"), ("tag", "b")),
        )
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="tag",
            occurrence_index=0,
            baseline_value=None,
        )
        binding = InputPointRequestContext.from_objects(input_point, template)
        self.assertEqual(binding.input_point_id, input_point.id)

    def test_input_point_request_context_accepts_valid_multi_context_binding(self) -> None:
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
        )
        second = RequestTemplate(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?q=chair",
            query=(("q", "chair"),),
        )
        InputPointRequestContext.from_objects(input_point, first)
        InputPointRequestContext.from_objects(input_point, second)

    def test_feature_vector_identity_includes_probe_runs_and_observations(self) -> None:
        observed_zero = FeatureObservation(
            name="marker_reflected",
            value=0.0,
            observed=True,
            source="reflection_marker_probe",
            extractor_version="reflection-v1",
        )
        observed_one = FeatureObservation(
            name="marker_reflected",
            value=1.0,
            observed=True,
            source="reflection_marker_probe",
            extractor_version="reflection-v1",
        )
        first = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-a", "probe-b"),
            features={"marker_reflected": observed_zero},
        )
        equivalent = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-b", "probe-a"),
            features={"marker_reflected": observed_zero},
        )
        different_value = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-a", "probe-b"),
            features={"marker_reflected": observed_one},
        )
        different_probe = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-c",),
            features={"marker_reflected": observed_zero},
        )
        self.assertEqual(first.id, equivalent.id)
        self.assertNotEqual(first.id, different_value.id)
        self.assertNotEqual(first.id, different_probe.id)

    def test_feature_vector_feature_mapping_order_is_canonical(self) -> None:
        first = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-a",),
            features={
                "a": FeatureObservation("a", 1.0, True, "s", "v"),
                "b": FeatureObservation("b", 0.0, True, "s", "v"),
            },
        )
        second = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-a",),
            features={
                "b": FeatureObservation("b", 0.0, True, "s", "v"),
                "a": FeatureObservation("a", 1.0, True, "s", "v"),
            },
        )
        self.assertEqual(first.id, second.id)

    def test_feature_vector_nested_details_are_canonical(self) -> None:
        first = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-a",),
            features={
                "x": FeatureObservation(
                    "x",
                    1.0,
                    True,
                    "s",
                    "v",
                    details={"outer": {"b": 2, "a": 1}, "items": ["one", "two"]},
                )
            },
        )
        second = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-a",),
            features={
                "x": FeatureObservation(
                    "x",
                    1.0,
                    True,
                    "s",
                    "v",
                    details={"items": ["one", "two"], "outer": {"a": 1, "b": 2}},
                )
            },
        )
        different = FeatureVector(
            input_point_id="inp",
            probe_run_ids=("probe-a",),
            features={
                "x": FeatureObservation(
                    "x",
                    1.0,
                    True,
                    "s",
                    "v",
                    details={"items": ["two", "one"], "outer": {"a": 1, "b": 2}},
                )
            },
        )
        self.assertEqual(first.id, second.id)
        self.assertNotEqual(first.id, different.id)

    def test_feature_observation_details_are_isolated_from_caller_mutation(self) -> None:
        details = {"outer": {"items": ["one"]}}
        observation = FeatureObservation(
            "x",
            1.0,
            True,
            "s",
            "v",
            details=details,
        )
        details["outer"]["items"].append("two")
        self.assertEqual(observation.details["outer"]["items"], ("one",))
        with self.assertRaises(TypeError):
            observation.details["new"] = "value"  # type: ignore[index]

    def test_feature_observation_rejects_unsupported_details_values(self) -> None:
        with self.assertRaises(TypeError):
            FeatureObservation(
                "x",
                1.0,
                True,
                "s",
                "v",
                details={"unsupported": {"a", "b"}},
            )


if __name__ == "__main__":
    unittest.main()
