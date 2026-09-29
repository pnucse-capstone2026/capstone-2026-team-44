from __future__ import annotations

import json
import unittest
from pathlib import Path

from vulnspider.discovery import LegacyCrawlerAdapter
from vulnspider.domain import (
    HttpMethod,
    InputLocation,
    RequestContextCompleteness,
    validate_input_point_request_context,
)

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "legacy_crawl_records.json"


def load_fixture(name: str) -> list[dict[str, object]]:
    fixtures = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return list(fixtures[name])


class LegacyCrawlerAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = LegacyCrawlerAdapter()

    def assertWarningContains(self, warnings: tuple[str, ...], text: str) -> None:
        self.assertTrue(
            any(text in warning for warning in warnings),
            f"expected warning containing {text!r}, got {warnings!r}",
        )

    def test_multiple_query_params_become_separate_input_points(self) -> None:
        result = self.adapter.convert(load_fixture("query_multi"))
        names = sorted(point.name for point in result.input_points)
        self.assertEqual(names, ["page", "q"])
        self.assertTrue(
            all(point.location == InputLocation.QUERY for point in result.input_points)
        )
        self.assertEqual(len(result.request_templates), 1)
        self.assertEqual(result.request_templates[0].query, (("q", "book"), ("page", "1")))
        self.assertEqual(len(result.input_point_request_contexts), 2)

    def test_repeated_url_with_different_values_deduplicates_input_point(self) -> None:
        result = self.adapter.convert(load_fixture("query_repeated_values"))
        self.assertEqual(len(result.input_points), 1)
        self.assertEqual(result.input_points[0].name, "q")
        self.assertIsNone(result.input_points[0].baseline_value)
        self.assertEqual(
            result.input_points[0].metadata["baseline_value_state"],
            "multiple_contexts_conflicting",
        )
        self.assertEqual(len(result.request_templates), 2)
        self.assertEqual(len(result.input_point_request_contexts), 2)
        self.assertWarningContains(result.warnings, "no canonical baseline selected")

    def test_get_form_creates_form_input_on_resolved_action_endpoint(self) -> None:
        result = self.adapter.convert(load_fixture("form_get"))
        self.assertEqual(len(result.input_points), 1)
        endpoint = result.endpoints[0]
        self.assertEqual(endpoint.method, HttpMethod.GET)
        self.assertEqual(endpoint.path, "/find")
        self.assertEqual(result.input_points[0].name, "term")
        self.assertEqual(result.input_points[0].location, InputLocation.FORM)
        self.assertEqual(result.request_templates[0].completeness, RequestContextCompleteness.PARTIAL)
        self.assertEqual(result.request_templates[0].form, (("term", ""),))
        self.assertWarningContains(result.warnings, "hidden inputs may have been omitted")

    def test_post_form_does_not_fabricate_merged_form_without_boundary(self) -> None:
        result = self.adapter.convert(load_fixture("form_post"))
        self.assertEqual(sorted(point.name for point in result.input_points), ["password", "username"])
        self.assertEqual({endpoint.method for endpoint in result.endpoints}, {HttpMethod.POST})
        self.assertEqual(len(result.request_templates), 2)
        self.assertEqual(
            sorted(template.form for template in result.request_templates),
            [(("password", ""),), (("username", ""),)],
        )
        self.assertEqual(len(result.input_point_request_contexts), 2)
        self.assertTrue(
            all(
                template.metadata["form_boundary_status"] == "unavailable"
                for template in result.request_templates
            )
        )
        self.assertWarningContains(result.warnings, "form-boundary-unavailable")

    def test_same_parameter_name_in_query_and_form_stays_distinct(self) -> None:
        result = self.adapter.convert(load_fixture("same_name_query_and_form"))
        self.assertEqual(len(result.input_points), 2)
        locations = {point.location for point in result.input_points}
        self.assertEqual(locations, {InputLocation.QUERY, InputLocation.FORM})
        self.assertEqual(len(result.input_point_request_contexts), 2)

    def test_duplicate_records_deduplicate_deterministically(self) -> None:
        result = self.adapter.convert(load_fixture("duplicate_records"))
        self.assertEqual(len(result.input_points), 1)
        self.assertEqual(len(result.endpoints), 1)
        self.assertEqual(len(result.request_templates), 1)
        self.assertEqual(len(result.input_point_request_contexts), 1)

    def test_missing_or_partial_legacy_fields_warn_without_guessing(self) -> None:
        result = self.adapter.convert(load_fixture("partial_fields"))
        self.assertEqual(result.input_points, ())
        self.assertGreaterEqual(len(result.warnings), 2)

    def test_hidden_input_is_preserved_when_legacy_record_exposes_it(self) -> None:
        result = self.adapter.convert(load_fixture("hidden_input"))
        self.assertEqual(len(result.input_points), 1)
        point = result.input_points[0]
        self.assertEqual(point.name, "csrf")
        self.assertEqual(point.type_hint, "hidden")
        self.assertTrue(point.metadata["hidden"])
        self.assertEqual(point.metadata["visibility"], "hidden")

    def test_same_action_method_distinct_forms_do_not_overwrite_templates(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/profile",
                    "query_params": "{}",
                    "input_fields": json.dumps(
                        [
                            {
                                "name": "email",
                                "type": "text",
                                "value": "a@example.test",
                                "form_method": "POST",
                                "form_action": "/update",
                            }
                        ]
                    ),
                },
                {
                    "link": "http://127.0.0.1/security",
                    "query_params": "{}",
                    "input_fields": json.dumps(
                        [
                            {
                                "name": "password",
                                "type": "password",
                                "value": "secret",
                                "form_method": "POST",
                                "form_action": "/update",
                            }
                        ]
                    ),
                },
            ]
        )
        self.assertEqual(sorted(point.name for point in result.input_points), ["email", "password"])
        self.assertEqual(len(result.request_templates), 2)
        self.assertEqual(
            sorted(template.form for template in result.request_templates),
            [(("email", "a@example.test"),), (("password", "secret"),)],
        )
        self.assertEqual(len(result.input_point_request_contexts), 2)
        self.assertEqual(
            len({template.id for template in result.request_templates}),
            2,
        )

    def test_same_page_same_action_method_fields_remain_separate_without_boundary(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/account",
                    "query_params": "{}",
                    "input_fields": json.dumps(
                        [
                            {
                                "name": "email",
                                "type": "text",
                                "value": "a@example.test",
                                "form_method": "POST",
                                "form_action": "/update",
                            },
                            {
                                "name": "password",
                                "type": "password",
                                "value": "secret",
                                "form_method": "POST",
                                "form_action": "/update",
                            },
                        ]
                    ),
                }
            ]
        )
        self.assertEqual(len(result.request_templates), 2)
        self.assertEqual(
            sorted(template.form for template in result.request_templates),
            [(("email", "a@example.test"),), (("password", "secret"),)],
        )
        self.assertTrue(
            all(
                template.metadata["reconstruction_status"] == "ambiguous"
                for template in result.request_templates
            )
        )
        self.assertWarningContains(result.warnings, "form-boundary-unavailable")

    def test_ambiguous_form_identity_is_stable_under_field_reorder(self) -> None:
        fields = [
            {
                "name": "email",
                "type": "text",
                "value": "a@example.test",
                "form_method": "POST",
                "form_action": "/update",
            },
            {
                "name": "password",
                "type": "password",
                "value": "secret",
                "form_method": "POST",
                "form_action": "/update",
            },
        ]
        forward = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/account",
                    "query_params": "{}",
                    "input_fields": json.dumps(fields),
                }
            ]
        )
        reversed_result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/account",
                    "query_params": "{}",
                    "input_fields": json.dumps(list(reversed(fields))),
                }
            ]
        )
        self.assertEqual(len(forward.request_templates), 2)
        self.assertEqual(
            sorted(template.id for template in forward.request_templates),
            sorted(template.id for template in reversed_result.request_templates),
        )
        self.assertEqual(
            sorted(binding.id for binding in forward.input_point_request_contexts),
            sorted(
                binding.id
                for binding in reversed_result.input_point_request_contexts
            ),
        )
        self.assertEqual(
            sorted(template.form for template in forward.request_templates),
            [(("email", "a@example.test"),), (("password", "secret"),)],
        )
        self.assertTrue(
            all(
                template.metadata["reconstruction_status"] == "ambiguous"
                and "form-boundary-unavailable"
                in template.metadata["non_probe_ready_reasons"]
                and "field-index=" not in (template.context_key or "")
                for template in forward.request_templates
            )
        )

    def test_ambiguous_distinct_field_observations_remain_distinct(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/account",
                    "query_params": "{}",
                    "input_fields": json.dumps(
                        [
                            {
                                "name": "token",
                                "type": "text",
                                "value": "a",
                                "form_method": "POST",
                                "form_action": "/update",
                            },
                            {
                                "name": "token",
                                "type": "text",
                                "value": "b",
                                "form_method": "POST",
                                "form_action": "/update",
                            },
                        ]
                    ),
                }
            ]
        )
        self.assertEqual(len(result.request_templates), 2)
        self.assertEqual(
            sorted(template.form for template in result.request_templates),
            [(("token", "a"),), (("token", "b"),)],
        )
        self.assertEqual(len({template.id for template in result.request_templates}), 2)
        self.assertEqual(len(result.input_points), 1)
        self.assertIsNone(result.input_points[0].baseline_value)
        self.assertEqual(
            result.input_points[0].metadata["baseline_value_state"],
            "multiple_contexts_conflicting",
        )

    def test_ambiguous_indistinguishable_fields_deduplicate_deterministically(self) -> None:
        field = {
            "name": "token",
            "type": "text",
            "value": "a",
            "form_method": "POST",
            "form_action": "/update",
        }
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/account",
                    "query_params": "{}",
                    "input_fields": json.dumps([field, dict(field)]),
                }
            ]
        )
        self.assertEqual(len(result.request_templates), 1)
        self.assertEqual(result.request_templates[0].form, (("token", "a"),))
        self.assertEqual(
            result.request_templates[0].metadata["reconstruction_status"],
            "ambiguous",
        )

    def test_stable_form_boundary_groups_fields_when_evidence_exists(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/login",
                    "query_params": "{}",
                    "input_fields": json.dumps(
                        [
                            {
                                "name": "username",
                                "value": "alice",
                                "form_method": "POST",
                                "form_action": "/login",
                                "form_instance_id": "login-form",
                            },
                            {
                                "name": "password",
                                "value": "secret",
                                "form_method": "POST",
                                "form_action": "/login",
                                "form_instance_id": "login-form",
                            },
                        ]
                    ),
                }
            ]
        )
        self.assertEqual(len(result.request_templates), 1)
        template = result.request_templates[0]
        self.assertEqual(template.form, (("username", "alice"), ("password", "secret")))
        self.assertEqual(template.metadata["form_boundary_status"], "stable")
        self.assertEqual(template.metadata["form_grouping_policy"], "stable_form_boundary")

    def test_missing_form_method_warns_and_marks_provenance(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search",
                    "query_params": "{}",
                    "input_fields": json.dumps(
                        [{"name": "term", "type": "text", "form_action": "/find"}]
                    ),
                }
            ]
        )
        point = result.input_points[0]
        template = result.request_templates[0]
        self.assertEqual(template.method, HttpMethod.GET)
        self.assertEqual(point.metadata["form_method_provenance"], "unknown_assumed_get")
        self.assertEqual(template.metadata["form_method_provenance"], "unknown_assumed_get")
        self.assertWarningContains(result.warnings, "missing form_method")

    def test_missing_form_action_warns_and_marks_provenance(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search",
                    "query_params": "{}",
                    "input_fields": json.dumps(
                        [{"name": "term", "type": "text", "form_method": "GET"}]
                    ),
                }
            ]
        )
        point = result.input_points[0]
        template = result.request_templates[0]
        self.assertEqual(template.url, "http://127.0.0.1/search")
        self.assertEqual(
            point.metadata["form_action_provenance"],
            "unknown_assumed_current_page",
        )
        self.assertEqual(
            template.metadata["form_action_provenance"],
            "unknown_assumed_current_page",
        )
        self.assertWarningContains(result.warnings, "missing form_action")

    def test_missing_form_method_and_action_warns_for_both(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search",
                    "query_params": "{}",
                    "input_fields": json.dumps([{"name": "term", "type": "text"}]),
                }
            ]
        )
        self.assertWarningContains(result.warnings, "missing form_method")
        self.assertWarningContains(result.warnings, "missing form_action")
        self.assertEqual(
            result.request_templates[0].metadata["form_method_provenance"],
            "unknown_assumed_get",
        )
        self.assertEqual(
            result.request_templates[0].metadata["form_action_provenance"],
            "unknown_assumed_current_page",
        )

    def test_explicit_form_method_and_action_have_explicit_provenance(self) -> None:
        result = self.adapter.convert(load_fixture("form_post"))
        self.assertTrue(
            all(
                template.metadata["form_method_provenance"] == "explicit"
                for template in result.request_templates
            )
        )
        self.assertTrue(
            all(
                template.metadata["form_action_provenance"] == "explicit"
                for template in result.request_templates
            )
        )
        self.assertFalse(any("missing form_method" in item for item in result.warnings))
        self.assertFalse(any("missing form_action" in item for item in result.warnings))

    def test_visible_form_context_surfaces_hidden_input_loss(self) -> None:
        result = self.adapter.convert(load_fixture("form_post"))
        template = result.request_templates[0]
        self.assertEqual(template.completeness, RequestContextCompleteness.PARTIAL)
        self.assertEqual(
            template.metadata["hidden_input_policy"],
            "legacy_collector_may_omit_hidden_inputs",
        )
        self.assertWarningContains(result.warnings, "hidden inputs may have been omitted")

    def test_same_resolved_form_request_with_different_provenance_does_not_collide(self) -> None:
        explicit = {
            "link": "http://127.0.0.1/search",
            "query_params": "{}",
            "input_fields": json.dumps(
                [
                    {
                        "name": "term",
                        "type": "text",
                        "form_method": "GET",
                        "form_action": "http://127.0.0.1/search",
                    }
                ]
            ),
            "collected_time": "1",
        }
        assumed = {
            "link": "http://127.0.0.1/search",
            "query_params": "{}",
            "input_fields": json.dumps([{"name": "term", "type": "text"}]),
            "collected_time": "2",
        }
        first = self.adapter.convert([explicit, assumed])
        second = self.adapter.convert([assumed, explicit])
        self.assertEqual(len(first.request_templates), 2)
        self.assertEqual(
            {
                template.metadata["form_method_provenance"]
                for template in first.request_templates
            },
            {"explicit", "unknown_assumed_get"},
        )
        self.assertEqual(
            {
                template.metadata["form_action_provenance"]
                for template in first.request_templates
            },
            {"explicit", "unknown_assumed_current_page"},
        )
        self.assertEqual(
            sorted(template.id for template in first.request_templates),
            sorted(template.id for template in second.request_templates),
        )
        repeated = self.adapter.convert([explicit, assumed])
        self.assertEqual(
            sorted(template.id for template in first.request_templates),
            sorted(template.id for template in repeated.request_templates),
        )

    def test_repeated_query_parameters_are_preserved_losslessly(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search?tag=a&tag=b&q=x",
                    "query_params": json.dumps({"tag": ["a", "b"], "q": "x"}),
                    "input_fields": "[]",
                }
            ]
        )
        template = result.request_templates[0]
        self.assertEqual(template.query, (("tag", "a"), ("tag", "b"), ("q", "x")))
        tag_points = sorted(
            [point for point in result.input_points if point.name == "tag"],
            key=lambda point: point.occurrence_index or 0,
        )
        self.assertEqual(len(tag_points), 2)
        self.assertEqual(
            [(point.occurrence_index, point.baseline_value) for point in tag_points],
            [(0, "a"), (1, "b")],
        )
        self.assertNotEqual(tag_points[0].id, tag_points[1].id)
        self.assertTrue(all(point.metadata["repeated_parameter"] for point in tag_points))
        self.assertEqual(template.metadata["repeated_parameters"], ("tag",))

    def test_repeated_query_occurrences_follow_url_order(self) -> None:
        first = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search?tag=a&tag=b",
                    "query_params": json.dumps({"tag": ["a", "b"]}),
                    "input_fields": "[]",
                }
            ]
        )
        second = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search?tag=b&tag=a",
                    "query_params": json.dumps({"tag": ["b", "a"]}),
                    "input_fields": "[]",
                }
            ]
        )
        first_values = sorted(
            (
                point.occurrence_index,
                point.baseline_value,
                point.id,
            )
            for point in first.input_points
        )
        second_values = sorted(
            (
                point.occurrence_index,
                point.baseline_value,
                point.id,
            )
            for point in second.input_points
        )
        self.assertEqual(
            [(index, value) for index, value, _ in first_values],
            [(0, "a"), (1, "b")],
        )
        self.assertEqual(
            [(index, value) for index, value, _ in second_values],
            [(0, "b"), (1, "a")],
        )
        self.assertEqual([item[2] for item in first_values], [item[2] for item in second_values])

    def test_same_repeated_query_values_still_have_distinct_occurrences(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search?tag=a&tag=a",
                    "query_params": json.dumps({"tag": ["a", "a"]}),
                    "input_fields": "[]",
                }
            ]
        )
        tag_points = sorted(result.input_points, key=lambda point: point.occurrence_index or 0)
        self.assertEqual(
            [(point.occurrence_index, point.baseline_value) for point in tag_points],
            [(0, "a"), (1, "a")],
        )
        self.assertNotEqual(tag_points[0].id, tag_points[1].id)

    def test_cross_name_query_order_comes_from_url(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search?tag=a&q=x&tag=b",
                    "query_params": json.dumps({"tag": ["a", "b"], "q": "x"}),
                    "input_fields": "[]",
                }
            ]
        )
        self.assertEqual(
            result.request_templates[0].query,
            (("tag", "a"), ("q", "x"), ("tag", "b")),
        )

    def test_blank_query_value_is_preserved_from_url(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search?q=&tag=a",
                    "query_params": json.dumps({"q": "", "tag": "a"}),
                    "input_fields": "[]",
                }
            ]
        )
        self.assertEqual(result.request_templates[0].query, (("q", ""), ("tag", "a")))
        q = next(point for point in result.input_points if point.name == "q")
        self.assertEqual(q.baseline_value, "")

    def test_conflicting_query_metadata_warns_and_uses_url_order(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search?tag=a&tag=b&q=x",
                    "query_params": json.dumps({"tag": ["a", "z"], "q": "x"}),
                    "input_fields": "[]",
                }
            ]
        )
        self.assertEqual(
            result.request_templates[0].query,
            (("tag", "a"), ("tag", "b"), ("q", "x")),
        )
        self.assertWarningContains(result.warnings, "conflicts with URL query")

    def test_duplicate_baseline_variants_are_explicitly_associated(self) -> None:
        result = self.adapter.convert(load_fixture("query_repeated_values"))
        input_point = result.input_points[0]
        associated_template_ids = {
            binding.request_template_id
            for binding in result.input_point_request_contexts
            if binding.input_point_id == input_point.id
        }
        self.assertEqual(associated_template_ids, {template.id for template in result.request_templates})
        self.assertEqual(len(associated_template_ids), 2)
        self.assertWarningContains(result.warnings, "no canonical baseline selected")

    def test_consistent_multi_context_baseline_can_expose_single_value(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search?q=book&page=1",
                    "query_params": json.dumps({"q": "book", "page": "1"}),
                    "input_fields": "[]",
                },
                {
                    "link": "http://127.0.0.1/search?q=book&page=2",
                    "query_params": json.dumps({"q": "book", "page": "2"}),
                    "input_fields": "[]",
                },
            ]
        )
        q = next(point for point in result.input_points if point.name == "q")
        self.assertEqual(q.baseline_value, "book")
        self.assertEqual(q.metadata["baseline_value_state"], "single")
        page = next(point for point in result.input_points if point.name == "page")
        self.assertIsNone(page.baseline_value)
        self.assertEqual(page.metadata["baseline_value_state"], "multiple_contexts_conflicting")

    def test_conflicting_multi_baseline_is_order_independent(self) -> None:
        records = load_fixture("query_repeated_values")
        first = self.adapter.convert(records)
        second = self.adapter.convert(list(reversed(records)))
        self.assertIsNone(first.input_points[0].baseline_value)
        self.assertIsNone(second.input_points[0].baseline_value)
        self.assertEqual(first.input_points[0].id, second.input_points[0].id)
        self.assertEqual(
            first.input_points[0].metadata["baseline_value_state"],
            second.input_points[0].metadata["baseline_value_state"],
        )

    def test_request_template_identity_is_deterministic_from_adapter(self) -> None:
        records = load_fixture("form_post")
        first = self.adapter.convert(records)
        second = self.adapter.convert(list(reversed(records)))
        self.assertEqual(
            [template.id for template in first.request_templates],
            [template.id for template in second.request_templates],
        )
        self.assertEqual(
            [binding.id for binding in first.input_point_request_contexts],
            [binding.id for binding in second.input_point_request_contexts],
        )

    def test_adapter_emits_only_validated_associations(self) -> None:
        result = self.adapter.convert(
            [
                {
                    "link": "http://127.0.0.1/search?tag=a&tag=b",
                    "query_params": json.dumps({"tag": ["a", "b"]}),
                    "input_fields": "[]",
                }
            ]
        )
        input_points = {point.id: point for point in result.input_points}
        templates = {template.id: template for template in result.request_templates}
        self.assertGreater(len(result.input_point_request_contexts), 0)
        for binding in result.input_point_request_contexts:
            validate_input_point_request_context(
                input_points[binding.input_point_id],
                templates[binding.request_template_id],
            )

    def test_adapter_does_not_import_legacy_runtime_modules(self) -> None:
        adapter_source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "vulnspider"
            / "discovery"
            / "legacy_adapter.py"
        ).read_text(encoding="utf-8")
        forbidden = ("reference.whspider_legacy", "local_llm", "rag", "playwright")
        self.assertFalse(any(item in adapter_source for item in forbidden))


if __name__ == "__main__":
    unittest.main()
