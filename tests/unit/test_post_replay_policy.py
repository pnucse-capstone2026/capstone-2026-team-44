from __future__ import annotations

import unittest

from vulnspider.discovery.post_replay_policy import (
    PostReplayDisposition,
    PostReplayPolicyFeatures,
    PostReplayReasonCode,
    classify_post_replay,
)
from vulnspider.discovery import dynamic_browser as browser_module


def _features(
    path: str,
    member_names: tuple[str, ...],
    **overrides: object,
) -> PostReplayPolicyFeatures:
    values: dict[str, object] = {
        "method": "POST",
        "path": path,
        "member_names": member_names,
        "resource_type": "fetch",
        "exact_authorized_loopback_origin": True,
        "content_type": "application/json",
        "charset": "utf-8",
        "top_level_json_object": True,
        "scalar_top_level_values": True,
        "reconstruction_complete": True,
    }
    values.update(overrides)
    return PostReplayPolicyFeatures(**values)  # type: ignore[arg-type]


class PostReplayPolicyTests(unittest.TestCase):
    def test_positive_json_search_and_filter_cases_are_safe(self) -> None:
        cases = (
            _features("/api/search", ("keyword",)),
            _features("/api/filter", ("category", "page"), resource_type="xhr"),
        )

        for features in cases:
            with self.subTest(path=features.path):
                decision = classify_post_replay(features)
                self.assertEqual(
                    decision.disposition,
                    PostReplayDisposition.SAFE_FOR_PROBE,
                )
                self.assertEqual(
                    decision.reason_code,
                    PostReplayReasonCode.MULTIPLE_READ_ONLY_SIGNALS,
                )

    def test_one_weak_read_only_signal_is_not_enough_for_safe(self) -> None:
        decision = classify_post_replay(_features("/api/search", ("payload",)))

        self.assertEqual(
            decision.disposition,
            PostReplayDisposition.STRUCTURAL_ONLY,
        )
        self.assertEqual(
            decision.reason_code,
            PostReplayReasonCode.READ_ONLY_EVIDENCE_INSUFFICIENT,
        )

    def test_action_intent_can_supply_independent_positive_evidence(self) -> None:
        decision = classify_post_replay(
            _features(
                "/api/items",
                ("keyword",),
                action_intent="autocomplete",
            )
        )

        self.assertEqual(
            decision.disposition,
            PostReplayDisposition.SAFE_FOR_PROBE,
        )

    def test_state_changing_paths_are_structural_only(self) -> None:
        cases = (
            "/api/update-profile",
            "/cart/add",
            "/checkout",
            "/api/orders/create",
            "/admin/users/remove",
            "/admin/users/grant",
            "/account/close",
            "/cart/clear",
            "/orders/cancel",
            "/api/%75pdate-profile",
        )

        for path in cases:
            with self.subTest(path=path):
                decision = classify_post_replay(
                    _features(path, ("keyword",), action_intent="search")
                )
                self.assertEqual(
                    decision.disposition,
                    PostReplayDisposition.STRUCTURAL_ONLY,
                )
                self.assertEqual(
                    decision.reason_code,
                    PostReplayReasonCode.STATE_CHANGING_SEMANTICS,
                )

    def test_nested_json_is_structural_only(self) -> None:
        decision = classify_post_replay(
            _features(
                "/api/search",
                ("filter",),
                scalar_top_level_values=False,
            )
        )

        self.assertEqual(
            decision.disposition,
            PostReplayDisposition.STRUCTURAL_ONLY,
        )
        self.assertEqual(
            decision.reason_code,
            PostReplayReasonCode.NESTED_JSON_UNSUPPORTED,
        )

    def test_camel_case_state_changing_action_is_structural_only(self) -> None:
        decision = classify_post_replay(
            _features(
                "/api/search",
                ("keyword",),
                action_intent="updateProfile",
            )
        )

        self.assertEqual(
            decision.disposition,
            PostReplayDisposition.STRUCTURAL_ONLY,
        )
        self.assertEqual(
            decision.reason_code,
            PostReplayReasonCode.STATE_CHANGING_SEMANTICS,
        )

    def test_literal_mutation_action_is_structural_only(self) -> None:
        decision = classify_post_replay(
            _features(
                "/api/search",
                ("keyword",),
                action_intent="mutationSearch",
            )
        )

        self.assertEqual(
            decision.disposition,
            PostReplayDisposition.STRUCTURAL_ONLY,
        )
        self.assertEqual(
            decision.reason_code,
            PostReplayReasonCode.STATE_CHANGING_SEMANTICS,
        )

    def test_gate_1c_a_normalized_camel_mutation_stays_structural(self) -> None:
        candidate, _material, reason = (
            browser_module._safe_blocked_post_json_candidate(
                method="POST",
                url="http://127.0.0.1:8080/api/search",
                resource_type="fetch",
                source_url="http://127.0.0.1:8080/",
                root_origin=("http", "127.0.0.1", 8080),
                content_type="application/json",
                credential_header_present=False,
                body=b'{"keyword":"phone","cartAdd":"item-1"}',
            )
        )
        self.assertIsNone(reason)
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.member_names, ("cartadd", "keyword"))

        decision = classify_post_replay(
            _features(
                "/api/search",
                candidate.member_names,
                action_intent="search",
            )
        )

        self.assertEqual(
            decision.disposition,
            PostReplayDisposition.STRUCTURAL_ONLY,
        )
        self.assertEqual(
            decision.reason_code,
            PostReplayReasonCode.STATE_CHANGING_SEMANTICS,
        )

    def test_ambiguous_endpoint_is_structural_only(self) -> None:
        decision = classify_post_replay(_features("/api/items", ("value",)))

        self.assertEqual(
            decision.disposition,
            PostReplayDisposition.STRUCTURAL_ONLY,
        )
        self.assertEqual(
            decision.reason_code,
            PostReplayReasonCode.READ_ONLY_EVIDENCE_INSUFFICIENT,
        )

    def test_graphql_non_goal_is_structural_only(self) -> None:
        cases = (
            _features(
                "/graphql",
                ("query",),
                action_intent="search",
            ),
            _features(
                "/api/search",
                ("query",),
                action_intent="search",
                graphql_semantics_present=True,
            ),
        )

        for features in cases:
            with self.subTest(path=features.path):
                decision = classify_post_replay(features)
                self.assertEqual(
                    decision.disposition,
                    PostReplayDisposition.STRUCTURAL_ONLY,
                )
                self.assertEqual(
                    decision.reason_code,
                    PostReplayReasonCode.GRAPHQL_UNSUPPORTED,
                )

    def test_empty_json_object_has_no_injectable_member(self) -> None:
        decision = classify_post_replay(
            _features(
                "/api/search",
                (),
                action_intent="autocomplete",
            )
        )

        self.assertEqual(
            decision.disposition,
            PostReplayDisposition.STRUCTURAL_ONLY,
        )
        self.assertEqual(
            decision.reason_code,
            PostReplayReasonCode.NO_INJECTABLE_TOP_LEVEL_MEMBER,
        )

    def test_sensitive_member_names_are_blocked(self) -> None:
        for member_name in (
            "password",
            "passwd",
            "pwd",
            "token",
            "secret",
            "csrf",
            "xsrf",
            "authorization",
            "session",
            "authToken",
            "sessionId",
        ):
            with self.subTest(member_name=member_name):
                decision = classify_post_replay(
                    _features("/api/search", ("keyword", member_name))
                )
                self.assertEqual(
                    decision.disposition,
                    PostReplayDisposition.BLOCKED_SENSITIVE,
                )
                self.assertEqual(
                    decision.reason_code,
                    PostReplayReasonCode.SENSITIVE_FIELD_NAME,
                )

    def test_sensitive_header_and_cookie_semantics_are_blocked(self) -> None:
        cases = (
            (
                {"header_names": ("Authorization",)},
                PostReplayReasonCode.SENSITIVE_HEADER,
            ),
            (
                {"credential_header_present": True},
                PostReplayReasonCode.SENSITIVE_HEADER,
            ),
            (
                {"cookie_names": ("session",)},
                PostReplayReasonCode.SENSITIVE_COOKIE,
            ),
            (
                {"credential_cookie_present": True},
                PostReplayReasonCode.SENSITIVE_COOKIE,
            ),
        )

        for overrides, reason in cases:
            with self.subTest(reason=reason):
                decision = classify_post_replay(
                    _features("/api/search", ("keyword",), **overrides)
                )
                self.assertEqual(
                    decision.disposition,
                    PostReplayDisposition.BLOCKED_SENSITIVE,
                )
                self.assertEqual(decision.reason_code, reason)

    def test_precomputed_jwt_or_bearer_material_flag_is_blocked(self) -> None:
        decision = classify_post_replay(
            _features(
                "/api/search",
                ("keyword", "data"),
                credential_material_present=True,
            )
        )

        self.assertEqual(
            decision.disposition,
            PostReplayDisposition.BLOCKED_SENSITIVE,
        )
        self.assertEqual(
            decision.reason_code,
            PostReplayReasonCode.SENSITIVE_VALUE_MATERIAL,
        )

    def test_ordinary_business_names_are_not_overblocked_as_secrets(self) -> None:
        for member_name in ("product_id", "category", "page", "key", "license_key"):
            with self.subTest(member_name=member_name):
                decision = classify_post_replay(
                    _features("/api/search", ("keyword", member_name))
                )
                self.assertNotEqual(
                    decision.disposition,
                    PostReplayDisposition.BLOCKED_SENSITIVE,
                )

    def test_cartography_set_business_field_is_not_a_cart_mutation(self) -> None:
        decision = classify_post_replay(
            _features("/api/search", ("keyword", "cartographySet"))
        )

        self.assertEqual(
            decision.disposition,
            PostReplayDisposition.SAFE_FOR_PROBE,
        )

    def test_eligibility_prerequisites_fail_closed_to_structural_only(self) -> None:
        cases = (
            ({"method": "PUT"}, PostReplayReasonCode.METHOD_UNSUPPORTED),
            (
                {"exact_authorized_loopback_origin": False},
                PostReplayReasonCode.ORIGIN_NOT_AUTHORIZED,
            ),
            (
                {"resource_type": "document"},
                PostReplayReasonCode.PROVENANCE_UNSUPPORTED,
            ),
            (
                {"content_type": "application/x-www-form-urlencoded"},
                PostReplayReasonCode.CONTENT_TYPE_UNSUPPORTED,
            ),
            ({"charset": "euc-kr"}, PostReplayReasonCode.CHARSET_UNSUPPORTED),
            (
                {"top_level_json_object": False},
                PostReplayReasonCode.JSON_TOP_LEVEL_NOT_OBJECT,
            ),
            (
                {"reconstruction_complete": False},
                PostReplayReasonCode.RECONSTRUCTION_INCOMPLETE,
            ),
        )

        for overrides, reason in cases:
            with self.subTest(reason=reason):
                decision = classify_post_replay(
                    _features("/api/search", ("keyword",), **overrides)
                )
                self.assertEqual(
                    decision.disposition,
                    PostReplayDisposition.STRUCTURAL_ONLY,
                )
                self.assertEqual(decision.reason_code, reason)

    def test_same_structure_has_same_decision_regardless_of_scalar_values(self) -> None:
        bodies = (
            {"keyword": "phone", "page": 1},
            {"keyword": "unrelated-value", "page": 999},
        )
        features = tuple(
            _features(
                "/api/search",
                tuple(body),
                scalar_top_level_values=all(
                    value is None or isinstance(value, str | int | float | bool)
                    for value in body.values()
                ),
            )
            for body in bodies
        )

        self.assertEqual(features[0], features[1])
        self.assertEqual(
            classify_post_replay(features[0]),
            classify_post_replay(features[1]),
        )


if __name__ == "__main__":
    unittest.main()
