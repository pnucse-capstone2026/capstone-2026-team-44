from __future__ import annotations

import pickle
import unittest
from dataclasses import replace
from unittest.mock import patch

from vulnspider.discovery import (
    BlockedPostJsonCandidate,
    CollectorKind,
    DiscoveryContractError,
    DiscoveryMetadata,
    NetworkDiscoveryCollection,
    NonProbeReadyReason,
    ProbeReadyStatus,
    ScopeMetadata,
    canonicalize_network_discovery,
    scope_id_for_root,
)
from vulnspider.discovery import dynamic_browser as browser_module
from vulnspider.discovery.post_replay_policy import (
    PostReplayDisposition,
    PostReplayPolicyFeatures,
    PostReplayReasonCode,
    classify_post_replay,
)
from vulnspider.domain import EphemeralRequestMaterial
from vulnspider.observation import ProbePlanner, ProbePlanningError


ROOT = "http://127.0.0.1:8080/"
ORIGIN = ("http", "127.0.0.1", 8080)


def _capture(
    body: bytes,
    *,
    url: str,
    credential_header_present: bool = False,
):
    return browser_module._safe_blocked_post_json_candidate(
        method="POST",
        url=url,
        resource_type="fetch",
        source_url=ROOT,
        root_origin=ORIGIN,
        content_type="application/json; charset=utf-8",
        credential_header_present=credential_header_present,
        body=body,
    )


def _canonical(
    candidate: BlockedPostJsonCandidate,
    material: EphemeralRequestMaterial | None,
):
    materials = () if material is None else ((candidate.id, material),)
    components = canonicalize_network_discovery(
        NetworkDiscoveryCollection(
            post_json_candidates=(candidate,),
            post_json_replay_materials=materials,
        ),
        discovery_metadata=DiscoveryMetadata(
            collector_kind=CollectorKind.NATIVE_DYNAMIC,
            collector_version="gate-1c-c-test/1",
            configuration_fingerprint="gate-1c-c",
        ),
        scope_metadata=ScopeMetadata(
            target_scope_id=scope_id_for_root(
                ROOT,
                policy_version="same-origin-v1",
            ),
            root_url=ROOT,
            scope_policy_version="same-origin-v1",
        ),
    )
    if len(components) != 1:
        raise AssertionError("expected one POST discovery component")
    return components[0]


class PostReadinessHandoffTests(unittest.TestCase):
    def test_safe_search_and_filter_are_ready_and_reach_planner(self) -> None:
        cases = (
            (
                "http://127.0.0.1:8080/api/search",
                b'{"keyword":"phone"}',
            ),
            (
                "http://127.0.0.1:8080/api/filter",
                b'{"category":"book","page":1}',
            ),
        )

        for url, body in cases:
            with self.subTest(url=url):
                candidate, material, reason = _capture(body, url=url)
                self.assertIsNone(reason)
                self.assertIsNotNone(candidate)
                self.assertIsNotNone(material)
                assert candidate is not None
                assert material is not None
                self.assertEqual(
                    candidate.replay_policy.disposition,
                    PostReplayDisposition.SAFE_FOR_PROBE,
                )

                result = _canonical(candidate, material)
                self.assertEqual(len(result.endpoints), 1)
                self.assertEqual(
                    len(result.ready_contexts()),
                    len(candidate.member_names),
                )
                self.assertTrue(
                    all(
                        item.status == ProbeReadyStatus.READY
                        for item in result.probe_readiness
                    )
                )
                for point, template, context in result.ready_contexts():
                    plan = ProbePlanner().plan(point, template, context)
                    self.assertEqual(
                        plan.baseline_request.json_body,
                        material.json_body,
                    )
                    self.assertEqual(
                        template.metadata["post_replay_disposition"],
                        PostReplayDisposition.SAFE_FOR_PROBE.value,
                    )

    def test_structural_policy_keeps_discovery_but_excludes_planner(self) -> None:
        cases = (
            (
                "http://127.0.0.1:8080/api/update-profile",
                b'{"nickname":"abc"}',
            ),
            (
                "http://127.0.0.1:8080/cart/add",
                b'{"product_id":1}',
            ),
            (
                "http://127.0.0.1:8080/api/items",
                b'{"value":"abc"}',
            ),
            (
                "http://127.0.0.1:8080/api/search",
                b'{"filter":{"category":"book"}}',
            ),
            (
                "http://127.0.0.1:8080/graphql",
                b'{"query":"query Search { items { id } }"}',
            ),
            (
                "http://127.0.0.1:8080/api/search",
                b'{"query":"mutation DeleteUser { deleteUser(id:1) { id } }"}',
            ),
            (
                "http://127.0.0.1:8080/api/search",
                (
                    '{"query":"\\ufeffmutation DeleteUser '
                    '{ deleteUser(id:1) { id } }"}'
                ).encode(),
            ),
            (
                "http://127.0.0.1:8080/api/search",
                (
                    '{"query":", mutation DeleteUser '
                    '{ deleteUser(id:1) { id } }"}'
                ).encode(),
            ),
            (
                "http://127.0.0.1:8080/api/search",
                (
                    '{"query":"\\ufeff, # ignored\\r\\n, '
                    'mutation DeleteUser { deleteUser(id:1) { id } }"}'
                ).encode(),
            ),
        )

        for url, body in cases:
            with self.subTest(url=url):
                candidate, material, reason = _capture(body, url=url)
                self.assertIsNone(reason)
                self.assertIsNotNone(candidate)
                self.assertIsNone(material)
                assert candidate is not None
                self.assertEqual(
                    candidate.replay_policy.disposition,
                    PostReplayDisposition.STRUCTURAL_ONLY,
                )

                result = _canonical(candidate, material)
                self.assertEqual(len(result.endpoints), 1)
                self.assertEqual(
                    len(result.input_points),
                    len(candidate.member_names),
                )
                self.assertEqual(len(result.request_templates), 1)
                self.assertEqual(
                    len(result.input_point_request_contexts),
                    len(candidate.member_names),
                )
                self.assertEqual(result.ready_contexts(), ())
                self.assertTrue(
                    all(
                        item.status == ProbeReadyStatus.NOT_READY
                        and item.reasons
                        == (NonProbeReadyReason.POST_POLICY_STRUCTURAL_ONLY,)
                        for item in result.probe_readiness
                    )
                )
                template = result.request_templates[0]
                self.assertIsNone(template.ephemeral_material)
                self.assertEqual(
                    template.metadata["post_replay_disposition"],
                    PostReplayDisposition.STRUCTURAL_ONLY.value,
                )
                self.assertEqual(
                    template.metadata["post_replay_reason"],
                    candidate.replay_policy.reason_code.value,
                )
                point = result.input_points[0]
                context = result.input_point_request_contexts[0]
                with self.assertRaisesRegex(
                    ProbePlanningError,
                    "POST_POLICY_STRUCTURAL_ONLY",
                ):
                    ProbePlanner().plan(point, template, context)

    def test_sensitive_policy_preserves_value_free_structure_only(self) -> None:
        jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."
        cases = (
            b'{"password":"PASSWORD_SECRET_SENTINEL"}',
            b'{"token":"TOKEN_SECRET_SENTINEL"}',
            b'{"session":"SESSION_SECRET_SENTINEL"}',
            b'{"csrf":"CSRF_SECRET_SENTINEL"}',
            ('{"note":"' + jwt + '"}').encode(),
        )

        for body in cases:
            with self.subTest(body=body[:24]):
                candidate, material, reason = _capture(
                    body,
                    url="http://127.0.0.1:8080/api/search",
                )
                self.assertIsNone(reason)
                self.assertIsNotNone(candidate)
                self.assertIsNone(material)
                assert candidate is not None
                self.assertEqual(
                    candidate.replay_policy.disposition,
                    PostReplayDisposition.BLOCKED_SENSITIVE,
                )
                serialized_candidate = pickle.dumps(candidate, protocol=5)
                self.assertNotIn(b"SECRET_SENTINEL", serialized_candidate)
                self.assertNotIn(jwt.encode(), serialized_candidate)

                result = _canonical(candidate, material)
                self.assertEqual(len(result.endpoints), 1)
                self.assertEqual(len(result.request_templates), 1)
                self.assertEqual(result.ready_contexts(), ())
                self.assertTrue(
                    all(
                        item.reasons
                        == (NonProbeReadyReason.POST_POLICY_BLOCKED_SENSITIVE,)
                        for item in result.probe_readiness
                    )
                )
                self.assertNotIn(b"SECRET_SENTINEL", pickle.dumps(result, protocol=5))
                self.assertNotIn(jwt, repr(result.to_dict()))
                template = result.request_templates[0]
                point = result.input_points[0]
                context = result.input_point_request_contexts[0]
                with self.assertRaisesRegex(
                    ProbePlanningError,
                    "POST_POLICY_BLOCKED_SENSITIVE",
                ):
                    ProbePlanner().plan(point, template, context)

    def test_incomplete_reconstruction_cannot_become_ready(self) -> None:
        decision = classify_post_replay(
            PostReplayPolicyFeatures(
                method="POST",
                path="/api/search",
                member_names=("keyword",),
                resource_type="fetch",
                exact_authorized_loopback_origin=True,
                content_type="application/json",
                charset="utf-8",
                top_level_json_object=True,
                scalar_top_level_values=True,
                reconstruction_complete=False,
            )
        )
        candidate = BlockedPostJsonCandidate(
            resource_type="fetch",
            source_url=ROOT,
            base_url="http://127.0.0.1:8080/api/search",
            member_names=("keyword",),
            replay_policy=decision,
        )

        result = _canonical(candidate, None)

        self.assertEqual(result.ready_contexts(), ())
        self.assertEqual(
            result.request_templates[0].metadata["post_replay_reason"],
            PostReplayReasonCode.RECONSTRUCTION_INCOMPLETE.value,
        )

    def test_safe_assessment_without_material_is_downgraded_fail_closed(self) -> None:
        candidate, material, reason = _capture(
            b'{"keyword":"phone"}',
            url="http://127.0.0.1:8080/api/search",
        )
        self.assertIsNone(reason)
        self.assertIsNotNone(candidate)
        self.assertIsNotNone(material)
        assert candidate is not None

        result = _canonical(candidate, None)

        self.assertEqual(result.ready_contexts(), ())
        self.assertTrue(
            all(
                item.reasons
                == (NonProbeReadyReason.POST_POLICY_STRUCTURAL_ONLY,)
                for item in result.probe_readiness
            )
        )
        self.assertEqual(
            result.request_templates[0].metadata["post_replay_reason"],
            PostReplayReasonCode.RECONSTRUCTION_INCOMPLETE.value,
        )

        live_result = _canonical(candidate, material)
        point, template, context = live_result.ready_contexts()[0]
        stripped_template = replace(template, ephemeral_material=None)
        with self.assertRaisesRegex(
            ProbePlanningError,
            "POST_REPLAY_MATERIAL_MISSING",
        ):
            ProbePlanner().plan(point, stripped_template, context)
        with self.assertRaisesRegex(
            DiscoveryContractError,
            "ephemeral replay material",
        ):
            replace(
                live_result,
                request_templates=(stripped_template,),
            ).validate()

    def test_classifier_failure_is_explicit_and_not_ready(self) -> None:
        with patch.object(
            browser_module,
            "classify_post_replay",
            side_effect=RuntimeError("classifier failed"),
        ):
            candidate, material, reason = _capture(
                b'{"keyword":"phone"}',
                url="http://127.0.0.1:8080/api/search",
            )
        self.assertIsNone(reason)
        self.assertIsNotNone(candidate)
        self.assertIsNone(material)
        assert candidate is not None
        self.assertEqual(
            candidate.replay_policy.reason_code,
            PostReplayReasonCode.POLICY_ASSESSMENT_FAILED,
        )

        result = _canonical(candidate, material)

        self.assertEqual(result.ready_contexts(), ())
        self.assertTrue(
            all(
                item.reasons
                == (NonProbeReadyReason.POST_POLICY_ASSESSMENT_FAILED,)
                for item in result.probe_readiness
            )
        )

    def test_owner_mismatch_never_reaches_ready_handoff(self) -> None:
        candidate, material, reason = _capture(
            b'{"keyword":"phone"}',
            url="http://127.0.0.1:8080/api/search",
        )
        self.assertIsNone(reason)
        self.assertIsNotNone(candidate)
        self.assertIsNotNone(material)
        assert candidate is not None
        assert material is not None
        mismatched = EphemeralRequestMaterial(
            url="http://127.0.0.1:8080/api/other",
            query=material.query,
            json_body=material.json_body,
        )

        with self.assertRaisesRegex(ValueError, "structural URL owner"):
            _canonical(candidate, mismatched)

    def test_duplicate_structure_uses_most_restrictive_policy(self) -> None:
        safe_candidate, safe_material, safe_reason = _capture(
            b'{"keyword":"phone"}',
            url="http://127.0.0.1:8080/api/search",
        )
        blocked_candidate, blocked_material, blocked_reason = _capture(
            b'{"keyword":"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."}',
            url="http://127.0.0.1:8080/api/search",
        )
        self.assertIsNone(safe_reason)
        self.assertIsNone(blocked_reason)
        self.assertIsNotNone(safe_candidate)
        self.assertIsNotNone(safe_material)
        self.assertIsNotNone(blocked_candidate)
        self.assertIsNone(blocked_material)
        assert safe_candidate is not None
        assert safe_material is not None
        assert blocked_candidate is not None
        self.assertEqual(safe_candidate.id, blocked_candidate.id)

        snapshots = []
        for observations in (
            (b'{"keyword":"phone"}', b'{"keyword":"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."}'),
            (b'{"keyword":"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."}', b'{"keyword":"phone"}'),
        ):
            recorder = browser_module._NetworkDiscoveryRecorder(
                candidate_limit=8,
            )
            for body in observations:
                recorder.record_blocked_post_json(
                    method="POST",
                    url="http://127.0.0.1:8080/api/search",
                    resource_type="fetch",
                    source_url=ROOT,
                    root_origin=ORIGIN,
                    content_type="application/json; charset=utf-8",
                    credential_header_present=False,
                    headers_available=True,
                    body=body,
                )
            snapshots.append(recorder.snapshot())

        for snapshot in snapshots:
            self.assertEqual(len(snapshot.post_json_candidates), 1)
            self.assertEqual(snapshot.post_json_replay_materials, ())
            self.assertEqual(
                snapshot.post_json_candidates[0].replay_policy.disposition,
                PostReplayDisposition.BLOCKED_SENSITIVE,
            )
            self.assertEqual(
                canonicalize_network_discovery(
                    snapshot,
                    discovery_metadata=DiscoveryMetadata(
                        collector_kind=CollectorKind.NATIVE_DYNAMIC,
                        collector_version="gate-1c-c-test/1",
                        configuration_fingerprint="gate-1c-c",
                    ),
                    scope_metadata=ScopeMetadata(
                        target_scope_id=scope_id_for_root(
                            ROOT,
                            policy_version="same-origin-v1",
                        ),
                        root_url=ROOT,
                        scope_policy_version="same-origin-v1",
                    ),
                )[0].ready_contexts(),
                (),
            )

    def test_secret_shaped_member_name_is_redacted_but_structure_remains(self) -> None:
        secret_names = (
            "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
        )
        for secret_name in secret_names:
            with self.subTest(secret_name=secret_name[:8]):
                candidate, material, reason = _capture(
                    ('{"' + secret_name + '":null}').encode(),
                    url="http://127.0.0.1:8080/api/search",
                )
                self.assertIsNone(reason)
                self.assertIsNotNone(candidate)
                self.assertIsNone(material)
                assert candidate is not None
                self.assertEqual(
                    candidate.replay_policy.disposition,
                    PostReplayDisposition.BLOCKED_SENSITIVE,
                )
                self.assertNotIn(
                    secret_name.lower().encode(),
                    pickle.dumps(candidate, protocol=5),
                )
                result = _canonical(candidate, material)
                self.assertEqual(len(result.input_points), 1)
                self.assertEqual(result.ready_contexts(), ())
                self.assertNotIn(secret_name.lower(), repr(result.to_dict()))


if __name__ == "__main__":
    unittest.main()
