from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
import unittest

from tests.unit.test_simple_cli import _native_analysis
from vulnspider.discovery import discovery_snapshot_id_for
from vulnspider.domain import FeatureObservation, FeatureVector
from vulnspider.features import FeatureExtractionError, extract_minimal_features
from vulnspider.handoff import (
    CandidateEvidence,
    HandoffContractError,
    build_candidate_handoff,
    normalize_selected_candidates,
)
from vulnspider.observation import pair_probe_responses
from vulnspider.reporting import build_analysis_report, build_crawl_report
from vulnspider.scoring import generate_candidates
from vulnspider.selection import select_top_k


JWT_VALUE = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"


def _refresh_discovery_snapshot(
    crawl: dict[str, object],
    analysis: dict[str, object] | None = None,
) -> str:
    crawl_payload = crawl["crawl"]
    assert isinstance(crawl_payload, dict)
    discovery = crawl_payload["discovery"]
    assert isinstance(discovery, dict)
    snapshot_id = discovery_snapshot_id_for(discovery)
    discovery["discovery_snapshot_id"] = snapshot_id
    if analysis is not None:
        reference = analysis["crawl_reference"]
        assert isinstance(reference, dict)
        reference["discovery_snapshot_id"] = snapshot_id
    return snapshot_id


def _selected_context(
    crawl: dict[str, object],
    analysis: dict[str, object],
) -> tuple[dict[str, object], dict[str, object], list[object]]:
    candidates = analysis["candidates"]
    observations = analysis["probe_observations"]
    crawl_payload = crawl["crawl"]
    assert isinstance(candidates, list)
    assert isinstance(observations, list)
    assert isinstance(crawl_payload, dict)
    discovery = crawl_payload["discovery"]
    assert isinstance(discovery, dict)
    inputs = discovery["input_points"]
    templates = discovery["request_templates"]
    assert isinstance(inputs, list)
    assert isinstance(templates, list)
    candidate = candidates[0]
    assert isinstance(candidate, dict)
    input_point = next(
        item
        for item in inputs
        if isinstance(item, dict) and item["id"] == candidate["input_point_id"]
    )
    observation = next(
        item
        for item in observations
        if isinstance(item, dict)
        and item["input_point_id"] == candidate["input_point_id"]
    )
    plan = observation["probe_plan"]
    assert isinstance(plan, dict)
    template = next(
        item
        for item in templates
        if isinstance(item, dict) and item["id"] == plan["request_template_id"]
    )
    location = input_point["location"]
    assert location in {"QUERY", "FORM"}
    pairs = template["query" if location == "QUERY" else "form"]
    assert isinstance(pairs, list)
    return input_point, template, pairs


class ProbeFeatureContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.analysis = _native_analysis()
        self.observation = self.analysis.probe_observations[0]
        discovery = self.analysis.discovery_result
        assert discovery is not None
        self.input_point = next(
            item
            for item in discovery.input_points
            if item.id == self.observation.input_point_id
        )

    def test_exact_pairing_preserves_existing_feature_behavior(self) -> None:
        observation = self.observation
        pair = pair_probe_responses(
            observation.probe_plan,
            observation.baseline_response,
            observation.probe_response,
        )

        actual = extract_minimal_features(
            self.input_point,
            observation.probe_plan,
            pair,
            observation.baseline_response,
            observation.probe_response,
        )
        expected = next(
            item
            for item in self.analysis.feature_vectors
            if item.id == observation.feature_vector_id
        )

        self.assertEqual(actual, expected)

    def test_cross_plan_response_mixing_is_rejected(self) -> None:
        observation = self.observation
        pair = pair_probe_responses(
            observation.probe_plan,
            observation.baseline_response,
            observation.probe_response,
        )
        foreign_probe = replace(
            observation.probe_response,
            probe_plan_id="probe_plan_from_another_run",
        )

        with self.assertRaisesRegex(FeatureExtractionError, "ProbePlan"):
            extract_minimal_features(
                self.input_point,
                observation.probe_plan,
                pair,
                observation.baseline_response,
                foreign_probe,
            )

    def test_missing_response_provenance_is_rejected(self) -> None:
        observation = self.observation
        pair = pair_probe_responses(
            observation.probe_plan,
            observation.baseline_response,
            observation.probe_response,
        )
        unowned_probe = replace(observation.probe_response, probe_plan_id=None)

        with self.assertRaisesRegex(FeatureExtractionError, "provenance"):
            extract_minimal_features(
                self.input_point,
                observation.probe_plan,
                pair,
                observation.baseline_response,
                unowned_probe,
            )


class CandidateHandoffContractTests(unittest.TestCase):
    def setUp(self) -> None:
        analysis = _native_analysis()
        self.crawl = build_crawl_report(analysis.crawl_result)
        self.analysis = build_analysis_report(analysis)

    def test_sqli_and_xss_candidates_resolve_and_serialize(self) -> None:
        handoff = build_candidate_handoff(self.crawl, self.analysis)
        candidates = handoff["candidates"]

        self.assertEqual(
            {item["vulnerability_type"] for item in candidates},
            {"SQLI", "REFLECTED_XSS"},
        )
        self.assertEqual(
            {item["category"] for item in candidates},
            {"INJECTION"},
        )
        crawl_inputs = {
            item["id"]: item
            for item in self.crawl["crawl"]["discovery"]["input_points"]
        }
        for candidate in candidates:
            input_point = crawl_inputs[candidate["input_point_id"]]
            self.assertEqual(candidate["endpoint_id"], input_point["endpoint_id"])
            self.assertEqual(
                candidate["selection_priority"],
                candidate["raw_rank_score"] / candidate["raw_rank_score_max"],
            )
            self.assertEqual(
                [item["feature_name"] for item in candidate["evidence"]],
                sorted(item["feature_name"] for item in candidate["evidence"]),
            )
            self.assertEqual(
                candidate["injection_context"]["parameter_location"],
                "QUERY",
            )

    def test_candidate_id_is_required(self) -> None:
        analysis = deepcopy(self.analysis)
        del analysis["candidates"][0]["candidate_id"]

        with self.assertRaisesRegex(HandoffContractError, "candidate_id"):
            build_candidate_handoff(self.crawl, analysis)

    def test_invalid_vulnerability_type_is_rejected(self) -> None:
        analysis = deepcopy(self.analysis)
        analysis["candidates"][0]["vulnerability_type"] = "COMMAND_INJECTION"

        with self.assertRaisesRegex(HandoffContractError, "vulnerability_type"):
            build_candidate_handoff(self.crawl, analysis)

    def test_candidate_requires_input_point_or_endpoint(self) -> None:
        candidate = normalize_selected_candidates(self.crawl, self.analysis)[0]

        with self.assertRaisesRegex(HandoffContractError, "input_point_id or endpoint_id"):
            replace(candidate, input_point_id=None, endpoint_id=None)

    def test_unobserved_evidence_is_not_fabricated_as_zero(self) -> None:
        unavailable = CandidateEvidence(
            feature_name="future_signal",
            feature_value=None,
            observed=False,
            weight=3.0,
            contribution=None,
            reason="The future signal was unavailable.",
        )

        self.assertIsNone(unavailable.to_dict()["feature_value"])
        self.assertIsNone(unavailable.to_dict()["contribution"])
        with self.assertRaisesRegex(HandoffContractError, "numeric zero"):
            CandidateEvidence(
                feature_name="future_signal",
                feature_value=0.0,
                observed=False,
                weight=3.0,
                contribution=0.0,
                reason="Unavailable must not become zero.",
            )

    def test_unobserved_feature_semantics_survive_full_handoff(self) -> None:
        source = _native_analysis()
        original_vector = source.feature_vectors[0]
        features = dict(original_vector.features)
        original_feature = features["marker_reflected"]
        features["marker_reflected"] = FeatureObservation.missing(
            "marker_reflected",
            source=original_feature.source,
            extractor_version=original_feature.extractor_version,
            details={"reason": "execution-error"},
        )
        vector = FeatureVector(
            input_point_id=original_vector.input_point_id,
            probe_run_ids=original_vector.probe_run_ids,
            features=features,
        )
        scoring = generate_candidates(vector)
        hardened = replace(
            source,
            feature_vectors=(vector,),
            scoring_results=scoring,
            selection=select_top_k(
                scoring,
                k=source.selection.summary.top_k_requested,
            ),
            probe_observations=(
                replace(
                    source.probe_observations[0],
                    feature_vector_id=vector.id or "",
                ),
            ),
        )
        crawl = build_crawl_report(hardened.crawl_result)
        analysis = build_analysis_report(hardened)

        handoff = build_candidate_handoff(crawl, analysis)

        unavailable = next(
            evidence
            for candidate in handoff["candidates"]
            for evidence in candidate["evidence"]
            if candidate["feature_vector_id"] == vector.id
            and evidence["feature_name"] == "marker_reflected"
        )
        self.assertFalse(unavailable["observed"])
        self.assertIsNone(unavailable["feature_value"])
        self.assertIsNone(unavailable["contribution"])
        self.assertIn("execution-error", unavailable["reason"])

    def test_handoff_serialization_is_deterministic(self) -> None:
        first = build_candidate_handoff(self.crawl, self.analysis)
        second = build_candidate_handoff(
            deepcopy(self.crawl),
            deepcopy(self.analysis),
        )

        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )
        self.assertEqual(
            [item["rank"] for item in first["candidates"]],
            list(range(1, len(first["candidates"]) + 1)),
        )


class AuthoritativeSelectionContractTests(unittest.TestCase):
    def setUp(self) -> None:
        analysis = _native_analysis()
        self.crawl = build_crawl_report(analysis.crawl_result)
        self.analysis = build_analysis_report(analysis)

    def test_forged_raw_rank_score_max_is_rejected(self) -> None:
        analysis = deepcopy(self.analysis)
        analysis["candidates"][0]["raw_rank_score_max"] = 100.0

        with self.assertRaisesRegex(HandoffContractError, "raw_rank_score_max"):
            build_candidate_handoff(self.crawl, analysis)

    def test_forged_selection_priority_is_rejected(self) -> None:
        analysis = deepcopy(self.analysis)
        analysis["candidates"][0]["selection_priority"] = 0.5

        with self.assertRaisesRegex(HandoffContractError, "selection_priority"):
            build_candidate_handoff(self.crawl, analysis)

    def test_reversed_candidates_and_forged_ranks_are_rejected(self) -> None:
        analysis = deepcopy(self.analysis)
        analysis["candidates"].reverse()
        for rank, candidate in enumerate(analysis["candidates"], start=1):
            candidate["rank"] = rank

        with self.assertRaisesRegex(HandoffContractError, "authoritative selection"):
            build_candidate_handoff(self.crawl, analysis)

    def test_false_summary_counts_are_rejected(self) -> None:
        analysis = deepcopy(self.analysis)
        analysis["summary"]["selected_results"] = 999

        with self.assertRaisesRegex(HandoffContractError, "selected_results"):
            build_candidate_handoff(self.crawl, analysis)

    def test_non_finite_score_and_priority_are_rejected(self) -> None:
        for field, value in (
            ("raw_rank_score", float("nan")),
            ("selection_priority", float("inf")),
        ):
            with self.subTest(field=field):
                analysis = deepcopy(self.analysis)
                analysis["candidates"][0][field] = value
                with self.assertRaises(HandoffContractError):
                    build_candidate_handoff(self.crawl, analysis)

    def test_bac_discriminator_is_reserved_but_not_supported(self) -> None:
        analysis = deepcopy(self.analysis)
        analysis["candidates"][0]["vulnerability_type"] = (
            "BROKEN_ACCESS_CONTROL"
        )

        with self.assertRaisesRegex(HandoffContractError, "Injection only"):
            build_candidate_handoff(self.crawl, analysis)


class AuthoritativeEvidenceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        analysis = _native_analysis()
        self.crawl = build_crawl_report(analysis.crawl_result)
        self.analysis = build_analysis_report(analysis)

    def _matching_evidence(self, analysis: dict[str, object]) -> tuple[dict, dict]:
        candidate = analysis["candidates"][0]
        scoring = next(
            item
            for item in analysis["scoring_results"]
            if item["candidate_id"] == candidate["candidate_id"]
        )
        return candidate["evidence"][0], scoring["evidence"][0]

    def test_feature_vector_value_mismatch_is_rejected(self) -> None:
        analysis = deepcopy(self.analysis)
        candidate_evidence, scoring_evidence = self._matching_evidence(analysis)
        candidate_evidence["feature_value"] = 0.25
        scoring_evidence["feature_value"] = 0.25

        with self.assertRaisesRegex(HandoffContractError, "authoritative"):
            build_candidate_handoff(self.crawl, analysis)

    def test_incorrect_weight_is_rejected(self) -> None:
        analysis = deepcopy(self.analysis)
        candidate_evidence, scoring_evidence = self._matching_evidence(analysis)
        candidate_evidence["weight"] += 1.0
        scoring_evidence["weight"] += 1.0

        with self.assertRaisesRegex(HandoffContractError, "authoritative"):
            build_candidate_handoff(self.crawl, analysis)

    def test_incorrect_contribution_is_rejected(self) -> None:
        analysis = deepcopy(self.analysis)
        candidate_evidence, scoring_evidence = self._matching_evidence(analysis)
        candidate_evidence["contribution"] = 1.0
        scoring_evidence["contribution"] = 1.0

        with self.assertRaisesRegex(HandoffContractError, "authoritative"):
            build_candidate_handoff(self.crawl, analysis)

    def test_contribution_sum_mismatch_is_rejected(self) -> None:
        analysis = deepcopy(self.analysis)
        candidate = analysis["candidates"][0]
        scoring = next(
            item
            for item in analysis["scoring_results"]
            if item["candidate_id"] == candidate["candidate_id"]
        )
        candidate["raw_rank_score"] = 1.0
        scoring["rank_score"] = 1.0

        with self.assertRaisesRegex(HandoffContractError, "rank_score"):
            build_candidate_handoff(self.crawl, analysis)


class CanonicalArtifactIdentityContractTests(unittest.TestCase):
    def setUp(self) -> None:
        analysis = _native_analysis()
        self.crawl = build_crawl_report(analysis.crawl_result)
        self.analysis = build_analysis_report(analysis)

    def test_wrong_input_point_id_fails_explicitly(self) -> None:
        analysis = deepcopy(self.analysis)
        analysis["candidates"][0]["input_point_id"] = "inp_missing"

        with self.assertRaisesRegex(HandoffContractError, "NOT_RESOLVED"):
            build_candidate_handoff(self.crawl, analysis)

    def test_two_canonical_artifacts_require_no_context_registry(self) -> None:
        handoff = build_candidate_handoff(self.crawl, self.analysis)

        self.assertEqual(
            handoff["source_artifacts"],
            ["vulnspider-crawl.json", "vulnspider-analysis.json"],
        )
        self.assertNotIn("context_registry", handoff)
        crawl = deepcopy(self.crawl)
        crawl["crawl"]["discovery"]["context_registry"] = {}
        with self.assertRaisesRegex(HandoffContractError, "context_registry"):
            build_candidate_handoff(crawl, self.analysis)

    def test_same_canonical_snapshot_is_deterministic_and_accepted(self) -> None:
        first = deepcopy(self.crawl)
        second = deepcopy(self.crawl)

        self.assertEqual(
            _refresh_discovery_snapshot(first),
            _refresh_discovery_snapshot(second),
        )
        build_candidate_handoff(first, self.analysis)

    def test_snapshot_ignores_nondeterministic_elapsed_time(self) -> None:
        first = deepcopy(self.crawl)
        second = deepcopy(self.crawl)
        first["crawl"]["discovery"]["crawl_statistics"]["elapsed_ms"] = 1.0
        second["crawl"]["discovery"]["crawl_statistics"]["elapsed_ms"] = 999.0

        self.assertEqual(
            _refresh_discovery_snapshot(first),
            _refresh_discovery_snapshot(second),
        )

    def test_endpoint_content_tamper_is_rejected(self) -> None:
        crawl = deepcopy(self.crawl)
        crawl["crawl"]["discovery"]["endpoints"][0]["path"] = "/tampered"

        with self.assertRaisesRegex(HandoffContractError, "snapshot"):
            build_candidate_handoff(crawl, self.analysis)

    def test_input_point_content_tamper_is_rejected(self) -> None:
        crawl = deepcopy(self.crawl)
        crawl["crawl"]["discovery"]["input_points"][0]["name"] = "tampered"

        with self.assertRaisesRegex(HandoffContractError, "snapshot"):
            build_candidate_handoff(crawl, self.analysis)

    def test_request_template_and_context_tamper_are_rejected(self) -> None:
        mutations = (
            ("request_templates", "url", "http://127.0.0.1/tampered"),
            ("input_point_request_contexts", "role", "tampered"),
        )
        for collection, key, value in mutations:
            with self.subTest(collection=collection):
                crawl = deepcopy(self.crawl)
                crawl["crawl"]["discovery"][collection][0][key] = value
                with self.assertRaisesRegex(HandoffContractError, "snapshot"):
                    build_candidate_handoff(crawl, self.analysis)

    def test_stale_analysis_and_different_crawl_are_rejected(self) -> None:
        crawl = deepcopy(self.crawl)
        crawl["crawl"]["discovery"]["endpoints"][0]["path"] = "/new-crawl"
        _refresh_discovery_snapshot(crawl)

        with self.assertRaisesRegex(HandoffContractError, "different discovery snapshot"):
            build_candidate_handoff(crawl, self.analysis)

    def test_snapshot_id_tamper_is_rejected(self) -> None:
        crawl = deepcopy(self.crawl)
        crawl["crawl"]["discovery"]["discovery_snapshot_id"] = "dsnap_forged"

        with self.assertRaisesRegex(HandoffContractError, "canonical content"):
            build_candidate_handoff(crawl, self.analysis)

    def test_unsupported_report_and_discovery_versions_are_rejected(self) -> None:
        mutations = (
            ("crawl", "schema_version"),
            ("analysis", "schema_version"),
            ("discovery", "contract_version"),
        )
        for owner, key in mutations:
            with self.subTest(owner=owner, key=key):
                crawl = deepcopy(self.crawl)
                analysis = deepcopy(self.analysis)
                if owner == "crawl":
                    crawl[key] = "99.0"
                elif owner == "analysis":
                    analysis[key] = "99.0"
                else:
                    crawl["crawl"]["discovery"][key] = "99.0"
                with self.assertRaisesRegex(HandoffContractError, "unsupported"):
                    build_candidate_handoff(crawl, analysis)

    def test_raw_cookie_context_is_rejected_and_not_propagated(self) -> None:
        crawl = deepcopy(self.crawl)
        analysis = deepcopy(self.analysis)
        crawl["crawl"]["discovery"]["request_templates"][0]["cookies"] = {
            "session": "raw-secret"
        }
        _refresh_discovery_snapshot(crawl, analysis)

        with self.assertRaisesRegex(HandoffContractError, "credentials"):
            build_candidate_handoff(crawl, analysis)

        encoded = json.dumps(build_candidate_handoff(self.crawl, self.analysis))
        self.assertNotIn("headers", encoded)
        self.assertNotIn("cookies", encoded)
        self.assertNotIn("decoded_text", encoded)
        self.assertNotIn("body", encoded)


class SensitiveMutationContextContractTests(unittest.TestCase):
    def setUp(self) -> None:
        analysis = _native_analysis()
        self.crawl = build_crawl_report(analysis.crawl_result)
        self.analysis = build_analysis_report(analysis)

    def test_jwt_shaped_original_value_is_rejected(self) -> None:
        crawl = deepcopy(self.crawl)
        analysis = deepcopy(self.analysis)
        input_point, _template, pairs = _selected_context(crawl, analysis)
        input_point["baseline_value"] = JWT_VALUE
        input_point["baseline_values"] = [JWT_VALUE]
        pairs[0][1] = JWT_VALUE
        _refresh_discovery_snapshot(crawl, analysis)

        with self.assertRaisesRegex(HandoffContractError, "credentials"):
            build_candidate_handoff(crawl, analysis)

    def test_raw_bearer_credential_is_rejected(self) -> None:
        crawl = deepcopy(self.crawl)
        analysis = deepcopy(self.analysis)
        input_point, _template, pairs = _selected_context(crawl, analysis)
        value = "Bearer synthetic-credential-value"
        input_point["baseline_value"] = value
        input_point["baseline_values"] = [value]
        pairs[0][1] = value
        _refresh_discovery_snapshot(crawl, analysis)

        with self.assertRaisesRegex(HandoffContractError, "credentials"):
            build_candidate_handoff(crawl, analysis)

    def test_nested_credential_is_rejected(self) -> None:
        crawl = deepcopy(self.crawl)
        analysis = deepcopy(self.analysis)
        _input_point, template, _pairs = _selected_context(crawl, analysis)
        template["metadata"] = {
            "nested": {"api_key": "sk-syntheticcredentialvalue123456"}
        }
        _refresh_discovery_snapshot(crawl, analysis)

        with self.assertRaisesRegex(HandoffContractError, "credentials"):
            build_candidate_handoff(crawl, analysis)

    def test_common_camel_case_credential_names_are_rejected(self) -> None:
        for parameter_name in (
            "accessToken",
            "account.sessionId",
            "authToken",
            "clientSecret",
            "oauthToken",
            "sessionId",
            "user[password]",
        ):
            with self.subTest(parameter_name=parameter_name):
                crawl = deepcopy(self.crawl)
                analysis = deepcopy(self.analysis)
                input_point, _template, pairs = _selected_context(crawl, analysis)
                input_point["name"] = parameter_name.lower()
                input_point["baseline_value"] = "raw-credential"
                input_point["baseline_values"] = ["raw-credential"]
                pairs[0] = [parameter_name, "raw-credential"]
                _refresh_discovery_snapshot(crawl, analysis)

                with self.assertRaisesRegex(HandoffContractError, "credentials"):
                    build_candidate_handoff(crawl, analysis)

    def test_analysis_artifact_credential_is_rejected(self) -> None:
        analysis = deepcopy(self.analysis)
        feature = analysis["feature_vectors"][0]["features"][0]
        feature["missing_reason"] = "Bearer raw-analysis-secret"

        with self.assertRaisesRegex(HandoffContractError, "credentials"):
            build_candidate_handoff(self.crawl, analysis)

    def test_plain_non_secret_query_value_is_allowed(self) -> None:
        handoff = build_candidate_handoff(self.crawl, self.analysis)

        self.assertEqual(
            handoff["candidates"][0]["injection_context"]["original_value"],
            "safe",
        )
        for parameter_name in ("cookieConsent", "pageToken", "passwordPolicy"):
            with self.subTest(parameter_name=parameter_name):
                crawl = deepcopy(self.crawl)
                analysis = deepcopy(self.analysis)
                input_point, _template, pairs = _selected_context(crawl, analysis)
                input_point["name"] = parameter_name.lower()
                input_point["baseline_value"] = "safe"
                input_point["baseline_values"] = ["safe"]
                pairs[0] = [parameter_name, "safe"]
                _refresh_discovery_snapshot(crawl, analysis)

                build_candidate_handoff(crawl, analysis)


class ParameterNameContractTests(unittest.TestCase):
    def setUp(self) -> None:
        analysis = _native_analysis()
        self.crawl = build_crawl_report(analysis.crawl_result)
        self.analysis = build_analysis_report(analysis)

    def test_canonical_name_normalization_accepts_template_casing(self) -> None:
        crawl = deepcopy(self.crawl)
        analysis = deepcopy(self.analysis)
        input_point, _template, pairs = _selected_context(crawl, analysis)
        pairs[0][0] = str(input_point["name"]).upper()
        _refresh_discovery_snapshot(crawl, analysis)

        handoff = build_candidate_handoff(crawl, analysis)

        self.assertEqual(
            handoff["candidates"][0]["injection_context"]["original_value"],
            "safe",
        )

    def test_actual_occurrence_ambiguity_is_rejected(self) -> None:
        crawl = deepcopy(self.crawl)
        analysis = deepcopy(self.analysis)
        input_point, _template, pairs = _selected_context(crawl, analysis)
        input_point["occurrence_index"] = None
        pairs.append([input_point["name"], "second"])
        _refresh_discovery_snapshot(crawl, analysis)

        with self.assertRaisesRegex(HandoffContractError, "ambiguous"):
            build_candidate_handoff(crawl, analysis)


if __name__ == "__main__":
    unittest.main()
