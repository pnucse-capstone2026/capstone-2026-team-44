from __future__ import annotations

from dataclasses import replace
import unittest

from vulnspider.domain import (
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
    ResponsePair,
    ResponseSnapshot,
)
from vulnspider.features import (
    FEATURE_AGGREGATION_VERSION,
    MARKER_REFLECTED,
    RESPONSE_LENGTH_DIFF_RATIO,
    SQL_ERROR_PATTERN,
    STATUS_CODE_CHANGED,
    FeatureExtractionError,
    combine_input_point_features,
    extract_minimal_features,
)
from vulnspider.scoring import generate_candidates

FEATURE_NAMES = (
    MARKER_REFLECTED,
    RESPONSE_LENGTH_DIFF_RATIO,
    SQL_ERROR_PATTERN,
    STATUS_CODE_CHANGED,
)


class CombineInputPointFeaturesTests(unittest.TestCase):
    """Native Dynamic/Combined discovery binds one InputPoint to many contexts."""

    def _observation(
        self,
        name: str,
        value: float | None,
    ) -> FeatureObservation:
        if value is None:
            return FeatureObservation.missing(
                name,
                source=f"{name}-source",
                extractor_version=f"{name}-v1",
                details={"reason": "execution-error"},
            )
        return FeatureObservation(
            name=name,
            value=value,
            observed=True,
            source=f"{name}-source",
            extractor_version=f"{name}-v1",
            details={"probe_run_detail": name},
        )

    def _vector(
        self,
        probe_run_id: str,
        values: dict[str, float | None],
        *,
        input_point_id: str = "inp_A",
        feature_schema_version: str = "feature-v0.1",
    ) -> FeatureVector:
        return FeatureVector(
            input_point_id=input_point_id,
            probe_run_ids=(probe_run_id,),
            features={
                name: self._observation(name, values.get(name, 0.0))
                for name in FEATURE_NAMES
            },
            feature_schema_version=feature_schema_version,
        )

    def test_single_probe_run_is_returned_unchanged(self) -> None:
        vector = self._vector("pair_1", {MARKER_REFLECTED: 1.0})

        combined = combine_input_point_features([vector])

        self.assertIs(combined, vector)
        self.assertEqual(combined.probe_run_ids, ("pair_1",))

    def test_strongest_observed_value_wins_and_keeps_its_probe_run(self) -> None:
        weak = self._vector(
            "pair_b",
            {MARKER_REFLECTED: 0.0, SQL_ERROR_PATTERN: 1.0},
        )
        strong = self._vector(
            "pair_a",
            {MARKER_REFLECTED: 1.0, SQL_ERROR_PATTERN: 0.0},
        )

        combined = combine_input_point_features([weak, strong])

        self.assertEqual(combined.input_point_id, "inp_A")
        self.assertEqual(combined.probe_run_ids, ("pair_a", "pair_b"))
        marker = combined.features[MARKER_REFLECTED]
        sql = combined.features[SQL_ERROR_PATTERN]
        self.assertEqual((marker.value, marker.observed), (1.0, True))
        self.assertEqual((sql.value, sql.observed), (1.0, True))
        self.assertEqual(marker.details["selected_probe_run_id"], "pair_a")
        self.assertEqual(sql.details["selected_probe_run_id"], "pair_b")
        self.assertEqual(
            marker.details["aggregation"],
            FEATURE_AGGREGATION_VERSION,
        )
        self.assertEqual(
            marker.details["aggregated_probe_run_ids"],
            ("pair_a", "pair_b"),
        )
        self.assertEqual(
            marker.details["probe_run_values"],
            (("pair_a", 1.0), ("pair_b", 0.0)),
        )
        self.assertEqual(marker.details["unobserved_probe_runs"], 0)
        self.assertEqual(marker.details["probe_run_detail"], MARKER_REFLECTED)

    def test_ties_resolve_by_ascending_probe_run_id(self) -> None:
        first = self._vector("pair_b", {MARKER_REFLECTED: 1.0})
        second = self._vector("pair_a", {MARKER_REFLECTED: 1.0})

        forward = combine_input_point_features([first, second])
        reversed_order = combine_input_point_features([second, first])

        self.assertEqual(forward.id, reversed_order.id)
        self.assertEqual(
            forward.features[MARKER_REFLECTED].details["selected_probe_run_id"],
            "pair_a",
        )

    def test_unobserved_run_does_not_hide_an_observed_one(self) -> None:
        failed = self._vector("pair_a", dict.fromkeys(FEATURE_NAMES))
        succeeded = self._vector("pair_b", {MARKER_REFLECTED: 1.0})

        combined = combine_input_point_features([failed, succeeded])

        marker = combined.features[MARKER_REFLECTED]
        self.assertTrue(marker.observed)
        self.assertEqual(marker.value, 1.0)
        self.assertEqual(marker.details["selected_probe_run_id"], "pair_b")
        self.assertEqual(marker.details["unobserved_probe_runs"], 1)
        self.assertEqual(
            marker.details["probe_run_values"],
            (("pair_a", None), ("pair_b", 1.0)),
        )

    def test_feature_stays_unobserved_when_no_run_observed_it(self) -> None:
        first = self._vector("pair_a", dict.fromkeys(FEATURE_NAMES))
        second = self._vector("pair_b", dict.fromkeys(FEATURE_NAMES))

        combined = combine_input_point_features([first, second])

        for name in FEATURE_NAMES:
            observation = combined.features[name]
            self.assertFalse(observation.observed, name)
            self.assertIsNone(observation.value, name)
            self.assertEqual(
                observation.details["reason"],
                "no-observed-probe-run",
                name,
            )
            self.assertEqual(observation.details["unobserved_probe_runs"], 2)

    def test_combined_vector_produces_one_candidate_per_type(self) -> None:
        combined = combine_input_point_features(
            [
                self._vector("pair_a", {MARKER_REFLECTED: 1.0}),
                self._vector("pair_b", {SQL_ERROR_PATTERN: 1.0}),
            ]
        )

        results = generate_candidates(combined)

        candidate_ids = [result.candidate.id for result in results]
        self.assertEqual(len(candidate_ids), len(set(candidate_ids)))
        self.assertEqual(len(candidate_ids), 2)

    def test_rejects_vectors_from_different_input_points(self) -> None:
        first = self._vector("pair_a", {})
        second = self._vector("pair_b", {}, input_point_id="inp_B")

        with self.assertRaisesRegex(FeatureExtractionError, "one InputPoint"):
            combine_input_point_features([first, second])

    def test_rejects_mixed_feature_schema_versions(self) -> None:
        first = self._vector("pair_a", {})
        second = self._vector(
            "pair_b",
            {},
            feature_schema_version="feature-v0.2",
        )

        with self.assertRaisesRegex(FeatureExtractionError, "schema version"):
            combine_input_point_features([first, second])

    def test_rejects_repeated_probe_runs(self) -> None:
        first = self._vector("pair_a", {})
        second = self._vector("pair_a", {MARKER_REFLECTED: 1.0})

        with self.assertRaisesRegex(FeatureExtractionError, "distinct probe runs"):
            combine_input_point_features([first, second])

    def test_rejects_already_combined_vectors(self) -> None:
        combined = combine_input_point_features(
            [self._vector("pair_a", {}), self._vector("pair_b", {})]
        )

        with self.assertRaisesRegex(FeatureExtractionError, "single-probe-run"):
            combine_input_point_features(
                [combined, self._vector("pair_c", {})]
            )

    def test_rejects_conflicting_extractors_for_one_feature(self) -> None:
        first = self._vector("pair_a", {MARKER_REFLECTED: 1.0})
        second = self._vector("pair_b", {MARKER_REFLECTED: 0.0})
        renamed = replace(
            second,
            features={
                **dict(second.features),
                MARKER_REFLECTED: FeatureObservation(
                    name=MARKER_REFLECTED,
                    value=0.0,
                    observed=True,
                    source=f"{MARKER_REFLECTED}-source",
                    extractor_version="reflection-v2",
                ),
            },
            id=None,
        )

        with self.assertRaisesRegex(FeatureExtractionError, "more than one extractor"):
            combine_input_point_features([first, renamed])

    def test_rejects_empty_input(self) -> None:
        with self.assertRaisesRegex(FeatureExtractionError, "at least one"):
            combine_input_point_features([])

    def test_rejects_non_feature_vector_input(self) -> None:
        with self.assertRaisesRegex(FeatureExtractionError, "FeatureVector"):
            combine_input_point_features(["not-a-vector"])


class UndecodedBodyFeatureTests(unittest.TestCase):
    """A body that could not be decoded is missing, never an observed zero."""

    def _plan(self) -> tuple[InputPoint, ProbePlan]:
        endpoint_id = "ep_search"
        endpoint_fingerprint = "endpoint-fingerprint"
        input_point = InputPoint(
            endpoint_id=endpoint_id,
            endpoint_fingerprint=endpoint_fingerprint,
            location=InputLocation.QUERY,
            name="q",
            baseline_value="a",
        )
        template = RequestTemplate(
            endpoint_id=endpoint_id,
            endpoint_fingerprint=endpoint_fingerprint,
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?q=a",
            query=(("q", "a"),),
            completeness=RequestContextCompleteness.COMPLETE,
        )
        context = InputPointRequestContext.from_objects(input_point, template)
        plan = ProbePlan(
            input_point_id=input_point.id or "",
            probe_family=ProbeFamily.REFLECTION_MARKER,
            baseline_request=RequestInstance(
                method=HttpMethod.GET,
                url=template.url,
                query=template.query,
            ),
            probe_request=RequestInstance(
                method=HttpMethod.GET,
                url="http://127.0.0.1/search?q=VULNSPIDER_MARKER",
                query=(("q", "VULNSPIDER_MARKER"),),
            ),
            changed_fields=("query.q",),
            request_template_id=template.id,
            request_context_id=context.id,
            probe_marker="VULNSPIDER_MARKER",
            marker_strategy="unit-v1",
        )
        return input_point, plan

    def _snapshot(
        self,
        plan: ProbePlan,
        role: str,
        *,
        decoded_text: str | None,
    ) -> ResponseSnapshot:
        request = plan.baseline_request if role == "baseline" else plan.probe_request
        return ResponseSnapshot(
            request_id=request.id or "",
            status_code=200,
            elapsed_ms=1.0,
            body_bytes_hash="0" * 64,
            body_length_bytes=10,
            decoded_text=decoded_text,
            probe_plan_id=plan.id,
            request_role=role,
        )

    def test_body_text_features_are_missing_without_decoded_text(self) -> None:
        input_point, plan = self._plan()
        baseline = self._snapshot(plan, "baseline", decoded_text="baseline")
        probe = self._snapshot(plan, "probe", decoded_text=None)
        pair = ResponsePair(
            input_point_id=input_point.id or "",
            probe_plan_id=plan.id or "",
            baseline_response_id=baseline.id or "",
            probe_response_id=probe.id or "",
        )

        vector = extract_minimal_features(
            input_point,
            plan,
            pair,
            baseline,
            probe,
        )

        for name in (MARKER_REFLECTED, SQL_ERROR_PATTERN):
            observation = vector.features[name]
            self.assertFalse(observation.observed, name)
            self.assertIsNone(observation.value, name)
            self.assertEqual(
                observation.details["reason"],
                "response-body-not-decoded",
                name,
            )
            self.assertFalse(observation.details["probe_body_decoded"], name)
            self.assertTrue(observation.details["baseline_body_decoded"], name)
        self.assertTrue(vector.features[STATUS_CODE_CHANGED].observed)
        self.assertTrue(vector.features[RESPONSE_LENGTH_DIFF_RATIO].observed)


if __name__ == "__main__":
    unittest.main()
