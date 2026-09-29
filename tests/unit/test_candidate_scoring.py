from __future__ import annotations

from dataclasses import replace
import inspect
import unittest

from vulnspider.domain import (
    FeatureObservation,
    FeatureVector,
    HttpMethod,
    InputLocation,
    InputPoint,
    ProbeFamily,
    ProbePlan,
    RequestInstance,
    ResponsePair,
    ResponseSnapshot,
    VulnerabilityCandidate,
    VulnerabilityType,
)
from vulnspider.features import (
    MARKER_REFLECTED,
    RESPONSE_LENGTH_DIFF_RATIO,
    SQL_ERROR_PATTERN,
    STATUS_CODE_CHANGED,
    extract_minimal_features,
)
from vulnspider.scoring import (
    SQLI_MAX_RANK_SCORE,
    XSS_MAX_RANK_SCORE,
    CandidateGenerator,
    ScoringError,
    ScoringResult,
    SQLiScorer,
    XSSScorer,
    generate_candidates,
)


class CandidateScoringTests(unittest.TestCase):
    def _input_point(
        self,
        *,
        occurrence_index: int | None = None,
        baseline_value: str = "a",
    ) -> InputPoint:
        return InputPoint(
            endpoint_id="ep_search",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.QUERY,
            name="tag" if occurrence_index is not None else "q",
            occurrence_index=occurrence_index,
            baseline_value=baseline_value,
        )

    def _observation(self, name: str, value: float) -> FeatureObservation:
        return FeatureObservation(
            name=name,
            value=value,
            observed=True,
            source="unit-test",
            extractor_version="unit-v1",
        )

    def _vector(
        self,
        *,
        input_point_id: str = "inp_A",
        status_code_changed: float = 0.0,
        response_length_diff_ratio: float = 0.0,
        marker_reflected: float = 0.0,
        sql_error_pattern: float = 0.0,
        missing: frozenset[str] = frozenset(),
        probe_run_id: str = "pair_1",
        reverse_features: bool = False,
    ) -> FeatureVector:
        values = (
            (STATUS_CODE_CHANGED, status_code_changed),
            (RESPONSE_LENGTH_DIFF_RATIO, response_length_diff_ratio),
            (MARKER_REFLECTED, marker_reflected),
            (SQL_ERROR_PATTERN, sql_error_pattern),
        )
        if reverse_features:
            values = tuple(reversed(values))
        features = {}
        for name, value in values:
            if name in missing:
                features[name] = FeatureObservation.missing(
                    name,
                    source="execution-error",
                    extractor_version="unit-v1",
                    details={"reason": "execution-error"},
                )
            else:
                features[name] = self._observation(name, value)
        return FeatureVector(
            input_point_id=input_point_id,
            probe_run_ids=(probe_run_id,),
            features=features,
        )

    def _execution_failure_vector(self) -> FeatureVector:
        input_point = self._input_point()
        baseline_request = RequestInstance(
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?q=a",
        )
        probe_request = RequestInstance(
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?q=VULNSPIDER_MARKER",
        )
        probe_plan = ProbePlan(
            input_point_id=input_point.id or "",
            probe_family=ProbeFamily.REFLECTION_MARKER,
            baseline_request=baseline_request,
            probe_request=probe_request,
            changed_fields=("query.q",),
            probe_marker="VULNSPIDER_MARKER",
        )
        baseline_response = ResponseSnapshot(
            request_id=baseline_request.id or "",
            status_code=0,
            elapsed_ms=0.0,
            body_bytes_hash="empty",
            body_length_bytes=0,
            decoded_text=None,
            execution_error="timeout",
            probe_plan_id=probe_plan.id,
            request_role="baseline",
        )
        probe_response = ResponseSnapshot(
            request_id=probe_request.id or "",
            status_code=200,
            elapsed_ms=1.0,
            body_bytes_hash="probe",
            body_length_bytes=12,
            decoded_text="response body",
            probe_plan_id=probe_plan.id,
            request_role="probe",
        )
        response_pair = ResponsePair(
            input_point_id=input_point.id or "",
            probe_plan_id=probe_plan.id or "",
            baseline_response_id=baseline_response.id or "",
            probe_response_id=probe_response.id or "",
        )
        return extract_minimal_features(
            input_point,
            probe_plan,
            response_pair,
            baseline_response,
            probe_response,
        )

    def test_one_vector_generates_distinct_type_specific_candidates(self) -> None:
        results = generate_candidates(self._vector())
        self.assertEqual(
            tuple(result.candidate.vulnerability_type for result in results),
            (VulnerabilityType.SQLI, VulnerabilityType.REFLECTED_XSS),
        )
        self.assertNotEqual(results[0].candidate.id, results[1].candidate.id)
        self.assertTrue(
            all(
                evidence.vulnerability_type == result.candidate.vulnerability_type
                for result in results
                for evidence in result.evidence
            )
        )
        self.assertTrue(
            all(
                evidence.candidate_id == result.candidate.id
                for result in results
                for evidence in result.evidence
            )
        )

    def test_equal_repeated_values_keep_occurrence_candidate_identity(self) -> None:
        first_input = self._input_point(occurrence_index=0, baseline_value="a")
        second_input = self._input_point(occurrence_index=1, baseline_value="a")
        first = SQLiScorer().score(
            self._vector(input_point_id=first_input.id or "")
        )
        second = SQLiScorer().score(
            self._vector(input_point_id=second_input.id or "")
        )
        self.assertNotEqual(first_input.id, second_input.id)
        self.assertNotEqual(first.candidate.id, second.candidate.id)

    def test_xss_only_feature_cannot_change_sqli_score(self) -> None:
        not_reflected = self._vector(marker_reflected=0.0, sql_error_pattern=1.0)
        reflected = self._vector(marker_reflected=1.0, sql_error_pattern=1.0)
        first = SQLiScorer().score(not_reflected)
        second = SQLiScorer().score(reflected)
        self.assertEqual(first.candidate.rank_score, second.candidate.rank_score)
        self.assertNotIn(MARKER_REFLECTED, {item.feature_name for item in first.evidence})

    def test_sqli_only_feature_cannot_change_xss_score(self) -> None:
        no_sql_error = self._vector(marker_reflected=1.0, sql_error_pattern=0.0)
        sql_error = self._vector(marker_reflected=1.0, sql_error_pattern=1.0)
        first = XSSScorer().score(no_sql_error)
        second = XSSScorer().score(sql_error)
        self.assertEqual(first.candidate.rank_score, second.candidate.rank_score)
        self.assertNotIn(SQL_ERROR_PATTERN, {item.feature_name for item in first.evidence})

    def test_scoring_is_deterministic_and_mapping_order_independent(self) -> None:
        vector = self._vector(
            status_code_changed=1.0,
            response_length_diff_ratio=0.25,
            marker_reflected=1.0,
            sql_error_pattern=1.0,
        )
        equivalent = self._vector(
            status_code_changed=1.0,
            response_length_diff_ratio=0.25,
            marker_reflected=1.0,
            sql_error_pattern=1.0,
            reverse_features=True,
        )
        first = generate_candidates(vector)
        self.assertEqual(vector.id, equivalent.id)
        self.assertEqual(first, generate_candidates(vector))
        self.assertEqual(first, generate_candidates(equivalent))

    def test_missing_feature_is_not_observed_zero(self) -> None:
        missing = XSSScorer().score(
            self._vector(missing=frozenset({MARKER_REFLECTED}))
        )
        observed_zero = XSSScorer().score(self._vector(marker_reflected=0.0))
        missing_marker = next(
            item for item in missing.evidence if item.feature_name == MARKER_REFLECTED
        )
        zero_marker = next(
            item
            for item in observed_zero.evidence
            if item.feature_name == MARKER_REFLECTED
        )
        self.assertFalse(missing_marker.observed)
        self.assertIsNone(missing_marker.feature_value)
        self.assertIsNone(missing_marker.contribution)
        self.assertTrue(zero_marker.observed)
        self.assertEqual(zero_marker.feature_value, 0.0)
        self.assertEqual(zero_marker.contribution, 0.0)

    def test_execution_failure_missing_evidence_stays_unavailable(self) -> None:
        vector = self._execution_failure_vector()
        self.assertTrue(all(not item.observed for item in vector.features.values()))
        for result in generate_candidates(vector):
            self.assertEqual(result.candidate.rank_score, 0.0)
            self.assertTrue(all(not item.observed for item in result.evidence))
            self.assertTrue(all(item.feature_value is None for item in result.evidence))
            self.assertTrue(all(item.contribution is None for item in result.evidence))
            self.assertTrue(
                all("execution-error" in item.reason for item in result.evidence)
            )

    def test_all_missing_features_create_no_artificial_evidence(self) -> None:
        vector = self._vector(
            missing=frozenset(
                {
                    STATUS_CODE_CHANGED,
                    RESPONSE_LENGTH_DIFF_RATIO,
                    MARKER_REFLECTED,
                    SQL_ERROR_PATTERN,
                }
            )
        )
        for result in generate_candidates(vector):
            self.assertEqual(result.candidate.rank_score, 0.0)
            self.assertTrue(all(not item.observed for item in result.evidence))
            explanation = " ".join(item.reason.lower() for item in result.evidence)
            self.assertNotIn("safe", explanation)
            self.assertNotIn("confirmed", explanation)

    def test_present_contributions_exactly_reconstruct_raw_scores(self) -> None:
        vector = self._vector(
            status_code_changed=1.0,
            response_length_diff_ratio=0.5,
            marker_reflected=1.0,
            sql_error_pattern=1.0,
        )
        sqli, xss = generate_candidates(vector)
        self.assertEqual(sqli.candidate.rank_score, 65.0)
        self.assertEqual(xss.candidate.rank_score, 40.0)
        for result in (sqli, xss):
            contributions = tuple(
                item.contribution
                for item in result.evidence
                if item.contribution is not None
            )
            self.assertEqual(result.candidate.rank_score, sum(contributions))

    def test_documented_available_score_scales_are_fixed(self) -> None:
        self.assertEqual(SQLI_MAX_RANK_SCORE, 75.0)
        self.assertEqual(XSS_MAX_RANK_SCORE, 45.0)

    def test_out_of_schema_feature_value_cannot_escape_score_scale(self) -> None:
        with self.assertRaisesRegex(ScoringError, "between 0.0 and 1.0"):
            SQLiScorer().score(self._vector(status_code_changed=1.1))

    def test_candidate_owner_can_only_come_from_feature_vector(self) -> None:
        vector = self._vector(input_point_id="inp_exact_owner")
        self.assertEqual(
            tuple(inspect.signature(generate_candidates).parameters),
            ("feature_vector",),
        )
        results = CandidateGenerator().generate(vector)
        self.assertTrue(
            all(
                result.candidate.input_point_id == vector.input_point_id
                for result in results
            )
        )

    def test_score_evidence_retains_exact_feature_vector_provenance(self) -> None:
        first_vector = self._vector(probe_run_id="pair_context_A")
        second_vector = self._vector(probe_run_id="pair_context_B")
        first = SQLiScorer().score(first_vector)
        second = SQLiScorer().score(second_vector)
        self.assertEqual(first.candidate.id, second.candidate.id)
        self.assertNotEqual(first.feature_vector_id, second.feature_vector_id)
        self.assertTrue(
            all(
                item.feature_vector_id == first_vector.id for item in first.evidence
            )
        )
        self.assertTrue(
            all(
                item.feature_vector_id == second_vector.id for item in second.evidence
            )
        )

    def test_scoring_does_not_mutate_feature_vector(self) -> None:
        vector = self._vector(
            status_code_changed=1.0,
            response_length_diff_ratio=0.5,
            marker_reflected=1.0,
            sql_error_pattern=1.0,
        )
        before = (
            vector.id,
            vector.input_point_id,
            vector.probe_run_ids,
            tuple(vector.features.items()),
        )
        generate_candidates(vector)
        after = (
            vector.id,
            vector.input_point_id,
            vector.probe_run_ids,
            tuple(vector.features.items()),
        )
        self.assertEqual(before, after)

    def test_rank_score_is_not_confidence_or_finding_state(self) -> None:
        result = SQLiScorer().score(self._vector(sql_error_pattern=1.0))
        self.assertIsInstance(result.candidate.rank_score, float)
        self.assertFalse(hasattr(result.candidate, "confidence"))
        self.assertFalse(hasattr(result.candidate, "confirmed"))
        self.assertFalse(hasattr(result, "finding"))


class ScoringResultOwnershipTests(unittest.TestCase):
    def _input_point(self, occurrence_index: int | None = None) -> InputPoint:
        return InputPoint(
            endpoint_id="ep_search",
            endpoint_fingerprint="endpoint-fingerprint",
            location=InputLocation.QUERY,
            name="tag" if occurrence_index is not None else "q",
            occurrence_index=occurrence_index,
            baseline_value="a",
        )

    def _vector(
        self,
        input_point_id: str,
        *,
        status_code_changed: float = 0.0,
        response_length_diff_ratio: float = 0.0,
        marker_reflected: float = 0.0,
        sql_error_pattern: float = 0.0,
        probe_run_id: str = "pair_ownership",
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
                    source="ownership-test",
                    extractor_version="unit-v1",
                )
                for name, value in values.items()
            },
        )

    def test_reported_public_cross_owner_construction_is_closed(self) -> None:
        input_a = self._input_point()
        input_b = InputPoint(
            endpoint_id="ep_items",
            endpoint_fingerprint="other-endpoint-fingerprint",
            location=InputLocation.QUERY,
            name="q",
            baseline_value="a",
        )
        vector_a = self._vector(input_a.id or "")
        candidate_b = VulnerabilityCandidate(
            input_point_id=input_b.id or "",
            vulnerability_type=VulnerabilityType.SQLI,
        )

        with self.assertRaisesRegex(TypeError, "from_objects"):
            ScoringResult(
                feature_vector_id=vector_a.id or "",
                candidate=candidate_b,
                evidence=(),
            )
        with self.assertRaisesRegex(ScoringError, "ownership mismatch"):
            ScoringResult.from_objects(vector_a, candidate_b, ())

    def test_valid_same_owner_cross_type_results_remain_supported(self) -> None:
        input_a = self._input_point()
        vector_a = self._vector(input_a.id or "")
        sqli_candidate = VulnerabilityCandidate(
            input_point_id=input_a.id or "",
            vulnerability_type=VulnerabilityType.SQLI,
        )
        xss_candidate = VulnerabilityCandidate(
            input_point_id=input_a.id or "",
            vulnerability_type=VulnerabilityType.REFLECTED_XSS,
        )

        sqli = ScoringResult.from_objects(vector_a, sqli_candidate, ())
        xss = ScoringResult.from_objects(vector_a, xss_candidate, ())

        self.assertEqual(sqli.candidate.input_point_id, vector_a.input_point_id)
        self.assertEqual(xss.candidate.input_point_id, vector_a.input_point_id)
        self.assertNotEqual(sqli.candidate.id, xss.candidate.id)

    def test_equal_repeated_occurrence_mismatch_is_rejected(self) -> None:
        first_input = self._input_point(occurrence_index=0)
        second_input = self._input_point(occurrence_index=1)
        first_vector = self._vector(first_input.id or "")
        second_candidate = VulnerabilityCandidate(
            input_point_id=second_input.id or "",
            vulnerability_type=VulnerabilityType.SQLI,
        )

        self.assertEqual(first_input.baseline_value, second_input.baseline_value)
        self.assertNotEqual(first_input.id, second_input.id)
        with self.assertRaisesRegex(ScoringError, "ownership mismatch"):
            ScoringResult.from_objects(first_vector, second_candidate, ())

    def test_evidence_candidate_vector_and_type_mismatches_are_rejected(self) -> None:
        input_a = self._input_point()
        vector_a = self._vector(
            input_a.id or "",
            status_code_changed=1.0,
            response_length_diff_ratio=0.5,
            sql_error_pattern=1.0,
        )
        valid = SQLiScorer().score(vector_a)
        self.assertEqual(
            ScoringResult.from_objects(vector_a, valid.candidate, valid.evidence),
            valid,
        )

        other_context = self._vector(
            input_a.id or "",
            status_code_changed=1.0,
            response_length_diff_ratio=0.5,
            sql_error_pattern=1.0,
            probe_run_id="pair_other_context",
        )
        with self.assertRaisesRegex(ScoringError, "FeatureVector ownership"):
            ScoringResult.from_objects(
                other_context,
                valid.candidate,
                valid.evidence,
            )

        wrong_candidate_evidence = (
            replace(valid.evidence[0], candidate_id="cand_wrong"),
            *valid.evidence[1:],
        )
        with self.assertRaisesRegex(ScoringError, "candidate ownership"):
            ScoringResult.from_objects(
                vector_a,
                valid.candidate,
                wrong_candidate_evidence,
            )

        wrong_type_evidence = (
            replace(
                valid.evidence[0],
                vulnerability_type=VulnerabilityType.REFLECTED_XSS,
            ),
            *valid.evidence[1:],
        )
        with self.assertRaisesRegex(ScoringError, "vulnerability type"):
            ScoringResult.from_objects(
                vector_a,
                valid.candidate,
                wrong_type_evidence,
            )

    def test_normal_scorer_arithmetic_is_unchanged(self) -> None:
        input_a = self._input_point()
        sqli_vector = self._vector(
            input_a.id or "",
            status_code_changed=1.0,
            response_length_diff_ratio=0.5,
            sql_error_pattern=1.0,
        )
        xss_vector = self._vector(
            input_a.id or "",
            response_length_diff_ratio=0.3,
            marker_reflected=1.0,
        )

        self.assertEqual(SQLiScorer().score(sqli_vector).candidate.rank_score, 65.0)
        self.assertEqual(XSSScorer().score(xss_vector).candidate.rank_score, 38.0)


if __name__ == "__main__":
    unittest.main()
