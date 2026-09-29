from __future__ import annotations

import unittest

from vulnspider.access.features import (
    ACCESS_BODY_SIZE_SIMILARITY_RATIO,
    ACCESS_UNAUTHORIZED_SUCCESS,
)
from vulnspider.access.scoring import score_access_plan
from vulnspider.access.selection import AccessSelectionError, select_top_k_access
from vulnspider.domain import (
    AccessCheckKind,
    AccessProbePlan,
    AccessSubjectContext,
    FeatureObservation,
    FeatureVector,
    HttpMethod,
    InputLocation,
    InputPoint,
    RequestInstance,
)
from vulnspider.features import (
    MARKER_REFLECTED,
    RESPONSE_LENGTH_DIFF_RATIO,
    SQL_ERROR_PATTERN,
    STATUS_CODE_CHANGED,
)
from vulnspider.scoring import SQLiScorer, XSSScorer
from vulnspider.selection import select_top_k
from vulnspider.selection.combined import CombinedSelectionError, select_combined_top_k


def _access_plan(resource_reference_suffix: str) -> AccessProbePlan:
    return AccessProbePlan(
        endpoint_id="ep",
        endpoint_fingerprint="fp",
        request_template_id="rt",
        check_kind=AccessCheckKind.CREDENTIAL_STRIP,
        reference_request=RequestInstance(
            method=HttpMethod.GET,
            url=f"http://127.0.0.1/account/{resource_reference_suffix}",
            cookies={"session": "abc"},
        ),
        comparison_request=RequestInstance(
            method=HttpMethod.GET,
            url=f"http://127.0.0.1/account/{resource_reference_suffix}",
        ),
        reference_subject=AccessSubjectContext.ORIGINAL,
        comparison_subject=AccessSubjectContext.ANONYMOUS,
        changed_aspect="credentials",
    )


def _access_result(*, suffix: str, unauthorized_success: float, similarity: float):
    plan = _access_plan(suffix)
    features = {
        ACCESS_UNAUTHORIZED_SUCCESS: FeatureObservation(
            name=ACCESS_UNAUTHORIZED_SUCCESS,
            value=unauthorized_success,
            observed=True,
            source="unit-test",
            extractor_version="unit-v1",
        ),
        ACCESS_BODY_SIZE_SIMILARITY_RATIO: FeatureObservation(
            name=ACCESS_BODY_SIZE_SIMILARITY_RATIO,
            value=similarity,
            observed=True,
            source="unit-test",
            extractor_version="unit-v1",
        ),
    }
    return score_access_plan(plan, features)


def _injection_vector(input_point_id: str, **values: float) -> FeatureVector:
    defaults = {
        STATUS_CODE_CHANGED: 0.0,
        RESPONSE_LENGTH_DIFF_RATIO: 0.0,
        MARKER_REFLECTED: 0.0,
        SQL_ERROR_PATTERN: 0.0,
    }
    defaults.update(values)
    return FeatureVector(
        input_point_id=input_point_id,
        probe_run_ids=("pair_1",),
        features={
            name: FeatureObservation(
                name=name,
                value=value,
                observed=True,
                source="unit-test",
                extractor_version="unit-v1",
            )
            for name, value in defaults.items()
        },
    )


class AccessSelectionTests(unittest.TestCase):
    def test_orders_by_priority_and_dedupes_candidate_identity(self) -> None:
        weak = _access_result(suffix="a", unauthorized_success=0.0, similarity=0.0)
        strong = _access_result(suffix="b", unauthorized_success=1.0, similarity=1.0)
        outcome = select_top_k_access((weak, strong), k=5)
        self.assertEqual(outcome.summary.selected_results, 2)
        self.assertEqual(
            outcome.selected[0].scoring_result.candidate.id, strong.candidate.id
        )
        self.assertEqual(outcome.selected[0].selection_priority, 1.0)

    def test_rejects_non_positive_k(self) -> None:
        with self.assertRaisesRegex(AccessSelectionError, "positive integer"):
            select_top_k_access((), k=0)


class CombinedSelectionTests(unittest.TestCase):
    def _input_point(self, name: str) -> InputPoint:
        return InputPoint(
            endpoint_id="ep",
            endpoint_fingerprint="fp",
            location=InputLocation.QUERY,
            name=name,
            baseline_value="a",
        )

    def test_top_access_candidate_outranks_weaker_injection_candidates(self) -> None:
        weak_sqli = SQLiScorer().score(
            self._injection_vector_for("weak", sql_error_pattern=0.1)
        )
        strong_access = _access_result(suffix="c", unauthorized_success=1.0, similarity=1.0)

        injection_outcome = select_top_k((weak_sqli,), k=3)
        access_outcome = select_top_k_access((strong_access,), k=3)
        combined = select_combined_top_k(injection_outcome, access_outcome, k=3)

        self.assertEqual(combined.summary.total_scoring_results, 2)
        self.assertEqual(combined.summary.selected_results, 2)
        self.assertEqual(combined.selected[0].origin, "access")
        self.assertEqual(combined.selected[1].origin, "injection")

    def test_merge_is_exact_subset_of_each_categorys_own_top_k(self) -> None:
        # Three injection candidates and three access candidates, ranked K=2:
        # the true global top-2 must equal running each selector at K=2 and
        # merging -- this is the correctness property select_combined_top_k
        # relies on instead of re-deriving a single flat ranking.
        strong_xss = XSSScorer().score(
            self._injection_vector_for(
                "s1", marker_reflected=1.0, response_length_diff_ratio=1.0
            )
        )
        medium_sqli = SQLiScorer().score(
            self._injection_vector_for("s2", status_code_changed=1.0)
        )
        weak_sqli = SQLiScorer().score(
            self._injection_vector_for("s3", response_length_diff_ratio=0.1)
        )
        # similarity=0.9 (not 1.0) keeps this strictly below strong_xss's 1.0
        # priority so the top rank is unambiguous rather than a same-priority tie.
        strong_access = _access_result(suffix="x1", unauthorized_success=1.0, similarity=0.9)
        medium_access = _access_result(suffix="x2", unauthorized_success=1.0, similarity=0.0)
        weak_access = _access_result(suffix="x3", unauthorized_success=0.0, similarity=0.2)

        injection_outcome = select_top_k(
            (strong_xss, medium_sqli, weak_sqli), k=2
        )
        access_outcome = select_top_k_access(
            (strong_access, medium_access, weak_access), k=2
        )
        combined = select_combined_top_k(injection_outcome, access_outcome, k=2)

        self.assertEqual(len(combined.selected), 2)
        self.assertEqual(combined.selected[0].origin, "injection")
        self.assertEqual(
            combined.selected[0].candidate_id, strong_xss.candidate.id
        )
        self.assertEqual(combined.selected[1].origin, "access")
        self.assertEqual(
            combined.selected[1].candidate_id, strong_access.candidate.id
        )

    def test_requires_same_k_used_for_both_sub_selections(self) -> None:
        access = _access_result(suffix="k", unauthorized_success=1.0, similarity=1.0)
        injection_outcome = select_top_k((), k=1)
        access_outcome = select_top_k_access((access,), k=3)
        with self.assertRaisesRegex(CombinedSelectionError, "same k"):
            select_combined_top_k(injection_outcome, access_outcome, k=1)

    def test_empty_access_results_leave_injection_only_behavior_unchanged(self) -> None:
        sqli = SQLiScorer().score(
            self._injection_vector_for("only", sql_error_pattern=1.0)
        )
        injection_outcome = select_top_k((sqli,), k=5)
        access_outcome = select_top_k_access((), k=5)
        combined = select_combined_top_k(injection_outcome, access_outcome, k=5)
        self.assertEqual(combined.summary.total_scoring_results, 1)
        self.assertEqual(len(combined.selected), 1)
        self.assertEqual(combined.selected[0].origin, "injection")
        self.assertEqual(
            combined.selected[0].injection_result.raw_rank_score,
            injection_outcome.selected[0].raw_rank_score,
        )

    def _injection_vector_for(self, suffix: str, **values: float) -> FeatureVector:
        return _injection_vector(self._input_point(suffix).id or "", **values)


if __name__ == "__main__":
    unittest.main()
