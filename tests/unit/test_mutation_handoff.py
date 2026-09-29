from __future__ import annotations

import unittest

from vulnspider.access.features import (
    ACCESS_BODY_SIZE_SIMILARITY_RATIO,
    ACCESS_UNAUTHORIZED_SUCCESS,
)
from vulnspider.access.scoring import ACCESS_SCORER_VERSION, score_access_plan
from vulnspider.access.selection import select_top_k_access
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
from vulnspider.selection import select_combined_top_k, select_top_k
from vulnspider.selection.handoff import (
    FAMILY_BROKEN_ACCESS_CONTROL,
    HANDOFF_CONTRACT_VERSION,
    SUBJECT_KIND_BAC_ACCESS_CONTEXT,
    SUBJECT_KIND_INPUT_POINT,
    MutationHandoff,
    MutationHandoffError,
    RankedCandidateContext,
    build_mutation_handoff,
)


def _access_plan(suffix: str) -> AccessProbePlan:
    return AccessProbePlan(
        endpoint_id="ep",
        endpoint_fingerprint="fp",
        request_template_id="rt",
        check_kind=AccessCheckKind.CREDENTIAL_STRIP,
        reference_request=RequestInstance(
            method=HttpMethod.GET,
            url=f"http://127.0.0.1/account/{suffix}",
            cookies={"session": "abc"},
        ),
        comparison_request=RequestInstance(
            method=HttpMethod.GET,
            url=f"http://127.0.0.1/account/{suffix}",
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


def _input_point(name: str) -> InputPoint:
    return InputPoint(
        endpoint_id="ep",
        endpoint_fingerprint="fp",
        location=InputLocation.QUERY,
        name=name,
        baseline_value="a",
    )


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


def _sqli_result(name: str, **values: float):
    return SQLiScorer().score(_injection_vector(_input_point(name).id or "", **values))


def _xss_result(name: str, **values: float):
    return XSSScorer().score(_injection_vector(_input_point(name).id or "", **values))


def _mixed_combined(k: int = 3):
    strong_xss = _xss_result(
        "s1", marker_reflected=1.0, response_length_diff_ratio=1.0
    )
    weak_sqli = _sqli_result("s3", response_length_diff_ratio=0.1)
    strong_access = _access_result(suffix="x1", unauthorized_success=1.0, similarity=0.9)
    injection_outcome = select_top_k((strong_xss, weak_sqli), k=k)
    access_outcome = select_top_k_access((strong_access,), k=k)
    return select_combined_top_k(injection_outcome, access_outcome, k=k), {
        "strong_xss": strong_xss,
        "strong_access": strong_access,
    }


class BuildMutationHandoffTests(unittest.TestCase):
    def test_projects_every_selected_candidate_in_rank_order(self) -> None:
        combined, ctx = _mixed_combined(k=3)
        handoff = build_mutation_handoff(combined, selection_run_id="run-1")

        self.assertIsInstance(handoff, MutationHandoff)
        self.assertEqual(handoff.contract_version, HANDOFF_CONTRACT_VERSION)
        self.assertEqual(handoff.selection_run_id, "run-1")
        self.assertEqual(handoff.top_k_requested, 3)
        self.assertEqual(handoff.selected_results, len(handoff.contexts))
        self.assertEqual(
            [c.candidate_id for c in handoff.contexts],
            [entry.candidate_id for entry in combined.selected],
        )
        self.assertEqual([c.rank for c in handoff.contexts], [1, 2, 3])

    def test_injection_context_carries_input_point_provenance(self) -> None:
        combined, ctx = _mixed_combined(k=3)
        handoff = build_mutation_handoff(combined, selection_run_id="run-1")
        injection = next(c for c in handoff.contexts if c.origin == "injection")

        self.assertEqual(injection.candidate_id, ctx["strong_xss"].candidate.id)
        self.assertEqual(injection.candidate_subject_kind, SUBJECT_KIND_INPUT_POINT)
        self.assertEqual(injection.family, "REFLECTED_XSS")
        self.assertIsNone(injection.check_kind)
        self.assertEqual(
            injection.feature_vector_id, ctx["strong_xss"].feature_vector_id
        )
        self.assertIsNone(injection.access_probe_plan_id)
        self.assertEqual(
            injection.candidate_subject_ref,
            ctx["strong_xss"].candidate.input_point_id,
        )
        self.assertEqual(injection.request_context_ref, injection.candidate_subject_ref)
        self.assertEqual(
            injection.score_evidence, tuple(ctx["strong_xss"].evidence)
        )

    def test_access_context_carries_access_probe_plan_provenance(self) -> None:
        combined, ctx = _mixed_combined(k=3)
        handoff = build_mutation_handoff(combined, selection_run_id="run-1")
        access = next(c for c in handoff.contexts if c.origin == "access")

        self.assertEqual(access.candidate_id, ctx["strong_access"].candidate.id)
        self.assertEqual(
            access.candidate_subject_kind, SUBJECT_KIND_BAC_ACCESS_CONTEXT
        )
        self.assertEqual(access.family, FAMILY_BROKEN_ACCESS_CONTROL)
        self.assertEqual(access.check_kind, AccessCheckKind.CREDENTIAL_STRIP.value)
        self.assertEqual(
            access.access_probe_plan_id,
            ctx["strong_access"].access_probe_plan_id,
        )
        self.assertIsNone(access.feature_vector_id)
        self.assertEqual(access.scorer_version, ACCESS_SCORER_VERSION)
        self.assertEqual(
            access.request_context_ref, ctx["strong_access"].access_probe_plan_id
        )

    def test_contexts_are_ordered_by_descending_selection_priority(self) -> None:
        combined, _ = _mixed_combined(k=3)
        handoff = build_mutation_handoff(combined, selection_run_id="run-1")
        priorities = [c.selection_priority for c in handoff.contexts]
        self.assertEqual(priorities, sorted(priorities, reverse=True))

    def test_does_not_recompute_priority_or_score(self) -> None:
        combined, _ = _mixed_combined(k=3)
        handoff = build_mutation_handoff(combined, selection_run_id="run-1")
        for context, entry in zip(handoff.contexts, combined.selected, strict=True):
            ranked = entry.injection_result or entry.access_result
            self.assertEqual(context.raw_rank_score, ranked.raw_rank_score)
            self.assertEqual(context.raw_rank_score_max, ranked.raw_rank_score_max)
            self.assertEqual(context.selection_priority, ranked.selection_priority)

    def test_ranked_context_id_is_deterministic_and_run_scoped(self) -> None:
        combined, _ = _mixed_combined(k=3)
        first = build_mutation_handoff(combined, selection_run_id="run-1")
        again = build_mutation_handoff(combined, selection_run_id="run-1")
        other_run = build_mutation_handoff(combined, selection_run_id="run-2")

        self.assertEqual(
            [c.ranked_context_id for c in first.contexts],
            [c.ranked_context_id for c in again.contexts],
        )
        self.assertNotEqual(
            {c.ranked_context_id for c in first.contexts},
            {c.ranked_context_id for c in other_run.contexts},
        )

    def test_empty_combined_outcome_produces_empty_handoff(self) -> None:
        injection_outcome = select_top_k((), k=4)
        access_outcome = select_top_k_access((), k=4)
        combined = select_combined_top_k(injection_outcome, access_outcome, k=4)
        handoff = build_mutation_handoff(combined, selection_run_id="run-1")
        self.assertEqual(handoff.contexts, ())
        self.assertEqual(handoff.selected_results, 0)
        self.assertEqual(handoff.top_k_requested, 4)

    def test_rejects_empty_selection_run_id(self) -> None:
        combined, _ = _mixed_combined(k=3)
        with self.assertRaisesRegex(MutationHandoffError, "selection_run_id"):
            build_mutation_handoff(combined, selection_run_id="")

    def test_rejects_non_combined_outcome(self) -> None:
        with self.assertRaisesRegex(MutationHandoffError, "CombinedSelectionOutcome"):
            build_mutation_handoff(object(), selection_run_id="run-1")

    def test_direct_construction_is_forbidden(self) -> None:
        with self.assertRaises(TypeError):
            RankedCandidateContext()
        with self.assertRaises(TypeError):
            MutationHandoff()


if __name__ == "__main__":
    unittest.main()
