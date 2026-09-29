"""Selection -> mutation handoff for the combined Top-K.

The mutation module (LLM-assisted Payload Mutation, owned by 석현) is the
consumer of the selection module's (수훈) authoritative Top-K. This module is
the boundary between them: it turns one already-validated
:class:`~vulnspider.selection.combined.CombinedSelectionOutcome` into an
ordered bundle of :class:`RankedCandidateContext` records -- the shape
``docs/TEAM_INTERFACES_V0_2.md`` #2 reserves for that handoff.

It is a projection only. It never recomputes a RankScore, ``selection_priority``,
or rank, and it never re-derives evidence: every field is copied from the
authoritative ranked result the combined selector already produced (ADR-010,
ADR-016). Each entry keeps its ``origin`` so the consumer can branch by family
-- inject a mutated payload into the referenced ``InputPoint`` for SQLi/XSS,
or run the reviewed BAC verification for an ``AccessCandidate`` (ADR-014).

Deliberately omitted fields
---------------------------
``docs/TEAM_INTERFACES_V0_2.md`` #2 also lists ``target_scope_id`` and
``allowed_verification_policy``. Those are owned by the scope/verification-policy
boundaries, not by selection; per the contract's "stable IDs are produced by
the authoritative owner, never reconstructed" and "display strings are not data
contracts" principles this module does not invent them. The consumer attaches
them from their real owners before any request is planned.
"""

from __future__ import annotations

from dataclasses import dataclass

from vulnspider.access.selection import RankedAccessScoringResult
from vulnspider.domain import (
    AccessScoreEvidence,
    ScoreEvidence,
    stable_fingerprint,
)
from vulnspider.selection.combined import (
    CandidateOrigin,
    CombinedRankedEntry,
    CombinedSelectionError,
    CombinedSelectionOutcome,
)
from vulnspider.selection.top_k import RankedScoringResult

HANDOFF_CONTRACT_VERSION = "0.1"

# Discriminators reserved by docs/TEAM_INTERFACES_V0_2.md #2.
SUBJECT_KIND_INPUT_POINT = "input_point"
SUBJECT_KIND_BAC_ACCESS_CONTEXT = "bac_access_context"

# Family label carried alongside the origin so the consumer can branch without
# re-reading the candidate object. Injection families reuse the exact
# VulnerabilityType value; BAC uses one family label with check_kind as its
# sub-discriminator.
FAMILY_BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"


class MutationHandoffError(ValueError):
    """Raised when a combined outcome cannot be projected into a handoff."""


@dataclass(frozen=True, slots=True, init=False)
class RankedCandidateContext:
    """One selected candidate and its authoritative ranking, ready for mutation.

    Carries only what the selection boundary authoritatively owns. ``origin``
    plus ``candidate_subject_kind`` tell the consumer which provenance fields
    are populated: injection entries carry ``feature_vector_id`` and an
    ``input_point`` subject; access entries carry ``access_probe_plan_id`` and
    a ``bac_access_context`` subject.
    """

    contract_version: str
    ranked_context_id: str
    selection_run_id: str
    rank: int
    origin: CandidateOrigin
    candidate_id: str
    candidate_subject_kind: str
    candidate_subject_ref: str
    family: str
    check_kind: str | None
    scorer_version: str
    raw_rank_score: float
    raw_rank_score_max: float
    selection_priority: float
    feature_vector_id: str | None
    access_probe_plan_id: str | None
    request_context_ref: str
    score_evidence: tuple[ScoreEvidence | AccessScoreEvidence, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "RankedCandidateContext is produced only by build_mutation_handoff()"
        )

    @classmethod
    def _from_entry(
        cls,
        entry: CombinedRankedEntry,
        *,
        selection_run_id: str,
        rank: int,
    ) -> RankedCandidateContext:
        if entry.origin == "injection":
            fields = _injection_fields(entry.injection_result)
        elif entry.origin == "access":
            fields = _access_fields(entry.access_result)
        else:  # pragma: no cover - CombinedRankedEntry already rejects this
            raise MutationHandoffError(f"unsupported entry origin: {entry.origin}")

        if fields.candidate_id != entry.candidate_id:
            raise MutationHandoffError(
                "combined entry candidate_id does not match its ranked result"
            )
        if fields.selection_priority != entry.selection_priority:
            raise MutationHandoffError(
                "combined entry selection_priority does not match its ranked result"
            )

        ranked_context_id = _ranked_context_id(
            selection_run_id=selection_run_id,
            candidate_id=fields.candidate_id,
            origin=entry.origin,
            provenance_ref=fields.request_context_ref,
            scorer_version=fields.scorer_version,
        )
        instance = object.__new__(cls)
        object.__setattr__(instance, "contract_version", HANDOFF_CONTRACT_VERSION)
        object.__setattr__(instance, "ranked_context_id", ranked_context_id)
        object.__setattr__(instance, "selection_run_id", selection_run_id)
        object.__setattr__(instance, "rank", rank)
        object.__setattr__(instance, "origin", entry.origin)
        object.__setattr__(instance, "candidate_id", fields.candidate_id)
        object.__setattr__(instance, "candidate_subject_kind", fields.subject_kind)
        object.__setattr__(instance, "candidate_subject_ref", fields.subject_ref)
        object.__setattr__(instance, "family", fields.family)
        object.__setattr__(instance, "check_kind", fields.check_kind)
        object.__setattr__(instance, "scorer_version", fields.scorer_version)
        object.__setattr__(instance, "raw_rank_score", fields.raw_rank_score)
        object.__setattr__(instance, "raw_rank_score_max", fields.raw_rank_score_max)
        object.__setattr__(instance, "selection_priority", fields.selection_priority)
        object.__setattr__(instance, "feature_vector_id", fields.feature_vector_id)
        object.__setattr__(instance, "access_probe_plan_id", fields.access_probe_plan_id)
        object.__setattr__(instance, "request_context_ref", fields.request_context_ref)
        object.__setattr__(instance, "score_evidence", fields.score_evidence)
        instance.validate()
        return instance

    def validate(self) -> None:
        if self.contract_version != HANDOFF_CONTRACT_VERSION:
            raise MutationHandoffError("unexpected handoff contract version")
        if not self.selection_run_id:
            raise MutationHandoffError("selection_run_id must not be empty")
        if isinstance(self.rank, bool) or not isinstance(self.rank, int):
            raise MutationHandoffError("rank must be an integer")
        if self.rank <= 0:
            raise MutationHandoffError("rank must be a positive integer")
        if not self.candidate_id:
            raise MutationHandoffError("candidate_id must not be empty")
        if not self.ranked_context_id:
            raise MutationHandoffError("ranked_context_id must not be empty")
        if not self.scorer_version:
            raise MutationHandoffError("scorer_version must not be empty")
        if self.raw_rank_score_max <= 0.0:
            raise MutationHandoffError("raw_rank_score_max must be positive")
        expected_priority = self.raw_rank_score / self.raw_rank_score_max
        if self.selection_priority != expected_priority:
            raise MutationHandoffError(
                "selection_priority must equal raw_rank_score / raw_rank_score_max"
            )
        if self.origin == "injection":
            if self.candidate_subject_kind != SUBJECT_KIND_INPUT_POINT:
                raise MutationHandoffError(
                    "injection context must use the input_point subject kind"
                )
            if self.feature_vector_id is None or self.access_probe_plan_id is not None:
                raise MutationHandoffError(
                    "injection context must carry exactly a feature_vector_id"
                )
            if self.check_kind is not None:
                raise MutationHandoffError("injection context must not carry a check_kind")
        elif self.origin == "access":
            if self.candidate_subject_kind != SUBJECT_KIND_BAC_ACCESS_CONTEXT:
                raise MutationHandoffError(
                    "access context must use the bac_access_context subject kind"
                )
            if self.access_probe_plan_id is None or self.feature_vector_id is not None:
                raise MutationHandoffError(
                    "access context must carry exactly an access_probe_plan_id"
                )
            if not self.check_kind:
                raise MutationHandoffError("access context must carry a check_kind")
        else:  # pragma: no cover - _from_entry already rejects this
            raise MutationHandoffError(f"unsupported origin: {self.origin}")
        if not self.request_context_ref:
            raise MutationHandoffError("request_context_ref must not be empty")


@dataclass(frozen=True, slots=True, init=False)
class MutationHandoff:
    """The ordered, validated bundle delivered to the mutation module."""

    contract_version: str
    selection_run_id: str
    top_k_requested: int
    selected_results: int
    contexts: tuple[RankedCandidateContext, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("MutationHandoff is produced only by build_mutation_handoff()")

    @classmethod
    def _from_contexts(
        cls,
        *,
        selection_run_id: str,
        top_k_requested: int,
        selected_results: int,
        contexts: tuple[RankedCandidateContext, ...],
    ) -> MutationHandoff:
        instance = object.__new__(cls)
        object.__setattr__(instance, "contract_version", HANDOFF_CONTRACT_VERSION)
        object.__setattr__(instance, "selection_run_id", selection_run_id)
        object.__setattr__(instance, "top_k_requested", top_k_requested)
        object.__setattr__(instance, "selected_results", selected_results)
        object.__setattr__(instance, "contexts", tuple(contexts))
        instance.validate()
        return instance

    def validate(self) -> None:
        if self.contract_version != HANDOFF_CONTRACT_VERSION:
            raise MutationHandoffError("unexpected handoff contract version")
        if not self.selection_run_id:
            raise MutationHandoffError("selection_run_id must not be empty")
        if self.selected_results != len(self.contexts):
            raise MutationHandoffError(
                "selected_results must match the number of ranked contexts"
            )
        if self.selected_results > self.top_k_requested:
            raise MutationHandoffError("selected_results cannot exceed requested top-k")
        for position, context in enumerate(self.contexts, start=1):
            if not isinstance(context, RankedCandidateContext):
                raise MutationHandoffError(
                    "contexts must contain RankedCandidateContext objects"
                )
            context.validate()
            if context.rank != position:
                raise MutationHandoffError("ranked contexts must be densely ranked from 1")
            if context.selection_run_id != self.selection_run_id:
                raise MutationHandoffError(
                    "every ranked context must share the bundle selection_run_id"
                )
        priorities = [context.selection_priority for context in self.contexts]
        if priorities != sorted(priorities, reverse=True):
            raise MutationHandoffError(
                "ranked contexts must be ordered by descending selection_priority"
            )
        context_ids = tuple(context.candidate_id for context in self.contexts)
        if len(context_ids) != len(set(context_ids)):
            raise MutationHandoffError("ranked contexts must reference unique candidates")


def build_mutation_handoff(
    combined_outcome: CombinedSelectionOutcome,
    *,
    selection_run_id: str,
) -> MutationHandoff:
    """Project a validated combined Top-K into the mutation-module handoff."""

    if not isinstance(combined_outcome, CombinedSelectionOutcome):
        raise MutationHandoffError("combined_outcome must be a CombinedSelectionOutcome")
    if not isinstance(selection_run_id, str) or not selection_run_id:
        raise MutationHandoffError("selection_run_id must be a non-empty string")
    try:
        combined_outcome.validate()
    except CombinedSelectionError as exc:
        raise MutationHandoffError(
            "combined selection outcome is internally inconsistent"
        ) from exc

    contexts = tuple(
        RankedCandidateContext._from_entry(
            entry,
            selection_run_id=selection_run_id,
            rank=rank,
        )
        for rank, entry in enumerate(combined_outcome.selected, start=1)
    )
    return MutationHandoff._from_contexts(
        selection_run_id=selection_run_id,
        top_k_requested=combined_outcome.summary.top_k_requested,
        selected_results=combined_outcome.summary.selected_results,
        contexts=contexts,
    )


@dataclass(frozen=True, slots=True)
class _ProjectedFields:
    candidate_id: str
    subject_kind: str
    subject_ref: str
    family: str
    check_kind: str | None
    scorer_version: str
    raw_rank_score: float
    raw_rank_score_max: float
    selection_priority: float
    feature_vector_id: str | None
    access_probe_plan_id: str | None
    request_context_ref: str
    score_evidence: tuple[ScoreEvidence | AccessScoreEvidence, ...]


def _injection_fields(item: RankedScoringResult | None) -> _ProjectedFields:
    if not isinstance(item, RankedScoringResult):
        raise MutationHandoffError("injection entry is missing its ranked result")
    result = item.scoring_result
    candidate = result.candidate
    scorer_version = candidate.scorer_version
    if not scorer_version:
        raise MutationHandoffError("injection candidate must carry a scorer_version")
    input_point_id = candidate.input_point_id
    if not input_point_id:
        raise MutationHandoffError("injection candidate must reference an input point")
    return _ProjectedFields(
        candidate_id=candidate.id or "",
        subject_kind=SUBJECT_KIND_INPUT_POINT,
        subject_ref=input_point_id,
        family=candidate.vulnerability_type.value,
        check_kind=None,
        scorer_version=scorer_version,
        raw_rank_score=item.raw_rank_score,
        raw_rank_score_max=item.raw_rank_score_max,
        selection_priority=item.selection_priority,
        feature_vector_id=result.feature_vector_id,
        access_probe_plan_id=None,
        request_context_ref=input_point_id,
        score_evidence=tuple(result.evidence),
    )


def _access_fields(item: RankedAccessScoringResult | None) -> _ProjectedFields:
    if not isinstance(item, RankedAccessScoringResult):
        raise MutationHandoffError("access entry is missing its ranked result")
    result = item.scoring_result
    candidate = result.candidate
    scorer_version = candidate.scorer_version
    if not scorer_version:
        raise MutationHandoffError("access candidate must carry a scorer_version")
    access_probe_plan_id = result.access_probe_plan_id
    if not access_probe_plan_id:
        raise MutationHandoffError("access candidate must reference an access probe plan")
    return _ProjectedFields(
        candidate_id=candidate.id or "",
        subject_kind=SUBJECT_KIND_BAC_ACCESS_CONTEXT,
        subject_ref=access_probe_plan_id,
        family=FAMILY_BROKEN_ACCESS_CONTROL,
        check_kind=candidate.check_kind.value,
        scorer_version=scorer_version,
        raw_rank_score=item.raw_rank_score,
        raw_rank_score_max=item.raw_rank_score_max,
        selection_priority=item.selection_priority,
        feature_vector_id=None,
        access_probe_plan_id=access_probe_plan_id,
        request_context_ref=access_probe_plan_id,
        score_evidence=tuple(result.evidence),
    )


def _ranked_context_id(
    *,
    selection_run_id: str,
    candidate_id: str,
    origin: str,
    provenance_ref: str,
    scorer_version: str,
) -> str:
    fingerprint = stable_fingerprint(
        "ranked-candidate-context",
        selection_run_id,
        candidate_id,
        origin,
        provenance_ref,
        scorer_version,
    )
    return f"rcc_{fingerprint[:16]}"
