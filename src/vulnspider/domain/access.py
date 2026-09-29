"""Domain objects for the Broken Access Control (BAC) relational model.

Kept deliberately separate from the SQLi/XSS injection-candidate model in
``domain.models``. That model is ``InputPoint x VulnerabilityType``: one
InputPoint's value is perturbed and the response is compared against its own
baseline. Access-control correctness is a different kind of question -- it is
a relationship between *who is asking* (subject_context) and *which resource*
(resource_reference) they can reach, not a property of one injected value
(ADR-014; docs/DOMAIN_MODEL.md reserves this exact shape as
``AccessCandidate``). Reusing ``VulnerabilityCandidate``/``ScoreEvidence``
here would also mix in their "higher observed value = more suspicious"
semantics with BAC's inverted one ("the request was NOT rejected = more
suspicious"), which is a real risk to keep separate rather than paper over.

This module only defines the relational candidate shape. It does not perform
network I/O, planning, feature extraction, or scoring.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from vulnspider.domain.models import (
    HttpMethod,
    RequestInstance,
    stable_fingerprint,
)

ACCESS_REQUEST_ROLE_REFERENCE = "reference"
ACCESS_REQUEST_ROLE_COMPARISON = "comparison"


class AccessSubjectContext(StrEnum):
    """Who made a concrete request, for one side of an access comparison."""

    ORIGINAL = "ORIGINAL"
    ANONYMOUS = "ANONYMOUS"


class AccessCheckKind(StrEnum):
    """Which BAC technique produced an :class:`AccessProbePlan`."""

    CREDENTIAL_STRIP = "CREDENTIAL_STRIP"
    IDENTIFIER_SUBSTITUTION = "IDENTIFIER_SUBSTITUTION"


class AccessPlanningError(ValueError):
    """Raised when an access probe plan cannot be constructed validly."""


@dataclass(frozen=True, slots=True)
class AccessProbePlan:
    """One planned comparison between two subject/resource contexts.

    ``reference_request`` is the request as originally observed (with the
    credentials or identifier the crawler actually saw). ``comparison_request``
    is the same request with exactly one access-relevant aspect changed:
    credentials removed (``CREDENTIAL_STRIP``) or the target identifier
    substituted (``IDENTIFIER_SUBSTITUTION``). Both are still real, safe,
    non-destructive GET requests -- this only changes who/what is being asked
    for, mirroring the injection model's "change exactly one aspect" discipline
    (AGENTS.md rule 4) applied to the access axis instead of an InputPoint.
    """

    endpoint_id: str
    endpoint_fingerprint: str
    request_template_id: str
    check_kind: AccessCheckKind
    reference_request: RequestInstance
    comparison_request: RequestInstance
    reference_subject: AccessSubjectContext
    comparison_subject: AccessSubjectContext
    changed_aspect: str
    input_point_id: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.endpoint_id:
            raise AccessPlanningError("AccessProbePlan.endpoint_id must not be empty")
        if not self.endpoint_fingerprint:
            raise AccessPlanningError(
                "AccessProbePlan.endpoint_fingerprint must not be empty"
            )
        if not self.request_template_id:
            raise AccessPlanningError(
                "AccessProbePlan.request_template_id must not be empty"
            )
        if not self.changed_aspect:
            raise AccessPlanningError("AccessProbePlan.changed_aspect must not be empty")
        if self.reference_request.method != HttpMethod.GET:
            raise AccessPlanningError("AccessProbePlan requests must be GET")
        if self.comparison_request.method != HttpMethod.GET:
            raise AccessPlanningError("AccessProbePlan requests must be GET")
        check_kind = AccessCheckKind(self.check_kind)
        reference_subject = AccessSubjectContext(self.reference_subject)
        comparison_subject = AccessSubjectContext(self.comparison_subject)
        object.__setattr__(self, "check_kind", check_kind)
        object.__setattr__(self, "reference_subject", reference_subject)
        object.__setattr__(self, "comparison_subject", comparison_subject)
        if not self.id:
            fingerprint = stable_fingerprint(
                "access-probe-plan",
                self.endpoint_id,
                self.endpoint_fingerprint,
                self.request_template_id,
                check_kind.value,
                self.reference_request.id,
                self.comparison_request.id,
                reference_subject.value,
                comparison_subject.value,
                self.changed_aspect,
                self.input_point_id,
            )
            object.__setattr__(self, "id", f"accplan_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class AccessCandidate:
    """The ranking unit for BAC: one subject_context x resource_reference check.

    Mirrors the field names ``docs/DOMAIN_MODEL.md`` reserved:
    ``subject_context``, ``endpoint``, ``resource_reference``,
    ``resource_owner_context``.
    """

    endpoint_id: str
    check_kind: AccessCheckKind
    subject_context: AccessSubjectContext
    resource_reference: str
    resource_owner_context: str
    access_probe_plan_id: str
    input_point_id: str | None = None
    rank_score: float | None = None
    scorer_version: str | None = None
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.endpoint_id:
            raise AccessPlanningError("AccessCandidate.endpoint_id must not be empty")
        if not self.resource_reference:
            raise AccessPlanningError(
                "AccessCandidate.resource_reference must not be empty"
            )
        if not self.resource_owner_context:
            raise AccessPlanningError(
                "AccessCandidate.resource_owner_context must not be empty"
            )
        if not self.access_probe_plan_id:
            raise AccessPlanningError(
                "AccessCandidate.access_probe_plan_id must not be empty"
            )
        check_kind = AccessCheckKind(self.check_kind)
        subject_context = AccessSubjectContext(self.subject_context)
        object.__setattr__(self, "check_kind", check_kind)
        object.__setattr__(self, "subject_context", subject_context)
        if not self.id:
            fingerprint = stable_fingerprint(
                "access-candidate",
                self.endpoint_id,
                check_kind.value,
                subject_context.value,
                self.resource_reference,
                self.input_point_id,
            )
            object.__setattr__(self, "id", f"acand_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class AccessScoreEvidence:
    """One feature's contribution to an :class:`AccessCandidate` rank_score."""

    candidate_id: str
    access_probe_plan_id: str
    feature_name: str
    feature_value: float | None
    weight: float
    contribution: float | None
    reason: str
    observed: bool = True
    check_kind: AccessCheckKind | None = None

    def __post_init__(self) -> None:
        check_kind = None if self.check_kind is None else AccessCheckKind(self.check_kind)
        object.__setattr__(self, "check_kind", check_kind)
        if self.observed:
            if self.feature_value is None or self.contribution is None:
                raise AccessPlanningError(
                    "observed access score evidence requires a value and contribution"
                )
        elif self.feature_value is not None or self.contribution is not None:
            raise AccessPlanningError(
                "unavailable access score evidence must not fabricate a value "
                "or contribution"
            )


@dataclass(frozen=True, slots=True, init=False)
class AccessScoringResult:
    """One candidate score and its evidence from one exact AccessProbePlan."""

    access_probe_plan_id: str
    candidate: AccessCandidate
    evidence: tuple[AccessScoreEvidence, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("AccessScoringResult must be created with from_objects()")

    @classmethod
    def from_objects(
        cls,
        access_probe_plan: AccessProbePlan,
        candidate: AccessCandidate,
        evidence: tuple[AccessScoreEvidence, ...],
    ) -> AccessScoringResult:
        if not isinstance(access_probe_plan, AccessProbePlan):
            raise TypeError("access_probe_plan must be an AccessProbePlan")
        if not isinstance(candidate, AccessCandidate):
            raise TypeError("candidate must be an AccessCandidate")
        if candidate.access_probe_plan_id != access_probe_plan.id:
            raise AccessPlanningError(
                "AccessScoringResult candidate and AccessProbePlan ownership mismatch"
            )

        access_probe_plan_id = access_probe_plan.id or ""
        candidate_id = candidate.id or ""
        evidence_items = tuple(evidence)
        for item in evidence_items:
            if not isinstance(item, AccessScoreEvidence):
                raise TypeError("evidence must contain only AccessScoreEvidence")
            if item.candidate_id != candidate_id:
                raise AccessPlanningError("AccessScoreEvidence candidate ownership mismatch")
            if item.access_probe_plan_id != access_probe_plan_id:
                raise AccessPlanningError(
                    "AccessScoreEvidence AccessProbePlan ownership mismatch"
                )
            if item.check_kind != candidate.check_kind:
                raise AccessPlanningError("AccessScoreEvidence check_kind mismatch")

        instance = object.__new__(cls)
        object.__setattr__(instance, "access_probe_plan_id", access_probe_plan_id)
        object.__setattr__(instance, "candidate", candidate)
        object.__setattr__(instance, "evidence", evidence_items)
        return instance
