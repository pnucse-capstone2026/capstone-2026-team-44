"""Provider-neutral payload mutation (LLM-assisted focused verification, step 2).

The confidence-update pipeline takes an already-ranked candidate and asks a
proposer for *variant* payloads of the same family as the original light probe:
special-character perturbations for a reflected-XSS candidate, SQL
metacharacters for a SQLi candidate, and out-of-range values for a numeric
parameter. Those payloads are re-sent, the response is re-probed, and the
resulting :class:`~vulnspider.domain.FeatureVector` is compared with the
baseline one to decide whether the confidence should move.

`docs/PROTOTYPE_V0_2.md` §4.3 makes the boundary explicit: **model output is
untrusted input**. A proposer -- whether it is the deterministic default here
or a GPT/Gemini client dropped in behind the same protocol -- only *suggests*.
Nothing a proposer emits reaches the network until the deterministic
:class:`~vulnspider.verification.validator.PayloadValidator` accepts it
(`AGENTS.md`: "Model output cannot execute until a deterministic
``PayloadValidator`` accepts it").

The default :class:`DeterministicMutationProposer` is the ``deterministic
baseline`` / ``no-model`` provider the ``VerificationResult`` contract
(`docs/TEAM_INTERFACES_V0_2.md` §3) enumerates. It exists so the whole pipeline
is reproducible and testable without a network model, and so the validator and
confidence rules can be exercised against a known payload set.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from vulnspider.domain import (
    InputLocation,
    VulnerabilityType,
    stable_fingerprint,
)
from vulnspider.observation.planner import MARKER_PREFIX

PROVIDER_DETERMINISTIC = "deterministic-baseline"
DETERMINISTIC_PROPOSER_VERSION = "deterministic-mutation-v1"

# Bounded identifier token embedded in reflection-bearing payloads so the reused
# feature extractor can attribute a reflection to this exact proposal. It mirror
# `observation.planner`'s marker shape (``VULNSPIDER_`` + uppercase hex) so it
# never contains ``Z`` and the sentinel split in `marker_identifier` recovers it
# unchanged.
VERIFICATION_MARKER_TOKEN_LENGTH = 16

# Non-executing, context-breaking character regions wrapped by the ``Z``
# sentinel delimiter. They carry no script and change no server state; they only
# let the encoding extractor observe whether the dangerous characters survive
# raw. The first region repeats the baseline sentinel set; the second widens it
# to break out of more reflection contexts.
_HTML_SENTINEL_REGIONS: tuple[str, ...] = ("<>\"'", "<>\"'`/=()")

# Single SQL metacharacters appended to the identifier to elicit a syntax error
# (``sql_error_pattern``). They are read-only: no statement keyword, no stacked
# query, no comment sequence. The validator independently blocks anything else.
_SQL_META_SUFFIXES: tuple[str, ...] = ("'", "\"", "')")

# Out-of-range values for an integer-looking parameter: below the usual floor,
# just past a signed 32-bit ceiling, and far past any 64-bit range. These probe
# boundary/error handling, the "index range 밖의 요청" case.
_BOUNDARY_INTEGER_VALUES: tuple[str, ...] = ("-1", "2147483648", "99999999999999999999")

MAX_PROPOSALS_PER_CANDIDATE = 4


class MutationProposalError(ValueError):
    """Raised when a payload proposal cannot be constructed honestly."""


class MutationFamily(StrEnum):
    """Allowlisted payload-mutation families (validator taxonomy anchor)."""

    HTML_SENTINEL = "HTML_SENTINEL"
    SQL_META = "SQL_META"
    BOUNDARY = "BOUNDARY"


# Which families are meaningful for each candidate type. The validator enforces
# this same table; the proposer only ever emits from it.
FAMILIES_FOR_TYPE: dict[VulnerabilityType, tuple[MutationFamily, ...]] = {
    VulnerabilityType.SQLI: (MutationFamily.SQL_META, MutationFamily.BOUNDARY),
    VulnerabilityType.REFLECTED_XSS: (
        MutationFamily.HTML_SENTINEL,
        MutationFamily.BOUNDARY,
    ),
}


@dataclass(frozen=True, slots=True)
class MutationSubject:
    """The minimum a proposer needs; deliberately not the full request.

    A proposer receives the candidate identity, the target parameter, and its
    baseline value -- never the response, the scope authority, or the transport.
    Those stay owned by the focused-verification orchestrator so a proposer
    cannot widen scope or fabricate provenance.
    """

    candidate_id: str
    input_point_id: str
    vulnerability_type: VulnerabilityType
    parameter_name: str
    parameter_location: InputLocation
    baseline_value: str | None

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise MutationProposalError("candidate_id must not be empty")
        if not self.input_point_id:
            raise MutationProposalError("input_point_id must not be empty")
        object.__setattr__(
            self,
            "vulnerability_type",
            VulnerabilityType(self.vulnerability_type),
        )
        object.__setattr__(
            self, "parameter_location", InputLocation(self.parameter_location)
        )
        if self.baseline_value is not None and not isinstance(self.baseline_value, str):
            raise MutationProposalError("baseline_value must be a string or None")


@dataclass(frozen=True, slots=True)
class PayloadProposal:
    """One suggested variant payload. Untrusted until the validator accepts it."""

    candidate_id: str
    input_point_id: str
    vulnerability_type: VulnerabilityType
    family: MutationFamily
    variant_index: int
    mutated_value: str
    based_on_value: str | None
    reflection_marker: str | None
    rationale: str
    provider: str
    proposer_version: str
    id: str = ""

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise MutationProposalError("candidate_id must not be empty")
        if not self.input_point_id:
            raise MutationProposalError("input_point_id must not be empty")
        object.__setattr__(
            self,
            "vulnerability_type",
            VulnerabilityType(self.vulnerability_type),
        )
        object.__setattr__(self, "family", MutationFamily(self.family))
        if isinstance(self.variant_index, bool) or not isinstance(
            self.variant_index, int
        ):
            raise MutationProposalError("variant_index must be an integer")
        if self.variant_index < 0:
            raise MutationProposalError("variant_index must be non-negative")
        if not isinstance(self.mutated_value, str):
            raise MutationProposalError("mutated_value must be a string")
        if self.based_on_value is not None and not isinstance(self.based_on_value, str):
            raise MutationProposalError("based_on_value must be a string or None")
        if self.reflection_marker is not None and not isinstance(
            self.reflection_marker, str
        ):
            raise MutationProposalError("reflection_marker must be a string or None")
        if not self.provider:
            raise MutationProposalError("provider must not be empty")
        if not self.proposer_version:
            raise MutationProposalError("proposer_version must not be empty")
        if not self.id:
            fingerprint = stable_fingerprint(
                "payload-proposal",
                self.candidate_id,
                self.input_point_id,
                self.vulnerability_type.value,
                self.family.value,
                self.variant_index,
                self.mutated_value,
                self.provider,
                self.proposer_version,
            )
            object.__setattr__(self, "id", f"prop_{fingerprint[:16]}")


class PayloadProposer(Protocol):
    """Provider-neutral proposal boundary.

    A real GPT/Gemini client implements this exact method behind the same
    validator gate. The orchestrator never calls a model directly; it calls
    ``propose`` and hands every result to the validator.
    """

    def propose(self, subject: MutationSubject) -> tuple[PayloadProposal, ...]:
        """Return bounded variant payloads for one candidate; never execute."""


def verification_identifier(candidate_id: str, family: MutationFamily, variant_index: int) -> str:
    """A bounded, deterministic reflection token unique to this proposal.

    Uppercase hex only, so it never contains ``Z`` and survives the sentinel
    split in ``observation.planner.marker_identifier`` -- which the reused
    feature extractor relies on to find a reflection.
    """

    fingerprint = stable_fingerprint(
        "verification-marker",
        candidate_id,
        MutationFamily(family).value,
        int(variant_index),
    )
    token = fingerprint[:VERIFICATION_MARKER_TOKEN_LENGTH].upper()
    return f"{MARKER_PREFIX}{token}"


def _looks_like_integer(value: str | None) -> bool:
    if value is None:
        return False
    text = value.strip()
    if not text:
        return False
    if text[0] in "+-":
        text = text[1:]
    return text.isdigit()


@dataclass(frozen=True, slots=True)
class DeterministicMutationProposer:
    """The default no-model proposer: reproducible, allowlisted mutations only.

    Emits the same variant set for the same subject every time, so a run is
    byte-reproducible and the validator/confidence rules can be tested against a
    known payload set. A network model would replace only this object; the
    validator, executor, and confidence rules are unchanged.
    """

    max_proposals: int = MAX_PROPOSALS_PER_CANDIDATE

    def propose(self, subject: MutationSubject) -> tuple[PayloadProposal, ...]:
        if not isinstance(subject, MutationSubject):
            raise MutationProposalError("subject must be a MutationSubject")
        families = FAMILIES_FOR_TYPE.get(subject.vulnerability_type, ())
        proposals: list[PayloadProposal] = []
        for family in families:
            proposals.extend(self._family_proposals(subject, family))
        return tuple(proposals[: self.max_proposals])

    def _family_proposals(
        self,
        subject: MutationSubject,
        family: MutationFamily,
    ) -> list[PayloadProposal]:
        if family == MutationFamily.HTML_SENTINEL:
            return self._html_sentinel(subject)
        if family == MutationFamily.SQL_META:
            return self._sql_meta(subject)
        if family == MutationFamily.BOUNDARY:
            return self._boundary(subject)
        return []

    def _html_sentinel(self, subject: MutationSubject) -> list[PayloadProposal]:
        proposals: list[PayloadProposal] = []
        for index, region in enumerate(_HTML_SENTINEL_REGIONS):
            marker = verification_identifier(
                subject.candidate_id, MutationFamily.HTML_SENTINEL, index
            )
            payload = f"{marker}Z{region}Z"
            proposals.append(
                self._build(
                    subject,
                    family=MutationFamily.HTML_SENTINEL,
                    variant_index=index,
                    mutated_value=payload,
                    reflection_marker=payload,
                    rationale=(
                        "Reflect an identifier plus raw HTML-significant "
                        "characters to test whether the app entity-encodes them."
                    ),
                )
            )
        return proposals

    def _sql_meta(self, subject: MutationSubject) -> list[PayloadProposal]:
        proposals: list[PayloadProposal] = []
        for index, suffix in enumerate(_SQL_META_SUFFIXES):
            marker = verification_identifier(
                subject.candidate_id, MutationFamily.SQL_META, index
            )
            payload = f"{marker}{suffix}"
            proposals.append(
                self._build(
                    subject,
                    family=MutationFamily.SQL_META,
                    variant_index=index,
                    mutated_value=payload,
                    reflection_marker=None,
                    rationale=(
                        "Append a single SQL metacharacter to elicit a database "
                        "syntax-error signal without any state-changing keyword."
                    ),
                )
            )
        return proposals

    def _boundary(self, subject: MutationSubject) -> list[PayloadProposal]:
        if not _looks_like_integer(subject.baseline_value):
            return []
        proposals: list[PayloadProposal] = []
        for index, value in enumerate(_BOUNDARY_INTEGER_VALUES):
            if value == subject.baseline_value:
                continue
            proposals.append(
                self._build(
                    subject,
                    family=MutationFamily.BOUNDARY,
                    variant_index=index,
                    mutated_value=value,
                    reflection_marker=None,
                    rationale=(
                        "Send an out-of-range integer to distinguish a genuine "
                        "boundary weakness from generic error handling."
                    ),
                )
            )
        return proposals

    def _build(
        self,
        subject: MutationSubject,
        *,
        family: MutationFamily,
        variant_index: int,
        mutated_value: str,
        reflection_marker: str | None,
        rationale: str,
    ) -> PayloadProposal:
        return PayloadProposal(
            candidate_id=subject.candidate_id,
            input_point_id=subject.input_point_id,
            vulnerability_type=subject.vulnerability_type,
            family=family,
            variant_index=variant_index,
            mutated_value=mutated_value,
            based_on_value=subject.baseline_value,
            reflection_marker=reflection_marker,
            rationale=rationale,
            provider=PROVIDER_DETERMINISTIC,
            proposer_version=DETERMINISTIC_PROPOSER_VERSION,
        )
