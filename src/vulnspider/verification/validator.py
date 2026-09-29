"""Deterministic payload validator (LLM-assisted focused verification, step 3).

Every proposal -- from the deterministic proposer or a network model -- passes
through here before anything is sent. This is the non-negotiable safety seam in
`AGENTS.md` ("Model output cannot execute until a deterministic
``PayloadValidator`` accepts it") and the ``validator_decision`` field of the
``VerificationResult`` contract (`docs/TEAM_INTERFACES_V0_2.md` §3).

The validator is intentionally strict and closed: a payload is rejected unless
it is a known family for the candidate type, stays within a bounded length and a
printable-ASCII character set, changes exactly the target value, and contains no
state-changing or destructive database keyword. Rejection reasons are a fixed
taxonomy so the report can show *why* a proposal never ran, and so a rejected
proposal is provably never executed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from vulnspider.domain import VulnerabilityType, stable_fingerprint
from vulnspider.verification.proposal import (
    FAMILIES_FOR_TYPE,
    MutationFamily,
    PayloadProposal,
)

VALIDATOR_POLICY_VERSION = "payload-validator-v1"

# Upper bound on a mutated value. Large enough for the sentinel payloads and the
# widest boundary integer, small enough that a proposer cannot smuggle a bulk
# body past the length gate.
MAX_PAYLOAD_LENGTH = 256

# Payloads must be printable ASCII (0x20-0x7E). This excludes NUL, CR, LF, and
# every other control byte -- the characters a header/body-smuggling attempt
# would need -- and all non-ASCII, without having to enumerate them.
_PRINTABLE_ASCII = re.compile(r"^[\x20-\x7e]*$")

# Database keywords that write, change structure, escalate, or run code. Their
# presence rejects the payload outright: focused verification is read-only
# (`docs/PROTOTYPE_V0_2.md` §5, `AGENTS.md` safety rules). Matched
# case-insensitively on word boundaries.
_DESTRUCTIVE_SQL_KEYWORDS: tuple[str, ...] = (
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "ALTER",
    "CREATE",
    "TRUNCATE",
    "REPLACE",
    "RENAME",
    "GRANT",
    "REVOKE",
    "MERGE",
    "CALL",
    "EXEC",
    "EXECUTE",
    "SHUTDOWN",
    "LOAD_FILE",
    "INTO OUTFILE",
    "INTO DUMPFILE",
)
_DESTRUCTIVE_SQL_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(word) for word in _DESTRUCTIVE_SQL_KEYWORDS) + r")\b",
    flags=re.IGNORECASE,
)

# A stacked-query separator turns one read into two statements. Blocked so a
# read-only metacharacter payload cannot become a second statement.
_STACKED_QUERY_CHAR = ";"


class ValidatorError(ValueError):
    """Raised when a validator decision itself is constructed inconsistently."""


class ValidatorDecision(StrEnum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


class ValidatorRejectionReason(StrEnum):
    FAMILY_TYPE_MISMATCH = "FAMILY_TYPE_MISMATCH"
    EMPTY_MUTATION = "EMPTY_MUTATION"
    UNCHANGED_FROM_BASELINE = "UNCHANGED_FROM_BASELINE"
    PAYLOAD_TOO_LONG = "PAYLOAD_TOO_LONG"
    DISALLOWED_CHARACTER = "DISALLOWED_CHARACTER"
    STACKED_QUERY = "STACKED_QUERY"
    DESTRUCTIVE_KEYWORD = "DESTRUCTIVE_KEYWORD"


@dataclass(frozen=True, slots=True)
class ValidatedPayload:
    """An approved payload record. Only ever produced for an accepted proposal."""

    proposal_id: str
    candidate_id: str
    family: MutationFamily
    mutated_value: str
    reflection_marker: str | None
    validator_policy_version: str
    id: str = ""

    def __post_init__(self) -> None:
        if not self.proposal_id:
            raise ValidatorError("proposal_id must not be empty")
        if not self.candidate_id:
            raise ValidatorError("candidate_id must not be empty")
        object.__setattr__(self, "family", MutationFamily(self.family))
        if not isinstance(self.mutated_value, str) or not self.mutated_value:
            raise ValidatorError("validated payload must carry a non-empty value")
        if self.validator_policy_version != VALIDATOR_POLICY_VERSION:
            raise ValidatorError("validated payload carries an unknown policy version")
        if not self.id:
            fingerprint = stable_fingerprint(
                "validated-payload",
                self.proposal_id,
                self.candidate_id,
                self.family.value,
                self.mutated_value,
                self.validator_policy_version,
            )
            object.__setattr__(self, "id", f"vpl_{fingerprint[:16]}")


@dataclass(frozen=True, slots=True)
class ValidatorResult:
    """The decision for one proposal: accepted with a payload, or rejected."""

    proposal_id: str
    candidate_id: str
    decision: ValidatorDecision
    validator_policy_version: str
    rejection_reasons: tuple[ValidatorRejectionReason, ...] = ()
    validated_payload: ValidatedPayload | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", ValidatorDecision(self.decision))
        object.__setattr__(
            self,
            "rejection_reasons",
            tuple(ValidatorRejectionReason(reason) for reason in self.rejection_reasons),
        )
        if self.validator_policy_version != VALIDATOR_POLICY_VERSION:
            raise ValidatorError("validator result carries an unknown policy version")
        if self.decision == ValidatorDecision.ACCEPTED:
            if self.rejection_reasons:
                raise ValidatorError("an accepted decision must carry no reasons")
            if not isinstance(self.validated_payload, ValidatedPayload):
                raise ValidatorError("an accepted decision must carry a payload")
        else:
            if not self.rejection_reasons:
                raise ValidatorError("a rejected decision must carry a reason")
            if self.validated_payload is not None:
                raise ValidatorError("a rejected decision must carry no payload")

    @property
    def accepted(self) -> bool:
        return self.decision == ValidatorDecision.ACCEPTED


@dataclass(frozen=True, slots=True)
class PayloadValidator:
    """Closed, deterministic accept/reject gate for a single proposal."""

    max_payload_length: int = MAX_PAYLOAD_LENGTH

    def validate(self, proposal: PayloadProposal) -> ValidatorResult:
        if not isinstance(proposal, PayloadProposal):
            raise ValidatorError("proposal must be a PayloadProposal")
        reasons = tuple(self._reject_reasons(proposal))
        if reasons:
            return ValidatorResult(
                proposal_id=proposal.id,
                candidate_id=proposal.candidate_id,
                decision=ValidatorDecision.REJECTED,
                validator_policy_version=VALIDATOR_POLICY_VERSION,
                rejection_reasons=reasons,
            )
        payload = ValidatedPayload(
            proposal_id=proposal.id,
            candidate_id=proposal.candidate_id,
            family=proposal.family,
            mutated_value=proposal.mutated_value,
            reflection_marker=proposal.reflection_marker,
            validator_policy_version=VALIDATOR_POLICY_VERSION,
        )
        return ValidatorResult(
            proposal_id=proposal.id,
            candidate_id=proposal.candidate_id,
            decision=ValidatorDecision.ACCEPTED,
            validator_policy_version=VALIDATOR_POLICY_VERSION,
            validated_payload=payload,
        )

    def _reject_reasons(
        self, proposal: PayloadProposal
    ) -> list[ValidatorRejectionReason]:
        reasons: list[ValidatorRejectionReason] = []
        allowed = FAMILIES_FOR_TYPE.get(
            VulnerabilityType(proposal.vulnerability_type), ()
        )
        if proposal.family not in allowed:
            reasons.append(ValidatorRejectionReason.FAMILY_TYPE_MISMATCH)

        value = proposal.mutated_value
        if value == "":
            reasons.append(ValidatorRejectionReason.EMPTY_MUTATION)
        if proposal.based_on_value is not None and value == proposal.based_on_value:
            reasons.append(ValidatorRejectionReason.UNCHANGED_FROM_BASELINE)
        if len(value) > self.max_payload_length:
            reasons.append(ValidatorRejectionReason.PAYLOAD_TOO_LONG)
        if not _PRINTABLE_ASCII.match(value):
            reasons.append(ValidatorRejectionReason.DISALLOWED_CHARACTER)
        if _STACKED_QUERY_CHAR in value:
            reasons.append(ValidatorRejectionReason.STACKED_QUERY)
        if _DESTRUCTIVE_SQL_PATTERN.search(value):
            reasons.append(ValidatorRejectionReason.DESTRUCTIVE_KEYWORD)
        return reasons
