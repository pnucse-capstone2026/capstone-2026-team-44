"""Rule-based confidence update (LLM-assisted focused verification, step 5).

This is the deterministic, reviewed rule set that turns a feature delta into a
``VerificationConfidence`` -- the last stage the user described: keep the
confidence when the re-probe barely moved the features, and update it when the
move is large, having first decided whether the move is a *genuine* weak point
or *just an error*.

The distinction is made per family from the vulnerability-specific signal, not
from the size of the change alone:

* SQLi is **supported** only when a new SQL error signature appears
  (``sql_error_pattern``). A big status/length swing with no SQL signature is
  read as generic error handling -> ``INCONCLUSIVE_ERROR``.
* Reflected XSS is **supported** only when the marker reflects *and* the
  dangerous characters survive un-encoded (``safe_html_encoding_detected`` == 0).
  A reflection that comes back entity-encoded is evidence the app defends
  itself -> ``WEAKENED``.

`AGENTS.md` rules 6 and 7 keep this independent of ``RankScore``: the update
starts from a *calibrated probability prior* (a pre-verification probability,
ADR-022) supplied by the orchestrator and never from the raw priority score, and
the result is verification evidence, not a re-derived rank. An LLM never sets
this number (`docs/PROTOTYPE_V0_2.md` §4.4).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from math import isfinite

from vulnspider.domain import VulnerabilityType
from vulnspider.features import (
    MARKER_REFLECTED,
    RESPONSE_LENGTH_DIFF_RATIO,
    SAFE_HTML_ENCODING_DETECTED,
    SQL_ERROR_PATTERN,
    STATUS_CODE_CHANGED,
)
from vulnspider.verification.calibration import (
    VerificationConfidenceModel,
    VerificationSignal,
)
from vulnspider.verification.delta import FeatureVectorDelta

CONFIDENCE_RULE_VERSION = "confidence-rule-v2"
CONFIDENCE_SCALE = "probability-0-1-v1"

# Keep the result strictly inside (0, 1) like the calibrated probability it
# updates, so it can be compared with priors on the same scale.
_CONFIDENCE_MIN = 1e-6
_CONFIDENCE_MAX = 1.0 - 1e-6

# Prior used when the orchestrator has none (e.g. the calibrated prior could not
# be computed). Deliberately the neutral middle so an update still moves it.
_DEFAULT_PRIOR = 0.5


class ConfidenceError(ValueError):
    """Raised when a confidence update is constructed inconsistently."""


class VerificationOutcome(StrEnum):
    """The five states a single verification probe can land in."""

    UNCHANGED = "UNCHANGED"
    SUPPORTED = "SUPPORTED"
    WEAKENED = "WEAKENED"
    INCONCLUSIVE_ERROR = "INCONCLUSIVE_ERROR"
    NOT_EXECUTED = "NOT_EXECUTED"


# The public outcome label each fine-grained calibration signal rolls up to.
OUTCOME_FOR_SIGNAL: dict[VerificationSignal, VerificationOutcome] = {
    VerificationSignal.SUPPORT_NEW: VerificationOutcome.SUPPORTED,
    VerificationSignal.SUPPORT_REPRODUCED: VerificationOutcome.SUPPORTED,
    VerificationSignal.WEAKEN: VerificationOutcome.WEAKENED,
    VerificationSignal.INCONCLUSIVE: VerificationOutcome.INCONCLUSIVE_ERROR,
    VerificationSignal.UNCHANGED: VerificationOutcome.UNCHANGED,
    VerificationSignal.NOT_EXECUTED: VerificationOutcome.NOT_EXECUTED,
}


@dataclass(frozen=True, slots=True)
class VerificationEvidenceItem:
    """One explainable reason the rule set reached its outcome."""

    feature_name: str
    baseline_value: float | None
    verification_value: float | None
    direction: str
    reason: str


@dataclass(frozen=True, slots=True)
class VerificationConfidence:
    """The rule-derived confidence for one verification probe."""

    rule_version: str
    scale: str
    outcome: VerificationOutcome
    signal: VerificationSignal
    model_version: str
    prior_probability: float
    confidence: float
    evidence: tuple[VerificationEvidenceItem, ...]
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome", VerificationOutcome(self.outcome))
        object.__setattr__(self, "signal", VerificationSignal(self.signal))
        if OUTCOME_FOR_SIGNAL[self.signal] != self.outcome:
            raise ConfidenceError("signal and outcome are inconsistent")
        for name, value in (
            ("prior_probability", self.prior_probability),
            ("confidence", self.confidence),
        ):
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise ConfidenceError(f"{name} must be numeric")
            if not isfinite(float(value)) or not 0.0 < float(value) < 1.0:
                raise ConfidenceError(f"{name} must lie strictly inside (0, 1)")
        if self.rule_version != CONFIDENCE_RULE_VERSION:
            raise ConfidenceError("unexpected confidence rule version")
        if self.scale != CONFIDENCE_SCALE:
            raise ConfidenceError("unexpected confidence scale")
        if not self.model_version:
            raise ConfidenceError("model_version must not be empty")
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "warnings", tuple(self.warnings))

    @property
    def confidence_delta(self) -> float:
        return self.confidence - self.prior_probability


# (signal, evidence, warnings) returned by a classifier. The outcome label is
# derived from the signal via OUTCOME_FOR_SIGNAL.
_Classification = tuple[
    VerificationSignal,
    tuple[VerificationEvidenceItem, ...],
    tuple[str, ...],
]


def _clamp(value: float) -> float:
    return max(_CONFIDENCE_MIN, min(_CONFIDENCE_MAX, value))


def _normalized_prior(prior_probability: float | None) -> float:
    if prior_probability is None:
        return _DEFAULT_PRIOR
    if isinstance(prior_probability, bool) or not isinstance(
        prior_probability, int | float
    ):
        raise ConfidenceError("prior_probability must be numeric or None")
    return _clamp(float(prior_probability))


def update_confidence(
    *,
    vulnerability_type: VulnerabilityType,
    prior_probability: float | None,
    delta: FeatureVectorDelta | None,
    executed: bool = True,
    model: VerificationConfidenceModel | None = None,
    probe_status_code: int | None = None,
    baseline_status_code: int | None = None,
) -> VerificationConfidence:
    """Classify one feature delta and apply the calibrated confidence update.

    The classifier is deterministic and vulnerability-specific; the *magnitude*
    of the confidence change comes from ``model`` (default: the conservative
    zero-corpus model), which adds a bounded log-likelihood ratio for the
    classified signal to the prior's log-odds. ``executed`` is False for a
    validator-rejected proposal (no payload was ever sent), and a delta whose
    execution failed is treated as an inconclusive error rather than evidence.

    ``INCONCLUSIVE_ERROR`` is reserved for a *genuine* error: a transport
    failure, or a payload-induced server error (a 5xx the baseline did not
    return). A response that merely changed length or moved to a non-5xx status
    without any vulnerability-specific signal is a benign difference and stays
    ``UNCHANGED`` -- this is what stops boundary/length noise from flooding the
    report with inconclusive labels.
    """

    vulnerability_type = VulnerabilityType(vulnerability_type)
    active_model = model or VerificationConfidenceModel.default()
    prior = _normalized_prior(prior_probability)
    family = vulnerability_type.value

    if not executed:
        return _apply_signal(
            VerificationSignal.NOT_EXECUTED,
            prior=prior,
            family=family,
            model=active_model,
            evidence=(),
            warnings=("verification payload did not execute; prior retained",),
        )

    if not isinstance(delta, FeatureVectorDelta):
        raise ConfidenceError("an executed verification requires a FeatureVectorDelta")

    if not delta.execution_ok:
        return _apply_signal(
            VerificationSignal.INCONCLUSIVE,
            prior=prior,
            family=family,
            model=active_model,
            evidence=(),
            warnings=("verification probe hit an execution error; prior retained",),
        )

    server_error = _payload_induced_server_error(
        probe_status_code, baseline_status_code
    )
    if vulnerability_type == VulnerabilityType.SQLI:
        signal, evidence, warnings = _classify_sqli(delta, server_error=server_error)
    elif vulnerability_type == VulnerabilityType.REFLECTED_XSS:
        signal, evidence, warnings = _classify_xss(delta, server_error=server_error)
    else:  # pragma: no cover - only injection families reach verification
        raise ConfidenceError(
            f"no confidence rule for vulnerability type {vulnerability_type.value}"
        )

    return _apply_signal(
        signal,
        prior=prior,
        family=family,
        model=active_model,
        evidence=evidence,
        warnings=warnings,
    )


def _classify_sqli(
    delta: FeatureVectorDelta,
    *,
    server_error: bool = False,
) -> _Classification:
    sql = delta.get(SQL_ERROR_PATTERN)
    sql_now = bool(sql and sql.verification_observed and sql.verification_value == 1.0)
    sql_base = bool(sql and sql.baseline_observed and sql.baseline_value == 1.0)
    if sql_now and not sql_base:
        return (
            VerificationSignal.SUPPORT_NEW,
            (
                _item(
                    sql,
                    "up",
                    "A SQL error signature appeared under the metacharacter "
                    "payload that the baseline probe did not raise; a genuine "
                    "SQLi indicator, so confidence is raised.",
                ),
            ),
            (),
        )
    if sql_now and sql_base:
        return (
            VerificationSignal.SUPPORT_REPRODUCED,
            (
                _item(
                    sql,
                    "flat",
                    "The SQL error signature reproduced under an independent "
                    "metacharacter payload; the baseline suspicion is confirmed.",
                ),
            ),
            (),
        )
    if sql_base and not sql_now:
        return (
            VerificationSignal.WEAKEN,
            (
                _item(
                    sql,
                    "down",
                    "The baseline SQL error did not reproduce under the "
                    "metacharacter payload; confidence is lowered.",
                ),
            ),
            (),
        )
    return _no_signal(delta, SQL_ERROR_PATTERN, server_error=server_error)


def _classify_xss(
    delta: FeatureVectorDelta,
    *,
    server_error: bool = False,
) -> _Classification:
    reflected = delta.get(MARKER_REFLECTED)
    encoding = delta.get(SAFE_HTML_ENCODING_DETECTED)
    reflected_now = bool(
        reflected and reflected.verification_observed
        and reflected.verification_value == 1.0
    )
    raw_now = bool(
        encoding and encoding.verification_observed
        and encoding.verification_value == 0.0
    )
    encoded_now = bool(
        encoding and encoding.verification_observed
        and encoding.verification_value == 1.0
    )
    baseline_raw = bool(
        reflected and reflected.baseline_observed and reflected.baseline_value == 1.0
        and encoding and encoding.baseline_observed and encoding.baseline_value == 0.0
    )
    if reflected_now and raw_now:
        if baseline_raw:
            return (
                VerificationSignal.SUPPORT_REPRODUCED,
                (
                    _item(
                        encoding,
                        "flat",
                        "The payload again reflected with its dangerous "
                        "characters un-encoded; the baseline suspicion is "
                        "confirmed.",
                    ),
                ),
                (),
            )
        return (
            VerificationSignal.SUPPORT_NEW,
            (
                _item(
                    reflected,
                    "up",
                    "The variant payload reflected un-encoded in a context the "
                    "baseline probe did not expose; a genuine reflected-XSS "
                    "indicator, so confidence is raised.",
                ),
                _item(
                    encoding,
                    "down",
                    "No safe HTML encoding was observed on the reflected "
                    "sentinel.",
                ),
            ),
            (),
        )
    if reflected_now and encoded_now:
        return (
            VerificationSignal.WEAKEN,
            (
                _item(
                    encoding,
                    "up",
                    "The reflected sentinel came back entity-encoded; the app "
                    "defends this context, so confidence is lowered.",
                ),
            ),
            (),
        )
    return _no_signal(delta, MARKER_REFLECTED, server_error=server_error)


def _payload_induced_server_error(
    probe_status_code: int | None,
    baseline_status_code: int | None,
) -> bool:
    """A 5xx the baseline did not return -- a real, payload-triggered error.

    Requiring the baseline *not* to be a 5xx avoids blaming the payload for an
    application that already errors on the unmodified request.
    """

    if probe_status_code is None or probe_status_code < 500:
        return False
    return baseline_status_code is None or baseline_status_code < 500


def _no_signal(
    delta: FeatureVectorDelta,
    missing_signal: str,
    *,
    server_error: bool = False,
) -> _Classification:
    """No vulnerability-specific signal: a genuine error, or a benign difference.

    Only a payload-induced server error is inconclusive. A response that merely
    changed length or moved to a non-5xx status is treated as a benign
    difference (``UNCHANGED``), which keeps boundary/length noise from producing
    a flood of inconclusive labels.
    """

    if server_error:
        evidence: list[VerificationEvidenceItem] = []
        for name in (STATUS_CODE_CHANGED, RESPONSE_LENGTH_DIFF_RATIO):
            item = delta.get(name)
            if item is not None and item.verification_observed:
                evidence.append(
                    _item(
                        item,
                        "up",
                        "The payload triggered a server error (5xx) without a "
                        f"{missing_signal} signal; treated as generic error "
                        "handling, so the prior is retained.",
                    )
                )
        return (
            VerificationSignal.INCONCLUSIVE,
            tuple(evidence),
            (
                "verification triggered a server error without a vulnerability-"
                "specific signal; prior retained pending manual review",
            ),
        )
    length = delta.get(RESPONSE_LENGTH_DIFF_RATIO)
    kept_evidence: tuple[VerificationEvidenceItem, ...] = ()
    if length is not None:
        kept_evidence = (
            _item(
                length,
                "flat",
                "The re-probe barely moved the feature vector; the prior "
                "confidence is kept.",
            ),
        )
    return (VerificationSignal.UNCHANGED, kept_evidence, ())


def _item(delta_item: object, direction: str, reason: str) -> VerificationEvidenceItem:
    return VerificationEvidenceItem(
        feature_name=getattr(delta_item, "feature_name"),
        baseline_value=getattr(delta_item, "baseline_value"),
        verification_value=getattr(delta_item, "verification_value"),
        direction=direction,
        reason=reason,
    )


def _apply_signal(
    signal: VerificationSignal,
    *,
    prior: float,
    family: str,
    model: VerificationConfidenceModel,
    evidence: tuple[VerificationEvidenceItem, ...],
    warnings: tuple[str, ...],
) -> VerificationConfidence:
    posterior = model.apply(prior, family, signal)
    return VerificationConfidence(
        rule_version=CONFIDENCE_RULE_VERSION,
        scale=CONFIDENCE_SCALE,
        outcome=OUTCOME_FOR_SIGNAL[signal],
        signal=signal,
        model_version=model.model_version,
        prior_probability=_clamp(prior),
        confidence=_clamp(posterior),
        evidence=evidence,
        warnings=warnings,
    )
