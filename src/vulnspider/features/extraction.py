"""Minimal v0.1 feature extraction from one baseline/probe response pair."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from vulnspider.domain import (
    FeatureObservation,
    FeatureVector,
    InputPoint,
    ProbePlan,
    ResponsePair,
    ResponseSnapshot,
)
from vulnspider.observation.planner import (
    SENTINEL_CHARS,
    marker_identifier,
)

FEATURE_SCHEMA_VERSION = "feature-v0.2"
DIFFERENTIAL_EXTRACTOR_VERSION = "differential-v1"
REFLECTION_EXTRACTOR_VERSION = "reflection-v1"
ENCODING_EXTRACTOR_VERSION = "html-encoding-v1"
SQL_EXTRACTOR_VERSION = "sql-signal-v1"
FEATURE_AGGREGATION_VERSION = "input-point-existential-v1"

STATUS_CODE_CHANGED = "status_code_changed"
RESPONSE_LENGTH_DIFF_RATIO = "response_length_diff_ratio"
MARKER_REFLECTED = "marker_reflected"
SAFE_HTML_ENCODING_DETECTED = "safe_html_encoding_detected"
REFLECTION_COUNT_NORM = "reflection_count_norm"
SQL_ERROR_PATTERN = "sql_error_pattern"
REQUEST_ROLE_BASELINE = "baseline"
REQUEST_ROLE_PROBE = "probe"

# Entity forms the extractor accepts as a "safely encoded" dangerous character.
_ENTITY_MARKERS: tuple[str, ...] = (
    "&lt;",
    "&gt;",
    "&quot;",
    "&#x27;",
    "&#39;",
    "&apos;",
    "&#34;",
    "&amp;",
)

SQL_ERROR_PATTERNS: tuple[tuple[str, str], ...] = (
    ("sql_syntax", r"\bSQL syntax\b"),
    ("sqlstate", r"\bSQLSTATE\b"),
    ("mysql", r"\bMySQL\b|\bMariaDB\b"),
    ("postgresql", r"\bPostgreSQL\b|unterminated quoted string"),
    ("sqlite", r"\bSQLite\b|near .{0,40}: syntax error"),
    ("oracle", r"\bORA-\d{5}\b"),
    ("odbc", r"\bODBC\b"),
    ("mssql", r"Unclosed quotation mark|Microsoft SQL Server"),
)


class FeatureExtractionError(ValueError):
    """Raised when one response pair cannot be attributed to one probe plan."""


@dataclass(frozen=True, slots=True)
class MinimalFeatureExtractor:
    def extract(
        self,
        input_point: InputPoint,
        probe_plan: ProbePlan,
        response_pair: ResponsePair,
        baseline_response: ResponseSnapshot,
        probe_response: ResponseSnapshot,
    ) -> FeatureVector:
        return extract_minimal_features(
            input_point,
            probe_plan,
            response_pair,
            baseline_response,
            probe_response,
        )


def extract_minimal_features(
    input_point: InputPoint,
    probe_plan: ProbePlan,
    response_pair: ResponsePair,
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> FeatureVector:
    _validate_feature_inputs(
        input_point,
        probe_plan,
        response_pair,
        baseline_response,
        probe_response,
    )
    if baseline_response.execution_error or probe_response.execution_error:
        features = _missing_features_for_execution_error(
            baseline_response,
            probe_response,
        )
    else:
        features = {
            STATUS_CODE_CHANGED: _status_code_changed(
                baseline_response,
                probe_response,
            ),
            RESPONSE_LENGTH_DIFF_RATIO: _response_length_diff_ratio(
                baseline_response,
                probe_response,
            ),
            MARKER_REFLECTED: _marker_reflected(probe_plan, baseline_response, probe_response),
            SAFE_HTML_ENCODING_DETECTED: _safe_html_encoding_detected(
                probe_plan,
                probe_response,
            ),
            REFLECTION_COUNT_NORM: _reflection_count_norm(probe_plan, probe_response),
            SQL_ERROR_PATTERN: _sql_error_pattern(baseline_response, probe_response),
        }
    return FeatureVector(
        input_point_id=input_point.id or "",
        probe_run_ids=(response_pair.id or "",),
        features=features,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )


def combine_input_point_features(
    feature_vectors: Sequence[FeatureVector],
) -> FeatureVector:
    """Combine every probe run observed for one InputPoint into one vector.

    Native Dynamic and Combined discovery routinely bind one `InputPoint` to
    several probe-ready request contexts, so one analysis executes several
    probe runs for the same observation unit. `docs/DOMAIN_MODEL.md` §9 owns
    the `FeatureVector` as "one InputPoint plus the probe runs that produced
    it", and ADR-002 keeps `InputPoint x VulnerabilityType` as the ranking
    atom, so those runs must reduce to exactly one vector.

    Each feature is combined existentially: the observation with the largest
    value wins, ties resolve by ascending probe-run id, and a feature stays
    unobserved when no run observed it (domain rule 8). `details` retains the
    run that supplied the retained value and every run's value.
    """

    vectors = tuple(feature_vectors)
    if not vectors:
        raise FeatureExtractionError("at least one FeatureVector is required")
    for vector in vectors:
        if not isinstance(vector, FeatureVector):
            raise FeatureExtractionError(
                "feature_vectors must contain only FeatureVector objects"
            )
    input_point_id = vectors[0].input_point_id
    schema_version = vectors[0].feature_schema_version
    if any(vector.input_point_id != input_point_id for vector in vectors):
        raise FeatureExtractionError(
            "FeatureVectors must belong to one InputPoint"
        )
    if any(
        vector.feature_schema_version != schema_version for vector in vectors
    ):
        raise FeatureExtractionError(
            "FeatureVectors must share one feature schema version"
        )
    if len(vectors) == 1:
        return vectors[0]

    runs: list[tuple[str, FeatureVector]] = []
    seen_run_ids: set[str] = set()
    for vector in vectors:
        if len(vector.probe_run_ids) != 1:
            raise FeatureExtractionError(
                "only single-probe-run FeatureVectors can be combined"
            )
        run_id = vector.probe_run_ids[0]
        if not run_id:
            raise FeatureExtractionError("probe run id must not be empty")
        if run_id in seen_run_ids:
            raise FeatureExtractionError(
                "FeatureVectors must reference distinct probe runs"
            )
        seen_run_ids.add(run_id)
        runs.append((run_id, vector))
    runs.sort(key=lambda item: item[0])

    names = sorted({name for _run_id, vector in runs for name in vector.features})
    features = {
        name: _combine_feature_observations(name, runs) for name in names
    }
    return FeatureVector(
        input_point_id=input_point_id,
        probe_run_ids=tuple(run_id for run_id, _vector in runs),
        features=features,
        feature_schema_version=schema_version,
    )


def _combine_feature_observations(
    name: str,
    runs: Sequence[tuple[str, FeatureVector]],
) -> FeatureObservation:
    entries: list[tuple[str, FeatureObservation]] = []
    for run_id, vector in runs:
        observation = vector.features.get(name)
        if observation is None:
            continue
        if not isinstance(observation, FeatureObservation):
            raise FeatureExtractionError(
                f"feature {name} must be a FeatureObservation"
            )
        if observation.name != name:
            raise FeatureExtractionError(
                f"feature key {name!r} does not match observation name "
                f"{observation.name!r}"
            )
        entries.append((run_id, observation))

    source, extractor_version = _consistent_feature_origin(name, entries)
    run_ids = tuple(run_id for run_id, _observation in entries)
    run_values = tuple(
        (run_id, observation.value) for run_id, observation in entries
    )
    observed = [
        (run_id, observation)
        for run_id, observation in entries
        if observation.observed
    ]
    if not observed:
        return FeatureObservation.missing(
            name,
            source=source,
            extractor_version=extractor_version,
            details={
                "reason": "no-observed-probe-run",
                "aggregation": FEATURE_AGGREGATION_VERSION,
                "aggregated_probe_run_ids": run_ids,
                "probe_run_values": run_values,
                "unobserved_probe_runs": len(entries),
            },
        )

    selected_run_id, selected = min(
        observed,
        key=lambda item: (-_numeric_feature_value(name, item[1].value), item[0]),
    )
    details = dict(selected.details)
    details.update(
        {
            "aggregation": FEATURE_AGGREGATION_VERSION,
            "aggregated_probe_run_ids": run_ids,
            "selected_probe_run_id": selected_run_id,
            "probe_run_values": run_values,
            "unobserved_probe_runs": len(entries) - len(observed),
        }
    )
    return FeatureObservation(
        name=name,
        value=selected.value,
        observed=True,
        source=source,
        extractor_version=extractor_version,
        details=details,
    )


def _consistent_feature_origin(
    name: str,
    entries: Sequence[tuple[str, FeatureObservation]],
) -> tuple[str, str]:
    sources = {observation.source for _run_id, observation in entries}
    versions = {observation.extractor_version for _run_id, observation in entries}
    if len(sources) != 1 or len(versions) != 1:
        raise FeatureExtractionError(
            f"feature {name} was produced by more than one extractor"
        )
    return sources.pop(), versions.pop()


def _numeric_feature_value(name: str, value: object) -> float:
    if value is None or not isinstance(value, bool | int | float):
        raise FeatureExtractionError(
            f"observed feature {name} must be numeric"
        )
    return float(value)


def _validate_feature_inputs(
    input_point: InputPoint,
    probe_plan: ProbePlan,
    response_pair: ResponsePair,
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> None:
    if not isinstance(input_point, InputPoint):
        raise FeatureExtractionError("input_point must be an InputPoint")
    if not isinstance(probe_plan, ProbePlan):
        raise FeatureExtractionError("probe_plan must be a ProbePlan")
    if response_pair.input_point_id != input_point.id:
        raise FeatureExtractionError("ResponsePair does not target this InputPoint")
    if probe_plan.input_point_id != input_point.id:
        raise FeatureExtractionError("ProbePlan does not target this InputPoint")
    if response_pair.probe_plan_id != probe_plan.id:
        raise FeatureExtractionError("ResponsePair does not target this ProbePlan")
    if response_pair.baseline_response_id != baseline_response.id:
        raise FeatureExtractionError("baseline ResponseSnapshot mismatch")
    if response_pair.probe_response_id != probe_response.id:
        raise FeatureExtractionError("probe ResponseSnapshot mismatch")
    _validate_response_ownership(
        label=REQUEST_ROLE_BASELINE,
        response=baseline_response,
        expected_probe_plan_id=probe_plan.id or "",
        expected_request_role=REQUEST_ROLE_BASELINE,
        expected_request_id=probe_plan.baseline_request.id or "",
    )
    _validate_response_ownership(
        label=REQUEST_ROLE_PROBE,
        response=probe_response,
        expected_probe_plan_id=probe_plan.id or "",
        expected_request_role=REQUEST_ROLE_PROBE,
        expected_request_id=probe_plan.probe_request.id or "",
    )


def _validate_response_ownership(
    *,
    label: str,
    response: ResponseSnapshot,
    expected_probe_plan_id: str,
    expected_request_role: str,
    expected_request_id: str,
) -> None:
    if response.probe_plan_id != expected_probe_plan_id:
        raise FeatureExtractionError(
            f"{label} response ProbePlan provenance mismatch"
        )
    if response.request_role != expected_request_role:
        raise FeatureExtractionError(f"{label} response role mismatch")
    if response.request_id != expected_request_id:
        raise FeatureExtractionError(f"{label} response request mismatch")


def _status_code_changed(
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> FeatureObservation:
    value = 1.0 if baseline_response.status_code != probe_response.status_code else 0.0
    return FeatureObservation(
        name=STATUS_CODE_CHANGED,
        value=value,
        observed=True,
        source="response_diff",
        extractor_version=DIFFERENTIAL_EXTRACTOR_VERSION,
        details={
            "baseline_status_code": baseline_response.status_code,
            "probe_status_code": probe_response.status_code,
        },
    )


def _response_length_diff_ratio(
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> FeatureObservation:
    baseline_length = baseline_response.body_length_bytes
    probe_length = probe_response.body_length_bytes
    raw_ratio = abs(probe_length - baseline_length) / max(baseline_length, 1)
    value = min(raw_ratio, 1.0)
    return FeatureObservation(
        name=RESPONSE_LENGTH_DIFF_RATIO,
        value=value,
        observed=True,
        source="response_diff",
        extractor_version=DIFFERENTIAL_EXTRACTOR_VERSION,
        details={
            "baseline_length": baseline_length,
            "probe_length": probe_length,
            "raw_ratio": raw_ratio,
            "formula": "abs(probe-baseline)/max(baseline,1), clipped to 1.0",
        },
    )


def _marker_reflected(
    probe_plan: ProbePlan,
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> FeatureObservation:
    marker = probe_plan.probe_marker
    if not marker:
        return FeatureObservation.missing(
            MARKER_REFLECTED,
            source="reflection_marker_probe",
            extractor_version=REFLECTION_EXTRACTOR_VERSION,
            details={"reason": "probe-marker-missing"},
        )
    baseline_text = baseline_response.decoded_text
    probe_text = probe_response.decoded_text
    if baseline_text is None or probe_text is None:
        return FeatureObservation.missing(
            MARKER_REFLECTED,
            source="reflection_marker_probe",
            extractor_version=REFLECTION_EXTRACTOR_VERSION,
            details=_undecoded_body_details(baseline_text, probe_text),
        )
    # Detect the alphanumeric identifier, not the full marker: a sentinel marker
    # carries `<`, `>`, `"`, `'`, and an app that entity-encodes them would drop
    # the raw marker from the body and read as "not reflected". The identifier
    # survives encoding, so reflection is judged on it and the encoding question
    # is answered separately by safe_html_encoding_detected.
    identifier = marker_identifier(marker)
    baseline_contains = identifier in baseline_text
    probe_contains = identifier in probe_text
    value = 1.0 if probe_contains and not baseline_contains else 0.0
    return FeatureObservation(
        name=MARKER_REFLECTED,
        value=value,
        observed=True,
        source="reflection_marker_probe",
        extractor_version=REFLECTION_EXTRACTOR_VERSION,
        details={
            "marker": marker,
            "identifier": identifier,
            "baseline_contains_marker": baseline_contains,
            "probe_contains_marker": probe_contains,
        },
    )


def _safe_html_encoding_detected(
    probe_plan: ProbePlan,
    probe_response: ResponseSnapshot,
) -> FeatureObservation:
    """Whether the reflected sentinel's dangerous characters were entity-encoded.

    Three states beyond the value (domain rule 8: missing is not observed 0):

    * marker has no sentinel (neutral strategy) -> unobserved.
    * identifier reflected but sentinel region absent -> filtered -> unobserved.
    * sentinel present -> 1.0 if every dangerous character is an entity, 0.0 if
      any survives raw. Partial encoding is 0.0: one raw character is enough to
      break out.
    """

    marker = probe_plan.probe_marker
    if not marker or "Z" not in marker:
        return FeatureObservation.missing(
            SAFE_HTML_ENCODING_DETECTED,
            source="reflection_encoding_probe",
            extractor_version=ENCODING_EXTRACTOR_VERSION,
            details={"reason": "marker-has-no-sentinel"},
        )
    probe_text = probe_response.decoded_text
    if probe_text is None:
        return FeatureObservation.missing(
            SAFE_HTML_ENCODING_DETECTED,
            source="reflection_encoding_probe",
            extractor_version=ENCODING_EXTRACTOR_VERSION,
            details=_undecoded_body_details(probe_text, probe_text),
        )
    identifier = marker_identifier(marker)
    regions = _sentinel_regions(probe_text, identifier)
    if not regions:
        return FeatureObservation.missing(
            SAFE_HTML_ENCODING_DETECTED,
            source="reflection_encoding_probe",
            extractor_version=ENCODING_EXTRACTOR_VERSION,
            details={"reason": "sentinel-filtered-or-not-reflected"},
        )
    raw_chars = sorted(
        {char for region in regions for char in SENTINEL_CHARS if char in region}
    )
    has_entity = any(
        entity in region for region in regions for entity in _ENTITY_MARKERS
    )
    if raw_chars:
        value = 0.0
    elif has_entity:
        value = 1.0
    else:
        return FeatureObservation.missing(
            SAFE_HTML_ENCODING_DETECTED,
            source="reflection_encoding_probe",
            extractor_version=ENCODING_EXTRACTOR_VERSION,
            details={"reason": "sentinel-stripped", "regions": tuple(regions)},
        )
    return FeatureObservation(
        name=SAFE_HTML_ENCODING_DETECTED,
        value=value,
        observed=True,
        source="reflection_encoding_probe",
        extractor_version=ENCODING_EXTRACTOR_VERSION,
        details={
            "regions": tuple(regions),
            "raw_characters": tuple(raw_chars),
            "any_entity_encoded": has_entity,
        },
    )


def _reflection_count_norm(
    probe_plan: ProbePlan,
    probe_response: ResponseSnapshot,
) -> FeatureObservation:
    """``min(identifier occurrences / 3, 1.0)`` in the probe response."""

    marker = probe_plan.probe_marker
    probe_text = probe_response.decoded_text
    if not marker or probe_text is None:
        return FeatureObservation.missing(
            REFLECTION_COUNT_NORM,
            source="reflection_marker_probe",
            extractor_version=REFLECTION_EXTRACTOR_VERSION,
            details=(
                {"reason": "probe-marker-missing"}
                if not marker
                else _undecoded_body_details(probe_text, probe_text)
            ),
        )
    identifier = marker_identifier(marker)
    count = probe_text.count(identifier)
    value = min(count / 3.0, 1.0)
    return FeatureObservation(
        name=REFLECTION_COUNT_NORM,
        value=value,
        observed=True,
        source="reflection_marker_probe",
        extractor_version=REFLECTION_EXTRACTOR_VERSION,
        details={"identifier": identifier, "occurrences": count},
    )


def _sentinel_regions(text: str, identifier: str) -> tuple[str, ...]:
    """Return the substrings between the sentinel's ``Z`` delimiters.

    The reflected value is ``identifier + "Z" + <chars> + "Z"``, contiguous even
    when the characters are entity-encoded (the delimiters are alphanumeric).
    Anchoring on ``identifier + "Z"`` guarantees the leading delimiter belongs to
    this reflection rather than to unrelated body text.
    """

    anchor = identifier + "Z"
    regions: list[str] = []
    start = 0
    while True:
        opened = text.find(anchor, start)
        if opened == -1:
            break
        content_start = opened + len(anchor)
        closed = text.find("Z", content_start)
        if closed != -1:
            regions.append(text[content_start:closed])
            start = closed + 1
        else:
            start = content_start
    return tuple(regions)


def _sql_error_pattern(
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> FeatureObservation:
    baseline_text = baseline_response.decoded_text
    probe_text = probe_response.decoded_text
    if baseline_text is None or probe_text is None:
        return FeatureObservation.missing(
            SQL_ERROR_PATTERN,
            source="sql_error_probe",
            extractor_version=SQL_EXTRACTOR_VERSION,
            details=_undecoded_body_details(baseline_text, probe_text),
        )
    baseline_patterns = _matched_sql_patterns(baseline_text)
    probe_patterns = _matched_sql_patterns(probe_text)
    new_patterns = tuple(
        pattern for pattern in probe_patterns if pattern not in baseline_patterns
    )
    value = 1.0 if new_patterns else 0.0
    return FeatureObservation(
        name=SQL_ERROR_PATTERN,
        value=value,
        observed=True,
        source="sql_error_probe",
        extractor_version=SQL_EXTRACTOR_VERSION,
        details={
            "baseline_patterns": baseline_patterns,
            "probe_patterns": probe_patterns,
            "new_patterns": new_patterns,
        },
    )


def _missing_features_for_execution_error(
    baseline_response: ResponseSnapshot,
    probe_response: ResponseSnapshot,
) -> dict[str, FeatureObservation]:
    details = {
        "reason": "execution-error",
        "baseline_execution_error": baseline_response.execution_error,
        "probe_execution_error": probe_response.execution_error,
    }
    return {
        STATUS_CODE_CHANGED: FeatureObservation.missing(
            STATUS_CODE_CHANGED,
            source="response_diff",
            extractor_version=DIFFERENTIAL_EXTRACTOR_VERSION,
            details=details,
        ),
        RESPONSE_LENGTH_DIFF_RATIO: FeatureObservation.missing(
            RESPONSE_LENGTH_DIFF_RATIO,
            source="response_diff",
            extractor_version=DIFFERENTIAL_EXTRACTOR_VERSION,
            details=details,
        ),
        MARKER_REFLECTED: FeatureObservation.missing(
            MARKER_REFLECTED,
            source="reflection_marker_probe",
            extractor_version=REFLECTION_EXTRACTOR_VERSION,
            details=details,
        ),
        SAFE_HTML_ENCODING_DETECTED: FeatureObservation.missing(
            SAFE_HTML_ENCODING_DETECTED,
            source="reflection_encoding_probe",
            extractor_version=ENCODING_EXTRACTOR_VERSION,
            details=details,
        ),
        REFLECTION_COUNT_NORM: FeatureObservation.missing(
            REFLECTION_COUNT_NORM,
            source="reflection_marker_probe",
            extractor_version=REFLECTION_EXTRACTOR_VERSION,
            details=details,
        ),
        SQL_ERROR_PATTERN: FeatureObservation.missing(
            SQL_ERROR_PATTERN,
            source="sql_error_probe",
            extractor_version=SQL_EXTRACTOR_VERSION,
            details=details,
        ),
    }


def _undecoded_body_details(
    baseline_text: str | None,
    probe_text: str | None,
) -> dict[str, object]:
    """Body-text features stay unobserved when a body could not be decoded."""

    return {
        "reason": "response-body-not-decoded",
        "baseline_body_decoded": baseline_text is not None,
        "probe_body_decoded": probe_text is not None,
    }


def _matched_sql_patterns(text: str) -> tuple[str, ...]:
    matches: list[str] = []
    for name, pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            matches.append(name)
    return tuple(matches)
