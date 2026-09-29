from __future__ import annotations

import unittest

from vulnspider.domain import (
    HttpMethod,
    InputLocation,
    InputPoint,
    InputPointRequestContext,
    ProbeFamily,
    ProbePlan,
    RequestContextCompleteness,
    RequestInstance,
    RequestTemplate,
    ResponseSnapshot,
)
from vulnspider.features.extraction import (
    REFLECTION_COUNT_NORM,
    SAFE_HTML_ENCODING_DETECTED,
    _marker_reflected,
    _reflection_count_norm,
    _safe_html_encoding_detected,
)
from vulnspider.observation.planner import (
    PROBE_SENTINEL,
    SENTINEL_MARKER_STRATEGY,
)

IDENT = "VULNSPIDER_0123456789ABCDEF"
SENTINEL_MARKER = IDENT + PROBE_SENTINEL  # VULNSPIDER_...Z<>"'Z


def _plan(marker: str, *, strategy: str = SENTINEL_MARKER_STRATEGY) -> ProbePlan:
    input_point = InputPoint(
        endpoint_id="ep",
        endpoint_fingerprint="fp",
        location=InputLocation.QUERY,
        name="q",
        baseline_value="a",
    )
    template = RequestTemplate(
        endpoint_id="ep",
        endpoint_fingerprint="fp",
        method=HttpMethod.GET,
        url="http://127.0.0.1/search?q=a",
        query=(("q", "a"),),
        completeness=RequestContextCompleteness.COMPLETE,
    )
    context = InputPointRequestContext.from_objects(input_point, template)
    return ProbePlan(
        input_point_id=input_point.id or "",
        probe_family=ProbeFamily.REFLECTION_MARKER,
        baseline_request=RequestInstance(
            method=HttpMethod.GET, url=template.url, query=template.query
        ),
        probe_request=RequestInstance(
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?q=" + marker,
            query=(("q", marker),),
        ),
        changed_fields=("query.q",),
        request_template_id=template.id,
        request_context_id=context.id,
        probe_marker=marker,
        marker_strategy=strategy,
    )


def _snapshot(plan: ProbePlan, role: str, decoded_text: str | None) -> ResponseSnapshot:
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


class SafeHtmlEncodingTests(unittest.TestCase):
    def _encoding(self, marker: str, probe_text: str | None, *, strategy=SENTINEL_MARKER_STRATEGY):
        plan = _plan(marker, strategy=strategy)
        return _safe_html_encoding_detected(plan, _snapshot(plan, "probe", probe_text))

    def test_all_characters_encoded_is_safe(self) -> None:
        obs = self._encoding(
            SENTINEL_MARKER, f"<p>{IDENT}Z&lt;&gt;&quot;&#x27;Z</p>"
        )
        self.assertTrue(obs.observed)
        self.assertEqual(obs.value, 1.0)

    def test_one_raw_character_is_dangerous(self) -> None:
        # `>` survives raw while the others are encoded: partial encoding is 0.0.
        obs = self._encoding(SENTINEL_MARKER, f"{IDENT}Z&lt;>&quot;&#x27;Z")
        self.assertTrue(obs.observed)
        self.assertEqual(obs.value, 0.0)

    def test_all_raw_is_dangerous(self) -> None:
        obs = self._encoding(SENTINEL_MARKER, f"<h2>{IDENT}Z<>\"'Z</h2>")
        self.assertTrue(obs.observed)
        self.assertEqual(obs.value, 0.0)

    def test_sentinel_stripped_is_unobserved(self) -> None:
        # Delimiters survive but the dangerous characters were removed.
        obs = self._encoding(SENTINEL_MARKER, f"{IDENT}ZZ")
        self.assertFalse(obs.observed)

    def test_identifier_reflected_without_sentinel_is_unobserved(self) -> None:
        # Filtered: the identifier came back but the sentinel region is gone.
        obs = self._encoding(SENTINEL_MARKER, f"welcome {IDENT} back")
        self.assertFalse(obs.observed)

    def test_not_reflected_is_unobserved(self) -> None:
        obs = self._encoding(SENTINEL_MARKER, "nothing reflected here")
        self.assertFalse(obs.observed)

    def test_neutral_marker_has_no_sentinel_to_judge(self) -> None:
        obs = self._encoding(IDENT, f"{IDENT} reflected", strategy="neutral-reflection-marker-v1")
        self.assertFalse(obs.observed)
        self.assertEqual(obs.name, SAFE_HTML_ENCODING_DETECTED)

    def test_undecoded_body_is_unobserved(self) -> None:
        obs = self._encoding(SENTINEL_MARKER, None)
        self.assertFalse(obs.observed)


class ReflectionCountTests(unittest.TestCase):
    def _count(self, probe_text: str | None):
        plan = _plan(SENTINEL_MARKER)
        return _reflection_count_norm(plan, _snapshot(plan, "probe", probe_text))

    def test_absent_is_zero(self) -> None:
        obs = self._count("no marker")
        self.assertTrue(obs.observed)
        self.assertEqual(obs.value, 0.0)

    def test_one_occurrence(self) -> None:
        obs = self._count(f"{IDENT}Z<>\"'Z")
        self.assertAlmostEqual(obs.value, 1.0 / 3.0)

    def test_clipped_at_one(self) -> None:
        obs = self._count(" ".join([IDENT] * 5))
        self.assertEqual(obs.value, 1.0)

    def test_undecoded_is_unobserved(self) -> None:
        obs = self._count(None)
        self.assertFalse(obs.observed)
        self.assertEqual(obs.name, REFLECTION_COUNT_NORM)


class MarkerReflectedWithSentinelTests(unittest.TestCase):
    def _reflected(self, baseline_text: str, probe_text: str) -> float | None:
        plan = _plan(SENTINEL_MARKER)
        obs = _marker_reflected(
            plan,
            _snapshot(plan, "baseline", baseline_text),
            _snapshot(plan, "probe", probe_text),
        )
        return obs.value

    def test_escaped_reflection_still_counts_as_reflected(self) -> None:
        # The dangerous characters were entity-encoded, so the full marker is
        # absent -- but the identifier survives, so this is still a reflection.
        value = self._reflected(
            "baseline", f"<p>{IDENT}Z&lt;&gt;&quot;&#x27;Z</p>"
        )
        self.assertEqual(value, 1.0)

    def test_raw_reflection_counts_as_reflected(self) -> None:
        value = self._reflected("baseline", f"{IDENT}Z<>\"'Z")
        self.assertEqual(value, 1.0)

    def test_marker_in_baseline_is_not_a_reflection(self) -> None:
        value = self._reflected(f"{IDENT} already here", f"{IDENT} still here")
        self.assertEqual(value, 0.0)


if __name__ == "__main__":
    unittest.main()
