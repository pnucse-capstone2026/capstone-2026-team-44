"""Tests for the local fine-tuned LLM payload proposer.

The model itself is replaced by an injected fake ``create_chat_completion``
client, so these tests exercise the prompt shape, the suggestion->proposal
mapping, the safety degradation path, and the full focused-verification loop
(propose -> validate -> re-probe -> delta -> confidence) without loading the
multi-gigabyte GGUF or importing ``llama_cpp``.
"""

from __future__ import annotations

import html
import json
import unittest
from dataclasses import dataclass, field

from vulnspider.domain import (
    Endpoint,
    HttpMethod,
    InputLocation,
    InputPoint,
    InputPointRequestContext,
    RequestContextCompleteness,
    RequestInstance,
    RequestTemplate,
    VulnerabilityType,
)
from vulnspider.features import (
    combine_input_point_features,
    extract_minimal_features,
)
from vulnspider.observation import TransportResponse
from vulnspider.observation.executor import RequestExecutor
from vulnspider.scoring import generate_candidates
from vulnspider.scoring.calibration import (
    CalibratedScorer,
    heuristic_prior_for_family,
)
from vulnspider.observation import ProbePlanner
from vulnspider.verification import (
    LLM_PROPOSER_VERSION,
    PROVIDER_LOCAL_LLM,
    LLMProposerError,
    LocalLLMMutationProposer,
    MutationFamily,
    MutationSubject,
    PayloadValidator,
    ResultStatus,
    VerificationConfig,
    VerificationTarget,
    verify_target,
)
from vulnspider.verification.llm_proposal import build_candidate_prompt, build_user_prompt


@dataclass
class FakeLlama:
    """Stand-in for ``llama_cpp.Llama`` that returns a scripted JSON body."""

    payloads: list[dict[str, object]] | None = None
    content: str | None = None
    error: Exception | None = None
    calls: list[list[dict[str, str]]] = field(default_factory=list)

    def create_chat_completion(self, messages, **kwargs):
        self.calls.append(messages)
        if self.error is not None:
            raise self.error
        if self.content is not None:
            body = self.content
        else:
            body = json.dumps({"payloads": self.payloads or [], "warnings": []})
        return {"choices": [{"message": {"content": body}}]}


_SQLI_PAYLOADS = [
    {"kind": "true_condition", "value": "4200", "rationale": "numeric replacement"},
    {"kind": "true_condition", "value": "42 AND (1000=1000)", "rationale": "true logic"},
    {"kind": "false_condition", "value": "invalid_probe_string", "rationale": "bad type"},
    {"kind": "false_condition", "value": "42 AND (ASCII('a')=99)", "rationale": "false"},
]

_XSS_PAYLOADS = [
    {"kind": "reflection_control", "value": "xss-probe-control", "rationale": "baseline"},
    {
        "kind": "reflection_marker",
        "value": '"><x-element aria-label="xss-probe"></x-element>',
        "rationale": "attribute breakout",
    },
]


def _subject(vtype: VulnerabilityType, value: str | None = "42") -> MutationSubject:
    return MutationSubject(
        candidate_id="cand_x",
        input_point_id="inp_x",
        vulnerability_type=vtype,
        parameter_name="id",
        parameter_location=InputLocation.QUERY,
        baseline_value=value,
    )


class PromptShapeTests(unittest.TestCase):
    def test_candidate_prompt_matches_training_shape(self) -> None:
        prompt = build_candidate_prompt(_subject(VulnerabilityType.SQLI))
        self.assertEqual(
            list(prompt.keys()),
            ["candidate_id", "vulnerability_type", "metadata", "request_context",
             "access_context"],
        )
        self.assertEqual(prompt["vulnerability_type"], "SQLI")
        self.assertIsNone(prompt["access_context"])
        self.assertEqual(prompt["request_context"]["parameter_location"], "query")
        self.assertEqual(prompt["request_context"]["original_value"], "42")

    def test_user_prompt_carries_rules_sentinel(self) -> None:
        text = build_user_prompt(_subject(VulnerabilityType.SQLI))
        self.assertIn("(Assume Type-specific rules are applied here)", text)
        self.assertIn('"vulnerability_type": "SQLI"', text)

    def test_form_location_uses_post_method(self) -> None:
        subject = MutationSubject(
            candidate_id="c",
            input_point_id="i",
            vulnerability_type=VulnerabilityType.SQLI,
            parameter_name="id",
            parameter_location=InputLocation.FORM,
            baseline_value="42",
        )
        prompt = build_candidate_prompt(subject)
        self.assertEqual(prompt["request_context"]["method"], "POST")
        self.assertEqual(prompt["request_context"]["parameter_location"], "form")


class MappingTests(unittest.TestCase):
    def test_sqli_maps_to_sql_meta_and_validator_accepts(self) -> None:
        proposer = LocalLLMMutationProposer(llm=FakeLlama(payloads=_SQLI_PAYLOADS))
        proposals = proposer.propose(_subject(VulnerabilityType.SQLI))
        self.assertEqual(len(proposals), 4)
        self.assertEqual({p.family for p in proposals}, {MutationFamily.SQL_META})
        self.assertTrue(all(p.reflection_marker is None for p in proposals))
        self.assertTrue(all(p.provider == PROVIDER_LOCAL_LLM for p in proposals))
        self.assertTrue(all(p.proposer_version == LLM_PROPOSER_VERSION for p in proposals))
        validator = PayloadValidator()
        self.assertTrue(all(validator.validate(p).accepted for p in proposals))

    def test_sqli_variant_indexes_are_unique(self) -> None:
        proposer = LocalLLMMutationProposer(llm=FakeLlama(payloads=_SQLI_PAYLOADS))
        proposals = proposer.propose(_subject(VulnerabilityType.SQLI))
        self.assertEqual(
            [p.variant_index for p in proposals], list(range(len(proposals)))
        )
        self.assertEqual(len({p.id for p in proposals}), len(proposals))

    def test_xss_wraps_model_value_in_sentinel_marker(self) -> None:
        proposer = LocalLLMMutationProposer(llm=FakeLlama(payloads=_XSS_PAYLOADS))
        proposals = proposer.propose(_subject(VulnerabilityType.REFLECTED_XSS, "7"))
        self.assertEqual({p.family for p in proposals}, {MutationFamily.HTML_SENTINEL})
        validator = PayloadValidator()
        for proposal in proposals:
            value = proposal.mutated_value
            # hybrid marker: identifier + "Z" + region + "Z"
            self.assertEqual(proposal.reflection_marker, value)
            self.assertTrue(value.startswith("VULNSPIDER_"))
            self.assertGreaterEqual(value.count("Z"), 2)
            identifier = value.split("Z", 1)[0]  # what the extractor keys on
            self.assertNotIn("Z", identifier)
            self.assertTrue(validator.validate(proposal).accepted)

    def test_xss_region_preserves_raw_breakout_characters(self) -> None:
        payloads = [{"kind": "reflection_marker", "value": '"><svg>', "rationale": "x"}]
        proposer = LocalLLMMutationProposer(llm=FakeLlama(payloads=payloads))
        (proposal,) = proposer.propose(_subject(VulnerabilityType.REFLECTED_XSS, "7"))
        # the region (between the Z delimiters) keeps the raw < > " the encoder needs
        region = proposal.mutated_value.split("Z", 1)[1].rsplit("Z", 1)[0]
        for char in '<>"':
            self.assertIn(char, region)

    def test_xss_region_strips_sentinel_delimiter(self) -> None:
        payloads = [{"kind": "reflection_marker", "value": 'aZbZc<>', "rationale": "x"}]
        proposer = LocalLLMMutationProposer(llm=FakeLlama(payloads=payloads))
        (proposal,) = proposer.propose(_subject(VulnerabilityType.REFLECTED_XSS, "7"))
        region = proposal.mutated_value.split("Z", 1)[1].rsplit("Z", 1)[0]
        self.assertNotIn("Z", region)

    def test_xss_hint_added_to_prompt(self) -> None:
        from vulnspider.verification.llm_proposal import build_user_prompt

        text = build_user_prompt(_subject(VulnerabilityType.REFLECTED_XSS, "7"))
        self.assertIn("raw", text.lower())
        self.assertIn("differ from the original", text)

    def test_kind_is_recorded_in_rationale(self) -> None:
        proposer = LocalLLMMutationProposer(llm=FakeLlama(payloads=_SQLI_PAYLOADS))
        proposals = proposer.propose(_subject(VulnerabilityType.SQLI))
        self.assertTrue(proposals[0].rationale.startswith("[true_condition]"))

    def test_null_and_blank_values_are_dropped(self) -> None:
        payloads = [
            {"kind": "true_condition", "value": None, "rationale": "x"},
            {"kind": "true_condition", "value": "", "rationale": "x"},
            {"kind": "true_condition", "value": "4200", "rationale": "x"},
        ]
        proposer = LocalLLMMutationProposer(llm=FakeLlama(payloads=payloads))
        proposals = proposer.propose(_subject(VulnerabilityType.SQLI))
        self.assertEqual([p.mutated_value for p in proposals], ["4200"])


class DegradationTests(unittest.TestCase):
    def test_empty_payloads_degrade_to_no_proposals(self) -> None:
        proposer = LocalLLMMutationProposer(
            llm=FakeLlama(payloads=[]), max_retries=2
        )
        self.assertEqual(proposer.propose(_subject(VulnerabilityType.SQLI)), ())
        self.assertEqual(len(proposer.warnings), 2)

    def test_model_error_degrades_to_no_proposals(self) -> None:
        proposer = LocalLLMMutationProposer(
            llm=FakeLlama(error=RuntimeError("boom")), max_retries=1
        )
        self.assertEqual(proposer.propose(_subject(VulnerabilityType.SQLI)), ())
        self.assertTrue(proposer.warnings)

    def test_unparseable_content_extracts_embedded_json(self) -> None:
        body = "Sure! Here is the JSON:\n" + json.dumps(
            {"payloads": _SQLI_PAYLOADS, "warnings": []}
        ) + "\nHope this helps."
        proposer = LocalLLMMutationProposer(llm=FakeLlama(content=body))
        proposals = proposer.propose(_subject(VulnerabilityType.SQLI))
        self.assertEqual(len(proposals), 4)

    def test_missing_model_path_raises_clear_error(self) -> None:
        proposer = LocalLLMMutationProposer()  # no model, no injected llm
        with self.assertRaises(LLMProposerError):
            proposer.propose(_subject(VulnerabilityType.SQLI))


@dataclass
class ScriptedTransport:
    """Loopback fake: a quote in the value yields a SQL syntax-error page."""

    calls: list[RequestInstance] = field(default_factory=list)

    def send(self, request: RequestInstance, *, timeout_seconds: float) -> TransportResponse:
        self.calls.append(request)
        values = [value for _name, value in (request.query or request.form)]
        target = values[-1] if values else ""
        if "'" in target or '"' in target:
            return TransportResponse(
                500, b"<html>error in your SQL syntax near</html>", {}, 1.0, "utf-8"
            )
        return TransportResponse(200, f"<p>{html.escape(target)}</p>".encode(), {}, 1.0, "utf-8")


def _sqli_target() -> VerificationTarget:
    endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
    input_point = InputPoint(
        endpoint_id=endpoint.id or "",
        endpoint_fingerprint=endpoint.fingerprint,
        location=InputLocation.QUERY,
        name="id",
        baseline_value="42",
    )
    template = RequestTemplate(
        endpoint_id=endpoint.id or "",
        endpoint_fingerprint=endpoint.fingerprint,
        method=HttpMethod.GET,
        url="http://127.0.0.1/search?id=42",
        query=(("id", "42"),),
        completeness=RequestContextCompleteness.COMPLETE,
        context_key="k",
    )
    context = InputPointRequestContext.from_objects(input_point, template)
    plan = ProbePlanner().plan(input_point, template, context)
    execution = RequestExecutor(transport=ScriptedTransport()).execute_plan(plan)
    vector = combine_input_point_features(
        [
            extract_minimal_features(
                input_point,
                plan,
                execution.response_pair,
                execution.baseline_response,
                execution.probe_response,
            )
        ]
    )
    candidate = next(
        result.candidate
        for result in generate_candidates(vector)
        if result.candidate.vulnerability_type == VulnerabilityType.SQLI
    )
    prior = (
        CalibratedScorer.from_prior(heuristic_prior_for_family("SQLI"))
        .probability(vector.features)
        .probability
    )
    return VerificationTarget(
        candidate_id=candidate.id or "",
        selection_rank=1,
        vulnerability_type=candidate.vulnerability_type,
        input_point=input_point,
        baseline_request=plan.baseline_request,
        baseline_feature_vector=vector,
        prior_probability=prior,
    )


class EndToEndTests(unittest.TestCase):
    def test_llm_proposer_drives_full_verification_loop(self) -> None:
        target = _sqli_target()
        transport = ScriptedTransport()
        config = VerificationConfig(
            proposer=LocalLLMMutationProposer(llm=FakeLlama(payloads=_SQLI_PAYLOADS)),
            transport=transport,
        )
        verification = verify_target(target, config=config)

        # Every model suggestion became a result, and the loop actually sent
        # loopback requests (proposal accepted -> re-probed).
        self.assertEqual(len(verification.results), 4)
        self.assertTrue(
            all(r.provider == PROVIDER_LOCAL_LLM for r in verification.results)
        )
        self.assertTrue(any(r.executed for r in verification.results))
        self.assertNotEqual(verification.final_outcome, ResultStatus.NOT_EXECUTED)
        self.assertTrue(transport.calls)  # requests really went to the loopback fake

    def test_no_proposals_keeps_prior_and_marks_not_executed(self) -> None:
        target = _sqli_target()
        config = VerificationConfig(
            proposer=LocalLLMMutationProposer(llm=FakeLlama(payloads=[]), max_retries=1),
            transport=ScriptedTransport(),
        )
        verification = verify_target(target, config=config)
        self.assertEqual(verification.results, ())
        self.assertEqual(verification.final_outcome, ResultStatus.NOT_EXECUTED)
        self.assertEqual(verification.final_confidence, target.prior_probability)


@dataclass
class _XssTransport:
    """Loopback fake that either reflects the value raw or entity-encodes it."""

    mode: str  # "raw" | "safe"
    calls: list[RequestInstance] = field(default_factory=list)

    def send(self, request: RequestInstance, *, timeout_seconds: float) -> TransportResponse:
        self.calls.append(request)
        values = [value for _name, value in (request.query or request.form)]
        target = values[-1] if values else ""
        body = target if self.mode == "raw" else html.escape(target)
        return TransportResponse(200, f"<div>{body}</div>".encode(), {}, 1.0, "utf-8")


def _xss_target(mode: str) -> VerificationTarget:
    endpoint = Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")
    input_point = InputPoint(
        endpoint_id=endpoint.id or "",
        endpoint_fingerprint=endpoint.fingerprint,
        location=InputLocation.QUERY,
        name="q",
        baseline_value="hello",
    )
    template = RequestTemplate(
        endpoint_id=endpoint.id or "",
        endpoint_fingerprint=endpoint.fingerprint,
        method=HttpMethod.GET,
        url="http://127.0.0.1/search?q=hello",
        query=(("q", "hello"),),
        completeness=RequestContextCompleteness.COMPLETE,
        context_key="k",
    )
    context = InputPointRequestContext.from_objects(input_point, template)
    plan = ProbePlanner().plan(input_point, template, context)
    execution = RequestExecutor(transport=_XssTransport(mode)).execute_plan(plan)
    vector = combine_input_point_features(
        [
            extract_minimal_features(
                input_point,
                plan,
                execution.response_pair,
                execution.baseline_response,
                execution.probe_response,
            )
        ]
    )
    candidate = next(
        result.candidate
        for result in generate_candidates(vector)
        if result.candidate.vulnerability_type == VulnerabilityType.REFLECTED_XSS
    )
    prior = (
        CalibratedScorer.from_prior(heuristic_prior_for_family("REFLECTED_XSS"))
        .probability(vector.features)
        .probability
    )
    return VerificationTarget(
        candidate_id=candidate.id or "",
        selection_rank=1,
        vulnerability_type=candidate.vulnerability_type,
        input_point=input_point,
        baseline_request=plan.baseline_request,
        baseline_feature_vector=vector,
        prior_probability=prior,
    )


class HybridMarkerXssTests(unittest.TestCase):
    """The sentinel-wrapped XSS payload is measurable: raw -> support, safe -> weaken."""

    _PAYLOAD = [{"kind": "reflection_marker", "value": '"><svg title="xss-probe">', "rationale": "raw breakout"}]

    def _run(self, mode: str):
        config = VerificationConfig(
            proposer=LocalLLMMutationProposer(llm=FakeLlama(payloads=self._PAYLOAD)),
            transport=_XssTransport(mode),
        )
        return verify_target(_xss_target(mode), config=config)

    def test_raw_reflection_supports(self) -> None:
        verification = self._run("raw")
        self.assertEqual(verification.final_outcome, ResultStatus.SUPPORTED)

    def test_safe_encoding_weakens_and_lowers_confidence(self) -> None:
        verification = self._run("safe")
        self.assertEqual(verification.final_outcome, ResultStatus.WEAKENED)
        self.assertLess(verification.final_confidence, verification.prior_probability)


if __name__ == "__main__":
    unittest.main()
