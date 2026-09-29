from __future__ import annotations

import html
import unittest
from dataclasses import dataclass, field, replace
from types import SimpleNamespace

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
    SQL_ERROR_PATTERN,
    combine_input_point_features,
    extract_minimal_features,
)
from vulnspider.observation import ProbePlanner, TransportResponse
from vulnspider.observation.executor import RequestExecutor
from vulnspider.pipeline import ProbeObservation
from vulnspider.scoring import generate_candidates
from vulnspider.scoring.calibration import (
    CalibratedScorer,
    heuristic_prior_for_family,
)
from vulnspider.selection import select_top_k
from vulnspider.verification import (
    DeterministicMutationProposer,
    FeatureVectorDelta,
    FocusedVerificationError,
    MutationFamily,
    MutationSubject,
    PayloadProposal,
    PayloadValidator,
    ResultStatus,
    ValidatorDecision,
    ValidatorRejectionReason,
    VerificationConfig,
    VerificationOutcome,
    VerificationResult,
    VerificationTarget,
    compute_feature_delta,
    plan_verification_probe,
    update_confidence,
    VerificationSelection,
    verify_analysis,
    verify_target,
)
from vulnspider.verification.result import ExecutionRefs


@dataclass
class ScriptedTransport:
    """Loopback fake whose response is decided by the last query/form value."""

    mode: str
    calls: list[RequestInstance] = field(default_factory=list)

    def send(
        self, request: RequestInstance, *, timeout_seconds: float
    ) -> TransportResponse:
        self.calls.append(request)
        values = [value for _name, value in (request.query or request.form)]
        target = values[-1] if values else ""
        return self._respond(target)

    def _respond(self, target: str) -> TransportResponse:
        if self.mode == "quote_error":
            if "'" in target or '"' in target:
                return TransportResponse(
                    500, b"<html>error in your SQL syntax near</html>", {}, 1.0, "utf-8"
                )
            return TransportResponse(200, f"<p>{target}</p>".encode(), {}, 1.0, "utf-8")
        if self.mode == "boundary_error":
            if target == "-1":
                return TransportResponse(
                    500, b"<html>ORA-01427 SQL syntax</html>", {}, 1.0, "utf-8"
                )
            return TransportResponse(200, b"<p>row</p>", {}, 1.0, "utf-8")
        if self.mode == "raw_reflect":
            return TransportResponse(
                200, f"<div>{target}</div>".encode(), {}, 1.0, "utf-8"
            )
        if self.mode == "safe_encode":
            return TransportResponse(
                200, f"<div>{html.escape(target)}</div>".encode(), {}, 1.0, "utf-8"
            )
        if self.mode == "static":
            return TransportResponse(200, b"<p>same</p>", {}, 1.0, "utf-8")
        raise AssertionError(f"unknown transport mode {self.mode}")


def _endpoint() -> Endpoint:
    return Endpoint(HttpMethod.GET, "http", "127.0.0.1", "/search")


def _query_input_point(baseline_value: str = "7") -> InputPoint:
    endpoint = _endpoint()
    return InputPoint(
        endpoint_id=endpoint.id or "",
        endpoint_fingerprint=endpoint.fingerprint,
        location=InputLocation.QUERY,
        name="q",
        baseline_value=baseline_value,
    )


def _baseline_run(mode: str, baseline_value: str = "7"):
    """Run the v0.1 light probe once and return (input_point, plan, vector)."""

    endpoint = _endpoint()
    input_point = _query_input_point(baseline_value)
    template = RequestTemplate(
        endpoint_id=endpoint.id or "",
        endpoint_fingerprint=endpoint.fingerprint,
        method=HttpMethod.GET,
        url=f"http://127.0.0.1/search?q={baseline_value}",
        query=(("q", baseline_value),),
        completeness=RequestContextCompleteness.COMPLETE,
        context_key="k",
    )
    context = InputPointRequestContext.from_objects(input_point, template)
    plan = ProbePlanner().plan(input_point, template, context)
    execution = RequestExecutor(transport=ScriptedTransport(mode)).execute_plan(plan)
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
    return input_point, plan, vector


def _target(mode: str, vtype: str, baseline_value: str = "7") -> VerificationTarget:
    input_point, plan, vector = _baseline_run(mode, baseline_value)
    candidate = next(
        result.candidate
        for result in generate_candidates(vector)
        if result.candidate.vulnerability_type.value == vtype
    )
    prior = (
        CalibratedScorer.from_prior(heuristic_prior_for_family(vtype))
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


class ProposerTests(unittest.TestCase):
    def _subject(self, vtype: str, value: str | None = "7") -> MutationSubject:
        return MutationSubject(
            candidate_id="cand_x",
            input_point_id="inp_x",
            vulnerability_type=VulnerabilityType(vtype),
            parameter_name="q",
            parameter_location=InputLocation.QUERY,
            baseline_value=value,
        )

    def test_sqli_families_are_sql_meta_and_boundary(self) -> None:
        proposals = DeterministicMutationProposer().propose(self._subject("SQLI"))
        families = {p.family for p in proposals}
        self.assertEqual(families, {MutationFamily.SQL_META, MutationFamily.BOUNDARY})

    def test_xss_uses_html_sentinel_with_embedded_marker(self) -> None:
        proposals = DeterministicMutationProposer().propose(
            self._subject("REFLECTED_XSS")
        )
        sentinel = [p for p in proposals if p.family == MutationFamily.HTML_SENTINEL]
        self.assertTrue(sentinel)
        for proposal in sentinel:
            self.assertIsNotNone(proposal.reflection_marker)
            self.assertEqual(proposal.reflection_marker, proposal.mutated_value)
            self.assertNotIn("Z", proposal.mutated_value.split("Z", 1)[0])

    def test_boundary_only_for_integer_baseline(self) -> None:
        numeric = DeterministicMutationProposer().propose(self._subject("SQLI", "7"))
        textual = DeterministicMutationProposer().propose(self._subject("SQLI", "book"))
        self.assertTrue(any(p.family == MutationFamily.BOUNDARY for p in numeric))
        self.assertFalse(any(p.family == MutationFamily.BOUNDARY for p in textual))

    def test_boundary_skips_value_equal_to_baseline(self) -> None:
        proposals = DeterministicMutationProposer().propose(self._subject("SQLI", "-1"))
        boundary = [p.mutated_value for p in proposals if p.family == MutationFamily.BOUNDARY]
        self.assertNotIn("-1", boundary)

    def test_deterministic_output_is_reproducible(self) -> None:
        subject = self._subject("SQLI")
        first = DeterministicMutationProposer().propose(subject)
        second = DeterministicMutationProposer().propose(subject)
        self.assertEqual([p.id for p in first], [p.id for p in second])

    def test_max_proposals_is_bounded(self) -> None:
        proposals = DeterministicMutationProposer(max_proposals=2).propose(
            self._subject("SQLI")
        )
        self.assertEqual(len(proposals), 2)


class ValidatorTests(unittest.TestCase):
    def _proposal(
        self,
        *,
        family: MutationFamily = MutationFamily.SQL_META,
        value: str = "abc'",
        vtype: str = "SQLI",
        based_on: str | None = "7",
    ) -> PayloadProposal:
        return PayloadProposal(
            candidate_id="cand_x",
            input_point_id="inp_x",
            vulnerability_type=VulnerabilityType(vtype),
            family=family,
            variant_index=0,
            mutated_value=value,
            based_on_value=based_on,
            reflection_marker=None,
            rationale="test",
            provider="test",
            proposer_version="test-v1",
        )

    def test_accepts_benign_metacharacter(self) -> None:
        result = PayloadValidator().validate(self._proposal())
        self.assertEqual(result.decision, ValidatorDecision.ACCEPTED)
        self.assertIsNotNone(result.validated_payload)
        self.assertEqual(result.rejection_reasons, ())

    def test_rejects_destructive_keyword(self) -> None:
        result = PayloadValidator().validate(self._proposal(value="1'; DROP TABLE t"))
        self.assertEqual(result.decision, ValidatorDecision.REJECTED)
        self.assertIn(
            ValidatorRejectionReason.DESTRUCTIVE_KEYWORD, result.rejection_reasons
        )
        self.assertIsNone(result.validated_payload)

    def test_rejects_stacked_query(self) -> None:
        result = PayloadValidator().validate(self._proposal(value="1'; select 2"))
        self.assertIn(ValidatorRejectionReason.STACKED_QUERY, result.rejection_reasons)

    def test_rejects_non_ascii_and_control(self) -> None:
        self.assertIn(
            ValidatorRejectionReason.DISALLOWED_CHARACTER,
            PayloadValidator().validate(self._proposal(value="café")).rejection_reasons,
        )
        self.assertIn(
            ValidatorRejectionReason.DISALLOWED_CHARACTER,
            PayloadValidator().validate(self._proposal(value="a\nb")).rejection_reasons,
        )

    def test_rejects_overlong_payload(self) -> None:
        result = PayloadValidator().validate(self._proposal(value="a" * 300))
        self.assertIn(ValidatorRejectionReason.PAYLOAD_TOO_LONG, result.rejection_reasons)

    def test_rejects_family_type_mismatch(self) -> None:
        result = PayloadValidator().validate(
            self._proposal(family=MutationFamily.HTML_SENTINEL, vtype="SQLI")
        )
        self.assertIn(
            ValidatorRejectionReason.FAMILY_TYPE_MISMATCH, result.rejection_reasons
        )

    def test_rejects_unchanged_value(self) -> None:
        result = PayloadValidator().validate(self._proposal(value="7", based_on="7"))
        self.assertIn(
            ValidatorRejectionReason.UNCHANGED_FROM_BASELINE, result.rejection_reasons
        )


class PlannerTests(unittest.TestCase):
    def test_query_injection_changes_only_target_value(self) -> None:
        endpoint = _endpoint()
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.QUERY,
            name="q",
            baseline_value="book",
        )
        baseline = RequestInstance(
            method=HttpMethod.GET,
            url="http://127.0.0.1/search?page=2&q=book",
            query=(("page", "2"), ("q", "book")),
        )
        plan = plan_verification_probe(
            input_point=input_point,
            baseline_request=baseline,
            injected_value="INJECT",
            probe_marker="INJECT",
            mutation_family=MutationFamily.HTML_SENTINEL,
        )
        self.assertEqual(plan.probe_request.query, (("page", "2"), ("q", "INJECT")))
        self.assertIn("page=2", plan.probe_request.url)
        self.assertIn("q=INJECT", plan.probe_request.url)
        self.assertEqual(plan.changed_fields, ("query.q",))
        self.assertEqual(plan.baseline_request.query, (("page", "2"), ("q", "book")))

    def test_form_injection_changes_body_pairs(self) -> None:
        endpoint = Endpoint(HttpMethod.POST, "http", "127.0.0.1", "/login")
        input_point = InputPoint(
            endpoint_id=endpoint.id or "",
            endpoint_fingerprint=endpoint.fingerprint,
            location=InputLocation.FORM,
            name="user",
            baseline_value="alice",
        )
        baseline = RequestInstance(
            method=HttpMethod.POST,
            url="http://127.0.0.1/login",
            form=(("user", "alice"), ("pw", "x")),
        )
        plan = plan_verification_probe(
            input_point=input_point,
            baseline_request=baseline,
            injected_value="INJECT",
            probe_marker=None,
            mutation_family=MutationFamily.SQL_META,
        )
        self.assertEqual(plan.probe_request.form, (("user", "INJECT"), ("pw", "x")))
        self.assertEqual(plan.probe_request.url, "http://127.0.0.1/login")


class DeltaTests(unittest.TestCase):
    def _delta(self, mode_baseline: str, mode_verify: str) -> FeatureVectorDelta:
        input_point, plan, baseline = _baseline_run(mode_baseline)
        verify_plan = plan_verification_probe(
            input_point=input_point,
            baseline_request=plan.baseline_request,
            injected_value="probe'",
            probe_marker=None,
            mutation_family=MutationFamily.SQL_META,
        )
        execution = RequestExecutor(
            transport=ScriptedTransport(mode_verify)
        ).execute_plan(verify_plan)
        verify_vector = extract_minimal_features(
            input_point,
            verify_plan,
            execution.response_pair,
            execution.baseline_response,
            execution.probe_response,
        )
        return compute_feature_delta(baseline, verify_vector)

    def test_static_probe_is_not_changed(self) -> None:
        delta = self._delta("static", "static")
        self.assertFalse(delta.changed)
        self.assertEqual(delta.max_abs_delta, 0.0)

    def test_new_sql_error_moves_the_feature(self) -> None:
        delta = self._delta("static", "quote_error")
        sql = delta.get(SQL_ERROR_PATTERN)
        self.assertIsNotNone(sql)
        assert sql is not None
        self.assertEqual(sql.verification_value, 1.0)
        self.assertTrue(delta.changed)


class ConfidenceRuleTests(unittest.TestCase):
    def _delta_from(self, baseline_pairs, verify_pairs) -> FeatureVectorDelta:
        from vulnspider.domain import FeatureObservation, FeatureVector

        def vector(pairs) -> FeatureVector:
            features = {
                name: FeatureObservation(
                    name=name,
                    value=value,
                    observed=value is not None,
                    source="test",
                    extractor_version="test-v1",
                )
                if value is not None
                else FeatureObservation.missing(
                    name, source="test", extractor_version="test-v1"
                )
                for name, value in pairs.items()
            }
            return FeatureVector(
                input_point_id="inp_x",
                probe_run_ids=("pair_x",),
                features=features,
            )

        return compute_feature_delta(vector(baseline_pairs), vector(verify_pairs))

    def test_reproduced_sql_signal_keeps_prior(self) -> None:
        delta = self._delta_from(
            {"sql_error_pattern": 1.0, "response_length_diff_ratio": 0.1},
            {"sql_error_pattern": 1.0, "response_length_diff_ratio": 0.1},
        )
        result = update_confidence(
            vulnerability_type=VulnerabilityType.SQLI,
            prior_probability=0.9,
            delta=delta,
        )
        self.assertEqual(result.outcome, VerificationOutcome.SUPPORTED)
        self.assertAlmostEqual(result.confidence, 0.9)

    def test_newly_revealed_sql_signal_raises(self) -> None:
        delta = self._delta_from(
            {"sql_error_pattern": 0.0},
            {"sql_error_pattern": 1.0},
        )
        result = update_confidence(
            vulnerability_type=VulnerabilityType.SQLI,
            prior_probability=0.3,
            delta=delta,
        )
        self.assertEqual(result.outcome, VerificationOutcome.SUPPORTED)
        self.assertGreater(result.confidence, 0.3)

    def test_encoded_reflection_weakens(self) -> None:
        delta = self._delta_from(
            {"marker_reflected": 1.0, "safe_html_encoding_detected": 0.0},
            {"marker_reflected": 1.0, "safe_html_encoding_detected": 1.0},
        )
        result = update_confidence(
            vulnerability_type=VulnerabilityType.REFLECTED_XSS,
            prior_probability=0.6,
            delta=delta,
        )
        self.assertEqual(result.outcome, VerificationOutcome.WEAKENED)
        self.assertLess(result.confidence, 0.6)

    def test_server_error_without_signal_is_inconclusive(self) -> None:
        delta = self._delta_from(
            {"sql_error_pattern": 0.0, "status_code_changed": 0.0},
            {"sql_error_pattern": 0.0, "status_code_changed": 1.0},
        )
        result = update_confidence(
            vulnerability_type=VulnerabilityType.SQLI,
            prior_probability=0.4,
            delta=delta,
            probe_status_code=500,
            baseline_status_code=200,
        )
        self.assertEqual(result.outcome, VerificationOutcome.INCONCLUSIVE_ERROR)
        self.assertAlmostEqual(result.confidence, 0.4)

    def test_length_change_without_server_error_is_unchanged(self) -> None:
        # A big length swing with no 5xx and no vuln signal is a benign
        # difference, not an inconclusive error (over-generation fix).
        delta = self._delta_from(
            {"sql_error_pattern": 0.0, "response_length_diff_ratio": 0.0},
            {"sql_error_pattern": 0.0, "response_length_diff_ratio": 0.9},
        )
        result = update_confidence(
            vulnerability_type=VulnerabilityType.SQLI,
            prior_probability=0.4,
            delta=delta,
            probe_status_code=200,
            baseline_status_code=200,
        )
        self.assertEqual(result.outcome, VerificationOutcome.UNCHANGED)
        self.assertAlmostEqual(result.confidence, 0.4)

    def test_non_5xx_status_change_is_not_inconclusive(self) -> None:
        # A 404/400 (app rejecting the payload) is benign, not a server error.
        delta = self._delta_from(
            {"sql_error_pattern": 0.0, "status_code_changed": 0.0},
            {"sql_error_pattern": 0.0, "status_code_changed": 1.0},
        )
        result = update_confidence(
            vulnerability_type=VulnerabilityType.SQLI,
            prior_probability=0.4,
            delta=delta,
            probe_status_code=404,
            baseline_status_code=200,
        )
        self.assertEqual(result.outcome, VerificationOutcome.UNCHANGED)

    def test_not_executed_keeps_prior(self) -> None:
        result = update_confidence(
            vulnerability_type=VulnerabilityType.SQLI,
            prior_probability=0.55,
            delta=None,
            executed=False,
        )
        self.assertEqual(result.outcome, VerificationOutcome.NOT_EXECUTED)
        self.assertAlmostEqual(result.confidence, 0.55)

    def test_confidence_stays_inside_unit_interval(self) -> None:
        delta = self._delta_from(
            {"sql_error_pattern": 0.0}, {"sql_error_pattern": 1.0}
        )
        result = update_confidence(
            vulnerability_type=VulnerabilityType.SQLI,
            prior_probability=0.999999,
            delta=delta,
        )
        self.assertLess(result.confidence, 1.0)
        self.assertGreater(result.confidence, 0.0)


class VerifyTargetTests(unittest.TestCase):
    def test_external_target_is_rejected_before_transport(self) -> None:
        target = _target("quote_error", "SQLI")
        target = replace(
            target,
            baseline_request=replace(
                target.baseline_request,
                url="https://example.com/search?q=7",
            ),
        )
        transport = ScriptedTransport("quote_error")

        with self.assertRaises(FocusedVerificationError):
            verify_target(
                target,
                config=VerificationConfig(transport=transport),
            )

        self.assertEqual(transport.calls, [])

    def test_reproduced_signal_keeps_confidence(self) -> None:
        target = _target("quote_error", "SQLI")
        outcome = verify_target(target, config=VerificationConfig(
            transport=ScriptedTransport("quote_error")
        ))
        self.assertEqual(outcome.final_outcome, ResultStatus.SUPPORTED)
        self.assertAlmostEqual(outcome.final_confidence, target.prior_probability)

    def test_boundary_only_error_raises_confidence(self) -> None:
        target = _target("boundary_error", "SQLI")
        outcome = verify_target(target, config=VerificationConfig(
            transport=ScriptedTransport("boundary_error")
        ))
        self.assertEqual(outcome.final_outcome, ResultStatus.SUPPORTED)
        self.assertGreater(outcome.final_confidence, target.prior_probability)

    def test_safe_encoding_weakens_confidence(self) -> None:
        target = _target("safe_encode", "REFLECTED_XSS")
        outcome = verify_target(target, config=VerificationConfig(
            transport=ScriptedTransport("safe_encode")
        ))
        self.assertEqual(outcome.final_outcome, ResultStatus.WEAKENED)
        self.assertLess(outcome.final_confidence, target.prior_probability)

    def test_every_executed_result_has_provenance(self) -> None:
        target = _target("quote_error", "SQLI")
        outcome = verify_target(target, config=VerificationConfig(
            transport=ScriptedTransport("quote_error")
        ))
        for result in outcome.results:
            self.assertEqual(result.contract_version, "0.1")
            if result.executed:
                self.assertIsNotNone(result.execution_refs)
                self.assertIsNotNone(result.feature_delta)


class MaliciousProposerTests(unittest.TestCase):
    @dataclass
    class DestructiveProposer:
        def propose(self, subject: MutationSubject) -> tuple[PayloadProposal, ...]:
            return (
                PayloadProposal(
                    candidate_id=subject.candidate_id,
                    input_point_id=subject.input_point_id,
                    vulnerability_type=subject.vulnerability_type,
                    family=MutationFamily.SQL_META,
                    variant_index=0,
                    mutated_value="1'; DROP TABLE users; --",
                    based_on_value=subject.baseline_value,
                    reflection_marker=None,
                    rationale="malicious",
                    provider="rogue-model",
                    proposer_version="rogue-v1",
                ),
            )

    def test_destructive_payload_is_rejected_and_never_sent(self) -> None:
        target = _target("quote_error", "SQLI")
        transport = ScriptedTransport("quote_error")
        outcome = verify_target(
            target,
            config=VerificationConfig(
                proposer=self.DestructiveProposer(),
                transport=transport,
            ),
        )
        self.assertEqual(len(outcome.results), 1)
        result = outcome.results[0]
        self.assertEqual(result.outcome_status, ResultStatus.REJECTED)
        self.assertIn(
            ValidatorRejectionReason.DESTRUCTIVE_KEYWORD.value,
            result.validator_rejection_reasons,
        )
        self.assertIsNone(result.execution_refs)
        self.assertEqual(transport.calls, [])
        self.assertAlmostEqual(outcome.final_confidence, target.prior_probability)


class ResultInvariantTests(unittest.TestCase):
    def test_rejected_result_forbids_execution_refs(self) -> None:
        proposal = PayloadProposal(
            candidate_id="cand_x",
            input_point_id="inp_x",
            vulnerability_type=VulnerabilityType.SQLI,
            family=MutationFamily.SQL_META,
            variant_index=0,
            mutated_value="1'; DROP TABLE t",
            based_on_value="7",
            reflection_marker=None,
            rationale="x",
            provider="p",
            proposer_version="v1",
        )
        validator_result = PayloadValidator().validate(proposal)
        confidence = update_confidence(
            vulnerability_type=VulnerabilityType.SQLI,
            prior_probability=0.5,
            delta=None,
            executed=False,
        )
        fake_refs = ExecutionRefs(
            probe_plan_id="probe_x",
            baseline_response_id="resp_a",
            probe_response_id="resp_b",
            verification_feature_vector_id="fv_x",
        )
        with self.assertRaises(Exception):
            VerificationResult.from_objects(
                proposal=proposal,
                validator_result=validator_result,
                confidence=confidence,
                baseline_feature_vector_id="fv_base",
                selection_rank=1,
                execution_refs=fake_refs,
            )


class VerifyAnalysisTests(unittest.TestCase):
    def _analysis(self, mode: str, vtype_hint: str) -> SimpleNamespace:
        input_point, plan, vector = _baseline_run(mode)
        # Re-run to capture baseline/probe responses for the observation record.
        execution = RequestExecutor(transport=ScriptedTransport(mode)).execute_plan(plan)
        scored = generate_candidates(vector)
        selection = select_top_k(scored, k=5)
        observation = ProbeObservation(
            feature_vector_id=vector.id or "",
            input_point_id=input_point.id or "",
            probe_plan=plan,
            baseline_response=execution.baseline_response,
            probe_response=execution.probe_response,
        )
        return SimpleNamespace(
            selection=selection,
            feature_vectors=(vector,),
            probe_observations=(observation,),
            input_points=(input_point,),
            endpoints=(_endpoint(),),
        )

    def test_verify_analysis_runs_over_top_k(self) -> None:
        analysis = self._analysis("quote_error", "SQLI")
        run = verify_analysis(
            analysis,
            config=VerificationConfig(transport=ScriptedTransport("quote_error")),
        )
        self.assertTrue(run.candidates)
        counts = run.counts()
        self.assertEqual(counts["rejected"], 0)
        self.assertGreater(counts["executed"], 0)
        payload = run.to_dict(target_url="http://127.0.0.1/")
        self.assertEqual(payload["report_version"], "verification-report-v1")
        self.assertEqual(payload["target"], "http://127.0.0.1/")
        self.assertTrue(payload["candidates"])

    def test_explicit_selection_overrides_the_heuristic_top_k(self) -> None:
        # The report ranks by calibrated probability, so a scan must be able to
        # point verification at that set with those priors; taking
        # analysis.selection instead verifies whatever the v0.1 heuristic
        # ordering happened to put on top.
        analysis = self._analysis("quote_error", "SQLI")
        ranked = analysis.selection.selected
        last = ranked[-1]
        chosen = VerificationSelection(
            candidate_id=last.scoring_result.candidate.id or "",
            input_point_id=last.scoring_result.candidate.input_point_id,
            feature_vector_id=last.scoring_result.feature_vector_id,
            vulnerability_type=last.scoring_result.candidate.vulnerability_type,
            prior_probability=0.42,
        )

        run = verify_analysis(
            analysis,
            config=VerificationConfig(transport=ScriptedTransport("quote_error")),
            selection=(chosen,),
        )

        self.assertEqual(len(run.candidates), 1)
        self.assertEqual(run.candidates[0].candidate_id, chosen.candidate_id)
        self.assertAlmostEqual(run.candidates[0].prior_probability, 0.42)

    def test_verify_analysis_is_deterministic(self) -> None:
        first = verify_analysis(
            self._analysis("quote_error", "SQLI"),
            config=VerificationConfig(transport=ScriptedTransport("quote_error")),
        )
        second = verify_analysis(
            self._analysis("quote_error", "SQLI"),
            config=VerificationConfig(transport=ScriptedTransport("quote_error")),
        )
        self.assertEqual(
            [c.candidate_id for c in first.candidates],
            [c.candidate_id for c in second.candidates],
        )
        self.assertEqual(
            [r.verification_result_id for r in first.results],
            [r.verification_result_id for r in second.results],
        )


if __name__ == "__main__":
    unittest.main()
