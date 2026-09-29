from __future__ import annotations

import unittest

from vulnspider.cli_decision import decision_report
from vulnspider.decision.candidate import DecisionCandidate
from vulnspider.decision.policy import run_decision_layer
from vulnspider.domain import VulnerabilityType
from vulnspider.reporting.decision_html_report import render_decision_html_report
from vulnspider.scoring.calibration import CalibrationEvidence, CalibratedProbability
from vulnspider.verification import ResultStatus, VerificationSignal
from vulnspider.verification.focused import CandidateVerification


def _candidate(probability: float = 0.4) -> DecisionCandidate:
    return DecisionCandidate(
        candidate_id="cand_1",
        family="SQLI",
        probability=probability,
        selection_rank=1,
        subject_ref="inp_1",
        feature_vector_ref="fv_1",
    )


def _verification(
    prior: float,
    final: float,
    outcome: ResultStatus,
    signal: VerificationSignal,
) -> dict[str, CandidateVerification]:
    return {
        "cand_1": CandidateVerification(
            candidate_id="cand_1",
            input_point_id="inp_1",
            vulnerability_type=VulnerabilityType.SQLI,
            selection_rank=1,
            prior_probability=prior,
            final_outcome=outcome,
            final_signal=signal,
            final_confidence=final,
            results=(),
        )
    }


class VerificationReportTests(unittest.TestCase):
    def test_headline_uses_updated_confidence_when_verified(self) -> None:
        outcome = run_decision_layer((_candidate(0.4),), top_k=1)
        html = render_decision_html_report(
            outcome,
            verification=_verification(
                0.4, 0.7, ResultStatus.SUPPORTED, VerificationSignal.SUPPORT_NEW
            ),
        )
        # The final (verified) confidence is the headline; the prior is shown as
        # context, not as the lead number.
        self.assertIn('class="prio high">70%', html)
        self.assertIn("검증 결과", html)
        self.assertIn("검증 후 최종 신뢰도", html)
        self.assertIn("검증 전 40%", html)
        self.assertIn("검증으로 뒷받침됨", html)

    def test_weakened_lowers_the_headline(self) -> None:
        outcome = run_decision_layer((_candidate(0.6),), top_k=1)
        html = render_decision_html_report(
            outcome,
            verification=_verification(
                0.6, 0.3, ResultStatus.WEAKENED, VerificationSignal.WEAKEN
            ),
        )
        self.assertIn('class="prio low">30%', html)
        self.assertIn("검증으로 약화됨", html)

    def test_without_verification_headline_is_the_prior(self) -> None:
        outcome = run_decision_layer((_candidate(0.4),), top_k=1)
        html = render_decision_html_report(outcome)
        self.assertIn('class="prio', html)
        self.assertIn("40%", html)
        self.assertIn("최종 신뢰도", html)
        self.assertIn("추가 검증 없음 · 검증 전 확률 유지", html)
        self.assertNotIn("검증 결과", html)
        self.assertNotIn("검증 후 최종 신뢰도", html)


class VerificationReorderTests(unittest.TestCase):
    """Verification re-orders the report by final confidence, keeping the set."""

    def _outcome_and_verification(self):
        # Prior order: A (0.6) then B (0.4). Verification flips it: B is
        # supported up to 0.8, A is weakened down to 0.3.
        cand_a = DecisionCandidate(
            candidate_id="cand_A",
            family="SQLI",
            probability=0.6,
            selection_rank=1,
            subject_ref="inp_a",
            feature_vector_ref="fv_a",
        )
        cand_b = DecisionCandidate(
            candidate_id="cand_B",
            family="REFLECTED_XSS",
            probability=0.4,
            selection_rank=2,
            subject_ref="inp_b",
            feature_vector_ref="fv_b",
        )
        outcome = run_decision_layer((cand_a, cand_b), top_k=2)
        verification = {
            "cand_A": CandidateVerification(
                candidate_id="cand_A",
                input_point_id="inp_a",
                vulnerability_type=VulnerabilityType.SQLI,
                selection_rank=1,
                prior_probability=0.6,
                final_outcome=ResultStatus.WEAKENED,
                final_signal=VerificationSignal.WEAKEN,
                final_confidence=0.3,
                results=(),
            ),
            "cand_B": CandidateVerification(
                candidate_id="cand_B",
                input_point_id="inp_b",
                vulnerability_type=VulnerabilityType.REFLECTED_XSS,
                selection_rank=2,
                prior_probability=0.4,
                final_outcome=ResultStatus.SUPPORTED,
                final_signal=VerificationSignal.SUPPORT_NEW,
                final_confidence=0.8,
                results=(),
            ),
        }
        return outcome, verification

    def test_html_reorders_by_final_confidence_keeping_membership(self) -> None:
        outcome, verification = self._outcome_and_verification()
        html = render_decision_html_report(outcome, verification=verification)
        # Both stay selected (membership by prior is unchanged)...
        self.assertIn("cand_A", html)
        self.assertIn("cand_B", html)
        # ...but the supported candidate is now shown first.
        self.assertLess(html.index("cand_B"), html.index("cand_A"))
        self.assertIn('class="prio high">80%', html)
        self.assertIn('class="prio low">30%', html)

    def test_decision_json_reorders_but_keeps_selection_rank(self) -> None:
        outcome, verification = self._outcome_and_verification()
        report = decision_report(
            outcome, target_url="t", models={}, verification=verification
        )
        order = report["verification_order"]
        self.assertEqual(order[0]["candidate_id"], "cand_B")
        self.assertEqual(order[1]["candidate_id"], "cand_A")
        # The pre-verification selection rank is preserved as provenance.
        self.assertEqual(order[0]["selection_rank"], 2)
        self.assertEqual(order[1]["selection_rank"], 1)
        self.assertEqual(report["selection"]["selected"], 2)


class DecisionHtmlCollapseTests(unittest.TestCase):
    def test_collapses_only_competing_types_to_the_final_confidence_winner(
        self,
    ) -> None:
        shared_sqli = DecisionCandidate(
            candidate_id="cand_shared_sqli",
            family="SQLI",
            probability=0.9,
            selection_rank=1,
            subject_ref="inp_shared",
            feature_vector_ref="fv_shared_sqli",
        )
        shared_xss = DecisionCandidate(
            candidate_id="cand_shared_xss",
            family="REFLECTED_XSS",
            probability=0.8,
            selection_rank=2,
            subject_ref="inp_shared",
            feature_vector_ref="fv_shared_xss",
        )
        other_input = DecisionCandidate(
            candidate_id="cand_other_input",
            family="SQLI",
            probability=0.7,
            selection_rank=3,
            subject_ref="inp_other",
            feature_vector_ref="fv_other",
        )
        candidates = (shared_sqli, shared_xss, other_input)
        outcome = run_decision_layer(candidates, top_k=3)
        final_scores = {
            "cand_shared_sqli": 0.2,
            "cand_shared_xss": 0.95,
            "cand_other_input": 0.6,
        }
        verification = {
            candidate.candidate_id: CandidateVerification(
                candidate_id=candidate.candidate_id,
                input_point_id=candidate.subject_ref,
                vulnerability_type=VulnerabilityType(candidate.family),
                selection_rank=candidate.selection_rank or 1,
                prior_probability=candidate.probability,
                final_outcome=ResultStatus.SUPPORTED,
                final_signal=VerificationSignal.SUPPORT_NEW,
                final_confidence=final_scores[candidate.candidate_id],
                results=(),
            )
            for candidate in candidates
        }
        evidence_names = {
            "cand_shared_sqli": "loser_evidence",
            "cand_shared_xss": "winner_evidence<script>alert(1)</script>",
            "cand_other_input": "other_evidence",
        }
        probabilities = {
            candidate.candidate_id: CalibratedProbability._from_parts(
                family=candidate.family,
                model_version="unit-v1",
                probability=candidate.probability,
                logit_mean=0.0,
                logit_variance=0.0,
                observed_feature_count=1,
                evidence=(
                    CalibrationEvidence(
                        feature_name=evidence_names[candidate.candidate_id],
                        feature_value=1.0,
                        weight=1.0,
                        logit_contribution=1.0,
                        deciban_contribution=1.0,
                        observed=True,
                        reason="unit evidence",
                    ),
                ),
            )
            for candidate in candidates
        }

        html = render_decision_html_report(
            outcome,
            verification=verification,
            probabilities=probabilities,
        )
        reversed_html = render_decision_html_report(
            outcome,
            verification=dict(reversed(tuple(verification.items()))),
            probabilities=dict(reversed(tuple(probabilities.items()))),
        )
        report = decision_report(
            outcome,
            target_url="target",
            models={},
            verification=verification,
        )

        self.assertEqual(html, reversed_html)
        self.assertEqual(html.count('<article class="finding '), 2)
        self.assertIn("cand_shared_xss", html)
        self.assertIn("cand_other_input", html)
        self.assertNotIn("cand_shared_sqli", html)
        self.assertLess(html.index("cand_shared_xss"), html.index("cand_other_input"))
        self.assertIn('class="prio high">95%', html)
        self.assertNotIn('class="prio low">20%', html)
        self.assertIn(
            "winner_evidence&lt;script&gt;alert(1)&lt;/script&gt;",
            html,
        )
        self.assertNotIn("winner_evidence<script>alert(1)</script>", html)
        self.assertNotIn("loser_evidence", html)
        self.assertIn("other_evidence", html)
        self.assertEqual(len(report["verification_order"]), 3)


if __name__ == "__main__":
    unittest.main()
