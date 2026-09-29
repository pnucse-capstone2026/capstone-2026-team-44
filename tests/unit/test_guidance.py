from __future__ import annotations

import unittest

from vulnspider.reporting.guidance import DefenseGuidance, build_defense_guidance


class _Evidence:
    """Duck-typed stand-in for a CalibratedProbability evidence item."""

    def __init__(
        self,
        feature_name: str,
        observed: bool = True,
        logit_contribution: float = 0.5,
    ) -> None:
        self.feature_name = feature_name
        self.observed = observed
        self.logit_contribution = logit_contribution


class BuildDefenseGuidanceTests(unittest.TestCase):
    def test_unknown_family_returns_none(self) -> None:
        self.assertIsNone(build_defense_guidance("XXE"))

    def test_supported_families_have_nonempty_content(self) -> None:
        for family in ("SQLI", "REFLECTED_XSS", "BROKEN_ACCESS_CONTROL"):
            guidance = build_defense_guidance(family)
            assert guidance is not None
            self.assertIsInstance(guidance, DefenseGuidance)
            self.assertEqual(guidance.family, family)
            self.assertTrue(guidance.lead)
            self.assertTrue(guidance.primary)
            self.assertTrue(guidance.secondary)
            self.assertTrue(guidance.case_label)

    def test_sqli_error_based_when_sql_error_signature_observed(self) -> None:
        guidance = build_defense_guidance(
            "SQLI",
            evidence=[_Evidence("sql_error_pattern", observed=True, logit_contribution=1.2)],
        )
        assert guidance is not None
        self.assertIn("에러", guidance.case_label)
        self.assertIn("오류", guidance.note)

    def test_sqli_inferential_when_only_length_signal(self) -> None:
        guidance = build_defense_guidance(
            "SQLI",
            evidence=[_Evidence("response_length_diff_ratio", observed=True)],
        )
        assert guidance is not None
        self.assertIn("추론", guidance.case_label)

    def test_sqli_error_feature_unobserved_is_inferential(self) -> None:
        guidance = build_defense_guidance(
            "SQLI",
            evidence=[_Evidence("sql_error_pattern", observed=False, logit_contribution=0.0)],
        )
        assert guidance is not None
        self.assertIn("추론", guidance.case_label)

    def test_sqli_error_feature_zero_contribution_is_inferential(self) -> None:
        guidance = build_defense_guidance(
            "SQLI",
            evidence=[_Evidence("sql_error_pattern", observed=True, logit_contribution=0.0)],
        )
        assert guidance is not None
        self.assertIn("추론", guidance.case_label)

    def test_xss_gives_context_aware_encoding(self) -> None:
        guidance = build_defense_guidance("REFLECTED_XSS")
        assert guidance is not None
        self.assertTrue(any("인코딩" in item for item in guidance.primary))
        self.assertTrue(guidance.note)

    def test_bac_idor_case(self) -> None:
        guidance = build_defense_guidance(
            "BROKEN_ACCESS_CONTROL",
            access_check_kind="IDENTIFIER_SUBSTITUTION",
        )
        assert guidance is not None
        self.assertIn("IDOR", guidance.case_label)
        self.assertIn("소유", guidance.note)

    def test_bac_credential_strip_case(self) -> None:
        guidance = build_defense_guidance(
            "BROKEN_ACCESS_CONTROL",
            access_check_kind="CREDENTIAL_STRIP",
        )
        assert guidance is not None
        self.assertIn("인증", guidance.case_label)

    def test_bac_default_when_kind_unknown(self) -> None:
        guidance = build_defense_guidance(
            "BROKEN_ACCESS_CONTROL",
            access_check_kind="SOMETHING_ELSE",
        )
        assert guidance is not None
        self.assertEqual(guidance.family, "BROKEN_ACCESS_CONTROL")
        self.assertTrue(guidance.primary)


if __name__ == "__main__":
    unittest.main()
