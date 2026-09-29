from __future__ import annotations

import unittest
from dataclasses import dataclass, field, replace
from types import SimpleNamespace

from vulnspider.access.features import ACCESS_UNAUTHORIZED_SUCCESS
from vulnspider.domain import (
    AccessCheckKind,
    FeatureObservation,
    HttpMethod,
    InputLocation,
    InputPoint,
    RequestInstance,
)
from vulnspider.observation import TransportResponse
from vulnspider.verification import ResultStatus, VerificationSignal
from vulnspider.verification.access_verify import (
    AccessVerificationConfig,
    verify_access,
    verify_access_candidate,
)


@dataclass
class FakeTransport:
    """Loopback fake: an IDOR target serves every id; a safe one 404s others."""

    mode: str
    calls: list[RequestInstance] = field(default_factory=list)

    def send(self, request: RequestInstance, *, timeout_seconds: float) -> TransportResponse:
        self.calls.append(request)
        values = [value for _name, value in request.query]
        target = values[-1] if values else ""
        if self.mode == "idor":
            status = 200
        else:
            status = 200 if target == "1" else 404
        return TransportResponse(status, b"private record data", {}, 1.0, "utf-8")


def _input_point(baseline: str = "1") -> InputPoint:
    return InputPoint(
        endpoint_id="ep_x",
        endpoint_fingerprint="fp_x",
        location=InputLocation.QUERY,
        name="id",
        baseline_value=baseline,
    )


def _observation(
    check_kind: AccessCheckKind = AccessCheckKind.IDENTIFIER_SUBSTITUTION,
    baseline: str = "1",
    baseline_success: bool = True,
) -> SimpleNamespace:
    reference = RequestInstance(
        method=HttpMethod.GET,
        url=f"http://127.0.0.1/account?id={baseline}",
        query=(("id", baseline),),
    )
    plan = SimpleNamespace(
        check_kind=check_kind,
        reference_request=reference,
        input_point_id="inp_id",
    )
    features = {
        ACCESS_UNAUTHORIZED_SUCCESS: FeatureObservation(
            name=ACCESS_UNAUTHORIZED_SUCCESS,
            value=1.0 if baseline_success else 0.0,
            observed=True,
            source="test",
            extractor_version="test-v1",
        )
    }
    return SimpleNamespace(
        candidate_id="acand_1",
        access_probe_plan=plan,
        features=features,
    )


class AccessVerifyTests(unittest.TestCase):
    def _verify(self, mode: str, **obs_kwargs):
        return verify_access_candidate(
            candidate_id="acand_1",
            selection_rank=1,
            prior_probability=0.9,
            observation=_observation(**obs_kwargs),
            input_point=_input_point(obs_kwargs.get("baseline", "1")),
            config=AccessVerificationConfig(transport=FakeTransport(mode)),
        )

    def test_idor_reproduces_across_ids_supported(self) -> None:
        result = self._verify("idor")
        assert result is not None
        self.assertEqual(result.final_outcome, ResultStatus.SUPPORTED)
        self.assertEqual(result.final_signal, VerificationSignal.SUPPORT_REPRODUCED)
        self.assertEqual(result.reproduced, result.attempted)
        self.assertGreater(result.attempted, 0)

    def test_external_target_is_rejected_before_transport(self) -> None:
        observation = _observation()
        reference = observation.access_probe_plan.reference_request
        observation.access_probe_plan.reference_request = replace(
            reference,
            url="https://example.com/account?id=1",
        )
        transport = FakeTransport("idor")

        with self.assertRaises(ValueError):
            verify_access_candidate(
                candidate_id="acand_1",
                selection_rank=1,
                prior_probability=0.9,
                observation=observation,
                input_point=_input_point(),
                config=AccessVerificationConfig(transport=transport),
            )

        self.assertEqual(transport.calls, [])

    def test_no_reproduction_weakens(self) -> None:
        result = self._verify("safe")
        assert result is not None
        self.assertEqual(result.final_outcome, ResultStatus.WEAKENED)
        self.assertEqual(result.final_signal, VerificationSignal.WEAKEN)
        self.assertLess(result.final_confidence, 0.9)

    def test_non_numeric_baseline_is_not_rechecked(self) -> None:
        result = self._verify("idor", baseline="abc")
        self.assertIsNone(result)

    def test_credential_strip_is_not_rechecked_this_way(self) -> None:
        result = self._verify("idor", check_kind=AccessCheckKind.CREDENTIAL_STRIP)
        self.assertIsNone(result)

    def test_verify_access_skips_injection_candidates(self) -> None:
        analysis = SimpleNamespace(
            input_points=(_input_point(),),
            access_probe_observations=(),
        )
        # No access observations -> nothing to verify, injection ids ignored.
        out = verify_access(
            analysis,
            probabilities={"inj_1": 0.8},
            config=AccessVerificationConfig(transport=FakeTransport("idor")),
        )
        self.assertEqual(out, {})


if __name__ == "__main__":
    unittest.main()
