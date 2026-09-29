"""Drive the local fine-tuned LLM payload proposer against the real GGUF model.

A fast, crawl-free sanity check that the merged local-LLM proposer works
end-to-end with the actual ``vulnspider-3b`` model: it loads the GGUF through
``llama-cpp-python``, asks the model for same-family variant payloads for one
SQLi and one reflected-XSS candidate, and prints each suggestion next to the
deterministic validator's accept/reject decision -- the exact gate the payload
passes through inside focused verification.

    PYTHONPATH=src python tools/llm_verify_demo.py --model path/to/vulnspider-3b_v3.gguf

If ``--model`` is omitted the ``VULNSPIDER_LLM_MODEL`` environment variable is
used. No network request is ever sent; only the model runs locally.
"""

from __future__ import annotations

import argparse
import os
import sys

from vulnspider.domain import InputLocation, VulnerabilityType
from vulnspider.verification import (
    LLM_MODEL_PATH_ENV,
    LocalLLMMutationProposer,
    MutationSubject,
    PayloadValidator,
)

_CASES = (
    ("SQLi (numeric id)", VulnerabilityType.SQLI, "id", "42"),
    ("Reflected XSS (search q)", VulnerabilityType.REFLECTED_XSS, "q", "hello"),
)


def _run(model_path: str) -> int:
    print(f"Loading local model: {model_path}")
    proposer = LocalLLMMutationProposer(model_path=model_path)
    validator = PayloadValidator()

    for title, vuln_type, parameter, baseline in _CASES:
        subject = MutationSubject(
            candidate_id=f"demo_{vuln_type.value.lower()}",
            input_point_id=f"inp_{parameter}",
            vulnerability_type=vuln_type,
            parameter_name=parameter,
            parameter_location=InputLocation.QUERY,
            baseline_value=baseline,
        )
        print(f"\n=== {title} :: baseline {parameter}={baseline!r} ===")
        proposals = proposer.propose(subject)
        if not proposals:
            print("  (model produced no usable payloads)")
            for warning in proposer.warnings:
                print(f"  warning: {warning}")
            continue
        for proposal in proposals:
            decision = validator.validate(proposal)
            verdict = decision.decision.value
            if not decision.accepted:
                verdict += " <- " + ", ".join(
                    reason.value for reason in decision.rejection_reasons
                )
            print(f"  [{proposal.family.value:<13}] {proposal.mutated_value!r}")
            print(f"      validator: {verdict}")
            print(f"      rationale: {proposal.rationale}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model",
        default=os.environ.get(LLM_MODEL_PATH_ENV),
        help=f"Path to the vulnspider-3b GGUF (default: ${LLM_MODEL_PATH_ENV}).",
    )
    args = parser.parse_args(argv)
    if not args.model:
        parser.error(
            "no model given: pass --model PATH or set "
            f"${LLM_MODEL_PATH_ENV} to the vulnspider-3b GGUF file"
        )
    if not os.path.isfile(args.model):
        parser.error(f"model file does not exist: {args.model}")
    return _run(args.model)


if __name__ == "__main__":
    sys.exit(main())
