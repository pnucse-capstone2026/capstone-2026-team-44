from __future__ import annotations

import json

from .models import (
    NormalizedCandidate,
    VulnerabilityType,
)


SYSTEM_PROMPT = """
You are a defensive payload mutation component for an
authorized web security verification pipeline.

Generate only safe and non-destructive verification values.

Never generate payloads that:
- modify, delete, insert, or extract data
- use stacked SQL queries
- use UNION-based SQL extraction
- use time-delay SQL functions
- execute JavaScript
- access cookies, localStorage, or sessionStorage
- load external resources
- create destructive HTTP requests
- invent resource identifiers
- invent authorization contexts
- modify the target host
- modify the target path
- modify the HTTP method

The application code will insert your generated value into
the exact input position.

Return JSON only.
"""


def build_sqli_rules() -> str:
    return """
Generate exactly 4 payload candidates.

Required kinds:
- exactly 2 true_condition
- exactly 2 false_condition

Rules:
- each value must be a complete replacement value for the
  existing parameter
- MAKE PAYLOADS STRUCTURALLY COMPLEX: Use varied techniques such as inline comments (/**/), string concatenation (e.g., 'a'||'b', CONCAT), mathematical operations (e.g., 50-8=42), or nested logic.
- For the FIRST true_condition, completely replace the original value with a DIFFERENT valid-looking number (e.g., 1000) WITHOUT any SQL syntax.
- For the SECOND true_condition, use complex but benign boolean logic (e.g., "42/**/AND/**/LEN('abc')=3" or "42 AND (SELECT 2+2)=4").
- For the FIRST false_condition, completely replace the original value with an invalid random text string (e.g., "invalid_id_string") WITHOUT any SQL syntax.
- For the SECOND false_condition, use complex but benign false logic (e.g., "42/**/AND/**/ABS(-1)=2").
- STRICTLY SAFE PROBES ONLY: Must evaluate to a simple boolean result.
- use boolean or response-behavior verification only
- do not use UNION
- do not use stacked queries
- do not use time-delay functions
- do not perform schema discovery
- do not extract data
- do not modify data
- auth_context_id must be null
"""


def build_xss_rules() -> str:
    return """
Generate exactly 3 payload candidates.

Required kinds:
- exactly 1 reflection_control
- exactly 2 reflection_marker

Rules:
- each value must be a complete replacement value for the existing parameter
- every payload value must contain the text "xss-probe"
- Keep HTML structures simple, safe, and clean to avoid parsing errors.
- Examples: 
  1. "<x-custom data-val='xss-probe'>Hello</x-custom>"
  2. "&lt;b&gt;xss-probe&lt;/b&gt;"
  3. "<div title='xss-probe'></div>"
- ALL MARKERS MUST REMAIN STRICTLY INERT AND NON-EXECUTABLE.
- do not use script elements
- do not use event-handler attributes
- do not use javascript URLs
- do not use data URLs
- do not use iframe
- do not use svg
- do not use external URLs
- do not access cookies or storage
- do not generate executable JavaScript
- auth_context_id must be null
"""


def build_bac_identifier_rules() -> str:
    return """
Generate exactly 4 authorization test candidates.

Required kinds:
- exactly 1 authorization_control
- exactly 3 authorization_variant

Rules:
- value must come from access_context.resources[].value
- auth_context_id must come from
  access_context.auth_contexts[].context_id
- do not invent resource values
- do not invent authorization contexts
- the control should use the baseline resource and baseline
  authorization context
- include same-role different-resource testing when possible
- include different-role same-resource testing when possible
- use safe read-only requests only
"""


def build_bac_credential_strip_rules() -> str:
    return """
Generate exactly 4 authorization test candidates.

Required kinds:
- exactly 1 authorization_control
- exactly 3 authorization_variant

Rules:
- authorization_control must use the baseline authorization
  context
- at least one authorization_variant must use the anonymous
  authorization context
- auth_context_id must come from
  access_context.auth_contexts[].context_id
- do not invent cookies
- do not invent tokens
- do not invent users or roles
- keep the URL and all request parameters unchanged
- value should be the original parameter value when one exists
"""


def build_type_rules(
    candidate: NormalizedCandidate,
) -> str:
    """
    취약점 유형과 BAC check_kind에 따라 프롬프트 규칙 선택.
    """

    vulnerability_type = candidate.vulnerability_type

    if vulnerability_type == VulnerabilityType.SQLI:
        return build_sqli_rules()

    if (
        vulnerability_type
        == VulnerabilityType.REFLECTED_XSS
    ):
        return build_xss_rules()

    if (
        vulnerability_type
        == VulnerabilityType.BROKEN_ACCESS_CONTROL
    ):
        check_kind = candidate.metadata.get(
            "check_kind"
        )

        if check_kind == "CREDENTIAL_STRIP":
            return build_bac_credential_strip_rules()

        return build_bac_identifier_rules()

    raise ValueError(
        "Unsupported vulnerability type: "
        f"{vulnerability_type}"
    )


def build_mutation_prompt(
    candidate: NormalizedCandidate,
) -> str:
    """
    Gemini에 전달할 최종 사용자 프롬프트.
    """

    candidate_json = json.dumps(
        candidate.model_dump(
            mode="json",
            exclude_none=True,
        ),
        ensure_ascii=False,
        indent=2,
    )

    type_rules = build_type_rules(
        candidate
    )

    return f"""
Generate safe verification values for the following candidate.

Candidate:
{candidate_json}

Type-specific rules:
{type_rules}

The application code will decide:
- which parameter is modified
- how the URL is encoded
- how the request body is reconstructed
- whether credentials are removed
- whether an authorization context is changed

Do not generate:
- a complete URL
- an HTTP method
- HTTP headers
- cookies
- Authorization header values

Each payload must contain:
- kind
- value
- auth_context_id
- rationale
- expected_signal

Return exactly this JSON structure:

{{
  "payloads": [
    {{
      "kind": "...",
      "value": "...",
      "auth_context_id": null,
      "rationale": "...",
      "expected_signal": "..."
    }}
  ],
  "warnings": []
}}
"""
