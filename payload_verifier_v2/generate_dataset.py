import json
import random

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

def generate_sqli_response():
    """주석(--, /*) 없이 대수학과 괄호 구조만 이용한 고급 SQLi"""
    true_2 = random.choice([
        "42 AND (1000=1000)",
        "42 OR (ABS(-1)=1)", 
        "42 AND (ASCII('a')=97)"
    ])
    false_2 = random.choice([
        "42 AND (1000=999)",
        "42 AND (ABS(-1)=2)",
        "42 AND (ASCII('a')=99)"
    ])
    
    return {
        "payloads": [
            {"kind": "true_condition", "value": "4200", "auth_context_id": None, "rationale": "Valid alternative numeric ID replacement.", "expected_signal": "Normal response."},
            {"kind": "true_condition", "value": true_2, "auth_context_id": None, "rationale": "Complex true boolean logic using math/functions without comments.", "expected_signal": "Normal response."},
            {"kind": "false_condition", "value": "invalid_probe_string", "auth_context_id": None, "rationale": "Invalid string type to trigger generic error.", "expected_signal": "Error or empty response."},
            {"kind": "false_condition", "value": false_2, "auth_context_id": None, "rationale": "Complex false boolean logic without comments.", "expected_signal": "Error or empty response."}
        ],
        "warnings": []
    }

def generate_xss_response():
    """자바스크립트(onerror 등) 없이 속성 탈옥과 인코딩만 테스트하는 고급 XSS"""
    marker_1 = random.choice([
        "\"><x-element aria-label=\"xss-probe\"></x-element>",
        "\" autofocus data-test=\"xss-probe",
        "</title><span title=\"xss-probe\">"
    ])
    marker_2 = random.choice([
        "&lt;b&gt;xss-probe&lt;/b&gt;",
        "%3C%2Fdiv%3E%3Cspan%20title%3D%22xss-probe%22%3E"
    ])
    
    return {
        "payloads": [
            # Validator가 1개의 reflection_control을 반드시 요구함
            {"kind": "reflection_control", "value": "xss-probe-control", "auth_context_id": None, "rationale": "Baseline text reflection check.", "expected_signal": "Reflected exactly in text."},
            {"kind": "reflection_marker", "value": marker_1, "auth_context_id": None, "rationale": "Context breakout using inert attributes/tags.", "expected_signal": "Reflected without encoding."},
            {"kind": "reflection_marker", "value": marker_2, "auth_context_id": None, "rationale": "Entity or URL encoded injection test.", "expected_signal": "Reflected exactly as input."}
        ],
        "warnings": []
    }

def generate_bac_response(is_credential_strip=False):
    """BAC 형식에 맞춘 완벽한 권한 제어 테스트"""
    if is_credential_strip:
        # CREDENTIAL_STRIP은 익명(None) auth_context_id가 반드시 1개 이상 포함되어야 함
        return {
            "payloads": [
                {"kind": "authorization_control", "value": "42", "auth_context_id": "user_a", "rationale": "Baseline access.", "expected_signal": "200 OK"},
                {"kind": "authorization_variant", "value": "42", "auth_context_id": None, "rationale": "Anonymous access attempt (credential strip).", "expected_signal": "401 Unauthorized"},
                {"kind": "authorization_variant", "value": "42", "auth_context_id": "user_b", "rationale": "Cross-user access.", "expected_signal": "403 Forbidden"},
                {"kind": "authorization_variant", "value": "42", "auth_context_id": "admin", "rationale": "Admin access.", "expected_signal": "200 OK"}
            ],
            "warnings": []
        }
    else:
        return {
            "payloads": [
                {"kind": "authorization_control", "value": "42", "auth_context_id": "user_a", "rationale": "Baseline access.", "expected_signal": "200 OK"},
                {"kind": "authorization_variant", "value": "43", "auth_context_id": "user_a", "rationale": "Cross-resource access.", "expected_signal": "403 Forbidden"},
                {"kind": "authorization_variant", "value": "42", "auth_context_id": "user_b", "rationale": "Cross-user access.", "expected_signal": "403 Forbidden"},
                {"kind": "authorization_variant", "value": "43", "auth_context_id": "admin", "rationale": "Admin access to other resource.", "expected_signal": "200 OK"}
            ],
            "warnings": []
        }

def main():
    print("🚀 Validator 룰을 완벽히 준수하는 최고급 훈련 데이터셋(v3) 생성을 시작합니다...")
    dataset = []
    
    for i in range(50):
        if i < 15:
            vuln_type, response_data = "SQLI", generate_sqli_response()
            check_kind = None
        elif i < 30:
            vuln_type, response_data = "REFLECTED_XSS", generate_xss_response()
            check_kind = None
        elif i < 40:
            vuln_type, response_data = "BROKEN_ACCESS_CONTROL", generate_bac_response(False)
            check_kind = "IDENTIFIER_SUBSTITUTION"
        else:
            vuln_type, response_data = "BROKEN_ACCESS_CONTROL", generate_bac_response(True)
            check_kind = "CREDENTIAL_STRIP"
            
        candidate_prompt = {
            "candidate_id": f"cand_gen_{i}",
            "vulnerability_type": vuln_type,
            "metadata": {"check_kind": check_kind} if check_kind else {},
            "request_context": {
                "method": "GET",
                "url": "http://127.0.0.1/test?id=42",
                "parameter_name": "id",
                "parameter_location": "query",
                "original_value": "42"
            } if vuln_type != "BROKEN_ACCESS_CONTROL" else None,
            "access_context": {
                "method": "GET",
                "url": "http://127.0.0.1/test?id=42",
                "parameter_name": "id",
                "parameter_location": "query",
                "original_value": "42",
                "baseline_auth_context_id": "user_a",
                "resources": [{"value": "42"}, {"value": "43"}],
                "auth_contexts": [
                    {"context_id": "user_a"}, 
                    {"context_id": "user_b"}, 
                    {"context_id": "admin"},
                    {"context_id": "anonymous", "is_anonymous": True}
                ]
            } if vuln_type == "BROKEN_ACCESS_CONTROL" else None
        }

        record = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT.strip()},
                {"role": "user", "content": f"Generate safe verification values for the following candidate.\n\nCandidate:\n{json.dumps(candidate_prompt, indent=2)}\n\n(Assume Type-specific rules are applied here)"},
                {"role": "assistant", "content": json.dumps(response_data, indent=2)}
            ]
        }
        dataset.append(record)

    output_file = "chatml_tuning_dataset_v3.jsonl"
    with open(output_file, 'w', encoding='utf-8') as f:
        for item in dataset:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')

    print(f"🎉 성공! 총 50개의 고품질 데이터가 '{output_file}'에 저장되었습니다.")

if __name__ == "__main__":
    main()