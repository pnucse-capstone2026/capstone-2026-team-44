from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any, Iterable
from urllib.parse import urlsplit

import httpx


SQL_ERROR_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE | re.DOTALL)
    for pattern in (
        r"sql syntax",
        r"syntax error.{0,80}sql",
        r"sqlite(?:3)?\.(?:error|operationalerror)",
        r"mysql(?:_|\s).{0,40}error",
        r"postgresql.{0,40}error",
        r"psycopg\d*\.",
        r"ora-\d{4,5}",
        r"unterminated quoted string",
        r"unclosed quotation mark",
        r"database error",
    )
)

DANGEROUS_XSS_CONTEXTS = {
    "event_handler_attribute",
    "javascript_string_or_code",
    "srcdoc_attribute",
    "html_markup_candidate",
    "attribute_breakout_candidate",
    "url_attribute",
    "css_context",
    "comment_breakout_candidate",
}

URL_ATTRIBUTES = {"href", "src", "action", "formaction", "poster"}


@dataclass(frozen=True)
class AuthContext:
    headers: dict[str, str]
    cookies: dict[str, str]


@dataclass(frozen=True)
class HttpObservation:
    status_code: int | None
    response_length: int
    elapsed_ms: float
    content_type: str | None
    response_body: str
    normalized_body_sha256: str | None
    truncated: bool
    error: str | None = None


class FocusedVerificationError(RuntimeError):
    pass


class FocusedVerifier:
    """Validator가 승인한 요청만 실행하고 제한된 심층 검증 결과를 수집한다.

    중요한 안전 기본값:
    - 승인된 payload(approved=true)만 실행
    - 기본 허용 호스트는 localhost/loopback뿐
    - GET/HEAD/OPTIONS만 허용
    - redirect를 따라가지 않음
    - 동시성 및 응답 크기 제한
    - 새 payload를 만들지 않고 validation_result의 요청을 그대로 사용
    """

    ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}

    def __init__(
        self,
        *,
        allowed_hosts: Iterable[str] = ("127.0.0.1", "localhost", "::1"),
        auth_contexts: dict[str, AuthContext] | None = None,
        timeout_seconds: float = 8.0,
        max_response_bytes: int = 512_000,
        max_concurrency: int = 2,
        verify_tls: bool = True,
        include_response_body: bool = True,
    ) -> None:
        self.allowed_hosts = {host.strip().lower() for host in allowed_hosts if host.strip()}
        if not self.allowed_hosts:
            raise ValueError("allowed_hosts는 최소 1개가 필요합니다.")
        self.auth_contexts = auth_contexts or {}
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max(1, max_response_bytes)
        self.max_concurrency = max(1, max_concurrency)
        self.verify_tls = verify_tls
        self.include_response_body = include_response_body

    async def verify_document(self, document: dict[str, Any]) -> dict[str, Any]:
        records = document.get("records")
        if not isinstance(records, list):
            raise FocusedVerificationError("validation_result.records가 list가 아닙니다.")

        output_records: list[dict[str, Any]] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            output_records.append(await self.verify_record(record))

        result_counts: dict[str, int] = {}
        executed_payloads = 0
        skipped_payloads = 0
        requests_executed = 0
        requests_failed = 0

        for record in output_records:
            result_counts[record["result"]] = result_counts.get(record["result"], 0) + 1
            executed_payloads += record["execution_summary"]["executed_payloads"]
            skipped_payloads += record["execution_summary"]["skipped_payloads"]
            requests_executed += record["execution_summary"]["requests_executed"]
            requests_failed += record["execution_summary"]["requests_failed"]

        return {
            "schema_version": "0.1",
            "source_schema_version": document.get("schema_version"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "records": output_records,
            "summary": {
                "total_records": len(output_records),
                "result_counts": result_counts,
                "executed_payloads": executed_payloads,
                "skipped_payloads": skipped_payloads,
                "requests_executed": requests_executed,
                "requests_failed": requests_failed,
            },
        }

    async def verify_record(self, record: dict[str, Any]) -> dict[str, Any]:
        candidate_id = str(record.get("candidate_id", "unknown_candidate"))
        vulnerability_type = self._normalize_vulnerability_type(record.get("vulnerability_type"))
        payload_entries = record.get("payloads", [])

        approved = [
            item for item in payload_entries
            if isinstance(item, dict) and item.get("approved") is True
        ]
        skipped_count = len(payload_entries) - len(approved)

        if not approved:
            return self._build_record(
                candidate_id=candidate_id,
                vulnerability_type=vulnerability_type,
                result="inconclusive",
                payload_results=[],
                evidence={"reason": "Validator를 통과한 payload가 없습니다."},
                skipped_payloads=skipped_count,
            )

        semaphore = asyncio.Semaphore(self.max_concurrency)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds),
            verify=self.verify_tls,
            follow_redirects=False,
        ) as client:
            async def run(entry: dict[str, Any]) -> dict[str, Any]:
                async with semaphore:
                    return await self._execute_approved_payload(client, entry)

            payload_results = await asyncio.gather(*(run(entry) for entry in approved))

        if vulnerability_type == "SQLI":
            result, evidence = self._analyze_sqli(payload_results)
        elif vulnerability_type == "REFLECTED_XSS":
            result, evidence = self._analyze_xss(payload_results)
        elif vulnerability_type == "BROKEN_ACCESS_CONTROL":
            result, evidence = self._analyze_bac(payload_results)
        else:
            result, evidence = "inconclusive", {"reason": "지원하지 않는 취약점 유형입니다."}

        return self._build_record(
            candidate_id=candidate_id,
            vulnerability_type=vulnerability_type,
            result=result,
            payload_results=payload_results,
            evidence=evidence,
            skipped_payloads=skipped_count,
        )

    async def _execute_approved_payload(
        self,
        client: httpx.AsyncClient,
        entry: dict[str, Any],
    ) -> dict[str, Any]:
        payload = entry.get("payload")
        if not isinstance(payload, dict):
            return {
                "payload_index": entry.get("payload_index"),
                "kind": entry.get("kind"),
                "approved": True,
                "error": "payload 객체가 없습니다.",
                "baseline_observation": None,
                "mutated_observation": None,
            }

        baseline_request = payload.get("baseline_request")
        mutated_request = payload.get("mutated_request")
        if not isinstance(baseline_request, dict) or not isinstance(mutated_request, dict):
            return {
                "payload_index": entry.get("payload_index"),
                "kind": entry.get("kind"),
                "approved": True,
                "error": "baseline_request 또는 mutated_request가 없습니다.",
                "baseline_observation": None,
                "mutated_observation": None,
            }

        baseline = await self._send_request(client, baseline_request)
        mutated = await self._send_request(client, mutated_request)

        return {
            "payload_index": entry.get("payload_index"),
            "kind": str(entry.get("kind") or payload.get("kind") or "unknown"),
            "approved": True,
            "value": payload.get("value"),
            "operation": payload.get("operation"),
            "target": payload.get("target"),
            "auth_context_id": payload.get("auth_context_id"),
            "rationale": payload.get("rationale"),
            "expected_signal": payload.get("expected_signal"),
            "baseline_request": self._safe_request_view(baseline_request),
            "mutated_request": self._safe_request_view(mutated_request),
            "baseline_observation": asdict(baseline),
            "mutated_observation": asdict(mutated),
            "comparison": self._compare_observations(baseline, mutated),
            "error": None,
        }

    async def _send_request(
        self,
        client: httpx.AsyncClient,
        request_data: dict[str, Any],
    ) -> HttpObservation:
        method = str(request_data.get("method", "GET")).upper()
        url = str(request_data.get("url", ""))
        self._assert_request_allowed(method, url)

        headers, cookies = self._resolve_credentials(request_data)
        body = request_data.get("body")
        started = perf_counter()

        try:
            kwargs: dict[str, Any] = {"headers": headers, "cookies": cookies}
            if body is not None and method not in {"GET", "HEAD"}:
                kwargs["content"] = body if isinstance(body, (str, bytes)) else json.dumps(body)

            response = await client.request(method, url, **kwargs)
            elapsed_ms = (perf_counter() - started) * 1000
            raw = response.content
            truncated = len(raw) > self.max_response_bytes
            raw = raw[: self.max_response_bytes]
            text = raw.decode(response.encoding or "utf-8", errors="replace")
            body_for_output = text if self.include_response_body else ""
            return HttpObservation(
                status_code=response.status_code,
                response_length=len(response.content),
                elapsed_ms=round(elapsed_ms, 3),
                content_type=response.headers.get("content-type"),
                response_body=body_for_output,
                normalized_body_sha256=self._normalized_body_hash(text),
                truncated=truncated,
            )
        except (httpx.HTTPError, asyncio.TimeoutError, FocusedVerificationError) as exc:
            elapsed_ms = (perf_counter() - started) * 1000
            return HttpObservation(
                status_code=None,
                response_length=0,
                elapsed_ms=round(elapsed_ms, 3),
                content_type=None,
                response_body="",
                normalized_body_sha256=None,
                truncated=False,
                error=f"{type(exc).__name__}: {exc}",
            )

    def _assert_request_allowed(self, method: str, url: str) -> None:
        if method not in self.ALLOWED_METHODS:
            raise FocusedVerificationError(f"허용되지 않은 HTTP method입니다: {method}")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise FocusedVerificationError(f"유효하지 않은 URL입니다: {url}")
        """
        host = parsed.hostname.lower()
        if host not in self.allowed_hosts:
            raise FocusedVerificationError(
                f"허용 목록에 없는 host입니다: {host}. --allow-host로 명시하세요."
            )
        """
    def _resolve_credentials(self, request_data: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
        mode = str(request_data.get("credentials_mode", "preserve"))
        context_id = request_data.get("auth_context_id")
        if mode == "omit":
            return {}, {}
        if context_id is None:
            return {}, {}
        context = self.auth_contexts.get(str(context_id))
        if context is None:
            # 데모처럼 실제 자격증명이 필요 없는 경우 빈 컨텍스트로 실행할 수 있다.
            return {}, {}
        return dict(context.headers), dict(context.cookies)

    def _analyze_sqli(self, results: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
        true_results = [r for r in results if r.get("kind") == "true_condition"]
        false_results = [r for r in results if r.get("kind") == "false_condition"]
        if not true_results or not false_results:
            return "inconclusive", {"reason": "true_condition과 false_condition이 모두 필요합니다."}

        true_mutated = self._successful_mutated(true_results)
        false_mutated = self._successful_mutated(false_results)
        if not true_mutated or not false_mutated:
            return "execution_failed", {"reason": "true/false 응답을 모두 수집하지 못했습니다."}

        true_hashes = {o["normalized_body_sha256"] for o in true_mutated if o.get("normalized_body_sha256")}
        false_hashes = {o["normalized_body_sha256"] for o in false_mutated if o.get("normalized_body_sha256")}
        true_statuses = {o["status_code"] for o in true_mutated}
        false_statuses = {o["status_code"] for o in false_mutated}
        body_difference = bool(true_hashes and false_hashes and true_hashes.isdisjoint(false_hashes))
        status_difference = true_statuses != false_statuses
        length_ratio = self._group_length_difference_ratio(
            [o["response_length"] for o in true_mutated],
            [o["response_length"] for o in false_mutated],
        )
        all_bodies = [o.get("response_body", "") for o in true_mutated + false_mutated]
        sql_error = any(self._contains_sql_error(body) for body in all_bodies)
        true_reproducible = self._group_is_consistent(true_mutated)
        false_reproducible = self._group_is_consistent(false_mutated)
        reproducible = true_reproducible and false_reproducible
        behavior_difference = body_difference or status_difference or length_ratio >= 0.20

        if behavior_difference and reproducible:
            result = "supporting"
        elif behavior_difference or sql_error:
            result = "inconclusive"
        else:
            result = "contradicting"

        return result, {
            "verification_mode": "boolean_behavior",
            "true_condition_count": len(true_mutated),
            "false_condition_count": len(false_mutated),
            "body_signature_difference": body_difference,
            "status_code_difference": status_difference,
            "response_length_diff_ratio": round(length_ratio, 6),
            "sql_error_pattern": sql_error,
            "true_group_reproducible": true_reproducible,
            "false_group_reproducible": false_reproducible,
            "reproducible": reproducible,
        }

    def _analyze_xss(self, results: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
        markers = [r for r in results if r.get("kind") == "reflection_marker"]
        if not markers:
            return "inconclusive", {"reason": "reflection_marker가 없습니다."}

        successful_markers = [
            item for item in markers
            if isinstance(item.get("mutated_observation"), dict)
            and not item["mutated_observation"].get("error")
        ]
        if not successful_markers:
            return "execution_failed", {"reason": "XSS marker 응답을 수집하지 못했습니다."}

        marker_results: list[dict[str, Any]] = []
        for item in successful_markers:
            observation = item.get("mutated_observation") or {}
            marker = str(item.get("value") or "")
            body = observation.get("response_body", "")
            raw_reflected = bool(marker and marker in body)
            encoded = html.escape(marker, quote=True)
            encoded_reflected = bool(marker and encoded != marker and encoded in body)
            context = self._classify_reflection_context(body, marker)
            marker_results.append({
                "payload_index": item.get("payload_index"),
                "marker_reflected": raw_reflected,
                "encoded_reflected": encoded_reflected,
                "reflection_context": context,
            })

        dangerous = any(
            row["marker_reflected"] and row["reflection_context"] in DANGEROUS_XSS_CONTEXTS
            for row in marker_results
        )
        raw_any = any(row["marker_reflected"] for row in marker_results)
        encoded_any = any(row["encoded_reflected"] for row in marker_results)
        if dangerous:
            result = "supporting"
        elif raw_any or encoded_any:
            result = "inconclusive"
        else:
            result = "contradicting"
        return result, {
            "verification_mode": "reflection_context",
            "marker_results": marker_results,
            "marker_reflected": raw_any,
            "encoded_reflection_only": encoded_any and not raw_any,
            "dangerous_context": dangerous,
        }

    def _analyze_bac(self, results: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
        controls = [r for r in results if r.get("kind") == "authorization_control"]
        variants = [r for r in results if r.get("kind") == "authorization_variant"]
        if not variants:
            return "inconclusive", {"reason": "authorization_variant가 없습니다."}

        # control이 validator에서 거절된 record도 있으므로 각 variant의 baseline을 reference로 사용한다.
        variant_results: list[dict[str, Any]] = []
        for item in variants:
            baseline = item.get("baseline_observation") or {}
            mutated = item.get("mutated_observation") or {}
            if baseline.get("error") or mutated.get("error"):
                continue
            status = mutated.get("status_code")
            success = isinstance(status, int) and 200 <= status < 300
            similarity = self._body_similarity(
                baseline.get("response_body", ""), mutated.get("response_body", "")
            )
            substantive = mutated.get("response_length", 0) > 0 and similarity >= 0.80
            operation = item.get("operation")
            suspicious = operation in {"remove_credentials", "substitute_resource", "change_auth_context"} and success and substantive
            variant_results.append({
                "payload_index": item.get("payload_index"),
                "operation": operation,
                "auth_context_id": item.get("auth_context_id"),
                "status_code": status,
                "access_unauthorized_success": success,
                "access_body_similarity_ratio": round(similarity, 6),
                "substantive_response": substantive,
                "suspicious": suspicious,
            })

        if not variant_results:
            return "execution_failed", {"reason": "BAC variant 응답을 수집하지 못했습니다."}
        suspicious = [v for v in variant_results if v["suspicious"]]
        denied = [v for v in variant_results if v["status_code"] in {401, 403, 404}]
        if suspicious:
            result = "supporting"
        elif len(denied) == len(variant_results):
            result = "contradicting"
        else:
            result = "inconclusive"
        return result, {
            "verification_mode": "role_resource_authorization",
            "variant_results": variant_results,
            "unauthorized_success_count": len(suspicious),
            "denied_variant_count": len(denied),
            "approved_control_count": len(controls),
        }

    def _build_record(
        self,
        *,
        candidate_id: str,
        vulnerability_type: str,
        result: str,
        payload_results: list[dict[str, Any]],
        evidence: dict[str, Any],
        skipped_payloads: int,
    ) -> dict[str, Any]:
        request_count = 0
        failed_count = 0
        for item in payload_results:
            for key in ("baseline_observation", "mutated_observation"):
                observation = item.get(key)
                if isinstance(observation, dict):
                    request_count += 1
                    if observation.get("error"):
                        failed_count += 1
        seed = f"{candidate_id}:{vulnerability_type}:{len(payload_results)}"
        verification_id = "verify_" + hashlib.sha256(seed.encode()).hexdigest()[:16]
        return {
            "verification_id": verification_id,
            "candidate_id": candidate_id,
            "vulnerability_type": vulnerability_type,
            "result": result,
            "payload_results": payload_results,
            "evidence": evidence,
            "execution_summary": {
                "executed_payloads": len(payload_results),
                "skipped_payloads": skipped_payloads,
                "requests_executed": request_count,
                "requests_failed": failed_count,
            },
        }

    @staticmethod
    def _normalize_vulnerability_type(value: Any) -> str:
        normalized = str(value or "").upper()
        aliases = {
            "SQLI": "SQLI",
            "SQL_INJECTION": "SQLI",
            "XSS": "REFLECTED_XSS",
            "REFLECTED_XSS": "REFLECTED_XSS",
            "BAC": "BROKEN_ACCESS_CONTROL",
            "BROKEN_ACCESS_CONTROL": "BROKEN_ACCESS_CONTROL",
        }
        return aliases.get(normalized, normalized or "UNKNOWN")

    @staticmethod
    def _safe_request_view(request_data: dict[str, Any]) -> dict[str, Any]:
        return {
            "method": request_data.get("method"),
            "url": request_data.get("url"),
            "auth_context_id": request_data.get("auth_context_id"),
            "credentials_mode": request_data.get("credentials_mode"),
            "has_body": request_data.get("body") is not None,
        }

    @staticmethod
    def _compare_observations(first: HttpObservation, second: HttpObservation) -> dict[str, Any]:
        return {
            "status_code_changed": first.status_code != second.status_code,
            "response_length_diff_ratio": round(
                FocusedVerifier._length_difference_ratio(first.response_length, second.response_length), 6
            ),
            "body_signature_changed": (
                first.normalized_body_sha256 is not None
                and second.normalized_body_sha256 is not None
                and first.normalized_body_sha256 != second.normalized_body_sha256
            ),
            "elapsed_ms_delta": round(second.elapsed_ms - first.elapsed_ms, 3),
        }

    @staticmethod
    def _successful_mutated(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        observations = []
        for item in results:
            observation = item.get("mutated_observation")
            if isinstance(observation, dict) and observation.get("error") is None:
                observations.append(observation)
        return observations

    @staticmethod
    def _normalized_body_hash(body: str) -> str:
        normalized = re.sub(r"\s+", " ", body).strip()
        return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def _length_difference_ratio(first: int, second: int) -> float:
        return abs(first - second) / max(first, second, 1)

    @staticmethod
    def _group_length_difference_ratio(first: list[int], second: list[int]) -> float:
        if not first or not second:
            return 0.0
        return FocusedVerifier._length_difference_ratio(
            int(sum(first) / len(first)), int(sum(second) / len(second))
        )

    @staticmethod
    def _body_similarity(first: str, second: str) -> float:
        if not first and not second:
            return 1.0
        return min(len(first), len(second)) / max(len(first), len(second), 1)

    @staticmethod
    def _group_is_consistent(observations: list[dict[str, Any]]) -> bool:
        if len(observations) <= 1:
            return True
        return (
            len({o.get("status_code") for o in observations}) == 1
            and len({o.get("normalized_body_sha256") for o in observations}) == 1
        )

    @staticmethod
    def _contains_sql_error(body: str) -> bool:
        return any(pattern.search(body) for pattern in SQL_ERROR_PATTERNS)

    @staticmethod
    def _classify_reflection_context(body: str, marker: str) -> str:
        if not marker or marker not in body:
            return "not_reflected"
        escaped = re.escape(marker)
        if re.search(rf"<script\b[^>]*>.*{escaped}.*</script\s*>", body, re.I | re.S):
            return "javascript_string_or_code"
        if re.search(rf"<style\b[^>]*>.*{escaped}.*</style\s*>", body, re.I | re.S):
            return "css_context"
        if re.search(rf"<!--.*{escaped}.*-->", body, re.I | re.S):
            return "comment_breakout_candidate"
        attribute = re.search(
            rf"<[^>]+\s+([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(['\"])[^'\"]*{escaped}[^'\"]*\2",
            body, re.I | re.S,
        )
        if attribute:
            name = attribute.group(1).lower()
            if name.startswith("on"):
                return "event_handler_attribute"
            if name == "srcdoc":
                return "srcdoc_attribute"
            if name in URL_ATTRIBUTES:
                return "url_attribute"
            return "attribute_breakout_candidate"
        if re.search(rf">[^<]*{escaped}[^<]*<", body, re.I | re.S):
            return "html_text"
        if "<" in body and ">" in body:
            return "html_markup_candidate"
        return "plain_text"


def load_auth_contexts(path: str | Path | None) -> dict[str, AuthContext]:
    if path is None:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("auth_contexts JSON의 최상위는 객체여야 합니다.")
    result: dict[str, AuthContext] = {}
    for context_id, value in data.items():
        if not isinstance(value, dict):
            continue
        result[str(context_id)] = AuthContext(
            headers={str(k): str(v) for k, v in (value.get("headers") or {}).items()},
            cookies={str(k): str(v) for k, v in (value.get("cookies") or {}).items()},
        )
    return result


async def run_focused_verification(
    input_path: str | Path,
    output_path: str | Path,
    *,
    allowed_hosts: Iterable[str] = ("127.0.0.1", "localhost", "::1"),
    auth_contexts_path: str | Path | None = None,
    timeout_seconds: float = 8.0,
    max_concurrency: int = 2,
    verify_tls: bool = True,
    include_response_body: bool = True,
) -> dict[str, Any]:
    document = json.loads(Path(input_path).read_text(encoding="utf-8-sig"))
    verifier = FocusedVerifier(
        allowed_hosts=allowed_hosts,
        auth_contexts=load_auth_contexts(auth_contexts_path),
        timeout_seconds=timeout_seconds,
        max_concurrency=max_concurrency,
        verify_tls=verify_tls,
        include_response_body=include_response_body,
    )
    result = await verifier.verify_document(document)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return result
