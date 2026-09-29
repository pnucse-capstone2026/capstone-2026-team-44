from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .focused_verification_complete import run_focused_verification


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="validation_result에서 approved=true인 payload만 실행해 심층 검증 결과를 수집합니다."
    )
    parser.add_argument("input", type=Path, help="validation_result JSON 경로")
    parser.add_argument("--out", type=Path, default=Path("focused_verification_result.json"))
    parser.add_argument(
        "--allow-host",
        action="append",
        dest="allowed_hosts",
        help="실행을 허용할 호스트. 여러 번 지정 가능. 기본: localhost/loopback",
    )
    parser.add_argument("--auth-contexts", type=Path, default=None)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--insecure", action="store_true", help="TLS 인증서 검증 비활성화")
    parser.add_argument("--no-response-body", action="store_true", help="결과 JSON에 응답 본문 저장 안 함")
    return parser


async def async_main() -> None:
    args = build_parser().parse_args()
    allowed_hosts = args.allowed_hosts or ["127.0.0.1", "localhost", "::1"]
    result = await run_focused_verification(
        args.input,
        args.out,
        allowed_hosts=allowed_hosts,
        auth_contexts_path=args.auth_contexts,
        timeout_seconds=args.timeout,
        max_concurrency=args.concurrency,
        verify_tls=not args.insecure,
        include_response_body=not args.no_response_body,
    )
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
    print(f"결과 저장: {args.out.resolve()}")


if __name__ == "__main__":
    asyncio.run(async_main())
