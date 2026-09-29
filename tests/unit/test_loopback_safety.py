from __future__ import annotations

import unittest
from dataclasses import dataclass, field

from vulnspider.discovery import StaticCrawlerRequest, StaticCrawlerResponse
from vulnspider.domain import RequestInstance
from vulnspider.observation import TransportResponse
from vulnspider.pipeline import (
    PipelineError,
    analyze_legacy_records,
    analyze_url,
)


@dataclass
class RecordingCrawlerTransport:
    requests: list[StaticCrawlerRequest] = field(default_factory=list)

    def send(
        self,
        request: StaticCrawlerRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> StaticCrawlerResponse:
        self.requests.append(request)
        return StaticCrawlerResponse(
            status_code=200,
            body=b"<p>external root</p>",
            content_type="text/html",
            encoding="utf-8",
        )


@dataclass
class RecordingProbeTransport:
    requests: list[RequestInstance] = field(default_factory=list)

    def send(
        self,
        request: RequestInstance,
        *,
        timeout_seconds: float,
    ) -> TransportResponse:
        self.requests.append(request)
        return TransportResponse(status_code=200, body=b"ok")


class LoopbackPipelineSafetyTests(unittest.TestCase):
    def test_static_external_root_is_rejected_before_crawler_transport(self) -> None:
        crawler_transport = RecordingCrawlerTransport()
        probe_transport = RecordingProbeTransport()

        with self.assertRaisesRegex(PipelineError, "loopback"):
            analyze_url(
                "https://example.com/",
                top_k=1,
                crawler_transport=crawler_transport,
                transport=probe_transport,
            )

        self.assertEqual(crawler_transport.requests, [])
        self.assertEqual(probe_transport.requests, [])

    def test_legacy_userinfo_external_host_is_rejected_before_probe(self) -> None:
        transport = RecordingProbeTransport()

        with self.assertRaisesRegex(PipelineError, "loopback"):
            analyze_legacy_records(
                [
                    {
                        "link": "http://127.0.0.1@example.com/search?q=book",
                        "query_params": {"q": "book"},
                        "input_fields": [],
                    }
                ],
                top_k=1,
                transport=transport,
            )

        self.assertEqual(transport.requests, [])


if __name__ == "__main__":
    unittest.main()
