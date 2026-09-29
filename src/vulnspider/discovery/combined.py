"""Strict Static-first orchestration for combined native discovery."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from vulnspider.discovery.contracts import (
    CanonicalDiscoveryResult,
    CollectorKind,
)
from vulnspider.discovery.dynamic_browser import DynamicRequestAuthority
from vulnspider.discovery.dynamic_crawler import (
    DynamicCrawler,
    DynamicCrawlCompletion,
    DynamicCrawlPolicy,
    DynamicCrawlResult,
)
from vulnspider.discovery.html_extractor import (
    extract_static_html_with_sensitive_form_elision,
)
from vulnspider.discovery.merge import (
    DiscoveryMergePolicy,
    DynamicIntegrityError,
    merge_discovery_results,
)
from vulnspider.discovery.static_crawler import (
    CrawlPolicy,
    StaticCrawler,
    StaticCrawlResult,
    canonicalize_crawl_url,
)


def _default_static_crawler() -> StaticCrawler:
    return StaticCrawler(
        extractor=extract_static_html_with_sensitive_form_elision,
    )


@dataclass(frozen=True, slots=True)
class CombinedDiscoveryResult:
    """Validated producer evidence plus the authoritative combined handoff."""

    root_url: str
    static_crawl: StaticCrawlResult
    dynamic_crawl: DynamicCrawlResult
    discovery: CanonicalDiscoveryResult
    merge_policy: DiscoveryMergePolicy = field(default_factory=DiscoveryMergePolicy)

    def __post_init__(self) -> None:
        canonical_root = canonicalize_crawl_url(self.root_url)
        if canonical_root != self.root_url:
            raise ValueError("combined discovery root URL must already be canonical")
        if type(self.static_crawl) is not StaticCrawlResult:
            raise TypeError("static_crawl must be a StaticCrawlResult")
        if type(self.dynamic_crawl) is not DynamicCrawlResult:
            raise TypeError("dynamic_crawl must be a DynamicCrawlResult")
        if type(self.discovery) is not CanonicalDiscoveryResult:
            raise TypeError("discovery must be a CanonicalDiscoveryResult")
        if type(self.merge_policy) is not DiscoveryMergePolicy:
            raise TypeError("merge_policy must be a DiscoveryMergePolicy")
        if self.static_crawl.root_url != canonical_root:
            raise ValueError("Static crawl root does not match combined root")
        if self.dynamic_crawl.root_url != canonical_root:
            raise ValueError("Dynamic crawl root does not match combined root")
        replace(self.static_crawl)
        replace(self.dynamic_crawl)
        self.discovery.validate()
        if (
            self.discovery.discovery_metadata.collector_kind
            != CollectorKind.NATIVE_COMBINED
        ):
            raise ValueError("combined discovery has the wrong collector kind")
        expected = merge_discovery_results(
            self.static_crawl.discovery,
            self.dynamic_crawl.discovery,
            self.merge_policy,
        )
        if self.discovery != expected:
            raise DynamicIntegrityError(
                "combined discovery does not match its producer components"
            )

    @property
    def completion(self) -> DynamicCrawlCompletion:
        """Expose Dynamic completion so partial output cannot look complete."""

        return self.dynamic_crawl.completion

    @property
    def degraded(self) -> bool:
        return self.completion == DynamicCrawlCompletion.DEGRADED

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_url": self.root_url,
            "completion": self.completion.value,
            "merge_policy_version": self.merge_policy.version,
            "static_crawl": self.static_crawl.to_dict(),
            "dynamic_crawl": self.dynamic_crawl.to_dict(),
            "discovery": self.discovery.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class NativeDiscoveryOrchestrator:
    """Run existing native producers and the existing deterministic merge core."""

    static_crawler: StaticCrawler = field(default_factory=_default_static_crawler)
    dynamic_crawler: DynamicCrawler = field(default_factory=DynamicCrawler)
    merge_policy: DiscoveryMergePolicy = field(default_factory=DiscoveryMergePolicy)

    def discover(
        self,
        root_url: str,
        *,
        authority: DynamicRequestAuthority,
        static_policy: CrawlPolicy | None = None,
        dynamic_policy: DynamicCrawlPolicy | None = None,
    ) -> CombinedDiscoveryResult:
        """Return one combined result or propagate the producer/integrity failure."""

        canonical_root = canonicalize_crawl_url(root_url)
        if type(authority) is not DynamicRequestAuthority:
            raise TypeError("authority must be a DynamicRequestAuthority")
        if authority.root_url != canonical_root:
            raise ValueError("authority root must match the combined discovery root")

        static_crawl = self.static_crawler.crawl(canonical_root, static_policy)
        if type(static_crawl) is not StaticCrawlResult:
            raise TypeError("Static producer must return StaticCrawlResult")
        static_crawl = replace(static_crawl)

        active_dynamic_policy = dynamic_policy or DynamicCrawlPolicy()
        dynamic_crawl = self.dynamic_crawler.crawl(
            canonical_root,
            active_dynamic_policy,
            authority,
        )
        if type(dynamic_crawl) is not DynamicCrawlResult:
            raise TypeError("Dynamic producer must return DynamicCrawlResult")
        dynamic_crawl = replace(dynamic_crawl)

        combined = merge_discovery_results(
            static_crawl.discovery,
            dynamic_crawl.discovery,
            self.merge_policy,
        )
        return CombinedDiscoveryResult(
            root_url=canonical_root,
            static_crawl=static_crawl,
            dynamic_crawl=dynamic_crawl,
            discovery=combined,
            merge_policy=self.merge_policy,
        )


def discover_native_combined(
    root_url: str,
    *,
    authority: DynamicRequestAuthority,
    static_policy: CrawlPolicy | None = None,
    dynamic_policy: DynamicCrawlPolicy | None = None,
    static_crawler: StaticCrawler | None = None,
    dynamic_crawler: DynamicCrawler | None = None,
    merge_policy: DiscoveryMergePolicy | None = None,
) -> CombinedDiscoveryResult:
    """Convenience entry point for strict Static-plus-Dynamic discovery."""

    orchestrator = NativeDiscoveryOrchestrator(
        static_crawler=(
            static_crawler if static_crawler is not None else _default_static_crawler()
        ),
        dynamic_crawler=(
            dynamic_crawler if dynamic_crawler is not None else DynamicCrawler()
        ),
        merge_policy=(
            merge_policy if merge_policy is not None else DiscoveryMergePolicy()
        ),
    )
    return orchestrator.discover(
        root_url,
        authority=authority,
        static_policy=static_policy,
        dynamic_policy=dynamic_policy,
    )
