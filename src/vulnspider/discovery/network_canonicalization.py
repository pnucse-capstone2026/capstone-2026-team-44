"""Transport-free canonicalization of bounded browser network candidates."""

from __future__ import annotations

from collections import Counter

from vulnspider.discovery.contracts import (
    CanonicalDiscoveryResult,
    DiscoveryMetadata,
    DiscoverySafetyInvariant,
    NonProbeReadyReason,
    ScopeMetadata,
)
from vulnspider.discovery.dynamic_browser import (
    BlockedPostJsonCandidate,
    NetworkDiscoveryCandidate,
    NetworkDiscoveryCollection,
    NetworkDiscoveryDisposition,
)
from vulnspider.discovery.html_extractor import CanonicalDiscoveryBuilder
from vulnspider.discovery.post_replay_policy import PostReplayDisposition
from vulnspider.discovery.static_crawler import same_origin_crawl_url


def canonicalize_network_discovery(
    collection: NetworkDiscoveryCollection,
    *,
    discovery_metadata: DiscoveryMetadata,
    scope_metadata: ScopeMetadata,
) -> tuple[CanonicalDiscoveryResult, ...]:
    """Build deterministic Dynamic components without issuing any request."""

    if type(collection) is not NetworkDiscoveryCollection:
        raise TypeError("collection must be NetworkDiscoveryCollection")
    by_source: dict[str, list[NetworkDiscoveryCandidate]] = {}
    for candidate in collection.candidates:
        if not same_origin_crawl_url(scope_metadata.root_url, candidate.source_url):
            raise ValueError("network discovery source escaped canonical scope")
        if not same_origin_crawl_url(scope_metadata.root_url, candidate.base_url):
            raise ValueError("network discovery endpoint escaped canonical scope")
        by_source.setdefault(candidate.source_url, []).append(candidate)
    post_by_source: dict[str, list[BlockedPostJsonCandidate]] = {}
    post_replay_materials = dict(collection.post_json_replay_materials)
    for candidate in collection.post_json_candidates:
        if not same_origin_crawl_url(scope_metadata.root_url, candidate.source_url):
            raise ValueError("POST JSON source escaped canonical scope")
        if not same_origin_crawl_url(scope_metadata.root_url, candidate.base_url):
            raise ValueError("POST JSON endpoint escaped canonical scope")
        post_by_source.setdefault(candidate.source_url, []).append(candidate)
    post_skip_by_source: dict[str, Counter[str]] = {}
    for source_url, reason, count in collection.post_json_skipped_counts:
        if not same_origin_crawl_url(scope_metadata.root_url, source_url):
            raise ValueError("POST JSON warning source escaped canonical scope")
        post_skip_by_source.setdefault(source_url, Counter())[reason.value] += count

    components: list[CanonicalDiscoveryResult] = []
    source_urls = set(by_source).union(post_by_source, post_skip_by_source)
    for source_url in sorted(source_urls):
        builder = CanonicalDiscoveryBuilder(
            source_url=source_url,
            metadata=discovery_metadata,
            scope=scope_metadata,
            parent_url=None,
            depth=0,
            request_authorizer=None,
            discovered_by="native_dynamic_network",
        )
        elision_counts: Counter[str] = Counter()
        elided_candidate_count = 0
        audit_only_candidate_count = 0
        for candidate in sorted(by_source.get(source_url, ()), key=lambda item: item.id):
            observation_key = (
                f"network:{candidate.resource_type}:{candidate.id}"
            )
            origin_kind = f"network_{candidate.resource_type}"
            if candidate.disposition == NetworkDiscoveryDisposition.SAFE:
                canonical_url = candidate.canonical_url
                if canonical_url is None:
                    raise ValueError("safe network candidate has no canonical URL")
                builder.add_url_surface(
                    canonical_url,
                    observation_key=observation_key,
                    query_origin_kind=origin_kind,
                )
                continue
            elided_candidate_count += 1
            for reason in candidate.elision_reasons:
                elision_counts[reason.value] += 1
            if not candidate.query_parameter_names:
                audit_only_candidate_count += 1
                continue
            builder.add_structural_query_surface(
                candidate.base_url,
                query_parameter_names=candidate.query_parameter_names,
                observation_key=observation_key,
                not_ready_reasons=(NonProbeReadyReason.REQUEST_CONTEXT_MISSING,),
                query_origin_kind=origin_kind,
            )
        if elision_counts:
            builder.add_warning(
                "NETWORK_GET_VALUES_ELIDED",
                "Allowed browser GET values were elided before canonical construction.",
                {
                    "elided_candidate_count": elided_candidate_count,
                    "structural_candidate_count": (
                        elided_candidate_count - audit_only_candidate_count
                    ),
                    "audit_only_candidate_count": audit_only_candidate_count,
                    "elision_reason_counts": tuple(sorted(elision_counts.items())),
                    "producer_kind": discovery_metadata.collector_kind.value,
                },
                skipped=False,
            )
        post_candidates = tuple(
            sorted(post_by_source.get(source_url, ()), key=lambda item: item.id)
        )
        post_policy_counts: Counter[str] = Counter()
        for candidate in post_candidates:
            post_policy_counts[candidate.replay_policy.disposition.value] += 1
            builder.add_structural_json_body_surface(
                candidate.canonical_url,
                member_names=candidate.member_names,
                ephemeral_material=post_replay_materials.get(candidate.id),
                replay_policy=candidate.replay_policy,
                observation_key=(
                    f"network:{candidate.resource_type}:{candidate.id}"
                ),
                not_ready_reasons=(),
                origin_kind=f"network_{candidate.resource_type}",
            )
        if post_candidates:
            builder.add_warning(
                "NETWORK_POST_JSON_CAPTURED",
                "Blocked browser POST JSON attempts were retained structurally and gated by replay policy.",
                {
                    "structural_candidate_count": len(post_candidates),
                    "replay_policy_counts": tuple(sorted(post_policy_counts.items())),
                    "probe_ready_candidate_count": post_policy_counts[
                        PostReplayDisposition.SAFE_FOR_PROBE.value
                    ],
                    "producer_kind": discovery_metadata.collector_kind.value,
                },
                skipped=False,
            )
        post_skip_counts = post_skip_by_source.get(source_url)
        if post_skip_counts:
            builder.add_warning(
                "NETWORK_POST_JSON_SKIPPED",
                "Blocked browser POST JSON attempts failed closed before canonical construction.",
                {
                    "skip_reason_counts": tuple(sorted(post_skip_counts.items())),
                    "skipped_attempt_count": sum(post_skip_counts.values()),
                    "producer_kind": discovery_metadata.collector_kind.value,
                },
                skipped=False,
            )
        components.append(
            builder.build(
                link_count=0,
                form_count=0,
                safety_invariants=(
                    DiscoverySafetyInvariant.SENSITIVE_FORM_PRE_CANONICAL_ELISION,
                ),
                pages_processed=0,
                html_pages=0,
            )
        )
    return tuple(components)
