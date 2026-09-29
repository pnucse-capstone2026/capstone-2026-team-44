import re
from rapidfuzz.distance import Levenshtein

def compile_patterns(pattern_str):
    return [re.compile(p.strip(), re.IGNORECASE) for p in pattern_str.split(",")] if pattern_str else []

def is_url_allowed(url, include_patterns, exclude_patterns):
    if include_patterns and not any(p.search(url) for p in include_patterns):
        return False
    if exclude_patterns and any(p.search(url) for p in exclude_patterns):
        return False
    return True

def similarity(url1, url2):
    url1, url2 = url1.strip(), url2.strip()
    max_len = max(len(url1), len(url2))
    if max_len == 0:
        return 100.0
    dist = Levenshtein.distance(url1, url2)
    return (1 - dist / max_len) * 100

def filter_similar_urls(urls, threshold=90.0, max_keep=3):
    urls = list(set(url.strip() for url in urls if url.strip()))
    candidate_groups = []

    for i in range(len(urls)):
        base = urls[i]
        group = [base]
        for j in range(len(urls)):
            if i == j:
                continue
            if similarity(base, urls[j]) >= threshold:
                group.append(urls[j])
        if len(group) >= max_keep:
            candidate_groups.append(set(group))

    final_groups = []
    for group in candidate_groups:
        merged = False
        for fg in final_groups:
            if group & fg:
                fg.update(group)
                merged = True
                break
        if not merged:
            final_groups.append(set(group))

    result = set()
    for group in final_groups:
        selected = list(group)[:max_keep]
        result.update(selected)

    grouped_all_urls = set().union(*final_groups) if final_groups else set()
    for url in urls:
        if url not in grouped_all_urls:
            result.add(url)

    return list(result)