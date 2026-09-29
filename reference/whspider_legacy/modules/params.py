import re
from urllib.parse import urlparse, parse_qs

param_pattern = re.compile(r'[?&]([a-zA-Z0-9_\-]+=[^&\s"\']+)')

def has_query_params(url: str) -> bool:
    return bool(param_pattern.search(url))

def extract_params_from_url(url: str) -> dict:
    if not has_query_params(url):
        return {}

    parsed = urlparse(url)
    query_dict = parse_qs(parsed.query)

    return {
        k: v[0] if len(v) == 1 else v
        for k, v in query_dict.items()
    }

def flatten_query_dict(query_dict: dict) -> str:
    return "&".join(
        f"{k}={v}" if isinstance(v, str) else f"{k}={','.join(v)}"
        for k, v in query_dict.items()
    )