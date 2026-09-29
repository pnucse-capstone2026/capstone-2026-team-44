import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag
import json
from collections import deque, defaultdict
from urllib import robotparser

from modules.config import TARGET_ATTRIBUTES
from modules.parser import extract_inputs_with_form_context
from modules.db import insert_link
from modules.params import extract_params_from_url
from modules.url_filter import compile_patterns, is_url_allowed, filter_similar_urls
from urllib.parse import urljoin, urldefrag
from modules.utils import DotsSpinner

UA = "whspider/1.0"

parent_url_groups = defaultdict(list)

def is_internal_url(url, base_netloc):
    return urlparse(url).netloc.endswith(base_netloc)

def parse_cookie_string(cookie_str):
    cookies = {}
    for pair in cookie_str.split(";"):
        if "=" in pair:
            name, value = pair.strip().split("=", 1)
            cookies[name.strip()] = value.strip()
    return cookies

def run_static_crawl_entry(start_url, max_depth=1, include=None, exclude=None, mode='dfs', cookie="", db_path="", ignore_robots=False):
    base_netloc = urlparse(start_url).netloc
    
    rp = robotparser.RobotFileParser()
    if not ignore_robots:
        try:
            rp.set_url(urljoin(start_url, "/robots.txt"))
            rp.read()
        except Exception as e:
            print(f"[!] robots.txt 읽기 실패: {e}")

    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    if cookie:
        for k, v in parse_cookie_string(cookie).items():
            session.cookies.set(k, v)

    include_patterns = compile_patterns(include)
    exclude_patterns = compile_patterns(exclude)

    spinner = DotsSpinner("크롤링 중")
    spinner.start()
    

    try:
        if mode == 'dfs':
            _run_static_dfs(start_url, max_depth, include_patterns, exclude_patterns, base_netloc, session, db_path, rp, ignore_robots)
        else:
            _run_static_bfs(start_url, max_depth, include_patterns, exclude_patterns, base_netloc, session, db_path, rp, ignore_robots)
    except KeyboardInterrupt:
        print("\n[!] 사용자에 의해 크롤링이 중지되었습니다.")
        save_filtered_urls(db_path)
        print("[i] 지금까지 수집한 데이터만 저장 후 종료합니다.\n")

    finally:
        spinner.stop()
        print()

def fetch_page(url, depth, parent, include_patterns, exclude_patterns, max_depth, visited, container, push, base_netloc, session, start_url, db_path, rp, ignore_robots):
    if url in visited or depth > max_depth:
        return
    visited.add(url)

    if not ignore_robots and not rp.can_fetch(UA, url):
        print(f"[!] robots.txt 에 의해 차단: {url}")
        return

    try:
        res = session.get(url, timeout=5)
        res.encoding = "utf-8"
        res.raise_for_status()
    except Exception as e:
        print(f"[!] 요청 실패: {url} - {e}")
        return

    parsed_url = urlparse(url)
    host = parsed_url.netloc
    query_dict = extract_params_from_url(url)
    query_params = json.dumps(query_dict, ensure_ascii=False)

    input_fields = extract_inputs_with_form_context(res.text)
    input_fields_json = json.dumps(input_fields, ensure_ascii=False)

    parent_key = parent if parent else start_url
    parent_url_groups[parent_key].append((url, parent, depth, host, query_params, input_fields_json))
    
    if depth == max_depth:
        return

    soup = BeautifulSoup(res.text, "html.parser")
    for tag in soup.find_all("a", href=True):
        raw = tag["href"].strip()
        if raw.startswith("#"):
            continue
        abs_url = urljoin(url, raw)
        next_url, _ = urldefrag(abs_url)
        next_url = next_url.rstrip('/')
        if not is_internal_url(next_url, base_netloc):
            continue
        if not is_url_allowed(next_url, include_patterns, exclude_patterns):
            continue
        push(container, (next_url, depth + 1, url))

def _run_static_dfs(start_url, max_depth, include_patterns, exclude_patterns, base_netloc, session, db_path, rp, ignore_robots):
    visited = set()
    stack = [(start_url, 0, None)]
    while stack:
        url, depth, parent = stack.pop()
        fetch_page(url, depth, parent, include_patterns, exclude_patterns, max_depth, visited, stack, list.append, base_netloc, session, start_url, db_path, rp, ignore_robots)
    save_filtered_urls(db_path)

def _run_static_bfs(start_url, max_depth, include_patterns, exclude_patterns, base_netloc, session, db_path, rp, ignore_robots):
    visited = set()
    queue = deque([(start_url, 0, None)])
    while queue:
        url, depth, parent = queue.popleft()
        fetch_page(url, depth, parent, include_patterns, exclude_patterns, max_depth, visited, queue, deque.append, base_netloc, session, start_url, db_path, rp, ignore_robots)
    save_filtered_urls(db_path)


def save_filtered_urls(db_path):
    final_urls = []

    for parent, url_info_list in parent_url_groups.items():
        urls = [info[0] for info in url_info_list]
        filtered_urls = filter_similar_urls(urls, threshold=90.0, max_keep=3)
        filtered_set = set(filtered_urls)

        for url, parent, depth, host, query_params, input_fields_json in url_info_list:
            if url in filtered_set:
                insert_link(db_path, url, parent, depth, host, query_params, input_fields_json)
                final_urls.append((depth, url))
    
    for depth, url in final_urls:
        print(f"[Depth {depth}] {url}")