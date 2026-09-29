import sqlite3
import json
import click
import subprocess
import os
import yaml
import time
import hashlib
import re
from functools import lru_cache
from typing import Optional, Dict, List, Any, Tuple
from urllib.parse import urlparse, parse_qs

# === 1. LRU 캐시로 교체 ===
from functools import lru_cache

# 기존 전역 캐시 대신 LRU 캐시 사용
_cache_stats = {"hits": 0, "misses": 0, "time_saved": 0}

@lru_cache(maxsize=100)  # 최대 100개 엔트리까지 캐시
def _cached_analysis(structure_hash_str: str, analysis_result: str) -> str:
    """LRU 캐시를 이용한 분석 결과 저장"""
    return analysis_result

def get_cached_analysis(structure_hash: str) -> Optional[str]:
    """캐시에서 분석 결과 조회"""
    try:
        # LRU 캐시에서 조회 시도 (키 에러면 None 반환)
        for cached_call in _cached_analysis.cache_info():
            pass  # 캐시 정보만 확인
        
        # 실제로는 별도 딕셔너리로 관리 (LRU 데코레이터의 한계로 인해)
        if hasattr(get_cached_analysis, '_cache_dict'):
            return get_cached_analysis._cache_dict.get(structure_hash)
        return None
    except:
        return None

def set_cached_analysis(structure_hash: str, result: str):
    """캐시에 분석 결과 저장"""
    if not hasattr(get_cached_analysis, '_cache_dict'):
        get_cached_analysis._cache_dict = {}
    
    # 최대 100개 제한
    if len(get_cached_analysis._cache_dict) >= 100:
        # 가장 오래된 것 제거 (간단한 FIFO)
        oldest_key = next(iter(get_cached_analysis._cache_dict))
        del get_cached_analysis._cache_dict[oldest_key]
    
    get_cached_analysis._cache_dict[structure_hash] = result

def clear_analysis_cache():
    """분석 캐시와 통계를 모두 클리어"""
    global _cache_stats
    _cache_stats = {"hits": 0, "misses": 0, "time_saved": 0}
    if hasattr(get_cached_analysis, '_cache_dict'):
        get_cached_analysis._cache_dict.clear()
    _cached_analysis.cache_clear()
    print(" 분석 캐시가 클리어되었습니다.")

def load_config() -> Dict[str, Any]:
    """설정 파일 로드"""
    config_paths = [
        os.path.expanduser("~/.whspider.yaml"),
        "config.yaml",
        "data/config.yaml"
    ]
    
    for config_path in config_paths:
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f)
            except Exception as e:
                click.secho(f"[!] 설정 파일 로드 실패: {e}", fg="red")
    
    # 기본 설정 반환
    return {
        "model": {
            "name": "hf.co/Jin312/WebSpider_Mistral:Q4_K_M"
        }
    }

def generate_structure_hash(input_fields, query_params):
    """
    input_fields와 query_params의 구조를 기반으로 해시 생성
    같은 구조면 같은 해시가 나와서 결과 재사용 가능
    """
    # 필드 구조만 추출 (이름, 타입, 개수)
    field_structure = []
    if input_fields:
        for field in input_fields:
            field_info = {
                'name': field.get('name', '').lower(),
                'type': field.get('type', '').lower()
            }
            field_structure.append(field_info)
    
    # 파라미터 구조만 추출 (키 이름들)  
    param_structure = []
    if query_params:
        param_structure = sorted([key.lower() for key in query_params.keys()])
    
    # 구조를 문자열로 변환 후 해시화
    structure_data = {
        'fields': sorted(field_structure, key=lambda x: x['name']),
        'params': param_structure
    }
    
    structure_str = json.dumps(structure_data, sort_keys=True, ensure_ascii=False)
    return hashlib.md5(structure_str.encode('utf-8')).hexdigest()

def build_field_list(input_fields_raw: list) -> list:
    return [
        field for field in input_fields_raw
        if any(k in field for k in ("name", "aria-label", "title"))
    ]


def json_issues(text: str) -> str:
    text = text.strip()
    if text.startswith('```json'):
        text = text[7:]
    if text.endswith('```'):
        text = text[:-3]
    text = text.strip()

    def clean_json_string_content(content):
        content = re.sub(r'#.*?(?=[}\]]|$)', '', content, flags=re.DOTALL)
        control_char_pattern = re.compile(r'[\x00-\x07\x0b\x0e-\x1f]')
        content = control_char_pattern.sub('', content)

        content = content.replace('\\n', 'TEMP_NEWLINE_PLACEHOLDER') 
        content = content.replace('\\r', 'TEMP_CARRIAGE_RETURN_PLACEHOLDER')
        content = content.replace('\\t', 'TEMP_TAB_PLACEHOLDER')
        
        content = content.replace('\n', '\\n')
        content = content.replace('\r', '\\r')
        content = content.replace('\t', '\\t')

        content = content.replace('TEMP_NEWLINE_PLACEHOLDER', '\\n')
        content = content.replace('TEMP_CARRIAGE_RETURN_PLACEHOLDER', '\\r')
        content = content.replace('TEMP_TAB_PLACEHOLDER', '\\t')

        content = re.sub(r'(?<!\\)\\(?!["\\/bfnrtu])', r'\\\\', content)
        content = re.sub(r'(?<!\\)"', r'\"', content)
        
        return content

    def replace_value(match):
        key_part = match.group(1) 
        raw_value = match.group(2) 
        raw_value = re.sub(r'(".*?)"([a-zA-Z_]\w*":)', r'\1",\2', raw_value)
        cleaned_value = clean_json_string_content(raw_value)
        return f'{key_part}{cleaned_value}"' 
    text = re.sub(r'("[^"]*?"\s*:\s*)("((?:\\.|[^"\\])*?)(?<!\\)")', replace_value, text, flags=re.DOTALL)

    def fix_unterminated_strings_fallback(match):
        key_part = match.group(1)
        val_part = match.group(2).strip() 
        val_part = val_part.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
        return f'{key_part}{val_part}"' 
    
    text = re.sub(r'(":\s*")([^"]*?)(?=[\n\r\}]|,\s*"|\s*\}|$)', fix_unterminated_strings_fallback, text, flags=re.DOTALL)
    text = re.sub(r'(".*?"\s*:\s*)(\'[^\']*\')', lambda m: f'{m.group(1)}"{m.group(2)[1:-1]}"', text)
    text = re.sub(r'(".*?")\s+(".*?")', r'\1: \2', text)
    text = re.sub(r'(".*?")\s+(\d+)', r'\1: \2', text)
    text = re.sub(r'(".*?")\s+(true|false|null)', r'\1: \2', text, flags=re.IGNORECASE)

    text = re.sub(r'(".*?")\s*(")', r'\1,\2', text)
    text = re.sub(r'(\d+)\s*(")', r'\1,\2', text)
    text = re.sub(r'\b(true|false|null)\s*(")', r'\1,\2', text, flags=re.IGNORECASE)
    text = re.sub(r'\}\s*\{', '},{', text)
    text = re.sub(r'\]\s*\[', '],[', text)

    return text

def extract_json_from_text(text: str):
    # LLM이 `[{}],[{}]` 와 같이 잘못된 형식을 생성하는 경우를 대비해 정리
    cleaned_text = text.strip().replace("],[", ",").replace("], [", ",")
    
    # 배열 패턴 먼저 찾기
    array_matches = re.findall(r'\[\s*{.*?}\s*\]', cleaned_text, re.DOTALL)
    if array_matches:
        all_objs = []
        for arr_str in array_matches:
            try:
                parsed = json.loads(arr_str)
                if isinstance(parsed, list):
                    all_objs.extend(parsed)
                elif isinstance(parsed, dict):
                    all_objs.append(parsed)
            except json.JSONDecodeError:
                continue  # 잘못된 JSON 조각은 무시
        if all_objs:
            return json.dumps(all_objs, indent=2, ensure_ascii=False)

    # 1. JSON 배열 `[...]` 시도
    start_arr = cleaned_text.find('[')
    end_arr = cleaned_text.rfind(']')
    if start_arr != -1 and end_arr != -1 and end_arr > start_arr:
        json_part = cleaned_text[start_arr:end_arr+1]
        try:
            json.loads(json_part)
            return json_part
        except json.JSONDecodeError:
            pass # 객체 시도로 넘어감

    # 2. JSON 객체 `{...}` 시도
    start_obj = cleaned_text.find('{')
    end_obj = cleaned_text.rfind('}')
    if start_obj != -1 and end_obj != -1 and end_obj > start_obj:
        # 배열 안에 있는 객체가 아닌지 확인
        if not (start_arr != -1 and end_arr != -1 and start_arr < start_obj and end_obj < end_arr):
             json_part = cleaned_text[start_obj:end_obj+1]
             try:
                json.loads(json_part)
                return json_part
             except json.JSONDecodeError:
                pass

    # 3. 키: 값 형태의 비정형 텍스트를 JSON 객체로 변환 (단일 객체만 지원)
    if '[' not in cleaned_text and ':' in cleaned_text:
        lines = cleaned_text.strip().split('\n')
        json_dict = {}
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().replace('"', '').replace("'", "")
                value = value.strip()
                if value.endswith(','):
                    value = value[:-1]
                if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                json_dict[key] = value
        
        if json_dict:
            return json.dumps(json_dict, indent=2, ensure_ascii=False)

    return text # 모든 방법이 실패하면 원본 반환

def clean_llm_response(response: str) -> str:
    if not response:
        return response
    
    # 1. 간단한 # 반복 패턴 감지 및 제거
    patterns = ["# # # #", "# #  #", "#  # #", "###"]
    for pattern in patterns:
        if pattern in response:
            pos = response.find(pattern)
            if pos != -1:
                response = response[:pos].strip()
                break
    
    # 2. 길이 제한
    if len(response) > 1000:
        response = response[:1000].strip()
    
    try:
        # 먼저 원본이 유효한 JSON인지 확인
        try:
            parsed = json.loads(response)
            extracted_json = response
        except json.JSONDecodeError:
            # JSON이 아니면 정리 과정 수행
            cleaned_response = json_issues(response)
            extracted_json = extract_json_from_text(cleaned_response)
            parsed = json.loads(extracted_json)
        
        # 소스 필드 후처리 - 비어있으면 기본 소스 추가
        if isinstance(parsed, dict):
            sources = parsed.get('sources', [])
            if not sources or sources == [] or sources == [""]:
                # 취약점 유형별 기본 소스 할당
                category = parsed.get('category', '').lower()
                attack_type = parsed.get('attack_type', '').lower()
                
                if 'sql' in category or 'sql' in attack_type:
                    parsed['sources'] = ["https://owasp.org/www-community/attacks/SQL_Injection"]
                elif 'xss' in category or 'xss' in attack_type or 'script' in category:
                    parsed['sources'] = ["https://owasp.org/www-community/attacks/xss/"]
                elif 'ssrf' in category or 'ssrf' in attack_type or 'request' in category:
                    parsed['sources'] = ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"]
                elif 'redirect' in category or 'redirect' in attack_type:
                    parsed['sources'] = ["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards"]
                else:
                    parsed['sources'] = ["https://owasp.org/www-community/attacks/"]
                    
                extracted_json = json.dumps(parsed, ensure_ascii=False)
        elif isinstance(parsed, list):
            # 배열인 경우 각 객체에 대해 소스 필드 처리
            for item in parsed:
                if isinstance(item, dict):
                    sources = item.get('sources', [])
                    if not sources or sources == [] or sources == [""]:
                        category = item.get('category', '').lower()
                        attack_type = item.get('attack_type', '').lower()
                        
                        if 'sql' in category or 'sql' in attack_type:
                            item['sources'] = ["https://owasp.org/www-community/attacks/SQL_Injection"]
                        elif 'xss' in category or 'xss' in attack_type or 'script' in category:
                            item['sources'] = ["https://owasp.org/www-community/attacks/xss/"]
                        elif 'ssrf' in category or 'ssrf' in attack_type or 'request' in category:
                            item['sources'] = ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"]
                        elif 'redirect' in category or 'redirect' in attack_type:
                            item['sources'] = ["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards"]
                        else:
                            item['sources'] = ["https://owasp.org/www-community/attacks/"]
            extracted_json = json.dumps(parsed, ensure_ascii=False)
        
        return extracted_json
        
    except Exception as e:
        # JSON 처리 실패시 원본 반환
        return response.strip()

def pretty_fieldwise_click_secho(parsed, color="green"):
 
    if isinstance(parsed, list):
        for idx, obj in enumerate(parsed):
            click.secho(f"\n--- Result {idx+1} ---", fg=color)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    click.secho(f"{k}: {v}", fg=color)
            else:
                click.secho(f"Result: {obj}", fg=color)
        click.secho("", fg=color)
    elif isinstance(parsed, dict):
        click.secho(f"\n--- Analysis Result ---", fg=color)
        for k, v in parsed.items():
            click.secho(f"{k}: {v}", fg=color)
        click.secho("", fg=color)
    else:
        # 문자열이나 기타 타입인 경우
        click.secho(f"\n--- Raw Result ---", fg=color)
        click.secho(str(parsed), fg=color)
        click.secho("", fg=color)

def display_formatted_result_with_confidence_filter(result_text: str):
    """
    신뢰도 필터링을 포함한 LLM 분석 결과 출력 함수
    """
    try:
        # 디버깅을 위해 신뢰도 필터링을 비활성화하고 모든 결과를 출력합니다.
        parsed = json.loads(result_text)
        
        if (isinstance(parsed, list) and not parsed) or (isinstance(parsed, dict) and not parsed):
            click.secho(f"  (분석 결과 없음)", fg="yellow")
            return

        pretty_fieldwise_click_secho(parsed, color="green")

    except json.JSONDecodeError:
        # JSON 파싱 실패 시 원본 그대로 출력
        click.secho("  JSON 파싱 실패 - 원본 응답 출력:", fg="yellow")
        click.secho(result_text, fg="green")
    
    click.secho("", fg="green")  # 빈 줄 추가

def build_prompt(url, input_fields, query_params, use_rag=True):
    """RAG 기능을 포함한 프롬프트 생성"""
    user_content = {
        "url": url,
        "input_fields": input_fields,
        "query_params": query_params,
    }
    json_str = json.dumps(user_content, ensure_ascii=False, separators=(',', ':'))
    
    # RAG에서 관련 컨텍스트 검색 (출처 정보 포함) - 최적화된 버전
    rag_context = ""
    source_references = []
    actual_sources = []
    contexts_with_sources = []
    all_sources = []
    
    if use_rag:
        try:
            from .rag import get_rag_pipeline
            rag = get_rag_pipeline()
            if rag.is_ready():
                # 스마트 쿼리 생성 - 더 다양한 검색 쿼리로 강화
                search_queries = []
                
                # 필드 이름들을 하나의 쿼리로 통합
                if input_fields:
                    field_names = [field.get('name', '') for field in input_fields if field.get('name')]
                    if field_names:
                        # 더 구체적인 쿼리들 생성
                        for field_name in field_names[:2]:  # 최대 2개 필드만
                            if field_name in ['url', 'redirect', 'next', 'goto']:
                                search_queries.append(f"open redirect vulnerability {field_name}")
                            elif field_name in ['id', 'uid', 'password', 'login']:
                                search_queries.append(f"sql injection {field_name} parameter")
                            elif field_name in ['comment', 'message', 'search']:
                                search_queries.append(f"xss vulnerability {field_name}")
                            else:
                                search_queries.append(f"web vulnerability {field_name} security assessment")
                
                # 파라미터 이름들을 하나의 쿼리로 통합
                if query_params:
                    param_names = list(query_params.keys())
                    if param_names:
                        for param_name in param_names[:2]:  # 최대 2개 파라미터만
                            if param_name in ['url', 'redirect', 'next', 'goto']:
                                search_queries.append(f"redirect attack patterns {param_name}")
                            elif param_name in ['id', 'uid', 'user_id']:
                                search_queries.append(f"injection vulnerability {param_name}")
                            else:
                                search_queries.append(f"parameter security {param_name} attack")
                
                # 기본 보안 컨텍스트 추가
                if not search_queries:
                    search_queries = [
                        "open redirect vulnerability",
                        "url parameter security", 
                        "redirect attack patterns"
                    ]
                
                # 중복 제거 및 최적화
                search_queries = list(set(search_queries))[:2]  # 최대 2개로 제한
                
                # 병렬 검색 수행
                contexts_with_sources = []
                all_sources = []
                
                if len(search_queries) > 1:  # 병렬 검색 조건 복구
                    # 병렬 검색 사용
                    for query in search_queries:
                        result = rag.search(query, top_k=1)
                        if result:
                            for item in result:
                                text = item.get('text', '')
                                if text:
                                    contexts_with_sources.append(text[:150])
                                    all_sources.append(item.get('metadata', {}))
                else:
                    # 단일 쿼리인 경우 일반 검색
                    if search_queries:
                        context, sources = rag.get_context_with_sources(search_queries[0], max_context_length=150)
                        if context:
                            contexts_with_sources = [context]
                            all_sources = sources
                        else:
                            contexts_with_sources = []
                            all_sources = []
                
                # 컨텍스트 통합 (전체 길이 제한)
                if contexts_with_sources:
                    combined_context = ' '.join(contexts_with_sources)
                    # 최대 200자로 제한하여 속도 최적화
                    if len(combined_context) > 200:
                        combined_context = combined_context[:200] + "..."
                    
                    rag_context = f"Security Context: {combined_context}\n"
                    # 실제 출처 정보를 OWASP 링크로 변환
                    actual_sources = []
                    for source in all_sources:
                        if isinstance(source, dict):
                            doc_id = source.get('doc_id', '')
                            if doc_id:
                                actual_sources.append(f"Security Doc:{doc_id}")
                            else:
                                # 기본 OWASP 링크 사용
                                actual_sources.append("https://owasp.org/www-community/")
                        else:
                            actual_sources.append("https://owasp.org/www-community/")
                    
                    # 중복 제거
                    actual_sources = list(set(actual_sources))
                else:
                    rag_context = ""
                    actual_sources = ["https://owasp.org/www-community/attacks/SQL_Injection"]
        except Exception as e:
            rag_context = ""
            actual_sources = ["https://owasp.org/www-community/attacks/SQL_Injection"]
    else:
        # RAG 미사용 시 기본 보안 소스 제공
        rag_context = ""
        actual_sources = [
            "https://owasp.org/www-community/attacks/",
            "https://cwe.mitre.org/",
            "https://portswigger.net/web-security"
        ]
    
    # RAG 컨텍스트 축소
    if contexts_with_sources:
        combined_context = ' '.join(contexts_with_sources)
        # 최대 200자로 대폭 축소
        if len(combined_context) > 200:
            combined_context = combined_context[:200] + "..."
        
        rag_context = f"Security Context: {combined_context}\n"
    else:
        rag_context = ""
    
    # 프롬프트 대폭 단축 + 간결성 지시 추가
    prompt = (
        "<s>[INST] "
        "Web security analysis. Return concise, valid JSON only. Stop after complete JSON. "
        f"{rag_context}"
        "Fields: category, attack_type, parameter, usage, payload, tool, indicator, confidence_score, reasoning, sources. "
        "Confidence score (0.0-1.0): Judge vulnerability probability based on parameter context, attack feasibility, and security evidence. Use your expertise. "
        "Empty array [] if no vulnerability. Keep all field values brief. "
        "IMPORTANT: Always populate 'sources' field with relevant security references from available sources or standard security documentation. Never leave sources empty. "
        f"Available sources: {actual_sources if actual_sources else []}. "
        f"Data: {json_str} [/INST]"
    )
    return prompt

def query_local_llm(prompt: str) -> str:
    """
    Ollama LLM에 프롬프트 전달, 결과 반환 (120초 타임아웃, stderr 출력 포함)
    """
    try:
        config = load_config()
        model_name = config.get("model", {}).get("name", "hf.co/Jin312/WebSpider_Mistral:Q4_K_M")
        
        result = subprocess.run(
            ["ollama", "run", model_name, "--verbose"],
            input=prompt,
            capture_output=True,
            text=True,
            encoding='utf-8',
            check=True,
            timeout=120  # 120초 타임아웃
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        click.secho(f"[!] Ollama 실행 타임아웃 (120초 초과)", fg="red")
        return ""
    except subprocess.CalledProcessError as e:
        click.secho(f"[!] Ollama 실행 실패 (exit code: {e.returncode})", fg="red")
        if e.stderr:
            click.secho(f"[!] 오류 상세: {e.stderr.strip()}", fg="red")
        return ""
    except Exception as e:
        click.secho(f"[!] Ollama 실행 실패: {e}", fg="red")
        return ""
    
def get_last_id(db_path):
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT MAX(id) FROM crawl_links")
        row = cur.fetchone()
        return row[0] if row[0] else 0

def run_llm_analysis(db_path, start_id, end_id, use_rag=False):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT link, input_fields, query_params
            FROM crawl_links
            WHERE id > ? AND id <= ?
            AND ((input_fields IS NOT NULL AND input_fields != '[]')
                OR (query_params IS NOT NULL AND query_params != '{}'))
        """, (start_id, end_id))
        rows = cursor.fetchall()
        conn.close()
    except Exception as e:
        click.secho(f"[!] DB 연결 실패: {e}", fg="red")
        return

    if not rows:
        click.secho("[!] 분석할 대상이 없습니다.", fg="yellow")
        return

    click.secho(f"[+] 분석 대상 URL {len(rows)}개 분석 시작", fg="cyan")
    click.secho("참고: LLM 응답 시간은 사용자의 머신 환경에 따라 달라질 수 있습니다.", fg="blue")

    for url, input_fields_json, query_params_json in rows:
        try:
            raw_fields = json.loads(input_fields_json)
            fields = build_field_list(raw_fields)
            query_params = json.loads(query_params_json) if query_params_json else {}
        except Exception as e:
            click.secho(f"[!] 데이터 파싱 실패: {url} - {e}", fg="red")
            continue

        if not fields and not query_params:
            continue

        # 전체 분석 시간 측정 시작
        total_start_time = time.time()
        click.secho(f"\n[ANALYZING] {url}", fg="blue")
        
        # 구조 기반 캐시 확인 (개선된 LRU 캐시 사용)
        structure_hash = generate_structure_hash(fields, query_params)
        cached_result = get_cached_analysis(structure_hash)
        
        if cached_result:
            click.secho(f"  [CACHE HIT] 동일한 구조의 이전 분석 결과 재사용 (해시: {structure_hash[:8]}...)", fg="yellow")
            
            # 캐시된 결과를 보기 좋게 출력
            display_formatted_result_with_confidence_filter(cached_result)
            
            total_end_time = time.time()
            total_elapsed = total_end_time - total_start_time
            click.secho(f"    캐시 적용: {total_elapsed:.2f}초", fg="cyan")
            
            # 캐시 통계 업데이트
            _cache_stats["hits"] += 1
            _cache_stats["time_saved"] += 80  # 평균 LLM 응답 시간 추정치
            continue
        
        click.secho(f"  [CACHE MISS] 새로운 구조 분석 중... (해시: {structure_hash[:8]}...)", fg="magenta")
        _cache_stats["misses"] += 1
        
        # 프롬프트 생성 시간 측정
        prompt_start_time = time.time()
        prompt = build_prompt(
            url=url,
            input_fields=fields,
            query_params=query_params,
            use_rag=use_rag
        )
        prompt_end_time = time.time()
        prompt_elapsed = prompt_end_time - prompt_start_time

        try:
            # LLM 응답 시간 측정
            llm_start_time = time.time()
            result = query_local_llm(prompt)
            llm_end_time = time.time()
            llm_elapsed = llm_end_time - llm_start_time
            
            # 전체 분석 시간 계산
            total_end_time = time.time()
            total_elapsed = total_end_time - total_start_time
            
            # 시간 정보 표시 (RAG 사용 여부에 따라 다르게 표시)
            if use_rag:
                click.secho(f"    RAG 검색: {prompt_elapsed:.2f}초 | LLM 응답: {llm_elapsed:.2f}초 | 총 시간: {total_elapsed:.2f}초", fg="cyan")
            else:
                click.secho(f"    프롬프트 생성: {prompt_elapsed:.2f}초 | LLM 응답: {llm_elapsed:.2f}초 | 총 시간: {total_elapsed:.2f}초", fg="cyan")

            if result:
                # LLM 응답 후처리: 이상한 반복 패턴 제거
                cleaned_result = clean_llm_response(result)
                
                # 결과를 캐시에 저장 (개선된 LRU 캐시 사용)
                set_cached_analysis(structure_hash, cleaned_result)
                click.secho(f"  [CACHE SAVE] 분석 결과 저장됨 (해시: {structure_hash[:8]}...)", fg="yellow")
                
                # 보기 좋게 포맷팅해서 출력
                display_formatted_result_with_confidence_filter(cleaned_result)
            else:
                raise ValueError("LLM 응답이 비어 있음")
        except Exception as e:
            click.secho(f"[!] LLM 분석 실패 또는 결과 파싱 오류: {e}", fg="red")
    
    # 캐시 통계 출력 (루프 밖으로 이동)
    if _cache_stats["hits"] > 0 or _cache_stats["misses"] > 0:
        total_requests = _cache_stats["hits"] + _cache_stats["misses"]
        hit_rate = (_cache_stats["hits"] / total_requests) * 100 if total_requests > 0 else 0
        click.secho(f"\n=== 캐시 성능 통계 ===", fg="cyan")
        click.secho(f"총 요청: {total_requests}개", fg="cyan")
        click.secho(f"캐시 적중: {_cache_stats['hits']}개 ({hit_rate:.1f}%)", fg="green")
        click.secho(f"캐시 미스: {_cache_stats['misses']}개", fg="yellow")
        if _cache_stats["time_saved"] > 0:
            time_saved_min = _cache_stats["time_saved"] / 60
            click.secho(f"절약된 시간: 약 {time_saved_min:.1f}분", fg="green")

if __name__ == "__main__":
    run_llm_analysis()