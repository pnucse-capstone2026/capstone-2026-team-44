import os
import yaml
import json
import pickle
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
from pathlib import Path
import click
from concurrent.futures import ThreadPoolExecutor
import threading

os.environ["TOKENIZERS_PARALLELISM"] = "false"
# 전역 쿼리 캐시
_query_cache = {}
_cache_lock = threading.Lock()

class RAGPipeline:
    def __init__(self, config_path=None):
        self.config = self._load_config(config_path)
        self.embedder = None
        self.index = None
        self.chunks = None
        self._initialize()
    
    def _load_config(self, config_path):
        """설정 파일 로드"""
        if config_path is None:
            # 기본 설정 경로들 시도
            config_paths = [
                os.path.expanduser("~/.whspider.yaml"),
                "config.yaml",
                "data/config.yaml"
            ]
            for path in config_paths:
                if os.path.exists(path):
                    config_path = path
                    break
            else:
                # 기본 설정 반환 (성능 최적화된 값들)
                return {
                    "rag": {
                        "index": "data/kb.index",
                        "chunks": "data/kb_chunks.pkl",
                        "top_k": 1,  # 3 -> 1로 감소 (이미 최소값)
                        "model": "paraphrase-MiniLM-L3-v2",  # 더 빠른 모델
                        "max_context_length": 200,  # 400 -> 200으로 감소
                        "max_concurrent_searches": 2  # 병렬 처리 설정
                    },
                    "model": {
                        "name": "webspider-mistral"
                    }
                }
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                # 기본값 설정 (설정 파일에 없는 경우)
                if "rag" not in config:
                    config["rag"] = {}
                config["rag"].setdefault("top_k", 1)
                config["rag"].setdefault("model", "paraphrase-MiniLM-L3-v2")
                config["rag"].setdefault("max_context_length", 200)
                config["rag"].setdefault("max_concurrent_searches", 2)
                return config
        except Exception as e:
            click.secho(f"[!] 설정 파일 로드 실패: {e}", fg="red")
            return {}
    
    def _initialize(self):
        """RAG 파이프라인 초기화"""
        try:
            # 임베딩 모델 로드
            model_name = self.config.get("rag", {}).get("model", "paraphrase-MiniLM-L3-v2")
            click.secho(f"[+] 임베딩 모델 로드 중: {model_name}", fg="cyan")
            self.embedder = SentenceTransformer(model_name)
            
            # FAISS 인덱스 로드
            index_path = self.config.get("rag", {}).get("index", "data/kb.index")
            if os.path.exists(index_path):
                click.secho(f"[+] FAISS 인덱스 로드 중: {index_path}", fg="cyan")
                self.index = faiss.read_index(index_path)
            else:
                click.secho(f"[!] FAISS 인덱스 파일을 찾을 수 없습니다: {index_path}", fg="yellow")
                click.secho(f"[!] 구글 드라이브에서 kb.index 파일을 다운로드하여 {index_path}에 배치하세요", fg="yellow")
            
            # 청크 데이터 로드
            chunks_path = self.config.get("rag", {}).get("chunks", "data/kb_chunks.pkl")
            if os.path.exists(chunks_path):
                click.secho(f"[+] 청크 데이터 로드 중: {chunks_path}", fg="cyan")
                with open(chunks_path, 'rb') as f:
                    self.chunks = pickle.load(f)
            else:
                click.secho(f"[!] 청크 데이터 파일을 찾을 수 없습니다: {chunks_path}", fg="yellow")
                click.secho(f"[!] 구글 드라이브에서 kb_chunks.pkl 파일을 다운로드하여 {chunks_path}에 배치하세요", fg="yellow")
                
        except Exception as e:
            click.secho(f"[!] RAG 파이프라인 초기화 실패: {e}", fg="red")
    
    def is_ready(self):
        """RAG 파이프라인이 사용 가능한지 확인"""
        return self.embedder is not None and self.index is not None and self.chunks is not None
    
    def _get_cache_key(self, query, top_k):
        """캐시 키 생성"""
        return f"{query}:{top_k}"
    
    def search(self, query, top_k=None):
        """쿼리에 대한 관련 청크 검색 (캐싱 지원)"""
        if not self.is_ready():
            return []
        
        if top_k is None:
            top_k = self.config.get("rag", {}).get("top_k", 1)
        
        # 캐시 확인
        cache_key = self._get_cache_key(query, top_k)
        with _cache_lock:
            if cache_key in _query_cache:
                return _query_cache[cache_key]
        
        try:
            # 쿼리 임베딩
            query_vector = self.embedder.encode([query])
            
            # FAISS 검색
            scores, indices = self.index.search(query_vector.astype('float32'), top_k)
            
            # 결과 조합
            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx < len(self.chunks):
                    chunk = self.chunks[idx]
                    # 청크가 딕셔너리인 경우 텍스트 추출
                    if isinstance(chunk, dict):
                        text = chunk.get('text', str(chunk))
                    else:
                        text = str(chunk)
                    
                    results.append({
                        "text": text,
                        "score": float(score),
                        "index": int(idx)
                    })
            
            # 캐시에 저장
            with _cache_lock:
                _query_cache[cache_key] = results
            
            return results
            
        except Exception as e:
            click.secho(f"[!] RAG 검색 실패: {e}", fg="red")
            return []
    
    def batch_search(self, queries, top_k=None):
        """배치 검색 - 여러 쿼리를 한번에 처리"""
        if not self.is_ready():
            return []
        
        if top_k is None:
            top_k = self.config.get("rag", {}).get("top_k", 1)
        
        # 캐시되지 않은 쿼리들만 필터링
        uncached_queries = []
        all_results = {}
        
        with _cache_lock:
            for query in queries:
                cache_key = self._get_cache_key(query, top_k)
                if cache_key in _query_cache:
                    all_results[query] = _query_cache[cache_key]
                else:
                    uncached_queries.append(query)
        
        if uncached_queries:
            try:
                # 배치 임베딩
                query_vectors = self.embedder.encode(uncached_queries)
                
                # 배치 검색
                for i, query in enumerate(uncached_queries):
                    scores, indices = self.index.search(
                        query_vectors[i:i+1].astype('float32'), top_k
                    )
                    
                    # 결과 조합
                    results = []
                    for score, idx in zip(scores[0], indices[0]):
                        if idx < len(self.chunks):
                            chunk = self.chunks[idx]
                            if isinstance(chunk, dict):
                                text = chunk.get('text', str(chunk))
                            else:
                                text = str(chunk)
                            
                            results.append({
                                "text": text,
                                "score": float(score),
                                "index": int(idx)
                            })
                    
                    all_results[query] = results
                    
                    # 캐시에 저장
                    with _cache_lock:
                        cache_key = self._get_cache_key(query, top_k)
                        _query_cache[cache_key] = results
                        
            except Exception as e:
                click.secho(f"[!] 배치 RAG 검색 실패: {e}", fg="red")
                # 실패한 쿼리들은 빈 결과로 설정
                for query in uncached_queries:
                    if query not in all_results:
                        all_results[query] = []
        
        return [all_results.get(query, []) for query in queries]
    
    def parallel_search(self, queries, top_k=None):
        """병렬 검색 - ThreadPoolExecutor 사용"""
        if not self.is_ready():
            return []
        
        max_workers = self.config.get("rag", {}).get("max_concurrent_searches", 2)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.search, query, top_k) for query in queries]
            results = [future.result() for future in futures]
        
        return results

    def get_context(self, query, max_context_length=None):
        """쿼리에 대한 컨텍스트 생성"""
        if max_context_length is None:
            max_context_length = self.config.get("rag", {}).get("max_context_length", 200)
            
        results = self.search(query)
        
        if not results:
            return ""
        
        context_parts = []
        current_length = 0
        
        for result in results:
            text = result["text"]
            if isinstance(text, str):
                if current_length + len(text) > max_context_length:
                    break
                context_parts.append(text)
                current_length += len(text)
        
        return "\n\n".join(context_parts)
    
    def get_context_with_sources(self, query, max_context_length=None):
        """쿼리에 대한 출처 정보가 포함된 컨텍스트 생성"""
        if max_context_length is None:
            max_context_length = self.config.get("rag", {}).get("max_context_length", 200)
            
        results = self.search(query)
        
        if not results:
            return "", []
        
        context_parts = []
        sources = []
        current_length = 0
        
        for i, result in enumerate(results):
            text = result["text"]
            score = result["score"]
            idx = result["index"]
            
            if isinstance(text, str):
                if current_length + len(text) > max_context_length:
                    break
                
                # 청크 ID에서 문서 타입 추출
                chunk_data = self.chunks[idx]
                chunk_id = chunk_data.get('chunk_id', f'doc_{idx}') if isinstance(chunk_data, dict) else f'doc_{idx}'
                
                # 더 읽기 쉬운 출처 정보 생성
                if 'attack-pattern' in chunk_id:
                    doc_type = "Attack Pattern"
                elif 'vulnerability' in chunk_id:
                    doc_type = "Vulnerability"
                elif 'cve' in chunk_id.lower():
                    doc_type = "CVE"
                else:
                    doc_type = "Security Doc"
                
                source_info = f"[Source {i+1}: {doc_type}] (Relevance: {score:.3f})"
                context_with_source = f"{source_info}\n{text}"
                
                context_parts.append(context_with_source)
                sources.append({
                    "source_id": i+1,
                    "doc_id": idx,
                    "doc_type": doc_type,
                    "chunk_id": chunk_id,
                    "relevance_score": score,
                    "text_preview": text[:100] + "..." if len(text) > 100 else text
                })
                current_length += len(context_with_source)
        
        full_context = "\n\n".join(context_parts)
        return full_context, sources

    @staticmethod
    def clear_cache():
        """캐시 초기화"""
        global _query_cache
        with _cache_lock:
            _query_cache.clear()
            click.secho("[+] RAG 쿼리 캐시가 초기화되었습니다.", fg="cyan")

def create_default_config():
    """기본 설정 파일 생성"""
    config = {
        "rag": {
            "index": "data/kb.index",
            "chunks": "data/kb_chunks.pkl", 
            "top_k": 3,
            "model": "all-MiniLM-L6-v2"
        },
        "model": {
            "name": "webspider-mistral"
        }
    }
    
    config_path = os.path.expanduser("~/.whspider.yaml")
    with open(config_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
    
    click.secho(f"[+] 기본 설정 파일 생성: {config_path}", fg="green")
    return config_path

# 전역 RAG 파이프라인 인스턴스
_rag_pipeline = None

def get_rag_pipeline():
    """RAG 파이프라인 싱글톤 인스턴스 반환"""
    global _rag_pipeline
    if _rag_pipeline is None:
        _rag_pipeline = RAGPipeline()
    return _rag_pipeline 