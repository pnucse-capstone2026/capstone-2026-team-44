import sqlite3
import os
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

# db_path는 이제 함수 인자로 전달됩니다.

def get_db_path(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.replace(":", "_").replace(".", "_") # 콜론과 점을 언더스코어로 대체
    os.makedirs("data", exist_ok=True)
    return os.path.join("data", f"{domain}.db")

def create_table(db_path):
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS crawl_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link TEXT,
            parent TEXT,
            depth INTEGER,
            host TEXT,
            query_params TEXT,
            input_fields TEXT,
            collected_time TEXT
        );
        """)
        conn.commit()


def insert_link(db_path, link, parent, depth, host, query_params, input_fields_json):
    kst_now = datetime.now(timezone(timedelta(hours=9))).strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO crawl_links
            (link, parent, depth, host, query_params, input_fields, collected_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (link, parent, depth, host, query_params, input_fields_json, kst_now))
        conn.commit()

def cleanup_by_age(db_path, days=14):
    """
    collected_time이 days 일 이전인 레코드 중에서,
    URL(link)별로 가장 최신(id가 최대)인 한 건만 남기고 나머지를 삭제합니다.
    기본값 days=14 (14일 보관).
    """
    cutoff = datetime.now(timezone(timedelta(hours=9))) - timedelta(days=days)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM crawl_links
            WHERE collected_time < ?
              AND id NOT IN (
                  SELECT MAX(id)
                  FROM crawl_links
                  WHERE collected_time < ?
                  GROUP BY link
              )
        """, (cutoff_str, cutoff_str))
        deleted = cursor.rowcount
        conn.commit()
    return deleted