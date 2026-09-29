import sqlite3
import csv
import json
import os
from urllib.parse import urlparse

EXPORT_DIR = "data"

def get_export_paths(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.replace(":", "_").replace(".", "_") # 콜론과 점을 언더스코어로 대체
    os.makedirs(EXPORT_DIR, exist_ok=True)
    return {
        "json": os.path.join(EXPORT_DIR, f"{domain}.json"),
        "csv": os.path.join(EXPORT_DIR, f"{domain}.csv")
    }

def export_json(db_path, url):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM crawl_links")
    rows = cursor.fetchall()
    columns = [description[0] for description in cursor.description]

    results = [dict(zip(columns, row)) for row in rows]
    
    export_paths = get_export_paths(url)
    json_path = export_paths["json"]

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"[+] JSON 저장 완료: {json_path}")
    conn.close()

def export_csv(db_path, url):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM crawl_links")
    rows = cursor.fetchall()
    columns = [description[0] for description in cursor.description]

    export_paths = get_export_paths(url)
    csv_path = export_paths["csv"]

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        writer.writerows(rows)

    print(f"[+] CSV 저장 완료: {csv_path}")
    conn.close()
