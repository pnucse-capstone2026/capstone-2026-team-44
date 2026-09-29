import click
from urllib.parse import urlparse
from modules.db import create_table, get_db_path, cleanup_by_age

@click.command()
@click.option('-u', '--url', required=True, help='타겟 URL')
@click.option('--depth', default=1, type=int, help='크롤링 깊이 (기본: 1)')
@click.option('--static', is_flag=True, help='정적 크롤링')
@click.option('--dynamic', is_flag=True, help='동적 크롤링 (Playwright)')
@click.option('--json', is_flag=True, help='JSON 결과 추출')
@click.option('--csv', is_flag=True, help='CSV 파일 추출')
@click.option("--graph", is_flag=True, help="크롤링된 링크 구조를 인터랙티브 그래프로 시각화")
@click.option('--llm', is_flag=True, help='LLM 보안 분석 실행 (RAG 미포함)')
@click.option('--deep', is_flag=True, help='LLM + RAG 심화 보안 분석 실행')
@click.option('--include', default="", help='포함할 키워드 (쉼표로 구분)')
@click.option('--exclude', default="", help='제외할 키워드 (쉼표로 구분)')
@click.option('--mode', default='dfs', type=click.Choice(['dfs', 'bfs']), help='탐색 방식 (dfs 또는 bfs)')
@click.option('--cookie', default="", help='요청에 사용할 쿠키들 "name1 = value1; name2=value2.."')
@click.option('--ignore-robots', is_flag=True, help='robots.txt 규칙 무시')

def webspider(url, depth, static, dynamic, json, csv, graph, llm, deep, include, exclude, mode, cookie, ignore_robots):
    logo = r'''
     _       ____  _______ ____  ________  __________ 
    | |     / / / / / ___// __ \/  _/ __ \/ ____/ __ \
    | | /| / / /_/ /\__ \/ /_/ // // / / / __/ / /_/ /
    | |/ |/ / __  /___/ / ____// // /_/ / /___/ _, _/ 
    |__/|__/_/ /_//____/_/   /___/_____/_____/_/ |_|  
    '''
    click.secho(logo, fg='cyan')
    
    # URL 유효성 검사
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        click.secho("URL 형식이 잘못되었습니다. “http://” 또는 “https://” 로 시작해야 합니다.", fg="red")
        return

    # DB 초기화
    db_path = get_db_path(url)
    create_table(db_path)

    deleted = cleanup_by_age(db_path, days=14)
    if deleted:
        click.secho(f"[!] 오래된 레코드(14일 이전) 중 URL별 최신만 남기고 {deleted}건 삭제 완료", fg="yellow")

    click.secho(f"\n [URL] {url}", fg="cyan")
    click.secho(f" [Depth] {depth}", fg="cyan")

    # 크롤링 전 시작 ID 확보
    from modules.local_llm import get_last_id
    start_id = get_last_id(db_path) or 0

    # 크롤링 방식 기본값 처리
    if not static and not dynamic:
        static = True
        click.secho(" 크롤링 방식이 지정되지 않아 정적 크롤링(--static)을 기본으로 수행합니다.", fg="yellow")

    # 정적 크롤링
    if static:
        from modules.static_crawler import run_static_crawl_entry
        click.secho("[+] 정적 크롤링 시작", fg="green")
        run_static_crawl_entry(url, depth, include, exclude, mode, cookie, db_path, ignore_robots)

    # 동적 크롤링
    if dynamic:
        from modules.dynamic_crawler import run_dynamic_crawl_entry
        click.secho("[+] 동적 크롤링 시작", fg="green")
        run_dynamic_crawl_entry(url, depth, include, exclude, mode, cookie, db_path, ignore_robots)

    # 결과 내보내기
    if json:
        from modules.export import export_json
        click.secho("[+] JSON 파일 추출", fg="green")
        export_json(db_path, url)

    if csv:
        from modules.export import export_csv
        click.secho("[+] CSV 파일 추출", fg="green")
        export_csv(db_path, url)

    if graph:
        from modules.visualize import generate_interactive_graph
        click.secho("[+] 인터랙티브 그래프 생성", fg="green")
        generate_interactive_graph(db_path, url)

    # LLM 분석
    if llm or deep:
        from modules.local_llm import run_llm_analysis

        end_id = get_last_id(db_path) or 0
        use_rag = deep
        analysis_type = "LLM + RAG 심화 보안 분석" if use_rag else "LLM 연계 취약점 분석"

        click.secho(f"[+] {analysis_type} 실행", fg="green")

        if end_id > start_id:
            run_llm_analysis(db_path, start_id, end_id, use_rag=use_rag)
        else:
            click.secho("[!] 새로운 크롤링 데이터가 없어 LLM 분석을 건너뜁니다.", fg="yellow")

if __name__ == '__main__':
    webspider()