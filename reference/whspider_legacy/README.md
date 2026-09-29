# 🕷️ WHSPIDER

(English Guide)

This project is a command-line based web crawling and automated analysis tool designed for web security diagnostics. Developed as part of the WHS3 project, it integrates static/dynamic crawling, input field extraction, site structure visualization, and local LLM-based security vulnerability analysis.

---

### Installation and Environment Setup

## 1. Install Python and Ollama

- Python 3.8 or higher required
- Install Ollama (local LLM engine)

### macOS
`brew install ollama`

### Ubuntu
`curl -fsSL https://ollama.com/install.sh | sh`

### Windows
Refer to `https://ollama.com/download`

## 2. Install whspider

```bash
git clone https://github.com/JKprokan/WebSpider-for-WebHacking.git

cd WebSpider-for-WebHacking

pip install .
```
## 3. Download AI Model (gguf) and Modelfile

`ollama pull hf.co/Jin312/WebSpider_Mistral:Q4_K_M`

## Usage Example

`whspider -u "http://localhost/index.php" --static --depth 5 --cookie "PHPSESSID=your cookie"--graph --ignore-robots `

<img width="796" height="565" alt="스크린샷 2025-07-18 오후 3 14 30" src="https://github.com/user-attachments/assets/4c1e1877-642f-4a0e-89f5-e77dd86f6da5" />

### Graph
<img width="1223" height="734" alt="스크린샷 2025-07-18 오후 3 16 51" src="https://github.com/user-attachments/assets/ab252071-635e-44f6-94da-5a0a01066ddc" />

### LLM
<img width="799" height="433" alt="스크린샷 2025-07-18 오후 3 23 12" src="https://github.com/user-attachments/assets/0c81a5d5-ee88-4c35-a98f-0366326c6874" />
<img width="789" height="433" alt="스크린샷 2025-07-18 오후 3 23 20" src="https://github.com/user-attachments/assets/d05aa6bc-ef52-42d7-b5f6-baa17f604ab5" />

### Key Options


| Option        | Description                               | Default |
|----------------|----------------------------------|--------|
| -u, --url      | Specify target URL (required)            |        |
| --depth     integer   | Crawling depth               | 1      |
| --mode    dfs or bfs     | Select DFS/BFS traversal method        | dfs    |
| --static       | Static crawling (default)         | True   |
| --dynamic      | Dynamic crawling (Playwright)         | False  |
| --include   "word1, word2"   | 	Keywords to include (comma-separated)      |        |
| --exclude    "word1, word2"  | Keywords to exclude (comma-separated)      |        |
| --json         | 	Save results as JSON file            | False  |
| --csv          | Save results as CSV file             | False  |
| --graph        | Visualize crawled link structure as an interactive graph        | False  |
| --cookie   "name1=value1; name2=value2"   | Specify cookies to use for requests         |        |
| --llm          | LLM-based input field vulnerability analysis    | False  |
| --ignore-robots| 	Ignore robots.txt rules             | False  |

### Result Save Path:
- All result files (DB, JSON, CSV, graph) are saved in the `data/` directory based on the target URL's domain name. (e.g., `suninatas.com` -> `data/suninatas_com.db`, `data/suninatas_com.json`)

### Notes:
If neither `--static` nor `--dynamic` options are specified, `--static` will be applied by default.

If `--mode`is not specified, DFS traversal will be applied by default. If you prefer BFS traversal, please set `--mode bfs`.

You can check all options with `whspider --help`.

Contact & Bug Reports: `whs3.spider@gmail.com`

License: MIT License

---

# 🕷️ WHSPIDER

(Korean Guide)

본 프로젝트는 웹 보안 진단을 위한 커맨드라인 기반 웹 크롤링 및 자동 분석 도구입니다.  
WHS3 프로젝트의 일환으로 개발되었으며, 정적/동적 크롤링, 입력 필드 추출, 사이트 구조 시각화,  
로컬 LLM 기반 보안 취약점 분석까지 통합 지원합니다.

---

### 설치 및 환경 준비

## 1. Python 및 Ollama 설치

- Python 3.8 이상 필요
- Ollama (로컬 LLM 엔진) 설치

### macOS
`brew install ollama`

### Ubuntu
`curl -fsSL https://ollama.com/install.sh | sh`

### Windows
`https://ollama.com/download 참고`

## 2. whspider 설치

```bash
git clone https://github.com/JKprokan/WebSpider-for-WebHacking.git

cd WebSpider-for-WebHacking

pip install .
```

## AI 모델(gguf) 및 Modelfile 다운로드
  `ollama pull hf.co/Jin312/WebSpider_Mistral:Q4_K_M`

## 사용 예시

`whspider -u "http://localhost/index.php" --static --depth 5 --cookie "PHPSESSID=your cookie"--graph --ignore-robots `

<img width="796" height="565" alt="스크린샷 2025-07-18 오후 3 14 30" src="https://github.com/user-attachments/assets/4c1e1877-642f-4a0e-89f5-e77dd86f6da5" />

### 그래프
<img width="1223" height="734" alt="스크린샷 2025-07-18 오후 3 16 51" src="https://github.com/user-attachments/assets/ab252071-635e-44f6-94da-5a0a01066ddc" />

### LLM
<img width="799" height="433" alt="스크린샷 2025-07-18 오후 3 23 12" src="https://github.com/user-attachments/assets/0c81a5d5-ee88-4c35-a98f-0366326c6874" />
<img width="789" height="433" alt="스크린샷 2025-07-18 오후 3 23 20" src="https://github.com/user-attachments/assets/d05aa6bc-ef52-42d7-b5f6-baa17f604ab5" />



### 주요 옵션 안내

| 옵션           | 설명                             | 기본값 |
|----------------|----------------------------------|--------|
| -u, --url      | 타겟 URL 지정 (필수)             |        |
| --depth     integer   | 크롤링 깊이                      | 1      |
| --mode    dfs or bfs     | dfs/bfs 탐색 방식 선택           | dfs    |
| --static       | 정적 크롤링 (기본값)             | True   |
| --dynamic      | 동적 크롤링 (Playwright)         | False  |
| --include   "word1, word2"   | 포함할 키워드 (쉼표로 구분)      |        |
| --exclude    "word1, word2"  | 제외할 키워드 (쉼표로 구분)      |        |
| --json         | JSON 파일로 결과 저장            | False  |
| --csv          | CSV 파일로 결과 저장             | False  |
| --graph        | 크롤링된 링크 구조를 인터랙티브 그래프로 시각화        | False  |
| --cookie   "name1=value1; name2=value2"   | 요청 시 사용할 쿠키 지정         |        |
| --llm          | LLM 기반 입력필드 취약점 분석    | False  |
| --ignore-robots| robots.txt 규칙 무시             | False  |

### 결과 저장 경로:
- 모든 결과 파일(DB, JSON, CSV, 그래프)은 타겟 URL의 도메인 이름을 기반으로 `data/` 디렉토리에 저장됩니다. (예: `suninatas.com` -> `data/suninatas_com.db`, `data/suninatas_com.json`)

### 참고사항:
- `--static` 또는 `--dynamic` 옵션이 지정되지 않으면 `--static`이 기본으로 적용됩니다.
- `--mode`를 지정하지 않는 경우에는 dfs 탐색이 기본으로 적용됩니다. bfs 탐색방법을 원하시는 경우 `--mode bfs`를 설정해주세요.

전체 옵션은 `whspider --help`로 확인할 수 있습니다.

문의 및 버그 리포트: `whs3.spider@gmail.com`

License : MIT License
