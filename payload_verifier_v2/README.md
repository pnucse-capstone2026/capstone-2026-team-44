# Payload Verifier

파인튜닝 모델을 이용해 상위 취약점 후보에 맞는
심층 검증용 페이로드 후보를 생성, 검증, 결과를 수집하는 모듈입니다.
한 번 실행하면 2~3분 정도 소요됩니다.

수행 범위:

1. vulnspider-crawl.json 읽기
2. 상위 후보 선택
3. vulnspider-analysis.json과 요청 문맥 결합
4. 파인튜닝 모델로 안전한 검증값 생성
5. 실제 파라미터 위치에 값 삽입
6. baseline_request 생성
7. mutated_request 생성
8. mutation_result.json 저장

실제 HTTP 요청은 전송하지 않습니다.

- Payload Mutation
- Payload Validator
- Focused Verification

## finetuned model, llama_cpp_python download link
https://huggingface.co/lsk0228/vulnspider-3b_v3/resolve/main/vulnspider-3b_v3.gguf
https://huggingface.co/lsk0228/vulnspider-3b_v3/resolve/main/llama_cpp_python-0.3.34-py3-none-win_amd64.whl

## 설치

가상환경 없이 실행하려면:

```powershell
pip instal -e .
pip install -r requirements.txt
pip install .\llama_cpp_python-0.3.34-py3-none-win_amd64.whl
```

## 실행

방법:

```powershell
.\run_pipeline.ps1
```

## 출력

```text
output/mutation_result.json
output/validation_result.json
output/focused_verification_result.json
```

## 주의

승인된 테스트 대상에 대해서만 사용하세요.

실제 Cookie, JWT, Authorization 값을 전달하지 않습니다.
인증정보 대신 auth_context_id만 사용합니다.
