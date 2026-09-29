$ErrorActionPreference = "Stop"
$env:PYTHONPATH = "$PWD\src"

$outputDir = "output"

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

Write-Host "[1/3] Running payload mutation..."

python -m payload_verifier.cli `
    examples\vulnspider-analysis.json `
    --context examples\vulnspider-crawl.json `
    --out output\mutation_result.json `
    --top-k 4 `
    --model ".\vulnspider-3b_v3.gguf"

if ($LASTEXITCODE -ne 0) {
    throw "Payload mutation failed. Exit code: $LASTEXITCODE"
}

Write-Host "[2/3] Running payload validation..."

python -m payload_verifier.validation_cli `
    output\mutation_result.json `
    --context examples\vulnspider-crawl.json `
    --out output\validation_result.json

if ($LASTEXITCODE -ne 0) {
    throw "Payload validation failed. Exit code: $LASTEXITCODE"
}

Write-Host "[3/3] Running focused verification..."

python -m payload_verifier.run_focused_verification `
    output\validation_result.json `
    --out output\focused_verification_result.json

if ($LASTEXITCODE -ne 0) {
    throw "Focused verification failed. Exit code: $LASTEXITCODE"
}

Write-Host ""
Write-Host "Pipeline completed successfully."
Write-Host "Mutation result    : output\mutation_result.json"
Write-Host "Validation result  : output\validation_result.json"
Write-Host "Verification result: output\focused_verification_result.json"