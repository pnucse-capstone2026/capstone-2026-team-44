$StartTime = Get-Date

$env:PYTHONPATH = "src"
cls

python -m vulnspider analyze --url http://127.0.0.1:8899 --top-k 20 --access-control `
    --verify --verify-proposer llm --llm-model models\vulnspider-3b_v3.gguf `
    --output analysis.json --html-output dashboard.html --verify-output verify.json --open

$EndTime = Get-Date
$ElapsedTime = $EndTime - $StartTime

Write-Host "total elapsed time: $($ElapsedTime.Hours)h $($ElapsedTime.Minutes)m $($ElapsedTime.Seconds)s" -ForegroundColor Yellow
