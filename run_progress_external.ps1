param (
    [Parameter(Mandatory=$true)]
    [string]$TargetUrl
)

$StartTime = Get-Date

$env:PYTHONPATH = "src"
cls

python -m vulnspider analyze --url $TargetUrl `
    --dynamic `
    --max-pages 60 `
    --max-requests 250 `
    --dynamic-max-pages 20 `
    --dynamic-max-depth 3 `
    --dynamic-max-navigation-attempts 15 `
    --dynamic-max-route-actions 3 `
    --dynamic-max-elapsed-seconds 30 `
    --dynamic-navigation-timeout-seconds 5 `
    --dynamic-max-redirects 5 `
    --dynamic-request-decision-budget 300 `
    --top-k 20 `
    --access-control `
    --verify `
    --verify-proposer llm `
    --llm-model models\vulnspider-3b_v3.gguf `
    --output analysis.json `
    --html-output dashboard.html `
    --verify-output verify.json `
    --open

$EndTime = Get-Date
$ElapsedTime = $EndTime - $StartTime

Write-Host "total elapsed time: $($ElapsedTime.Hours)h $($ElapsedTime.Minutes)m $($ElapsedTime.Seconds)s" -ForegroundColor Yellow