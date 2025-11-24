param([switch]$ShowMatrix)
Write-Host "Simple test" -ForegroundColor Green
if ($ShowMatrix) {
    Write-Host "Matrix test" -ForegroundColor Cyan
}
Write-Host "Done" -ForegroundColor Yellow