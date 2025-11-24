param([switch]$ShowMatrix)

# Test backtick characters
Write-Host "`nTesting backticks" -ForegroundColor Green
Write-Host "Normal newline`nworking" -ForegroundColor Cyan

# Test quotes
Write-Host "Testing quotes: 'single' and `"double`"" -ForegroundColor Yellow

if ($ShowMatrix) {
    Write-Host "Matrix parameter works" -ForegroundColor Magenta
}

Write-Host "Test complete" -ForegroundColor Green