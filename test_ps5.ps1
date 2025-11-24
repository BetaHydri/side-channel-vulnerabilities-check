param(
    [switch]$ShowMatrix
)

# Simple test for PowerShell 5.1
Write-Host "Testing PowerShell 5.1 compatibility..." -ForegroundColor Green

if ($ShowMatrix) {
    Write-Host "ShowMatrix parameter is working!" -ForegroundColor Cyan
}

Write-Host "PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
Write-Host "Test completed successfully!" -ForegroundColor Green