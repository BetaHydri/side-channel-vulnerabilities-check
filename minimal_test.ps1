# Minimal test of the exact problematic line
Write-Host "Testing exact problematic line from script..." -ForegroundColor Yellow

# This is the exact line that's causing issues:
function Write-ColorOutput {
    param($Message, $Color)
    Write-Host $Message -ForegroundColor $Color
}

Write-ColorOutput "Use numbers to select (e.g., 1,3,5 or 1-3 or all for all mitigations):`n" -Color 'Info'

Write-Host "Test completed successfully!" -ForegroundColor Green