# Test specific PowerShell 5.1 compatibility issues
Write-Host "Testing PowerShell version compatibility..." -ForegroundColor Yellow
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan

# Test 1: Backtick escaping
Write-Host "`nTest 1: Backtick escaping" -ForegroundColor Green
$test1 = "Status: $(if ($true) { '`[+`] Good' } else { '`[-`] Bad' })"
Write-Host $test1

# Test 2: Nested if statements with colors
Write-Host "`nTest 2: Nested if with color arrays" -ForegroundColor Green
$Colors = @{
    'Good'    = 'Green'
    'Bad'     = 'Red'
    'Warning' = 'Yellow'
}
$hwStatus = @{ IsUEFI = $true }
Write-Host "UEFI Status: $(if ($hwStatus.IsUEFI) { '`[+`] Met' } else { '`[-`] Not Met' })" -ForegroundColor $(if ($hwStatus.IsUEFI) { $Colors['Good'] } else { $Colors['Bad'] })

# Test 3: Complex string with parameters
Write-Host "`nTest 3: Complex string parsing" -ForegroundColor Green
$testString = "Use numbers to select (e.g., 1,3,5 or 1-3 or all for all mitigations):`n"
Write-Host $testString

Write-Host "`nAll tests completed successfully!" -ForegroundColor Green