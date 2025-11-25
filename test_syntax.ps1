# Test basic PowerShell syntax validation
Write-Host "Testing basic syntax..."

# Test bracket escaping
$testStatus = "Test"
$statusIcon = if ($testStatus -eq "Test") { "`[+`]" } else { "`[-`]" }
Write-Host "Status: $statusIcon $testStatus"

Write-Host "Basic syntax test completed successfully!"