try {
    $scriptContent = Get-Content 'SideChannel_Check.ps1' -Raw
    $scriptBlock = [ScriptBlock]::Create($scriptContent)
    Write-Host "PowerShell syntax check: PASSED" -ForegroundColor Green
}
catch {
    Write-Host "PowerShell syntax check: FAILED" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    
    # Try to find specific line issues
    if ($_.Exception.Message -match "line:(\d+)") {
        $lineNumber = $Matches[1]
        Write-Host "Problem appears to be around line $lineNumber" -ForegroundColor Yellow
    }
}