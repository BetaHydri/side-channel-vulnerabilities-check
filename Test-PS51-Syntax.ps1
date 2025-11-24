# PowerShell 5.1 Syntax Test Script
Write-Host "Testing PowerShell 5.1 Compatibility..." -ForegroundColor Cyan

# Parse the main script file
$errors = @()
[void] [System.Management.Automation.Language.Parser]::ParseFile('.\SideChannel_Check.ps1', [ref]$null, [ref]$errors)

if ($errors.Count -eq 0) {
    Write-Host "[+] Syntax Check: PASSED" -ForegroundColor Green
    
    # Try to load the script without executing
    try {
        $scriptContent = Get-Content '.\SideChannel_Check.ps1' -Raw
        $scriptBlock = [ScriptBlock]::Create($scriptContent)
        Write-Host "[+] Script Block Creation: PASSED" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Script Block Creation: FAILED" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
}
else {
    Write-Host "[-] Syntax Check: FAILED ($($errors.Count) errors)" -ForegroundColor Red
    Write-Host "`nFirst 5 errors:" -ForegroundColor Yellow
    $errors | Select-Object -First 5 | ForEach-Object {
        Write-Host "Line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red
    }
}

Write-Host "`nPowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan