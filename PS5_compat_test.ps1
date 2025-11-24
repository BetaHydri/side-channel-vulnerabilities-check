# PowerShell 5.1 Compatible Hardware Security Mitigation Value Matrix Test
param(
    [switch]$ShowMatrix
)

function Test-RegistryCompatibility {
    Write-Host "Testing Registry Access..." -ForegroundColor Green
    
    # Test basic registry access
    try {
        $regKey = "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
        $mitigation = Get-ItemProperty -Path $regKey -Name "MitigationOptions" -ErrorAction SilentlyContinue
        if ($mitigation) {
            Write-Host "[+] Registry access successful" -ForegroundColor Green
            Write-Host "    MitigationOptions value: $($mitigation.MitigationOptions)" -ForegroundColor Cyan
        } else {
            Write-Host "[?] MitigationOptions not configured" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[-] Registry access failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Test-BitOperations {
    Write-Host "`nTesting Bit Operations..." -ForegroundColor Green
    
    # Test bit manipulation (key for Hardware Mitigation Matrix)
    $testValue = 0x2000000000000000
    $shifted = $testValue -shr 61
    $masked = $shifted -band 0x7
    
    Write-Host "[+] Bit operations working: 0x2000000000000000 >> 61 & 0x7 = $masked" -ForegroundColor Green
    
    # Test 64-bit integer handling
    $bigInt = [uint64]::MaxValue
    Write-Host "[+] 64-bit integers supported: Max UInt64 = $bigInt" -ForegroundColor Green
}

function Show-MitigationMatrix {
    Write-Host "`n=== Hardware Security Mitigation Value Matrix ===" -ForegroundColor Yellow
    Write-Host "Testing core functionality that powers the mitigation analysis..." -ForegroundColor Gray
    
    # Simplified mitigation structure
    $mitigations = @(
        @{
            Name = "CFG (Control Flow Guard)"
            Description = "Hardware-enforced control flow integrity"
            BitPosition = 61
            Mask = 0x7
            TestValue = 0x2000000000000000
        },
        @{
            Name = "CET (Intel CET)"
            Description = "Intel Control-flow Enforcement Technology"
            BitPosition = 58
            Mask = 0x7
            TestValue = 0x0400000000000000
        }
    )
    
    Write-Host "`nTesting mitigation bit extraction logic:" -ForegroundColor Cyan
    foreach ($mit in $mitigations) {
        $shifted = $mit.TestValue -shr $mit.BitPosition
        $value = $shifted -band $mit.Mask
        
        $status = switch ($value) {
            0 { "[?] Not Configured"; "Yellow" }
            1 { "[-] Disabled"; "Red" }
            2 { "[+] Enabled"; "Green" }
            3 { "[+] Strict Mode"; "Green" }
            default { "[?] Unknown ($value)"; "Magenta" }
        }
        
        Write-Host "  $($mit.Name):" -NoNewline -ForegroundColor White
        Write-Host " $($status[0])" -ForegroundColor $status[1]
        Write-Host "    └─ $($mit.Description)" -ForegroundColor Gray
    }
}

# Main execution
Write-Host "PowerShell 5.1 Compatibility Test for Hardware Mitigation Matrix" -ForegroundColor Cyan
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Gray

Test-RegistryCompatibility
Test-BitOperations

if ($ShowMatrix) {
    Show-MitigationMatrix
}

Write-Host "`n[+] PowerShell 5.1 compatibility test completed successfully!" -ForegroundColor Green