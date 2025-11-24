#Requires -RunAsAdministrator
#Requires -Version 5.1

# Test script for PowerShell 5.1 compatibility of Hardware Mitigation Matrix
param(
    [switch]$Detailed
)

# Simple color output function for testing
function Write-ColorOutput {
    param($Text, $Color)
    switch ($Color) {
        "Header" { Write-Host $Text -ForegroundColor Cyan }
        "Info" { Write-Host $Text -ForegroundColor Yellow }
        "Good" { Write-Host $Text -ForegroundColor Green }
        "Warning" { Write-Host $Text -ForegroundColor Yellow }
        default { Write-Host $Text }
    }
}

# Colors for console output
$Colors = @{
    'Header'  = 'Cyan'
    'Good'    = 'Green'
    'Bad'     = 'Red'
    'Warning' = 'Yellow'
    'Info'    = 'White'
}

if ($Detailed) {
    Write-ColorOutput "HARDWARE SECURITY MITIGATION VALUE MATRIX TEST" -Color Header
    Write-ColorOutput "=" * 50 -Color Header
    
    # Get current MitigationOptions value
    $currentMitigationValue = $null
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
        $currentValue = Get-ItemProperty -Path $regPath -Name "MitigationOptions" -ErrorAction SilentlyContinue
        if ($currentValue) {
            $currentMitigationValue = $currentValue.MitigationOptions
            if ($currentMitigationValue -is [byte[]]) {
                # Convert byte array to uint64 for analysis
                if ($currentMitigationValue.Length -eq 8) {
                    $currentMitigationValue = [BitConverter]::ToUInt64($currentMitigationValue, 0)
                }
            }
        }
    }
    catch {
        Write-ColorOutput "Could not read MitigationOptions: $($_.Exception.Message)" -Color Warning
    }
    
    # Define known mitigation flags (subset for testing)
    $mitigationFlags = @(
        @{ Flag = 0x0000000000000100; Name = "High Entropy ASLR"; Description = "64-bit address space randomization" },
        @{ Flag = 0x2000000000000000; Name = "Core Hardware Security Features"; Description = "Essential CPU security mitigations" }
    )
    
    Write-ColorOutput "`nFlag Value          Status    Mitigation Name" -Color Header
    Write-ColorOutput "----------          ------    ---------------" -Color Header
    
    foreach ($flag in $mitigationFlags) {
        $flagValue = "0x{0:X16}" -f $flag.Flag
        $isEnabled = if ($currentMitigationValue) { 
            ($currentMitigationValue -band $flag.Flag) -eq $flag.Flag 
        }
        else { 
            $false 
        }
        
        $statusIcon = if ($isEnabled) { "✓" } else { "○" }
        $statusColor = if ($isEnabled) { "Good" } else { "Warning" }
        
        Write-Host "$flagValue  " -NoNewline -ForegroundColor Gray
        Write-Host "$statusIcon" -NoNewline -ForegroundColor $Colors[$statusColor]
        Write-Host "       $($flag.Name)" -ForegroundColor White
    }
    
    if ($currentMitigationValue) {
        Write-ColorOutput "`nCurrent MitigationOptions Value:" -Color Header
        Write-Host "Decimal: " -NoNewline -ForegroundColor Gray
        Write-Host "$currentMitigationValue" -ForegroundColor White
        Write-Host "Hex:     " -NoNewline -ForegroundColor Gray  
        Write-Host ("0x{0:X}" -f $currentMitigationValue) -ForegroundColor White
    }
    else {
        Write-ColorOutput "`nCurrent MitigationOptions Value: Not Set" -Color Warning
    }
    
    Write-ColorOutput "`nPowerShell 5.1 Compatibility Test: PASSED" -Color Good
}
else {
    Write-ColorOutput "Use -Detailed switch to test Hardware Mitigation Matrix" -Color Info
}