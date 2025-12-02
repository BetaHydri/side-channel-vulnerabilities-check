<#
.SYNOPSIS
    Quick diagnostic for Hyper-V host CPU mitigation requirements
    
.DESCRIPTION
    Checks if a Hyper-V host has the necessary CPU mitigations enabled
    to properly expose security features to guest VMs.
    
    Run this on the Windows 11 Hyper-V HOST machine.
    
.EXAMPLE
    .\Check-HyperVHostMitigations.ps1
    
.NOTES
    Version: 1.0
    Requires: Administrator privileges
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = 'SilentlyContinue'

Write-Host "`n=========================================================================" -ForegroundColor Cyan
Write-Host "  Hyper-V Host CPU Mitigation Diagnostic Tool" -ForegroundColor Cyan
Write-Host "=========================================================================" -ForegroundColor Cyan

# Get computer info
$computerName = $env:COMPUTERNAME
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$os = Get-CimInstance -ClassName Win32_OperatingSystem

Write-Host "`nHost Information:" -ForegroundColor Yellow
Write-Host "  Computer: $computerName"
Write-Host "  OS:       $($os.Caption) (Build $($os.BuildNumber))"
Write-Host "  Model:    $($computerSystem.Model)"

# Check if Hyper-V is installed
Write-Host "`nHyper-V Status:" -ForegroundColor Yellow
$hvService = Get-Service -Name vmms -ErrorAction SilentlyContinue
if ($hvService) {
    Write-Host "  Status:   " -NoNewline
    if ($hvService.Status -eq 'Running') {
        Write-Host "Running" -ForegroundColor Green
    } else {
        Write-Host "$($hvService.Status)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Status:   NOT INSTALLED" -ForegroundColor Red
    Write-Host "`nERROR: Hyper-V is not installed on this machine." -ForegroundColor Red
    exit 1
}

# Define required mitigations for VM CPU feature exposure
$requiredMitigations = @(
    @{
        Name = "SBDR/SBDS Mitigation"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
        ValueName = "SBDRMitigationLevel"
        ExpectedValue = 1
        Impact = "Required for VM SBDR/FBSDP support"
    },
    @{
        Name = "SRBDS Mitigation"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
        ValueName = "SRBDSMitigationLevel"
        ExpectedValue = 1
        Impact = "Required for VM SRBDS support"
    },
    @{
        Name = "DRPW Mitigation"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
        ValueName = "DRPWMitigationLevel"
        ExpectedValue = 1
        Impact = "Required for VM DRPW support"
    },
    @{
        Name = "PSDP (Predictive Store Forwarding)"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
        ValueName = "PredictiveStoreForwardingDisable"
        ExpectedValue = 1
        Impact = "Required for VM PSDP support"
    },
    @{
        Name = "Retbleed Mitigation"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
        ValueName = "RetpolineConfiguration"
        ExpectedValue = 1
        Impact = "Required for VM Retbleed support"
    },
    @{
        Name = "MMIO Stale Data Mitigation"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
        ValueName = "MmioStaleDataMitigationLevel"
        ExpectedValue = 1
        Impact = "Required for VM MMIO protection"
    }
)

Write-Host "`n=========================================================================" -ForegroundColor Cyan
Write-Host "CPU Mitigation Status (Required for VM Support)" -ForegroundColor Cyan
Write-Host "=========================================================================" -ForegroundColor Cyan

$allConfigured = $true
$missingMitigations = @()

foreach ($mitigation in $requiredMitigations) {
    Write-Host "`n$($mitigation.Name):" -ForegroundColor Yellow
    
    try {
        $regValue = Get-ItemProperty -Path $mitigation.Path -Name $mitigation.ValueName -ErrorAction Stop
        $currentValue = $regValue.($mitigation.ValueName)
        
        # Handle byte array (REG_BINARY)
        if ($currentValue -is [byte[]]) {
            if ($currentValue.Length -ge 4) {
                $currentValue = [BitConverter]::ToUInt32($currentValue, 0)
            }
        }
        
        if ($currentValue -eq $mitigation.ExpectedValue) {
            Write-Host "  Status:   " -NoNewline
            Write-Host "ENABLED" -ForegroundColor Green
            Write-Host "  Value:    $currentValue (Expected: $($mitigation.ExpectedValue))"
        } else {
            Write-Host "  Status:   " -NoNewline
            Write-Host "MISCONFIGURED" -ForegroundColor Red
            Write-Host "  Value:    $currentValue (Expected: $($mitigation.ExpectedValue))"
            Write-Host "  Impact:   $($mitigation.Impact)" -ForegroundColor Yellow
            $allConfigured = $false
            $missingMitigations += $mitigation
        }
    }
    catch {
        Write-Host "  Status:   " -NoNewline
        Write-Host "NOT CONFIGURED" -ForegroundColor Red
        Write-Host "  Impact:   $($mitigation.Impact)" -ForegroundColor Yellow
        $allConfigured = $false
        $missingMitigations += $mitigation
    }
}

Write-Host "`n=========================================================================" -ForegroundColor Cyan
Write-Host "Summary & Recommendations" -ForegroundColor Cyan
Write-Host "=========================================================================" -ForegroundColor Cyan

if ($allConfigured) {
    Write-Host "`nRESULT: " -NoNewline
    Write-Host "ALL MITIGATIONS ENABLED" -ForegroundColor Green
    Write-Host "`nYour Hyper-V host is properly configured to expose CPU security features to VMs."
    Write-Host "`nNext Steps:"
    Write-Host "  1. If you recently enabled these, " -NoNewline
    Write-Host "RESTART THIS HOST" -ForegroundColor Yellow
    Write-Host "  2. After host restart, " -NoNewline
    Write-Host "RESTART YOUR VMs" -ForegroundColor Yellow
    Write-Host "  3. VMs should then detect CPU features properly"
} else {
    Write-Host "`nRESULT: " -NoNewline
    Write-Host "MISSING $($missingMitigations.Count) MITIGATION(S)" -ForegroundColor Red
    
    Write-Host "`nRequired Actions:" -ForegroundColor Yellow
    Write-Host "`n1. Run your main mitigation tool to enable missing mitigations:"
    Write-Host "   .\SideChannel_Check_v2.ps1 -Mode ApplyInteractive" -ForegroundColor Cyan
    Write-Host "   (Choose [R]ecommended when prompted)"
    
    Write-Host "`n2. CRITICAL: Restart this Hyper-V host:" -ForegroundColor Yellow
    Write-Host "   Restart-Computer -Force" -ForegroundColor Cyan
    
    Write-Host "`n3. After host restart, restart your VMs:" -ForegroundColor Yellow
    Write-Host "   Get-VM 'ao-dc' | Stop-VM" -ForegroundColor Cyan
    Write-Host "   Get-VM 'ao-dc' | Start-VM" -ForegroundColor Cyan
    
    Write-Host "`n4. Verify in VM using Microsoft's tool:" -ForegroundColor Yellow
    Write-Host "   Get-SpeculationControlSettings" -ForegroundColor Cyan
    
    Write-Host "`nMissing Mitigations Details:" -ForegroundColor Yellow
    foreach ($missing in $missingMitigations) {
        Write-Host "`n  - $($missing.Name)"
        Write-Host "    Registry: $($missing.Path)"
        Write-Host "    Value:    $($missing.ValueName) = $($missing.ExpectedValue)"
    }
}

Write-Host "`n=========================================================================" -ForegroundColor Cyan
Write-Host ""
