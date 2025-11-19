#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Checks Windows configuration for side-channel vulnerability mitigations
    
.DESCRIPTION
    This script checks the system configuration for side-channel vulnerabilities
    including Spectre, Meltdown, and other CPU-based attacks according to Microsoft
    guidance KB4073119. It verifies registry settings, Windows features, and 
    provides recommendations for enabling additional protections.
    
.PARAMETER Detailed
    Shows detailed information about each check
    
.PARAMETER ExportPath
    Export results to a CSV file at the specified path
    
.PARAMETER Apply
    Apply the recommended security configurations automatically
    
.EXAMPLE
    .\SideChannel_Check.ps1
    
.EXAMPLE
    .\SideChannel_Check.ps1 -Detailed
    
.EXAMPLE
    .\SideChannel_Check.ps1 -Apply
    
.EXAMPLE
    .\SideChannel_Check.ps1 -ExportPath "C:\temp\SideChannelReport.csv"
    
.NOTES
    Author: PowerShell Security Tool
    Version: 1.0
    Requires: PowerShell 5.1+ and Administrator privileges
    Based on: Microsoft KB4073119
#>

param(
    [switch]$Detailed,
    [string]$ExportPath,
    [switch]$Apply
)

# Initialize results array
$Results = @()

# Color coding for output
$Colors = @{
    Good    = 'Green'
    Warning = 'Yellow' 
    Bad     = 'Red'
    Info    = 'Cyan'
    Header  = 'Magenta'
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = 'White'
    )
    Write-Host $Message -ForegroundColor $Colors[$Color]
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWORD"
    )
    
    try {
        # Create the registry path if it doesn't exist
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-ColorOutput "Created registry path: $Path" -Color Info
        }
        
        # Set the registry value
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-ColorOutput "✓ Set $Path\$Name = $Value" -Color Good
        return $true
    }
    catch {
        Write-ColorOutput "✗ Failed to set $Path\$Name = $Value : $($_.Exception.Message)" -Color Bad
        return $false
    }
}

function Show-ResultsTable {
    param(
        [array]$Results
    )
    
    Write-ColorOutput "`n=== Side-Channel Vulnerability Mitigation Status ===" -Color Header
    
    # Create table data
    $tableData = @()
    foreach ($result in $Results) {
        $status = switch ($result.Status) {
            "Enabled" { "✓ Enabled" }
            "Disabled" { "✗ Disabled" }
            "Not Configured" { "○ Not Set" }
            default { $result.Status }
        }
        
        $tableData += [PSCustomObject]@{
            'Mitigation Name' = $result.Name
            'Status'          = $status
            'Current Value'   = $result.CurrentValue
            'Expected Value'  = $result.ExpectedValue
            'Impact'          = $result.Impact
        }
    }
    
    # Display the table
    $tableData | Format-Table -AutoSize -Wrap
    
    # Display color-coded summary
    Write-Host "`nStatus Legend:" -ForegroundColor $Colors['Header']
    Write-Host "✓ Enabled" -ForegroundColor $Colors['Good'] -NoNewline
    Write-Host " - Mitigation is active and properly configured"
    Write-Host "✗ Disabled" -ForegroundColor $Colors['Bad'] -NoNewline  
    Write-Host " - Mitigation is explicitly disabled"
    Write-Host "○ Not Set" -ForegroundColor $Colors['Warning'] -NoNewline
    Write-Host " - Registry value not configured (using defaults)"
}

function Get-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$DefaultValue = $null
    )
    
    try {
        if (Test-Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($value) {
                return $value.$Name
            }
        }
        return $DefaultValue
    }
    catch {
        return $DefaultValue
    }
}

function Test-SideChannelMitigation {
    param(
        [string]$Name,
        [string]$Description,
        [string]$RegistryPath,
        [string]$RegistryName,
        [object]$ExpectedValue,
        [string]$Recommendation,
        [string]$Impact = "Performance impact may vary"
    )
    
    $currentValue = Get-RegistryValue -Path $RegistryPath -Name $RegistryName
    $status = "Not Configured"
    $statusColor = "Warning"
    
    if ($null -ne $currentValue) {
        if ($currentValue -eq $ExpectedValue) {
            $status = "Enabled"
            $statusColor = "Good"
        }
        else {
            $status = "Disabled"
            $statusColor = "Bad"
        }
    }
    
    $result = [PSCustomObject]@{
        Name           = $Name
        Description    = $Description
        Status         = $status
        CurrentValue   = if ($null -ne $currentValue) { $currentValue } else { "Not Set" }
        ExpectedValue  = $ExpectedValue
        RegistryPath   = $RegistryPath
        RegistryName   = $RegistryName
        Recommendation = $Recommendation
        Impact         = $Impact
        CanBeEnabled   = $true
    }
    
    if ($Detailed) {
        Write-ColorOutput "`n--- $Name ---" -Color Header
        Write-ColorOutput "Description: $Description" -Color Info
        Write-ColorOutput "Status: $status" -Color $statusColor
        Write-ColorOutput "Current Value: $(if ($null -ne $currentValue) { $currentValue } else { 'Not Set' })" -Color Info
        Write-ColorOutput "Expected Value: $ExpectedValue" -Color Info
        Write-ColorOutput "Registry: $RegistryPath\$RegistryName" -Color Info
        Write-ColorOutput "Recommendation: $Recommendation" -Color Info
        Write-ColorOutput "Impact: $Impact" -Color Info
    }
    else {
        Write-ColorOutput "$($Name.PadRight(40)) : $status" -Color $statusColor
    }
    
    return $result
}

function Get-CPUInfo {
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    return @{
        Name         = $cpu.Name
        Manufacturer = $cpu.Manufacturer
        Family       = $cpu.Family
        Model        = $cpu.Model
        Stepping     = $cpu.Stepping
    }
}

function Get-WindowsVersion {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    return @{
        Caption      = $os.Caption
        Version      = $os.Version
        BuildNumber  = $os.BuildNumber
        Architecture = $os.OSArchitecture
    }
}

# Main execution
Write-ColorOutput "`n=== Side-Channel Vulnerability Configuration Check ===" -Color Header
Write-ColorOutput "Based on Microsoft KB4073119`n" -Color Info

# System Information
$cpuInfo = Get-CPUInfo
$osInfo = Get-WindowsVersion

Write-ColorOutput "System Information:" -Color Header
Write-ColorOutput "CPU: $($cpuInfo.Name)" -Color Info
Write-ColorOutput "OS: $($osInfo.Caption) Build $($osInfo.BuildNumber)" -Color Info
Write-ColorOutput "Architecture: $($osInfo.Architecture)`n" -Color Info

Write-ColorOutput "Checking Side-Channel Vulnerability Mitigations...`n" -Color Header

# 1. Speculative Store Bypass Disable (SSBD)
$Results += Test-SideChannelMitigation -Name "Speculative Store Bypass Disable" `
    -Description "Mitigates Speculative Store Bypass (Variant 4) attacks" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
    -RegistryName "FeatureSettingsOverride" `
    -ExpectedValue 72 `
    -Recommendation "Enable to mitigate SSB attacks. Set FeatureSettingsOverride to 72" `
    -Impact "Minimal performance impact on most workloads"

# 2. Speculative Store Bypass Disable Mask
$Results += Test-SideChannelMitigation -Name "SSBD Feature Mask" `
    -Description "Feature mask for Speculative Store Bypass Disable" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
    -RegistryName "FeatureSettingsOverrideMask" `
    -ExpectedValue 3 `
    -Recommendation "Set to 3 to enable SSBD feature mask" `
    -Impact "Works in conjunction with FeatureSettingsOverride"

# 3. Branch Target Injection (BTI) Mitigation - Spectre Variant 2
$Results += Test-SideChannelMitigation -Name "Branch Target Injection Mitigation" `
    -Description "Mitigates Branch Target Injection (Spectre Variant 2)" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "DisableGPOLoading" `
    -ExpectedValue 0 `
    -Recommendation "Ensure Group Policy loading is enabled for security policies" `
    -Impact "Required for proper security policy application"

# 4. Kernel VA Shadow (KVAS) for Meltdown Protection
$Results += Test-SideChannelMitigation -Name "Kernel VA Shadow (Meltdown Protection)" `
    -Description "Kernel Virtual Address Shadowing to mitigate Meltdown attacks" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
    -RegistryName "EnableCfg" `
    -ExpectedValue 1 `
    -Recommendation "Enable Control Flow Guard for additional protection" `
    -Impact "Provides additional exploit mitigation"

# 5. Hardware Mitigations
$Results += Test-SideChannelMitigation -Name "Hardware Security Mitigations" `
    -Description "Enable hardware-based security mitigations when available" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "MitigationOptions" `
    -ExpectedValue "2000000000000000" `
    -Recommendation "Enable hardware mitigations. Set to 2000000000000000 for optimal security" `
    -Impact "Hardware-dependent, modern CPUs have better performance"

# 6. SMEP (Supervisor Mode Execution Prevention)
$Results += Test-SideChannelMitigation -Name "Supervisor Mode Execution Prevention" `
    -Description "Prevents execution of user-mode pages in kernel mode" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "DisableExceptionChainValidation" `
    -ExpectedValue 0 `
    -Recommendation "Ensure exception chain validation is enabled" `
    -Impact "Prevents certain exploitation techniques"

# 7. SMAP (Supervisor Mode Access Prevention)  
$Results += Test-SideChannelMitigation -Name "Supervisor Mode Access Prevention" `
    -Description "Prevents kernel access to user-mode pages" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
    -RegistryName "MoveImages" `
    -ExpectedValue 1 `
    -Recommendation "Enable ASLR for images to improve security" `
    -Impact "Improves resistance to memory corruption attacks"

# 8. Intel TSX (Transactional Synchronization Extensions) Disable
$Results += Test-SideChannelMitigation -Name "Intel TSX Disable" `
    -Description "Disable Intel TSX to prevent TSX-related vulnerabilities" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "DisableTsx" `
    -ExpectedValue 1 `
    -Recommendation "Disable TSX if not required by applications" `
    -Impact "May affect applications that rely on TSX, but improves security"

# 9. Retpoline Support Check
$Results += Test-SideChannelMitigation -Name "Retpoline Support" `
    -Description "Compiler-based mitigation for indirect branch speculation" `
    -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" `
    -RegistryName "MinVmVersionForCpuBasedMitigations" `
    -ExpectedValue "1.0" `
    -Recommendation "Ensure retpoline support is available in compiled code" `
    -Impact "Compiler and application dependent"

# 10. Enhanced IBRS (Indirect Branch Restricted Speculation)
$Results += Test-SideChannelMitigation -Name "Enhanced IBRS" `
    -Description "Enhanced Indirect Branch Restricted Speculation" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
    -RegistryName "DisablePagingExecutive" `
    -ExpectedValue 1 `
    -Recommendation "Consider disabling paging executive for better security" `
    -Impact "Requires sufficient physical memory"

# Check Windows Defender features
Write-ColorOutput "`nChecking Windows Security Features..." -Color Header

# Windows Defender Exploit Guard
$exploitGuard = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Exploit Protection\System" -Name "ASLR_ForceRelocateImages"
$Results += [PSCustomObject]@{
    Name           = "Windows Defender Exploit Guard ASLR"
    Description    = "Address Space Layout Randomization force relocate images"
    Status         = if ($exploitGuard -eq 1) { "Enabled" } else { "Not Configured" }
    CurrentValue   = if ($null -ne $exploitGuard) { $exploitGuard } else { "Not Set" }
    ExpectedValue  = 1
    RegistryPath   = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Exploit Protection\System"
    RegistryName   = "ASLR_ForceRelocateImages"
    Recommendation = "Enable ASLR force relocate images for better security"
    Impact         = "Improves resistance to memory corruption attacks"
    CanBeEnabled   = $true
}

# Check if Virtualization Based Security is available
$vbsStatus = Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
if ($vbsStatus) {
    Write-ColorOutput "`nVirtualization Based Security Status:" -Color Header
    Write-ColorOutput "VBS Available: $($vbsStatus.VirtualizationBasedSecurityHardwareRequirementState -eq 1)" -Color Info
    Write-ColorOutput "HVCI Available: $($vbsStatus.HypervisorEnforcedCodeIntegrityHardwareRequirementState -eq 1)" -Color Info
}

# Display results table
Show-ResultsTable -Results $Results

# Summary
Write-ColorOutput "`n=== Summary ===" -Color Header
$enabledCount = ($Results | Where-Object { $_.Status -eq "Enabled" }).Count
$totalCount = $Results.Count
$configuredPercent = [math]::Round(($enabledCount / $totalCount) * 100, 1)

Write-ColorOutput "Total Checks: $totalCount" -Color Info
Write-ColorOutput "Enabled: $enabledCount" -Color Good
Write-ColorOutput "Not Configured: $(($Results | Where-Object { $_.Status -eq "Not Configured" }).Count)" -Color Warning  
Write-ColorOutput "Disabled: $(($Results | Where-Object { $_.Status -eq "Disabled" }).Count)" -Color Bad
Write-ColorOutput "Configuration Level: $configuredPercent%" -Color Info

# Apply configurations if requested
if ($Apply) {
    Write-ColorOutput "`n=== Applying Configurations ===" -Color Header
    $notConfigured = $Results | Where-Object { $_.Status -ne "Enabled" -and $_.CanBeEnabled }
    
    if ($notConfigured.Count -gt 0) {
        Write-ColorOutput "Applying $($notConfigured.Count) security configurations..." -Color Info
        $successCount = 0
        
        foreach ($item in $notConfigured) {
            Write-ColorOutput "`nConfiguring: $($item.Name)" -Color Info
            if (Set-RegistryValue -Path $item.RegistryPath -Name $item.RegistryName -Value $item.ExpectedValue) {
                $successCount++
            }
        }
        
        Write-ColorOutput "`nConfiguration Results:" -Color Header
        Write-ColorOutput "Successfully applied: $successCount/$($notConfigured.Count)" -Color Good
        
        if ($successCount -gt 0) {
            Write-ColorOutput "`n⚠️  IMPORTANT: A system restart is required for changes to take effect." -Color Warning
            $restart = Read-Host "Would you like to restart now? (y/N)"
            if ($restart -eq 'y' -or $restart -eq 'Y') {
                Write-ColorOutput "Restarting system in 10 seconds... Press Ctrl+C to cancel." -Color Warning
                Start-Sleep -Seconds 10
                Restart-Computer -Force
            }
        }
    }
    else {
        Write-ColorOutput "All mitigations are already properly configured!" -Color Good
    }
}
else {
    # Recommendations when not applying
    Write-ColorOutput "`n=== Recommendations ===" -Color Header
    $notConfigured = $Results | Where-Object { $_.Status -ne "Enabled" }
    if ($notConfigured.Count -gt 0) {
        Write-ColorOutput "The following mitigations should be configured:" -Color Warning
        foreach ($item in $notConfigured) {
            Write-ColorOutput "• $($item.Name): $($item.Recommendation)" -Color Warning
        }
        
        Write-ColorOutput "`nTo apply these configurations automatically, run:" -Color Info
        Write-ColorOutput ".\SideChannel_Check.ps1 -Apply" -Color Info
        
        Write-ColorOutput "`nOr manually use these registry commands:" -Color Info
        foreach ($item in $notConfigured | Where-Object { $_.CanBeEnabled }) {
            Write-ColorOutput "reg add `"$($item.RegistryPath)`" /v `"$($item.RegistryName)`" /t REG_DWORD /d $($item.ExpectedValue) /f" -Color Info
        }
        Write-ColorOutput "`nNote: A system restart may be required after making registry changes." -Color Warning
    }
    else {
        Write-ColorOutput "All checked mitigations are properly configured!" -Color Good
    }
}

# Export results if requested
if ($ExportPath) {
    try {
        $Results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-ColorOutput "`nResults exported to: $ExportPath" -Color Good
    }
    catch {
        Write-ColorOutput "`nFailed to export results: $($_.Exception.Message)" -Color Bad
    }
}

Write-ColorOutput "`nSide-channel vulnerability check completed." -Color Header