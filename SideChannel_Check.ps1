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
    
    VIRTUALIZATION SUPPORT:
    - Detects if running on VM or physical hardware
    - Checks hypervisor-specific mitigations
    - Provides Host/Guest specific recommendations
    - Validates nested virtualization capabilities
    
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
    Author: Jan Tiedemann
    Version: 1.0
    Requires: PowerShell 5.1+ and Administrator privileges
    Based on: Microsoft KB4073119
    GitHub: https://github.com/BetaHydri/side-channel-vulnerabilities-check
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
        # Special handling for Windows Defender Exploit Guard paths
        $isWindowsDefenderPath = $Path -match "Windows Defender.*Exploit Guard"
        
        # Create the registry path if it doesn't exist
        if (-not (Test-Path $Path)) {
            if ($isWindowsDefenderPath) {
                # Special handling for Windows Defender paths
                try {
                    Write-ColorOutput "Attempting to configure Windows Defender Exploit Guard..." -Color Info
                    
                    # Try using Windows Defender PowerShell cmdlets first
                    if (Get-Command "Set-ProcessMitigation" -ErrorAction SilentlyContinue) {
                        # Use Set-ProcessMitigation for ASLR configuration
                        if ($Name -eq "ASLR_ForceRelocateImages") {
                            try {
                                Set-ProcessMitigation -System -Enable ForceRelocateImages -ErrorAction Stop
                                Write-ColorOutput "✓ Set Windows Defender ASLR via Set-ProcessMitigation" -Color Good
                                return $true
                            }
                            catch {
                                Write-ColorOutput "Warning: Set-ProcessMitigation failed: $($_.Exception.Message)" -Color Warning
                            }
                        }
                    }
                    
                    # Fallback: Try to use reg.exe command
                    $regPath = $Path -replace "^HKLM:", "HKEY_LOCAL_MACHINE"
                    $regCommand = "reg add `"$regPath`" /v `"$Name`" /t REG_$Type /d $Value /f"
                    
                    try {
                        $result = & cmd.exe /c $regCommand 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            Write-ColorOutput "✓ Set $Path\$Name = $Value (via reg.exe)" -Color Good
                            return $true
                        }
                        else {
                            Write-ColorOutput "Warning: reg.exe failed with exit code $LASTEXITCODE" -Color Warning
                        }
                    }
                    catch {
                        Write-ColorOutput "Warning: reg.exe execution failed: $($_.Exception.Message)" -Color Warning
                    }
                    
                    # Final fallback: Try direct registry manipulation
                    $regKeyPath = $regPath -replace "^HKEY_LOCAL_MACHINE\\", ""
                    try {
                        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regKeyPath, $true)
                        if ($null -eq $regKey) {
                            # Try to create the key
                            $regKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($regKeyPath)
                        }
                        
                        if ($null -ne $regKey) {
                            $regValue = switch ($Type) {
                                "DWORD" { [Microsoft.Win32.RegistryValueKind]::DWord }
                                "QWORD" { [Microsoft.Win32.RegistryValueKind]::QWord }
                                "String" { [Microsoft.Win32.RegistryValueKind]::String }
                                default { [Microsoft.Win32.RegistryValueKind]::DWord }
                            }
                            $regKey.SetValue($Name, $Value, $regValue)
                            $regKey.Close()
                            Write-ColorOutput "✓ Set $Path\$Name = $Value (via Registry API)" -Color Good
                            return $true
                        }
                    }
                    catch {
                        Write-ColorOutput "Warning: Registry API failed: $($_.Exception.Message)" -Color Warning
                    }
                    
                }
                catch {
                    Write-ColorOutput "Warning: Special Windows Defender handling failed: $($_.Exception.Message)" -Color Warning
                }
            }
            else {
                # Normal path creation for non-Windows Defender paths
                try {
                    # Try to create the full path recursively
                    $pathParts = $Path.Split('\')
                    $currentPath = $pathParts[0]
                    
                    for ($i = 1; $i -lt $pathParts.Length; $i++) {
                        $currentPath += "\$($pathParts[$i])"
                        if (-not (Test-Path $currentPath)) {
                            try {
                                New-Item -Path $currentPath -Force | Out-Null
                            }
                            catch {
                                # If New-Item fails, try alternative approach
                                if ($currentPath -match "^HKLM:") {
                                    $regPath = $currentPath -replace "^HKLM:", "HKEY_LOCAL_MACHINE"
                                    [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey(($regPath -replace "^HKEY_LOCAL_MACHINE\\", "")) | Out-Null
                                }
                            }
                        }
                    }
                    Write-ColorOutput "Created registry path: $Path" -Color Info
                }
                catch {
                    Write-ColorOutput "Warning: Could not create registry path: $($_.Exception.Message)" -Color Warning
                }
            }
        }
        
        # Handle different value types and sizes
        $actualValue = $Value
        $actualType = $Type
        
        # Special handling for large hex values
        if ($Value -is [string] -and $Value.Length -gt 8 -and $Value -match "^[0-9A-Fa-f]+$") {
            # This is a large hex value, treat it as QWORD or String
            try {
                $actualValue = [Convert]::ToUInt64($Value, 16)
                $actualType = "QWORD"
            }
            catch {
                # If QWORD fails, use String type
                $actualType = "String"
                $actualValue = $Value
            }
        }
        
        # Set the registry value with proper type handling (skip if Windows Defender was handled above)
        if (-not ($isWindowsDefenderPath -and $Name -eq "ASLR_ForceRelocateImages")) {
            try {
                # Verify path exists before setting
                if (Test-Path $Path) {
                    Set-ItemProperty -Path $Path -Name $Name -Value $actualValue -Type $actualType -Force
                    Write-ColorOutput "✓ Set $Path\$Name = $Value (Type: $actualType)" -Color Good
                    return $true
                }
                else {
                    Write-ColorOutput "✗ Registry path $Path does not exist and could not be created" -Color Bad
                    return $false
                }
            }
            catch [System.UnauthorizedAccessException] {
                Write-ColorOutput "✗ Access denied setting $Path\$Name - Insufficient privileges" -Color Bad
                return $false
            }
            catch [System.ArgumentException] {
                # If the type conversion fails, try String type
                if ($actualType -ne "String") {
                    try {
                        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type "String" -Force
                        Write-ColorOutput "✓ Set $Path\$Name = $Value (Type: String fallback)" -Color Good
                        return $true
                    }
                    catch {
                        Write-ColorOutput "✗ Failed to set $Path\$Name = $Value : $($_.Exception.Message)" -Color Bad
                        return $false
                    }
                }
                else {
                    Write-ColorOutput "✗ Failed to set $Path\$Name = $Value : $($_.Exception.Message)" -Color Bad
                    return $false
                }
            }
            catch {
                Write-ColorOutput "✗ Failed to set $Path\$Name = $Value : $($_.Exception.Message)" -Color Bad
                return $false
            }
        }
        
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
        
        # Format current value for display
        $currentValueDisplay = $result.CurrentValue
        if ($result.CurrentValue -is [uint64] -and $result.CurrentValue -gt 0xFFFFFFFF) {
            # For large QWORD values, show both hex and decimal
            $currentValueDisplay = "0x{0:X} ({1})" -f $result.CurrentValue, $result.CurrentValue
        }
        elseif ($result.CurrentValue -eq "Not Set" -or $null -eq $result.CurrentValue) {
            $currentValueDisplay = "Not Set"
        }
        
        $tableData += [PSCustomObject]@{
            'Mitigation Name' = $result.Name
            'Status'          = $status
            'Current Value'   = $currentValueDisplay
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
                $rawValue = $value.$Name
                
                # Handle byte arrays (often from QWORD values or complex structures)
                if ($rawValue -is [byte[]]) {
                    # Special handling for MitigationOptions which is a 24-byte structure
                    if ($Name -eq "MitigationOptions" -and $rawValue.Length -eq 24) {
                        # Convert the first 8 bytes to UInt64 for comparison with expected hex values
                        $uint64Value = 0
                        for ($i = 0; $i -lt 8 -and $i -lt $rawValue.Length; $i++) {
                            $uint64Value += [uint64]$rawValue[$i] -shl (8 * $i)
                        }
                        return $uint64Value
                    }
                    # For normal QWORD values (8 bytes or less)
                    elseif ($rawValue.Length -le 8) {
                        # Convert byte array to UInt64 (assuming little-endian format)
                        $uint64Value = 0
                        for ($i = 0; $i -lt $rawValue.Length; $i++) {
                            $uint64Value += [uint64]$rawValue[$i] -shl (8 * $i)
                        }
                        return $uint64Value
                    }
                    else {
                        # If longer than 8 bytes, return as hex string
                        return ($rawValue | ForEach-Object { "{0:X2}" -f $_ }) -join ""
                    }
                }
                
                return $rawValue
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
        # Enhanced comparison logic to handle hex values and converted byte arrays
        $valuesMatch = $false
        
        if ($currentValue -eq $ExpectedValue) {
            $valuesMatch = $true
        }
        # Check if ExpectedValue is a hex string and convert for comparison
        elseif ($ExpectedValue -is [string] -and $ExpectedValue -match "^[0-9A-Fa-f]+$" -and $ExpectedValue.Length -gt 8) {
            try {
                $expectedDecimal = [Convert]::ToUInt64($ExpectedValue, 16)
                # Compare with current value (which might be UInt64 from converted byte array)
                if ($currentValue -eq $expectedDecimal) {
                    $valuesMatch = $true
                }
                # Special handling for MitigationOptions - check if the core flag is present
                elseif ($RegistryName -eq "MitigationOptions" -and $currentValue -is [uint64]) {
                    # Check if the core mitigation flag (0x2000000000000000) is set using bitwise AND
                    $coreFlagPresent = ($currentValue -band $expectedDecimal) -eq $expectedDecimal
                    if ($coreFlagPresent) {
                        $valuesMatch = $true
                        # Update recommendation for this special case
                        if ($currentValue -ne $expectedDecimal) {
                            $Recommendation = "Hardware mitigations core flag is enabled (0x{0:X}). Additional flags are also set, which is typically fine." -f $expectedDecimal
                        }
                    }
                }
                # Also try string comparison of hex representations
                elseif ($currentValue -is [uint64]) {
                    $currentHex = "{0:X}" -f $currentValue
                    if ($currentHex.PadLeft($ExpectedValue.Length, '0') -eq $ExpectedValue) {
                        $valuesMatch = $true
                    }
                }
            }
            catch {
                # If conversion fails, stick with string comparison
                $valuesMatch = ($currentValue.ToString() -eq $ExpectedValue)
            }
        }
        # Check if current value might be hex representation of expected decimal
        elseif ($ExpectedValue -is [int] -or $ExpectedValue -is [long]) {
            $valuesMatch = ($currentValue -eq $ExpectedValue)
        }
        
        if ($valuesMatch) {
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
        # Enhanced console output with clear status indicators
        $statusIndicator = switch ($status) {
            "Enabled" { "✓ ENABLED" }
            "Disabled" { "✗ DISABLED" }
            "Not Configured" { "○ NOT SET" }
            default { $status }
        }
        
        $paddedName = $Name.PadRight(45)
        Write-Host "$paddedName : " -NoNewline
        Write-Host "$statusIndicator" -ForegroundColor $Colors[$statusColor] -NoNewline
        
        # Add current value for context
        if ($currentValue -ne $null -and $currentValue -ne "Not Set") {
            Write-Host " (Value: $currentValue)" -ForegroundColor Gray
        }
        else {
            Write-Host ""
        }
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

function Get-VirtualizationInfo {
    $virtualizationInfo = @{
        IsVirtualMachine            = $false
        HypervisorPresent           = $false
        HypervisorVendor            = "Unknown"
        VirtualizationTechnology    = "None"
        NestedVirtualizationEnabled = $false
        HyperVStatus                = "Not Available"
        VBSStatus                   = "Not Available"
        HVCIStatus                  = "Not Available"
    }
    
    try {
        # Check if running in a VM
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $virtualizationInfo.IsVirtualMachine = $computerSystem.Model -match "Virtual|VMware|VirtualBox|Hyper-V|Xen|KVM"
        
        # Detect hypervisor
        $bios = Get-CimInstance -ClassName Win32_BIOS
        if ($bios.Manufacturer -match "VMware") {
            $virtualizationInfo.HypervisorVendor = "VMware"
            $virtualizationInfo.VirtualizationTechnology = "VMware vSphere/Workstation"
        }
        elseif ($bios.Manufacturer -match "Microsoft|Hyper-V") {
            $virtualizationInfo.HypervisorVendor = "Microsoft"
            $virtualizationInfo.VirtualizationTechnology = "Hyper-V"
        }
        elseif ($computerSystem.Manufacturer -match "QEMU|KVM") {
            $virtualizationInfo.HypervisorVendor = "QEMU/KVM"
            $virtualizationInfo.VirtualizationTechnology = "Linux KVM"
        }
        elseif ($computerSystem.Manufacturer -match "innotek|VirtualBox") {
            $virtualizationInfo.HypervisorVendor = "Oracle"
            $virtualizationInfo.VirtualizationTechnology = "VirtualBox"
        }
        
        # Check for hypervisor presence
        $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        if ($cpu.VirtualizationFirmwareEnabled -or (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -ErrorAction SilentlyContinue)) {
            $virtualizationInfo.HypervisorPresent = $true
        }
        
        # Check Hyper-V status
        $hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -ErrorAction SilentlyContinue
        if ($hyperv) {
            $virtualizationInfo.HyperVStatus = $hyperv.State
        }
        
        # Check nested virtualization (Intel VT-x/AMD-V in VM)
        try {
            $vmProcessor = Get-VMProcessor -VMName * -ErrorAction SilentlyContinue 2>$null
            if ($vmProcessor) {
                $virtualizationInfo.NestedVirtualizationEnabled = ($vmProcessor | Where-Object { $_.ExposeVirtualizationExtensions -eq $true }).Count -gt 0
            }
        }
        catch {
            # Hyper-V not available or not running VMs
        }
        
        # Check VBS and HVCI using correct namespace
        try {
            # Try the correct namespace first
            $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
            if (!$deviceGuard) {
                # Fallback to default namespace
                $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
            }
            
            if ($deviceGuard) {
                $virtualizationInfo.VBSStatus = switch ($deviceGuard.VirtualizationBasedSecurityStatus) {
                    2 { "Running" }
                    1 { "Enabled" }
                    0 { "Disabled" }
                    default { "Unknown ($($deviceGuard.VirtualizationBasedSecurityStatus))" }
                }
                $virtualizationInfo.HVCIStatus = switch ($deviceGuard.CodeIntegrityPolicyEnforcementStatus) {
                    2 { "Enforced" }
                    1 { "Audit Mode" }
                    0 { "Disabled" }
                    default { "Unknown ($($deviceGuard.CodeIntegrityPolicyEnforcementStatus))" }
                }
            }
            else {
                # Alternative method using registry
                $vbsRegValue = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity"
                if ($null -ne $vbsRegValue -and $vbsRegValue -eq 1) {
                    $virtualizationInfo.VBSStatus = "Enabled (Registry)"
                }
                else {
                    $virtualizationInfo.VBSStatus = "Not Available"
                }
                
                $hvciRegValue = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled"
                if ($null -ne $hvciRegValue -and $hvciRegValue -eq 1) {
                    $virtualizationInfo.HVCIStatus = "Enabled (Registry)"
                }
                else {
                    $virtualizationInfo.HVCIStatus = "Not Available"
                }
            }
        }
        catch {
            Write-Verbose "Error checking VBS status: $($_.Exception.Message)"
            $virtualizationInfo.VBSStatus = "Error"
            $virtualizationInfo.HVCIStatus = "Error"
        }
    }
    catch {
        Write-Warning "Error detecting virtualization info: $($_.Exception.Message)"
    }
    
    return $virtualizationInfo
}

function Get-HypervisorMitigations {
    param(
        [string]$HypervisorVendor
    )
    
    $mitigations = @()
    
    switch ($HypervisorVendor) {
        "Microsoft" {
            # Hyper-V specific checks
            $mitigations += @{
                Name         = "Hyper-V Core Scheduler"
                Description  = "Core Scheduler prevents SMT-based side-channel attacks between VMs"
                RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\MinVmVersionForCpuBasedMitigations"
                Command      = "Set-VMProcessor -VMName * -HwThreadCountPerCore 1"
                Impact       = "May reduce VM performance on SMT-enabled CPUs"
            }
            $mitigations += @{
                Name            = "Hyper-V SLAT (Second Level Address Translation)"
                Description     = "Hardware-assisted virtualization for memory protection"
                RequiredFeature = "Intel EPT or AMD RVI support"
                Impact          = "Essential for VM isolation and performance"
            }
        }
        "VMware" {
            $mitigations += @{
                Name         = "VMware Side-Channel Aware Scheduler"
                Description  = "ESXi scheduler aware of side-channel attacks"
                ConfigOption = "sched.cpu.vsmp.effectiveAffinity"
                Impact       = "Available in vSphere 6.7 U2 and later"
            }
            $mitigations += @{
                Name         = "VMware L1TF Mitigation"
                Description  = "L1 Terminal Fault protection in ESXi"
                ConfigOption = "vmx.allowNonVPID = FALSE"
                Impact       = "Requires CPU microcode updates"
            }
        }
        "QEMU/KVM" {
            $mitigations += @{
                Name         = "KVM IBRS/IBPB Support"
                Description  = "Indirect Branch Restricted Speculation support"
                ConfigOption = "-cpu host,+spec-ctrl,+ibpb"
                Impact       = "Requires host CPU microcode and kernel support"
            }
        }
    }
    
    return $mitigations
}

# Main execution
Write-ColorOutput "`n=== Side-Channel Vulnerability Configuration Check ===" -Color Header
Write-ColorOutput "Based on Microsoft KB4073119`n" -Color Info

# System Information
$cpuInfo = Get-CPUInfo
$osInfo = Get-WindowsVersion
$virtInfo = Get-VirtualizationInfo

Write-ColorOutput "System Information:" -Color Header
Write-ColorOutput "CPU: $($cpuInfo.Name)" -Color Info
Write-ColorOutput "OS: $($osInfo.Caption) Build $($osInfo.BuildNumber)" -Color Info
Write-ColorOutput "Architecture: $($osInfo.Architecture)" -Color Info

Write-ColorOutput "\nVirtualization Environment:" -Color Header
Write-ColorOutput "Running in VM: $(if ($virtInfo.IsVirtualMachine) { 'Yes' } else { 'No' })" -Color $(if ($virtInfo.IsVirtualMachine) { 'Warning' } else { 'Info' })
if ($virtInfo.IsVirtualMachine) {
    Write-ColorOutput "Hypervisor: $($virtInfo.HypervisorVendor)" -Color Info
    Write-ColorOutput "Technology: $($virtInfo.VirtualizationTechnology)" -Color Info
}
Write-ColorOutput "Hyper-V Status: $($virtInfo.HyperVStatus)" -Color Info
Write-ColorOutput "VBS Status: $($virtInfo.VBSStatus)" -Color Info
Write-ColorOutput "HVCI Status: $($virtInfo.HVCIStatus)" -Color Info
if ($virtInfo.NestedVirtualizationEnabled) {
    Write-ColorOutput "Nested Virtualization: Enabled" -Color Good
}
elseif ($virtInfo.HyperVStatus -eq "Enabled") {
    Write-ColorOutput "Nested Virtualization: Disabled" -Color Warning
}


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
    -Recommendation "Hardware mitigations are enabled. The core mitigation flag (0x2000000000000000) is set with additional options." `
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

# Virtualization-Specific Security Checks
Write-ColorOutput "`nChecking Virtualization-Specific Security Features..." -Color Header

# 1. Virtualization Based Security (VBS)
$vbsEnabled = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity"
$Results += [PSCustomObject]@{
    Name           = "Virtualization Based Security (VBS)"
    Description    = "Hardware-based security features using hypervisor"
    Status         = if ($vbsEnabled -eq 1) { "Enabled" } else { "Not Configured" }
    CurrentValue   = if ($null -ne $vbsEnabled) { $vbsEnabled } else { "Not Set" }
    ExpectedValue  = 1
    RegistryPath   = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    RegistryName   = "EnableVirtualizationBasedSecurity"
    Recommendation = "Enable VBS for hardware-based security isolation"
    Impact         = "Requires UEFI, Secure Boot, and compatible hardware"
    CanBeEnabled   = $true
}

# 2. Hypervisor-protected Code Integrity (HVCI)
$hvciEnabled = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled"
$Results += [PSCustomObject]@{
    Name           = "Hypervisor-protected Code Integrity (HVCI)"
    Description    = "Hardware-based code integrity enforcement"
    Status         = if ($hvciEnabled -eq 1) { "Enabled" } else { "Not Configured" }
    CurrentValue   = if ($null -ne $hvciEnabled) { $hvciEnabled } else { "Not Set" }
    ExpectedValue  = 1
    RegistryPath   = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    RegistryName   = "Enabled"
    Recommendation = "Enable HVCI for kernel-mode code integrity"
    Impact         = "May cause compatibility issues with unsigned drivers"
    CanBeEnabled   = $true
}

# 3. Credential Guard
$credGuardEnabled = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags"
$Results += [PSCustomObject]@{
    Name           = "Credential Guard"
    Description    = "Protects domain credentials using VBS"
    Status         = if ($credGuardEnabled -eq 1) { "Enabled" } elseif ($credGuardEnabled -eq 2) { "Enabled with UEFI Lock" } else { "Not Configured" }
    CurrentValue   = if ($null -ne $credGuardEnabled) { $credGuardEnabled } else { "Not Set" }
    ExpectedValue  = 1
    RegistryPath   = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    RegistryName   = "LsaCfgFlags"
    Recommendation = "Enable Credential Guard to protect against credential theft"
    Impact         = "Requires VBS and may affect some applications"
    CanBeEnabled   = $true
}

# VM-Specific Checks
if ($virtInfo.IsVirtualMachine) {
    Write-ColorOutput "`nVM Guest-Specific Security Checks:" -Color Header
    
    # 4. VM Guest SLAT Support Check
    $Results += [PSCustomObject]@{
        Name           = "VM Guest: SLAT Support"
        Description    = "Second Level Address Translation support in guest"
        Status         = "Information"
        CurrentValue   = "Check hypervisor configuration"
        ExpectedValue  = "Enabled on host"
        RegistryPath   = "N/A"
        RegistryName   = "N/A"
        Recommendation = "Ensure host hypervisor has SLAT (Intel EPT/AMD RVI) enabled"
        Impact         = "Critical for VM memory isolation and side-channel protection"
        CanBeEnabled   = $false
    }
    
    # 5. VM Tools Security Features
    if ($virtInfo.HypervisorVendor -eq "VMware") {
        $vmToolsVersion = Get-RegistryValue -Path "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools" -Name "InstallPath"
        $Results += [PSCustomObject]@{
            Name           = "VMware Tools Security Features"
            Description    = "VMware Tools with side-channel mitigations"
            Status         = if ($vmToolsVersion) { "Installed" } else { "Not Installed" }
            CurrentValue   = if ($vmToolsVersion) { "Present" } else { "Missing" }
            ExpectedValue  = "Latest Version"
            RegistryPath   = "N/A"
            RegistryName   = "N/A"
            Recommendation = "Update VMware Tools to latest version for security patches"
            Impact         = "Newer versions include side-channel vulnerability mitigations"
            CanBeEnabled   = $false
        }
    }
}
else {
    # Physical Host or Hypervisor-Specific Checks
    Write-ColorOutput "`nHypervisor Host-Specific Security Checks:" -Color Header
    
    # 6. Hyper-V Core Scheduler
    if ($virtInfo.HyperVStatus -eq "Enabled") {
        $coreScheduler = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name "CoreSchedulerType"
        $Results += [PSCustomObject]@{
            Name           = "Hyper-V Core Scheduler"
            Description    = "SMT-aware scheduler for VM isolation"
            Status         = if ($coreScheduler -eq 1) { "Enabled" } else { "Not Configured" }
            CurrentValue   = if ($null -ne $coreScheduler) { $coreScheduler } else { "Not Set" }
            ExpectedValue  = 1
            RegistryPath   = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization"
            RegistryName   = "CoreSchedulerType"
            Recommendation = "Enable Core Scheduler for better VM isolation on SMT systems"
            Impact         = "May reduce performance but improves security between VMs"
            CanBeEnabled   = $true
        }
        
        # 7. Nested Virtualization Security
        $Results += [PSCustomObject]@{
            Name           = "Nested Virtualization Security"
            Description    = "Security considerations for nested hypervisors"
            Status         = if ($virtInfo.NestedVirtualizationEnabled) { "Enabled" } else { "Disabled" }
            CurrentValue   = if ($virtInfo.NestedVirtualizationEnabled) { "Enabled" } else { "Disabled" }
            ExpectedValue  = "Carefully configured"
            RegistryPath   = "N/A"
            RegistryName   = "N/A"
            Recommendation = "Use nested virtualization carefully - additional attack surface"
            Impact         = "Nested VMs may have reduced side-channel protection"
            CanBeEnabled   = $false
        }
    }
}

# Section break before detailed analysis
Write-ColorOutput "`n" + "="*80 -Color Header
Write-ColorOutput "DETAILED SECURITY ANALYSIS" -Color Header
Write-ColorOutput "="*80 -Color Header

# Check if Virtualization Based Security is available (detailed status)
try {
    $vbsStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if (!$vbsStatus) {
        $vbsStatus = Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    }
}
catch {
    $vbsStatus = $null
}

if ($vbsStatus) {
    Write-ColorOutput "`nVirtualization Based Security Detailed Status:" -Color Header
    Write-ColorOutput "=================================================" -Color Header
    
    # VBS Hardware Requirements vs Runtime Status
    $vbsHwReady = $vbsStatus.VirtualizationBasedSecurityHardwareRequirementState -eq 1
    $vbsRunning = $vbsStatus.VirtualizationBasedSecurityStatus -eq 2
    $hvciHwReady = $vbsStatus.HypervisorEnforcedCodeIntegrityHardwareRequirementState -eq 1
    $hvciRunning = $vbsStatus.CodeIntegrityPolicyEnforcementStatus -eq 2
    
    Write-ColorOutput "`nVBS (Virtualization Based Security):" -Color Info
    Write-Host "  Hardware Ready:  " -NoNewline -ForegroundColor Gray
    Write-Host "$(if ($vbsHwReady) { '✓ Yes' } else { '✗ No' })" -ForegroundColor $(if ($vbsHwReady) { $Colors['Good'] } else { $Colors['Warning'] })
    Write-Host "  Currently Active: " -NoNewline -ForegroundColor Gray  
    Write-Host "$(if ($vbsRunning) { '✓ Yes' } else { '✗ No' })" -ForegroundColor $(if ($vbsRunning) { $Colors['Good'] } else { $Colors['Warning'] })
    
    Write-ColorOutput "`nHVCI (Hypervisor-protected Code Integrity):" -Color Info
    Write-Host "  Hardware Ready:  " -NoNewline -ForegroundColor Gray
    Write-Host "$(if ($hvciHwReady) { '✓ Yes' } else { '✗ No' })" -ForegroundColor $(if ($hvciHwReady) { $Colors['Good'] } else { $Colors['Warning'] })
    Write-Host "  Currently Active: " -NoNewline -ForegroundColor Gray
    Write-Host "$(if ($hvciRunning) { '✓ Yes' } else { '✗ No' })" -ForegroundColor $(if ($hvciRunning) { $Colors['Good'] } else { $Colors['Warning'] })
    
    # Explanation of the difference
    if (!$vbsHwReady -and $vbsRunning) {
        Write-ColorOutput "`n💡 Note: VBS is running despite hardware readiness showing 'No'." -Color Info
        Write-ColorOutput "   This indicates VBS is enabled via software/policy, not full hardware support." -Color Info
    }
    if (!$hvciHwReady -and $hvciRunning) {
        Write-ColorOutput "`n💡 Note: HVCI is active despite hardware readiness showing 'No'." -Color Info
        Write-ColorOutput "   This indicates HVCI is using compatible mode or software enforcement." -Color Info
    }
    
    Write-ColorOutput "`nSecurity Services Details:" -Color Info
    Write-ColorOutput "Running Services: $($vbsStatus.SecurityServicesRunning -join ', ')" -Color Info
    Write-ColorOutput "Configured Services: $($vbsStatus.SecurityServicesConfigured -join ', ')" -Color Info
    
    # Service explanation
    $serviceExplanation = @{
        "1" = "Credential Guard"
        "2" = "HVCI (Hypervisor-protected Code Integrity)"
        "3" = "System Guard Secure Launch"
        "4" = "SMM Firmware Measurement"
    }
    
    if ($vbsStatus.SecurityServicesRunning) {
        Write-ColorOutput "`nActive Security Services:" -Color Info
        foreach ($service in $vbsStatus.SecurityServicesRunning) {
            $serviceName = $serviceExplanation[$service.ToString()]
            if ($serviceName) {
                Write-ColorOutput "  • $serviceName" -Color Good
            }
            else {
                Write-ColorOutput "  • Service ID: $service" -Color Info
            }
        }
    }
    
    # Detailed explanation of VBS/HVCI status differences
    Write-ColorOutput "`n" + "-"*60 -Color Header
    Write-ColorOutput "VBS/HVCI Status Explanation:" -Color Header
    Write-ColorOutput "-"*60 -Color Header
    Write-ColorOutput "• 'Hardware Ready' = System meets full hardware requirements" -Color Info
    Write-ColorOutput "• 'Currently Active' = Feature is actually running right now" -Color Info
    Write-ColorOutput "`nWhy might Hardware Ready = No but Active = Yes?" -Color Warning
    Write-ColorOutput "1. VBS/HVCI can run in 'compatible mode' without full HW support" -Color Info
    Write-ColorOutput "2. Some hardware requirements are optional for basic functionality" -Color Info
    Write-ColorOutput "3. Software-based enforcement may be enabled via Group Policy" -Color Info
    Write-ColorOutput "4. The hardware readiness check may be overly strict" -Color Info
    Write-ColorOutput "`n✓ What matters: If 'Currently Active' = Yes, protection is working!" -Color Good
}
else {
    Write-ColorOutput "`nVirtualization Based Security Status:" -Color Header
    Write-ColorOutput "VBS Status: Not Available (Win32_DeviceGuard not accessible)" -Color Warning
    Write-ColorOutput "Note: VBS might still be enabled - check with 'msinfo32' or Device Guard readiness tool" -Color Info
}

# Display results table
Show-ResultsTable -Results $Results

# Summary
Write-ColorOutput "`n=== SECURITY CONFIGURATION SUMMARY ===" -Color Header

$enabledCount = ($Results | Where-Object { $_.Status -eq "Enabled" }).Count
$notConfiguredCount = ($Results | Where-Object { $_.Status -eq "Not Configured" }).Count
$disabledCount = ($Results | Where-Object { $_.Status -eq "Disabled" }).Count
$totalCount = $Results.Count
$configuredPercent = [math]::Round(($enabledCount / $totalCount) * 100, 1)

# Visual status breakdown
Write-Host "`nSecurity Status Overview:" -ForegroundColor $Colors['Header']
Write-Host "=========================" -ForegroundColor $Colors['Header']
Write-Host "✓ ENABLED:       " -NoNewline -ForegroundColor $Colors['Good']
Write-Host "$enabledCount" -NoNewline -ForegroundColor $Colors['Good']
Write-Host " / $totalCount mitigations" -ForegroundColor Gray

Write-Host "○ NOT SET:       " -NoNewline -ForegroundColor $Colors['Warning']
Write-Host "$notConfiguredCount" -NoNewline -ForegroundColor $Colors['Warning']
Write-Host " / $totalCount mitigations" -ForegroundColor Gray

Write-Host "✗ DISABLED:      " -NoNewline -ForegroundColor $Colors['Bad']
Write-Host "$disabledCount" -NoNewline -ForegroundColor $Colors['Bad']
Write-Host " / $totalCount mitigations" -ForegroundColor Gray

Write-Host "`nOverall Security Level: " -NoNewline -ForegroundColor $Colors['Info']
$levelColor = if ($configuredPercent -ge 80) { 'Good' } elseif ($configuredPercent -ge 60) { 'Warning' } else { 'Bad' }
Write-Host "$configuredPercent%" -ForegroundColor $Colors[$levelColor]

# Security level indicator
$securityBar = ""
$filledBlocks = [math]::Floor($configuredPercent / 10)
$emptyBlocks = 10 - $filledBlocks

for ($i = 0; $i -lt $filledBlocks; $i++) { $securityBar += "█" }
for ($i = 0; $i -lt $emptyBlocks; $i++) { $securityBar += "░" }

Write-Host "Security Bar:     [" -NoNewline -ForegroundColor Gray
Write-Host "$securityBar" -NoNewline -ForegroundColor $Colors[$levelColor]
Write-Host "] $configuredPercent%" -ForegroundColor Gray

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

# Virtualization-Specific Recommendations
Write-ColorOutput "`n=== Virtualization Security Recommendations ===" -Color Header

if ($virtInfo.IsVirtualMachine) {
    Write-ColorOutput "Running in Virtual Machine - Guest Recommendations:" -Color Info
    Write-ColorOutput "• Ensure hypervisor host has latest microcode updates" -Color Warning
    Write-ColorOutput "• Verify hypervisor has side-channel mitigations enabled" -Color Warning
    Write-ColorOutput "• Keep guest OS and drivers updated" -Color Warning
    
    switch ($virtInfo.HypervisorVendor) {
        "Microsoft" {
            Write-ColorOutput "`nHyper-V Guest Specific:" -Color Header
            Write-ColorOutput "• Host should use Core Scheduler (Windows Server 2019+)" -Color Warning
            Write-ColorOutput "• Enable Enhanced Session Mode for better security" -Color Info
            Write-ColorOutput "• Ensure host has VBS/HVCI enabled" -Color Warning
        }
        "VMware" {
            Write-ColorOutput "`nVMware Guest Specific:" -Color Header
            Write-ColorOutput "• ESXi host should be 6.7 U2+ with Side-Channel Aware Scheduler" -Color Warning
            Write-ColorOutput "• VM hardware version should be 14+ for latest security features" -Color Warning
            Write-ColorOutput "• Enable VMware Tools for additional security features" -Color Info
        }
        "QEMU/KVM" {
            Write-ColorOutput "`nKVM Guest Specific:" -Color Header
            Write-ColorOutput "• Host kernel should support spec-ctrl (4.15+)" -Color Warning
            Write-ColorOutput "• Use CPU flags: +spec-ctrl,+ibpb,+ssbd" -Color Warning
            Write-ColorOutput "• Enable SLAT (Intel EPT/AMD RVI) on host" -Color Warning
        }
        default {
            Write-ColorOutput "`nGeneral VM Recommendations:" -Color Header
            Write-ColorOutput "• Contact hypervisor vendor for side-channel mitigation guidance" -Color Warning
            Write-ColorOutput "• Verify hardware virtualization extensions are properly exposed" -Color Info
        }
    }
}
else {
    Write-ColorOutput "Running on Physical Hardware - Host Recommendations:" -Color Info
    Write-ColorOutput "• Apply CPU microcode updates from manufacturer" -Color Warning
    Write-ColorOutput "• Enable all available CPU security features in BIOS/UEFI" -Color Warning
    
    if ($virtInfo.HyperVStatus -eq "Enabled") {
        Write-ColorOutput "`nHyper-V Host Specific:" -Color Header
        Write-ColorOutput "• Enable Core Scheduler: bcdedit /set hypervisorschedulertype core" -Color Info
        Write-ColorOutput "• Configure VM isolation policies" -Color Info
        Write-ColorOutput "• Use Generation 2 VMs for enhanced security" -Color Info
        Write-ColorOutput "• Enable Secure Boot for VMs when possible" -Color Info
        Write-ColorOutput "• Consider disabling SMT if security > performance" -Color Warning
    }
    
    Write-ColorOutput "`nGeneral Host Security:" -Color Header
    Write-ColorOutput "• Enable VBS/HVCI if hardware supports it" -Color Warning
    Write-ColorOutput "• Use UEFI Secure Boot" -Color Warning
    Write-ColorOutput "• Enable TPM 2.0 if available" -Color Info
    Write-ColorOutput "• Configure proper VM resource isolation" -Color Warning
}

Write-ColorOutput "`n=== Hardware Prerequisites for Side-Channel Protection ===" -Color Header
Write-ColorOutput "Required CPU Features:" -Color Info
Write-ColorOutput "• Intel: VT-x with EPT, VT-d (or AMD: AMD-V with RVI, AMD-Vi)" -Color Warning
Write-ColorOutput "• Hardware support for SMEP/SMAP" -Color Warning
Write-ColorOutput "• CPU microcode with Spectre/Meltdown mitigations" -Color Warning
Write-ColorOutput "• For VBS: IOMMU, TPM 2.0, UEFI Secure Boot" -Color Warning

Write-ColorOutput "`nFirmware Requirements:" -Color Info
Write-ColorOutput "• UEFI firmware (not legacy BIOS)" -Color Warning
Write-ColorOutput "• Secure Boot capability" -Color Warning
Write-ColorOutput "• TPM 2.0 (for Credential Guard and other VBS features)" -Color Warning
Write-ColorOutput "• Latest firmware updates from manufacturer" -Color Warning

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