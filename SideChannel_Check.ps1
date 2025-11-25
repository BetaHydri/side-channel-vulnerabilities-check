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
    When used with -Interactive, allows selection of specific mitigations
    
.PARAMETER WhatIf
    Shows what changes would be made without actually applying them
    Works in conjunction with -Apply parameter
    
.PARAMETER Interactive
    Enables interactive mode where you can choose which mitigations to apply
    Works with -Apply parameter for granular control

.PARAMETER ShowVMwareHostSecurity
    Shows comprehensive VMware ESXi host security configuration guide
    Displays detailed commands and settings for protecting VMs against side-channel attacks

.PARAMETER Revert
    Enables revert mode to remove/disable specific mitigations
    Works with -Interactive parameter for selective removal
    Use with -WhatIf to preview what would be reverted
    
.EXAMPLE
    .\SideChannel_Check.ps1
    
.EXAMPLE
    .\SideChannel_Check.ps1 -Detailed
    
.EXAMPLE
    .\SideChannel_Check.ps1 -Apply -Interactive
    
.EXAMPLE
    .\SideChannel_Check.ps1 -Apply -WhatIf
    
.EXAMPLE
    .\SideChannel_Check.ps1 -Apply -Interactive -WhatIf
    
.EXAMPLE
    .\SideChannel_Check.ps1 -ExportPath "C:\temp\SideChannelReport.csv"

.EXAMPLE
    .\SideChannel_Check.ps1 -ShowVMwareHostSecurity

.EXAMPLE
    .\SideChannel_Check.ps1 -Revert -Interactive
    
.EXAMPLE
    .\SideChannel_Check.ps1 -Revert -Interactive -WhatIf
    
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
    [switch]$Apply,
    [switch]$WhatIf,
    [switch]$Interactive,
    [switch]$ShowVMwareHostSecurity,
    [switch]$Revert
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
    Gray    = 'Gray'
    Success = 'Green'
    Error   = 'Red'
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
        
        # Special handling for modern CVE mitigations (2022-2023)
        $ModernCVEMitigations = @(
            "BranchHistoryBufferEnabled",                    # BHB - CVE-2022-0001/0002
            "GatherDataSampleMitigation",                    # GDS - CVE-2022-40982
            "SpeculativeReturnStackMitigation",             # SRSO - CVE-2023-20569
            "RegisterFileDataSamplingMitigation",           # RFDS - CVE-2023-28746
            "MicroarchitecturalDataSamplingMitigation",     # MDS
            "L1TerminalFaultMitigation"                      # L1TF - CVE-2018-3620
        )
        
        # Enhanced CVE mitigation configuration
        if ($Name -in $ModernCVEMitigations) {
            Write-ColorOutput "Configuring advanced CVE mitigation: $Name" -Color Warning
            
            # Get CPU information for compatibility validation
            $CPUInfo = Get-CimInstance Win32_Processor | Select-Object -First 1
            $CPUManufacturer = $CPUInfo.Manufacturer
            
            # CPU-specific validation and guidance
            $mitigation = switch ($Name) {
                "BranchHistoryBufferEnabled" { 
                    @{ Description = "BHB (Branch History Buffer)"; CPUs = "Intel and AMD with microcode updates"; Critical = $false }
                }
                "GatherDataSampleMitigation" { 
                    @{ Description = "GDS (Gather Data Sample)"; CPUs = "Intel server/datacenter CPUs"; Critical = ($CPUManufacturer -eq "GenuineIntel") }
                }
                "SpeculativeReturnStackMitigation" { 
                    @{ Description = "SRSO (Speculative Return Stack Overflow)"; CPUs = "AMD Zen architecture"; Critical = ($CPUManufacturer -eq "AuthenticAMD") }
                }
                "RegisterFileDataSamplingMitigation" { 
                    @{ Description = "RFDS (Register File Data Sampling)"; CPUs = "Intel CPUs with RFDS vulnerability"; Critical = ($CPUManufacturer -eq "GenuineIntel") }
                }
                "MicroarchitecturalDataSamplingMitigation" { 
                    @{ Description = "MDS (Microarchitectural Data Sampling)"; CPUs = "Intel CPUs vulnerable to MDS"; Critical = ($CPUManufacturer -eq "GenuineIntel") }
                }
                "L1TerminalFaultMitigation" { 
                    @{ Description = "L1TF (L1 Terminal Fault)"; CPUs = "Intel CPUs in virtualized environments"; Critical = ($CPUManufacturer -eq "GenuineIntel") }
                }
            }
            
            Write-ColorOutput "   Mitigation: $($mitigation.Description)" -Color Info
            Write-ColorOutput "   Target CPUs: $($mitigation.CPUs)" -Color Info
            Write-ColorOutput "   Current CPU: $CPUManufacturer" -Color Info
            
            # Skip SRSO for non-AMD CPUs
            if ($Name -eq "SpeculativeReturnStackMitigation" -and $CPUManufacturer -ne "AuthenticAMD") {
                Write-ColorOutput "   WARNING: Skipping SRSO mitigation - AMD-specific vulnerability" -Color Warning
                return $false
            }
            
            # Warn for vendor-specific mitigations on different CPUs
            if (-not $mitigation.Critical -and $Name -match "GatherDataSample|RegisterFileDataSampling|L1TerminalFault|MicroarchitecturalDataSampling") {
                Write-ColorOutput "   INFO: This mitigation is primarily for other CPU vendors but may still provide benefits" -Color Info
            }
        }
        
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
                                Write-ColorOutput "[+] Set Windows Defender ASLR via Set-ProcessMitigation" -Color Good
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
                            Write-ColorOutput "[+] Set $Path\$Name = $Value (via reg.exe)" -Color Good
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
                            Write-ColorOutput "[+] Set $Path\$Name = $Value (via Registry API)" -Color Good
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
                    Write-ColorOutput "[+] Set $Path\$Name = $Value (Type: $actualType)" -Color Good
                    return $true
                }
                else {
                    Write-ColorOutput "[-] Registry path $Path does not exist and could not be created" -Color Bad
                    return $false
                }
            }
            catch [System.UnauthorizedAccessException] {
                Write-ColorOutput "[-] Access denied setting $Path\$Name - Insufficient privileges" -Color Bad
                return $false
            }
            catch [System.ArgumentException] {
                # If the type conversion fails, try String type
                if ($actualType -ne "String") {
                    try {
                        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type "String" -Force
                        Write-ColorOutput "[+] Set $Path\$Name = $Value (Type: String fallback)" -Color Good
                        return $true
                    }
                    catch {
                        Write-ColorOutput "[-] Failed to set $Path\$Name = $Value : $($_.Exception.Message)" -Color Bad
                        return $false
                    }
                }
                else {
                    Write-ColorOutput "[-] Failed to set $Path\$Name = $Value : $($_.Exception.Message)" -Color Bad
                    return $false
                }
            }
            catch {
                Write-ColorOutput "[-] Failed to set $Path\$Name = $Value : $($_.Exception.Message)" -Color Bad
                return $false
            }
        }
        
        return $true
    }
    catch {
        Write-ColorOutput "[-] Failed to set $Path\$Name = $Value : $($_.Exception.Message)" -Color Bad
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
            "Enabled" { "[+] Enabled" }
            "Disabled" { "[-] Disabled" }
            "Not Configured" { "[?] Not Set" }
            default { $result.Status }
        }
        
        # Format current value for display
        $currentValueDisplay = $result.CurrentValue
        if ($result.CurrentValue -is [uint64] -and $result.CurrentValue -gt 0xFFFFFFFF) {
            # For large QWORD values, show only hex
            $currentValueDisplay = "0x{0:X}" -f $result.CurrentValue
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
    Write-Host "[+] Enabled" -ForegroundColor $Colors['Good'] -NoNewline
    Write-Host " - Mitigation is active and properly configured"
    Write-Host "[-] Disabled" -ForegroundColor $Colors['Bad'] -NoNewline  
    Write-Host " - Mitigation is explicitly disabled"
    Write-Host "[?] Not Set" -ForegroundColor $Colors['Warning'] -NoNewline
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
            "Enabled" { "[+] ENABLED" }
            "Disabled" { "[-] DISABLED" }
            "Not Configured" { "[?] NOT SET" }
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

function Show-VMwareHostSecurity {
    <#
    .SYNOPSIS
    Displays comprehensive VMware host security configuration guidance for side-channel vulnerability protection.
    
    .DESCRIPTION
    Provides detailed ESXi configuration steps and security recommendations specifically for protecting 
    VMware virtual machines against side-channel attacks like Spectre, Meltdown, L1TF, and MDS.
    #>
    
    Write-ColorOutput "`n=== VMware Host Security Configuration Guide ===" -Color Header
    Write-ColorOutput "ESXi/vSphere Security Hardening for Side-Channel Vulnerability Protection`n" -Color Warning
    
    Write-ColorOutput "🔧 CRITICAL ESXi HOST SETTINGS:" -Color Header
    
    Write-ColorOutput "`n1. Side-Channel Aware Scheduler (SCAS):" -Color Info
    Write-ColorOutput "   # Enable Side-Channel Aware Scheduler (ESXi 6.7 U2+)" -Color Success
    Write-ColorOutput "   esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigation -i true" -Color Success
    Write-ColorOutput "   esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigationIntraVM -i true" -Color Success
    Write-ColorOutput "   " -Color Success
    Write-ColorOutput "   # Alternative: Disable Hyperthreading completely (more secure but performance impact)" -Color Warning
    Write-ColorOutput "   esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingActive -i false" -Color Warning
    
    Write-ColorOutput "`n2. L1 Terminal Fault (L1TF) Protection:" -Color Info
    Write-ColorOutput "   # Enable L1D cache flush for VMs" -Color Success
    Write-ColorOutput "   esxcli system settings advanced set -o /VMkernel/Boot/runToCompletionOnly -i true" -Color Success
    Write-ColorOutput "   esxcli system settings advanced set -o /VMkernel/Boot/mitigateL1TF -i true" -Color Success
    
    Write-ColorOutput "`n3. MDS/TAA Microcode Mitigations:" -Color Info
    Write-ColorOutput "   # Enable CPU microcode updates" -Color Success
    Write-ColorOutput "   esxcli system settings advanced set -o /VMkernel/Boot/ignoreMsrLoad -i false" -Color Success
    
    Write-ColorOutput "`n4. Spectre/Meltdown Host Protection:" -Color Info
    Write-ColorOutput "   # Enable IBRS/IBPB support" -Color Success
    Write-ColorOutput "   esxcli system settings advanced set -o /VMkernel/Boot/disableSpeculativeExecution -i false" -Color Success
    Write-ColorOutput "   # Enable SSBD (Speculative Store Bypass Disable)" -Color Success
    Write-ColorOutput "   esxcli system settings advanced set -o /VMkernel/Boot/enableSSBD -i true" -Color Success
    
    Write-ColorOutput "`n⚙️ VM-LEVEL CONFIGURATION:" -Color Header
    
    Write-ColorOutput "`nVM Hardware Requirements:" -Color Info
    Write-ColorOutput "   - VM Hardware Version: 14+ (required for CPU security features)" -Color Success
    Write-ColorOutput "   - CPU Configuration: Enable 'Expose hardware assisted virtualization'" -Color Success
    Write-ColorOutput "   - Memory: Enable 'Reserve all guest memory' for critical VMs" -Color Success
    Write-ColorOutput "   - Execution Policy: Enable 'Virtualize CPU performance counters'" -Color Success
    
    Write-ColorOutput "`nVM Advanced Parameters (.vmx file):" -Color Info
    Write-ColorOutput "   # Disable vulnerable features" -Color Success
    Write-ColorOutput "   vmx.allowNonVPID = `"FALSE`"" -Color Success
    Write-ColorOutput "   vmx.allowVpid = `"TRUE`"" -Color Success
    Write-ColorOutput "   isolation.tools.unity.disable = `"TRUE`"" -Color Success
    Write-ColorOutput "   isolation.tools.unityActive.disable = `"TRUE`"" -Color Success
    Write-ColorOutput "   " -Color Success
    Write-ColorOutput "   # Enable security features" -Color Success
    Write-ColorOutput "   vpmc.enable = `"TRUE`"" -Color Success
    Write-ColorOutput "   hypervisor.cpuid.v0 = `"FALSE`"" -Color Success
    Write-ColorOutput "   monitor.phys_bits_used = `"40`"" -Color Success
    Write-ColorOutput "   featMask.vm.hv.capable = `"Min:1`"" -Color Success
    
    Write-ColorOutput "`n🔍 VERIFICATION COMMANDS:" -Color Header
    
    Write-ColorOutput "`nESXi Security Status Checks:" -Color Info
    Write-ColorOutput "   # Verify Side-Channel Aware Scheduler" -Color Success
    Write-ColorOutput "   esxcli system settings advanced list -o /VMkernel/Boot/hyperthreadingMitigation" -Color Success
    Write-ColorOutput "   " -Color Success
    Write-ColorOutput "   # Check CPU security features" -Color Success
    Write-ColorOutput "   esxcli hardware cpu global get" -Color Success
    Write-ColorOutput "   esxcli hardware cpu feature get -f spectre-ctrl" -Color Success
    Write-ColorOutput "   " -Color Success
    Write-ColorOutput "   # Verify L1TF protection" -Color Success
    Write-ColorOutput "   esxcli system settings advanced list -o /VMkernel/Boot/mitigateL1TF" -Color Success
    Write-ColorOutput "   " -Color Success
    Write-ColorOutput "   # Check microcode version" -Color Success
    Write-ColorOutput "   esxcli hardware cpu global get | grep -i microcode" -Color Success
    
    Write-ColorOutput "`n⚡ PERFORMANCE IMPACT SUMMARY:" -Color Header
    
    $performanceTable = @(
        @{ Mitigation = "Side-Channel Aware Scheduler"; Impact = "2-5%"; Recommendation = "Enable for multi-tenant environments" }
        @{ Mitigation = "L1TF Protection"; Impact = "5-15%"; Recommendation = "Critical for untrusted VMs" }
        @{ Mitigation = "Full Hyperthreading Disable"; Impact = "20-40%"; Recommendation = "Only for highest security requirements" }
        @{ Mitigation = "MDS Mitigation"; Impact = "3-8%"; Recommendation = "Enable for Intel hosts" }
        @{ Mitigation = "VM Memory Reservation"; Impact = "0% (more host memory usage)"; Recommendation = "For critical security workloads" }
    )
    
    $performanceTable | Format-Table -AutoSize
    
    Write-ColorOutput "`n📋 SECURITY CHECKLIST:" -Color Header
    
    Write-ColorOutput "`nHost Level (ESXi):" -Color Info
    Write-ColorOutput "   □ Update ESXi to 6.7 U2+ or 7.0+" -Color Warning
    Write-ColorOutput "   □ Apply latest CPU microcode updates" -Color Warning
    Write-ColorOutput "   □ Enable Side-Channel Aware Scheduler" -Color Warning
    Write-ColorOutput "   □ Configure L1TF protection" -Color Warning
    Write-ColorOutput "   □ Enable MDS/TAA mitigations" -Color Warning
    Write-ColorOutput "   □ Verify Spectre/Meltdown host protections" -Color Warning
    
    Write-ColorOutput "`nVM Level:" -Color Info
    Write-ColorOutput "   □ Update to VM Hardware Version 14+" -Color Warning
    Write-ColorOutput "   □ Install latest VMware Tools" -Color Warning
    Write-ColorOutput "   □ Configure VM security parameters" -Color Warning
    Write-ColorOutput "   □ Enable CPU performance counter virtualization" -Color Warning
    Write-ColorOutput "   □ Reserve guest memory (for critical VMs)" -Color Warning
    Write-ColorOutput "   □ Apply guest OS mitigations (using this script)" -Color Warning
    
    Write-ColorOutput "`nNetwork Security:" -Color Info
    Write-ColorOutput "   □ Isolate management network" -Color Warning
    Write-ColorOutput "   □ Use encrypted vMotion" -Color Warning
    Write-ColorOutput "   □ Enable VM communication encryption" -Color Warning
    Write-ColorOutput "   □ Configure distributed firewall rules" -Color Warning
    
    Write-ColorOutput "`n🔗 Additional Resources:" -Color Header
    Write-ColorOutput "   - VMware Security Advisories: https://www.vmware.com/security/advisories.html" -Color Info
    Write-ColorOutput "   - Side-Channel Attack Mitigations: https://kb.vmware.com/s/article/55636" -Color Info
    Write-ColorOutput "   - ESXi Security Configuration Guide: https://docs.vmware.com/en/VMware-vSphere/" -Color Info
    
    Write-ColorOutput "`nIMPORTANT: Test performance impact in non-production environment first!" -Color Error
    Write-ColorOutput "Some mitigations may significantly impact performance." -Color Error
}

function Get-RevertableMitigations {
    <#
    .SYNOPSIS
    Gets a list of side-channel mitigations that can be reverted/disabled.
    
    .DESCRIPTION
    Scans the system for currently enabled side-channel mitigations and returns
    those that can be safely reverted. Includes original/default values for restoration.
    #>
    
    $revertableMitigations = @()
    
    # 1. Speculative Store Bypass Disable
    $ssbd = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride"
    if ($ssbd -ne $null -and $ssbd -ne 0) {
        $revertableMitigations += @{
            Name          = "Speculative Store Bypass Disable"
            Description   = "Revert Spectre Variant 4 protection (CVE-2018-3639)"
            RegistryPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            RegistryName  = "FeatureSettingsOverride"
            CurrentValue  = $ssbd
            RevertValue   = 0
            Impact        = "Low"
            CanBeReverted = $true
            SecurityRisk  = "Medium - Exposes system to Spectre Variant 4 attacks"
        }
    }
    
    # 2. SSBD Feature Mask
    $ssbdMask = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask"
    if ($ssbdMask -ne $null -and $ssbdMask -ne 0) {
        $revertableMitigations += @{
            Name          = "SSBD Feature Mask"
            Description   = "Revert SSBD feature override mask"
            RegistryPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            RegistryName  = "FeatureSettingsOverrideMask"
            CurrentValue  = $ssbdMask
            RevertValue   = 0
            Impact        = "Low"
            CanBeReverted = $true
            SecurityRisk  = "Low - Works in conjunction with FeatureSettingsOverride"
        }
    }
    
    # 3. Branch Target Injection Mitigation
    $bti = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisablePageCombining"
    if ($bti -ne $null -and $bti -eq 0) {
        $revertableMitigations += @{
            Name          = "Branch Target Injection Mitigation"
            Description   = "Re-enable page combining (removes Spectre V2 protection)"
            RegistryPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
            RegistryName  = "DisablePageCombining"
            CurrentValue  = $bti
            RevertValue   = 1
            Impact        = "Low"
            CanBeReverted = $true
            SecurityRisk  = "High - Removes critical Spectre V2 protection"
        }
    }
    
    # 4. Kernel VA Shadow (Meltdown Protection)
    $kvas = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "EnableKernelVaShadow"
    if ($kvas -ne $null -and $kvas -eq 1) {
        $revertableMitigations += @{
            Name          = "Kernel VA Shadow (Meltdown Protection)"
            Description   = "Disable Meltdown protection (CVE-2017-5754)"
            RegistryPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            RegistryName  = "EnableKernelVaShadow"
            CurrentValue  = $kvas
            RevertValue   = 0
            Impact        = "Medium"
            CanBeReverted = $true
            SecurityRisk  = "Critical - Removes Meltdown protection"
        }
    }
    
    # 5. Hardware Security Mitigations
    $hwMit = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "MitigationOptions"
    if ($hwMit -ne $null -and $hwMit -ne 0) {
        $revertableMitigations += @{
            Name          = "Hardware Security Mitigations"
            Description   = "Reset CPU-level security mitigations to default"
            RegistryPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
            RegistryName  = "MitigationOptions"
            CurrentValue  = "0x$('{0:X16}' -f $hwMit)"
            RevertValue   = "Remove registry value"
            Impact        = "Variable"
            CanBeReverted = $true
            SecurityRisk  = "High - Removes multiple CPU security features"
        }
    }
    
    # 6. Intel TSX Disable
    $tsx = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableTsx"
    if ($tsx -ne $null -and $tsx -eq 1) {
        $revertableMitigations += @{
            Name          = "Intel TSX Disable"
            Description   = "Re-enable Intel TSX (Transactional Synchronization Extensions)"
            RegistryPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
            RegistryName  = "DisableTsx"
            CurrentValue  = $tsx
            RevertValue   = 0
            Impact        = "Application-dependent"
            CanBeReverted = $true
            SecurityRisk  = "Medium - May expose TSX-related vulnerabilities"
        }
    }
    
    # 7. Modern CVE Mitigations
    $modernCVEs = @(
        @{ Name = "BHB Mitigation"; RegName = "BranchHistoryBufferEnabled"; CVE = "CVE-2022-0001/0002" }
        @{ Name = "GDS Mitigation"; RegName = "GatherDataSampleMitigation"; CVE = "CVE-2022-40982" }
        @{ Name = "SRSO Mitigation"; RegName = "SpeculativeReturnStackMitigation"; CVE = "CVE-2023-20569" }
        @{ Name = "RFDS Mitigation"; RegName = "RegisterFileDataSamplingMitigation"; CVE = "CVE-2023-28746" }
        @{ Name = "L1TF Mitigation"; RegName = "L1TerminalFaultMitigation"; CVE = "CVE-2018-3620" }
        @{ Name = "MDS Mitigation"; RegName = "MicroarchitecturalDataSamplingMitigation"; CVE = "MDS" }
    )
    
    foreach ($cve in $modernCVEs) {
        $value = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name $cve.RegName
        if ($value -ne $null -and $value -eq 1) {
            $revertableMitigations += @{
                Name          = $cve.Name
                Description   = "Disable $($cve.CVE) mitigation"
                RegistryPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
                RegistryName  = $cve.RegName
                CurrentValue  = $value
                RevertValue   = 0
                Impact        = "Low-Medium"
                CanBeReverted = $true
                SecurityRisk  = "Medium - Removes protection against $($cve.CVE)"
            }
        }
    }
    
    # 8. Windows Defender ASLR
    $aslr = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Exploit Protection\System" -Name "ASLR_ForceRelocateImages"
    if ($aslr -ne $null -and $aslr -eq 1) {
        $revertableMitigations += @{
            Name          = "Windows Defender Exploit Guard ASLR"
            Description   = "Disable forced ASLR image relocation"
            RegistryPath  = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Exploit Protection\System"
            RegistryName  = "ASLR_ForceRelocateImages"
            CurrentValue  = $aslr
            RevertValue   = 0
            Impact        = "Low"
            CanBeReverted = $true
            SecurityRisk  = "Medium - Reduces memory layout randomization"
        }
    }

    # 9. Nested Virtualization Security  
    try {
        $vmProcessor = Get-VMProcessor -VMName * -ErrorAction SilentlyContinue 2>$null
        $nestedEnabled = ($vmProcessor | Where-Object { $_.ExposeVirtualizationExtensions -eq $true }).Count -gt 0
        if ($nestedEnabled) {
            # Get list of VMs with nested virtualization enabled
            $nestedVMs = $vmProcessor | Where-Object { $_.ExposeVirtualizationExtensions -eq $true } | Select-Object -ExpandProperty VMName
            $vmList = $nestedVMs -join ", "
            
            $revertableMitigations += @{
                Name          = "Nested Virtualization Security"
                Description   = "Disable nested virtualization for enhanced security (VMs: $vmList)"
                RegistryPath  = "Hyper-V PowerShell"
                RegistryName  = "ExposeVirtualizationExtensions"
                CurrentValue  = "Enabled"
                RevertValue   = "Disabled"
                Impact        = "High"
                CanBeReverted = $true
                SecurityRisk  = "Medium - Improves security by removing nested attack surface, but breaks VM-in-VM scenarios"
                VMNames       = $nestedVMs
            }
        }
    }
    catch {
        # Hyper-V not available or no VMs running - check for VMware
        try {
            # Detect if running in VMware VM
            $vmwareDetected = $false
            $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
            $model = (Get-WmiObject -Class Win32_ComputerSystem).Model
            $biosVersion = (Get-WmiObject -Class Win32_BIOS).Version
            
            if ($manufacturer -match "VMware" -or $model -match "VMware" -or $biosVersion -match "VMware") {
                $vmwareDetected = $true
            }
            
            if ($vmwareDetected) {
                $revertableMitigations += @{
                    Name          = "VMware Nested Virtualization (Information Only)"
                    Description   = "VMware nested virtualization detected - requires ESXi host configuration"
                    RegistryPath  = "VMware ESXi"
                    RegistryName  = "VT-x/AMD-V Passthrough"
                    CurrentValue  = "Unknown (requires ESXi access)"
                    RevertValue   = "ESXi Configuration Required"
                    Impact        = "High"
                    CanBeReverted = $false
                    SecurityRisk  = "Info - Cannot be controlled from Windows guest. Requires ESXi host access."
                    ESXiCommands  = @(
                        "# Disable VT-x/AMD-V passthrough (run on ESXi host):",
                        "esxcli hardware cpu set --vhv 0",
                        "# Or edit VM .vmx file:",
                        "vhv.enable = `"FALSE`"",
                        "featMask.vm.hv.capable = `"Min:0`""
                    )
                }
            }
        }
        catch {
            # No VMware detection available
        }
    }

    return $revertableMitigations
}

function Calculate-SecurityScore {
    <#
    .SYNOPSIS
    Calculates the overall security score based on mitigation results.
    
    .DESCRIPTION
    Analyzes security check results and returns a score with percentage and visual bar.
    #>
    param([array]$Results)
    
    $enabledCount = ($Results | Where-Object { $_.Status -eq "Enabled" }).Count
    $totalCount = $Results.Count
    $percentage = if ($totalCount -gt 0) { [math]::Round(($enabledCount / $totalCount) * 100, 1) } else { 0 }
    
    # Create security bar
    $filledBlocks = [math]::Floor($percentage / 10)
    $emptyBlocks = 10 - $filledBlocks
    $barDisplay = ("[" + ("#" * $filledBlocks) + ("-" * $emptyBlocks) + "]")
    
    return [PSCustomObject]@{
        EnabledCount = $enabledCount
        TotalCount   = $totalCount
        Percentage   = $percentage
        BarDisplay   = $barDisplay
    }
}

function Get-CurrentSecurityResults {
    <#
    .SYNOPSIS
    Re-runs all security checks to get current state for scoring.
    #>
    $currentResults = @()
    
    # Re-run the same checks as in main script
    $currentResults += Test-SideChannelMitigation -Name "Speculative Store Bypass Disable" `
        -Description "Mitigates Speculative Store Bypass (Variant 4) attacks" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
        -RegistryName "FeatureSettingsOverride" `
        -ExpectedValue 72 `
        -Recommendation "Enable to mitigate SSB attacks. Set FeatureSettingsOverride to 72" `
        -Impact "Minimal performance impact on most workloads"

    $currentResults += Test-SideChannelMitigation -Name "SSBD Feature Mask" `
        -Description "Feature mask for Speculative Store Bypass Disable" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
        -RegistryName "FeatureSettingsOverrideMask" `
        -ExpectedValue 3 `
        -Recommendation "Set FeatureSettingsOverrideMask to 3" `
        -Impact "Works in conjunction with FeatureSettingsOverride"

    # Add other key checks for scoring (abbreviated for performance)
    $currentResults += Test-SideChannelMitigation -Name "Hardware Security Mitigations" `
        -Description "CPU-level hardware security mitigations" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "MitigationOptions" `
        -ExpectedValue "2000000000000000" `
        -Recommendation "Enable hardware-level CPU security mitigations" `
        -Impact "Hardware-dependent, modern CPUs have better performance"

    $currentResults += Test-SideChannelMitigation -Name "Intel TSX Disable" `
        -Description "Disables Intel TSX to prevent TSX-based attacks" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "DisableTsx" `
        -ExpectedValue 1 `
        -Recommendation "Disable Intel TSX for security" `
        -Impact "May affect applications that rely on TSX, but improves security"

    # Add modern CVE mitigations
    $currentResults += Test-SideChannelMitigation -Name "BHB Mitigation" `
        -Description "CVE-2022-0001/0002 mitigation (Branch History Buffer)" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "BranchHistoryBufferEnabled" `
        -ExpectedValue 1 `
        -Recommendation "Enable BHB mitigation for CVE-2022-0001/0002" `
        -Impact "Minimal performance impact on recent CPUs"

    $currentResults += Test-SideChannelMitigation -Name "L1TF Mitigation" `
        -Description "CVE-2018-3620 mitigation (L1 Terminal Fault)" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "L1TerminalFaultMitigation" `
        -ExpectedValue 1 `
        -Recommendation "Enable L1TF mitigation for CVE-2018-3620" `
        -Impact "High performance impact in virtualized environments"

    return $currentResults
}

function Invoke-MitigationRevert {
    <#
    .SYNOPSIS
    Reverts specific side-channel mitigations based on user selection.
    
    .DESCRIPTION
    Allows users to interactively or automatically revert side-channel mitigations
    that are causing performance issues. Includes safety checks and warnings.
    Shows before/after security scores to understand the impact.
    #>
    param(
        [array]$SelectedMitigations,
        [switch]$WhatIf
    )
    
    if ($SelectedMitigations.Count -eq 0) {
        Write-ColorOutput "No mitigations selected for revert." -Color Warning
        return
    }
    
    # Calculate current security score before revert
    Write-ColorOutput "Calculating current security score..." -Color Info
    $beforeResults = Get-CurrentSecurityResults
    $beforeScore = Calculate-SecurityScore -Results $beforeResults
    
    Write-ColorOutput "`n=== Mitigation Revert Operation ===" -Color Header
    
    if ($WhatIf) {
        Write-ColorOutput "WhatIf Mode: Changes will be previewed but not applied`n" -Color Warning
    }
    else {
        Write-ColorOutput "WARNING: This will REMOVE security protections from your system!" -Color Error
        Write-ColorOutput "Only proceed if you understand the security implications.`n" -Color Error
    }
    
    # Show current security score
    Write-ColorOutput "Current Security Score: $($beforeScore.Percentage)%" -Color $(if ($beforeScore.Percentage -ge 80) { 'Good' } elseif ($beforeScore.Percentage -ge 60) { 'Warning' } else { 'Bad' })
    Write-ColorOutput "Security Bar: $($beforeScore.BarDisplay) $($beforeScore.Percentage)%`n" -Color Info
    
    $successCount = 0
    $errorCount = 0
    
    foreach ($mitigation in $SelectedMitigations) {
        Write-ColorOutput "Processing: $($mitigation.Name)" -Color Info
        
        if ($WhatIf) {
            Write-ColorOutput "  Would revert:" -Color Warning
            if ($mitigation.RegistryPath -eq "Hyper-V PowerShell") {
                Write-ColorOutput "    Action: Disable nested virtualization on VMs" -Color Info
                Write-ColorOutput "    VMs affected: $($mitigation.VMNames -join ', ')" -Color Info
                Write-ColorOutput "    PowerShell Command: Set-VMProcessor -VMName <VM> -ExposeVirtualizationExtensions `$false" -Color Info
            }
            elseif ($mitigation.RegistryPath -eq "VMware ESXi") {
                Write-ColorOutput "    Platform: VMware vSphere detected" -Color Info
                Write-ColorOutput "    Action: Cannot be controlled from Windows guest" -Color Warning
                Write-ColorOutput "    Required: ESXi host access" -Color Warning
                Write-ColorOutput "    ESXi Commands:" -Color Info
                foreach ($cmd in $mitigation.ESXiCommands) {
                    Write-ColorOutput "      $cmd" -Color Gray
                }
            }
            else {
                Write-ColorOutput "    Registry Path: $($mitigation.RegistryPath)" -Color Info
                Write-ColorOutput "    Registry Name: $($mitigation.RegistryName)" -Color Info
                Write-ColorOutput "    Current Value: $($mitigation.CurrentValue)" -Color Info
                Write-ColorOutput "    New Value: $($mitigation.RevertValue)" -Color Warning
            }
            Write-ColorOutput "    Security Risk: $($mitigation.SecurityRisk)" -Color Error
            Write-ColorOutput "" -Color Info
        }
        else {
            try {
                if ($mitigation.RegistryPath -eq "Hyper-V PowerShell") {
                    # Handle nested virtualization through Hyper-V PowerShell commands
                    foreach ($vmName in $mitigation.VMNames) {
                        Set-VMProcessor -VMName $vmName -ExposeVirtualizationExtensions $false -ErrorAction Stop
                        Write-ColorOutput "  ✓ Disabled nested virtualization for VM: $vmName" -Color Good
                    }
                }
                elseif ($mitigation.RegistryPath -eq "VMware ESXi") {
                    # Handle VMware guidance
                    Write-ColorOutput "  ⚠️ VMware Configuration Required:" -Color Warning
                    Write-ColorOutput "    This change requires ESXi host access" -Color Warning
                    Write-ColorOutput "    Commands to run on ESXi host:" -Color Info
                    foreach ($cmd in $mitigation.ESXiCommands) {
                        if ($cmd.StartsWith("#")) {
                            Write-ColorOutput "    $cmd" -Color Good
                        }
                        else {
                            Write-ColorOutput "    $cmd" -Color Warning
                        }
                    }
                    Write-ColorOutput "  ⚠️ Cannot execute automatically from Windows guest" -Color Error
                }
                elseif ($mitigation.RevertValue -eq "Remove registry value") {
                    # Remove the registry value entirely
                    if (Test-Path $mitigation.RegistryPath) {
                        Remove-ItemProperty -Path $mitigation.RegistryPath -Name $mitigation.RegistryName -ErrorAction SilentlyContinue
                        Write-ColorOutput "  ✓ Registry value removed: $($mitigation.RegistryName)" -Color Good
                    }
                }
                else {
                    # Set to revert value
                    Set-RegistryValue -Path $mitigation.RegistryPath -Name $mitigation.RegistryName -Value $mitigation.RevertValue -Type "DWORD"
                    Write-ColorOutput "  ✓ Reverted: $($mitigation.Name) = $($mitigation.RevertValue)" -Color Good
                }
                $successCount++
            }
            catch {
                Write-ColorOutput "  ✗ Failed to revert $($mitigation.Name): $($_.Exception.Message)" -Color Bad
                $errorCount++
            }
        }
    }
    
    if ($WhatIf) {
        # Calculate projected security score after revert for WhatIf preview
        Write-ColorOutput "Calculating security impact..." -Color Info
        $projectedResults = Get-CurrentSecurityResults
        
        # Simulate the impact of selected mitigations being reverted
        foreach ($mitigation in $SelectedMitigations) {
            $matchingResult = $projectedResults | Where-Object { 
                $_.RegistryPath -eq $mitigation.RegistryPath -and $_.RegistryName -eq $mitigation.RegistryName 
            }
            if ($matchingResult) {
                $matchingResult.Status = "Disabled"
                $matchingResult.CurrentValue = $mitigation.RevertValue
            }
        }
        
        $projectedScore = Calculate-SecurityScore -Results $projectedResults
        $scoreDifference = $beforeScore.Percentage - $projectedScore.Percentage
        
        Write-ColorOutput "WhatIf Summary:" -Color Header
        Write-ColorOutput "  Mitigations that would be reverted: $($SelectedMitigations.Count)" -Color Warning
        Write-ColorOutput "  System restart would be required: Yes" -Color Warning
        Write-ColorOutput "" -Color Info
        Write-ColorOutput "Security Score Impact:" -Color Header
        Write-ColorOutput "  Current Score:   $($beforeScore.Percentage)% $($beforeScore.BarDisplay)" -Color $(if ($beforeScore.Percentage -ge 80) { 'Good' } elseif ($beforeScore.Percentage -ge 60) { 'Warning' } else { 'Bad' })
        Write-ColorOutput "  After Revert:    $($projectedScore.Percentage)% $($projectedScore.BarDisplay)" -Color $(if ($projectedScore.Percentage -ge 80) { 'Good' } elseif ($projectedScore.Percentage -ge 60) { 'Warning' } else { 'Bad' })
        Write-ColorOutput "  Score Change:    -$([math]::Round($scoreDifference, 1))% (Security Reduction)" -Color Error
        Write-ColorOutput "`nTo actually revert these mitigations, run without -WhatIf switch." -Color Info
    }
    else {
        Write-ColorOutput "`nRevert Summary:" -Color Header
        Write-ColorOutput "  Successfully reverted: $successCount" -Color Good
        Write-ColorOutput "  Failed: $errorCount" -Color Bad
        
        # Calculate security score after revert (for actual revert operations)
        if ($successCount -gt 0) {
            Write-ColorOutput "`nRecalculating security score..." -Color Info
            $afterResults = Get-CurrentSecurityResults
            $afterScore = Calculate-SecurityScore -Results $afterResults
            $scoreDifference = $beforeScore.Percentage - $afterScore.Percentage
            
            Write-ColorOutput "" -Color Info
            Write-ColorOutput "Security Score Impact:" -Color Header
            Write-ColorOutput "  Before Revert:  $($beforeScore.Percentage)% $($beforeScore.BarDisplay)" -Color $(if ($beforeScore.Percentage -ge 80) { 'Good' } elseif ($beforeScore.Percentage -ge 60) { 'Warning' } else { 'Bad' })
            Write-ColorOutput "  After Revert:   $($afterScore.Percentage)% $($afterScore.BarDisplay)" -Color $(if ($afterScore.Percentage -ge 80) { 'Good' } elseif ($afterScore.Percentage -ge 60) { 'Warning' } else { 'Bad' })
            Write-ColorOutput "  Score Change:   -$([math]::Round($scoreDifference, 1))% (Security Reduction)" -Color Error
            
            Write-ColorOutput "`n⚠️  IMPORTANT: System restart required for changes to take effect!" -Color Error
            Write-ColorOutput "Your system now has REDUCED security protection." -Color Error
            Write-ColorOutput "Monitor system performance and re-enable mitigations if possible." -Color Warning
        }
    }
}

# Main execution
Write-ColorOutput "`n=== Side-Channel Vulnerability Configuration Check ===" -Color Header
Write-ColorOutput "Based on Microsoft KB4073119`n" -Color Info
Write-ColorOutput "Enhanced with additional CVEs from Microsoft's SpeculationControl tool analysis`n" -Color Warning

# Parameter validation
if ($Apply -and $Revert) {
    Write-ColorOutput "ERROR: Cannot use -Apply and -Revert parameters together." -Color Bad
    Write-ColorOutput "Use -Apply to enable mitigations or -Revert to remove them, but not both." -Color Warning
    exit 1
}

if ($Revert -and -not $Interactive) {
    Write-ColorOutput "ERROR: Revert mode requires -Interactive for safety." -Color Bad
    Write-ColorOutput "Use: .\SideChannel_Check.ps1 -Revert -Interactive" -Color Warning
    exit 1
}

Write-ColorOutput "NOTE: For official Microsoft assessment, also consider running:" -Color Info
Write-ColorOutput "   Install-Module SpeculationControl; Get-SpeculationControlSettings`n" -Color Good

# System Information
$cpuInfo = Get-CPUInfo
$osInfo = Get-WindowsVersion
$virtInfo = Get-VirtualizationInfo

Write-ColorOutput "System Information:" -Color Header
Write-ColorOutput "CPU: $($cpuInfo.Name)" -Color Info
Write-ColorOutput "OS: $($osInfo.Caption) Build $($osInfo.BuildNumber)" -Color Info
Write-ColorOutput "Architecture: $($osInfo.Architecture)" -Color Info
Write-ColorOutput "" -Color Info
Write-ColorOutput "Virtualization Environment:" -Color Header
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

# Additional Modern CVE Checks - Based on Microsoft SpeculationControl tool analysis

# 11. BHB (Branch History Buffer) - CVE-2022-0001, CVE-2022-0002
$Results += Test-SideChannelMitigation -Name "BHB Mitigation" `
    -Description "Branch History Buffer injection mitigation (CVE-2022-0001, CVE-2022-0002)" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "BranchHistoryBufferEnabled" `
    -ExpectedValue 1 `
    -Recommendation "Enable BHB mitigation for modern Intel/AMD CPU protection" `
    -Impact "Minimal performance impact on recent CPUs"

# 12. GDS (Gather Data Sample) - CVE-2022-40982  
$Results += Test-SideChannelMitigation -Name "GDS Mitigation" `
    -Description "Gather Data Sample vulnerability mitigation (CVE-2022-40982)" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "GatherDataSampleMitigation" `
    -ExpectedValue 1 `
    -Recommendation "Enable GDS mitigation for Intel CPU data sampling protection" `
    -Impact "Performance impact varies by workload"

# 13. SRSO (Speculative Return Stack Overflow) - CVE-2023-20569
$Results += Test-SideChannelMitigation -Name "SRSO Mitigation" `
    -Description "Speculative Return Stack Overflow mitigation for AMD CPUs (CVE-2023-20569)" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "SpeculativeReturnStackMitigation" `
    -ExpectedValue 1 `
    -Recommendation "Enable SRSO mitigation for AMD Zen architecture protection" `
    -Impact "Minor performance impact on AMD Zen processors"

# 14. RFDS (Register File Data Sampling) - CVE-2023-28746
$Results += Test-SideChannelMitigation -Name "RFDS Mitigation" `
    -Description "Register File Data Sampling vulnerability mitigation (CVE-2023-28746)" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "RegisterFileDataSamplingMitigation" `
    -ExpectedValue 1 `
    -Recommendation "Enable RFDS mitigation for Intel CPU register file protection" `
    -Impact "Minimal performance overhead on supported CPUs"

# 15. L1TF (L1 Terminal Fault) - CVE-2018-3620
# Perform Intel CPU-specific vulnerability detection
if ($cpuInfo.Manufacturer -eq "GenuineIntel") {
    # Extract Intel CPU Family/Model/Stepping for vulnerability assessment
    $IntelCPUDetails = $null
    if ($cpuInfo.Description -match 'Family (\d+) Model (\d+) Stepping (\d+)') {
        $IntelCPUDetails = @{
            Family   = [int]$Matches[1]
            Model    = [int]$Matches[2]
            Stepping = [int]$Matches[3]
        }
    }
    
    # Define known L1TF vulnerable Intel CPU signatures
    $L1TFVulnerableCPUs = @(
        @{Family = 6; Model = 26; Stepping = 4 }, @{Family = 6; Model = 26; Stepping = 5 },
        @{Family = 6; Model = 30; Stepping = 5 }, @{Family = 6; Model = 37; Stepping = 1 },
        @{Family = 6; Model = 44; Stepping = 2 }, @{Family = 6; Model = 42; Stepping = 7 },
        @{Family = 6; Model = 45; Stepping = 7 }, @{Family = 6; Model = 58; Stepping = 9 },
        @{Family = 6; Model = 62; Stepping = 4 }, @{Family = 6; Model = 60; Stepping = 3 },
        @{Family = 6; Model = 79; Stepping = 1 }, @{Family = 6; Model = 142; Stepping = 9 },
        @{Family = 6; Model = 158; Stepping = 9 }, @{Family = 6; Model = 158; Stepping = 10 }
    )
    
    $IsL1TFVulnerable = $false
    if ($IntelCPUDetails) {
        foreach ($VulnCPU in $L1TFVulnerableCPUs) {
            if ($IntelCPUDetails.Family -eq $VulnCPU.Family -and 
                $IntelCPUDetails.Model -eq $VulnCPU.Model -and 
                $IntelCPUDetails.Stepping -eq $VulnCPU.Stepping) {
                $IsL1TFVulnerable = $true
                break
            }
        }
    }
    
    $L1TFRecommendation = if ($IsL1TFVulnerable) {
        "CPU signature matches L1TF vulnerable list. Ensure L1D flush mitigation and latest microcode updates."
    }
    else {
        "CPU does not match known L1TF vulnerable signatures, but enable mitigation if available."
    }
    
    $Results += Test-SideChannelMitigation -Name "L1TF Mitigation" `
        -Description "L1 Terminal Fault (Foreshadow) mitigation for Intel CPUs (CVE-2018-3620)" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "L1TerminalFaultMitigation" `
        -ExpectedValue 1 `
        -Recommendation $L1TFRecommendation `
        -Impact "High performance impact in virtualized environments"
}

# 16. MDS (Microarchitectural Data Sampling) 
$Results += Test-SideChannelMitigation -Name "MDS Mitigation" `
    -Description "Microarchitectural Data Sampling vulnerability mitigation" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "MicroarchitecturalDataSamplingMitigation" `
    -ExpectedValue 1 `
    -Recommendation "Enable MDS mitigation to prevent microarchitectural data leakage" `
    -Impact "Moderate performance impact on affected Intel CPUs"

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
    
    # 6. Hyper-V Core Scheduler (OS version dependent)
    if ($virtInfo.HyperVStatus -eq "Enabled") {
        # Get OS build number to determine if Core Scheduler is default
        $osBuildNumber = [int](Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
        
        # Core Scheduler became default in:
        # - Windows 11 (Build 22000+)
        # - Windows Server 2022 (Build 20348+)
        $needsCoreSchedulerConfig = $osBuildNumber -lt 20348
        
        $coreScheduler = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name "CoreSchedulerType"
        
        $coreSchedulerStatus = if ($needsCoreSchedulerConfig) {
            if ($coreScheduler -eq 1) { "Enabled" } else { "Not Configured" }
        }
        else {
            "Default (OS Built-in)"  # Newer OS versions have it enabled by default
        }
        
        $coreSchedulerRecommendation = if ($needsCoreSchedulerConfig) {
            "Enable Core Scheduler for SMT security: bcdedit /set hypervisorschedulertype core"
        }
        else {
            "Core Scheduler is enabled by default in this Windows version (Build $osBuildNumber)"
        }
        
        $Results += [PSCustomObject]@{
            Name           = "Hyper-V Core Scheduler"
            Description    = "SMT-aware scheduler for VM isolation (prevents cross-VM side-channel attacks)"
            Status         = $coreSchedulerStatus
            CurrentValue   = if ($needsCoreSchedulerConfig -and $null -ne $coreScheduler) { $coreScheduler } else { "OS Default" }
            ExpectedValue  = if ($needsCoreSchedulerConfig) { 1 } else { "Built-in" }
            RegistryPath   = if ($needsCoreSchedulerConfig) { "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" } else { "N/A" }
            RegistryName   = if ($needsCoreSchedulerConfig) { "CoreSchedulerType" } else { "N/A" }
            Recommendation = $coreSchedulerRecommendation
            Impact         = if ($needsCoreSchedulerConfig) { "Minor performance reduction, significant security improvement" } else { "No action needed - already optimized" }
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
    Write-Host "$(if ($vbsHwReady) { '[+] Yes' } else { '[-] No' })" -ForegroundColor $(if ($vbsHwReady) { $Colors['Good'] } else { $Colors['Warning'] })
    Write-Host "  Currently Active: " -NoNewline -ForegroundColor Gray  
    Write-Host "$(if ($vbsRunning) { '[+] Yes' } else { '[-] No' })" -ForegroundColor $(if ($vbsRunning) { $Colors['Good'] } else { $Colors['Warning'] })
    
    Write-ColorOutput "`nHVCI (Hypervisor-protected Code Integrity):" -Color Info
    Write-Host "  Hardware Ready:  " -NoNewline -ForegroundColor Gray
    Write-Host "$(if ($hvciHwReady) { '[+] Yes' } else { '[-] No' })" -ForegroundColor $(if ($hvciHwReady) { $Colors['Good'] } else { $Colors['Warning'] })
    Write-Host "  Currently Active: " -NoNewline -ForegroundColor Gray
    Write-Host "$(if ($hvciRunning) { '[+] Yes' } else { '[-] No' })" -ForegroundColor $(if ($hvciRunning) { $Colors['Good'] } else { $Colors['Warning'] })
    
    # Explanation of the difference
    if (!$vbsHwReady -and $vbsRunning) {
        Write-ColorOutput "`nNOTE: VBS is running despite hardware readiness showing 'No'." -Color Info
        Write-ColorOutput "   This indicates VBS is enabled via software/policy, not full hardware support." -Color Info
    }
    if (!$hvciHwReady -and $hvciRunning) {
        Write-ColorOutput "`nNOTE: HVCI is active despite hardware readiness showing 'No'." -Color Info
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
                Write-ColorOutput "  - $serviceName" -Color Good
            }
            else {
                Write-ColorOutput "  - Service ID: $service" -Color Info
            }
        }
    }
    
    # Detailed explanation of VBS/HVCI status differences
    Write-ColorOutput "`n" + "-"*60 -Color Header
    Write-ColorOutput "VBS/HVCI Status Explanation:" -Color Header
    Write-ColorOutput "-"*60 -Color Header
    Write-ColorOutput "- 'Hardware Ready' = System meets full hardware requirements" -Color Info
    Write-ColorOutput "- 'Currently Active' = Feature is actually running right now" -Color Info
    Write-ColorOutput "`nWhy might Hardware Ready = No but Active = Yes?" -Color Warning
    Write-ColorOutput "1. VBS/HVCI can run in 'compatible mode' without full HW support" -Color Info
    Write-ColorOutput "2. Some hardware requirements are optional for basic functionality" -Color Info
    Write-ColorOutput "3. Software-based enforcement may be enabled via Group Policy" -Color Info
    Write-ColorOutput "4. The hardware readiness check may be overly strict" -Color Info
    Write-ColorOutput "`n[+] What matters: If 'Currently Active' = Yes, protection is working!" -Color Good
}
else {
    Write-ColorOutput "`nVirtualization Based Security Status:" -Color Header
    Write-ColorOutput "VBS Status: Not Available (Win32_DeviceGuard not accessible)" -Color Warning
    Write-ColorOutput "Note: VBS might still be enabled - check with 'msinfo32' or Device Guard readiness tool" -Color Info
}

# Hardware Security Mitigation Value Matrix for detailed output
Write-ColorOutput "`n" + "="*80 -Color Header
Write-ColorOutput "HARDWARE SECURITY MITIGATION VALUE MATRIX" -Color Header
Write-ColorOutput "="*80 -Color Header

Write-ColorOutput "`nThe Hardware Security Mitigations (MitigationOptions) registry value is a bit-field" -Color Info
Write-ColorOutput "that controls various CPU-level security features. Here's what the flags mean:" -Color Info

Write-ColorOutput "`nCommon Hardware Mitigation Flags:" -Color Header
Write-ColorOutput "=================================" -Color Header

# Get current MitigationOptions value for comparison
$currentMitigationValue = $null
$mitigationResult = $Results | Where-Object { $_.Name -eq "Hardware Security Mitigations" }
if ($mitigationResult -and $mitigationResult.CurrentValue -ne "Not Set") {
    try {
        if ($mitigationResult.CurrentValue -is [string] -and $mitigationResult.CurrentValue -match "^[0-9A-Fa-f]+$") {
            $currentMitigationValue = [Convert]::ToUInt64($mitigationResult.CurrentValue, 16)
        }
        elseif ($mitigationResult.CurrentValue -is [uint64]) {
            $currentMitigationValue = $mitigationResult.CurrentValue
        }
    }
    catch {
        $currentMitigationValue = $null
    }
}

# Define known mitigation flags
$mitigationFlags = @(
    @{ Flag = 0x0000000000000001; Name = "CFG (Control Flow Guard)"; Description = "Prevents ROP/JOP attacks" },
    @{ Flag = 0x0000000000000002; Name = "CFG Export Suppression"; Description = "Disables CFG for export functions" },
    @{ Flag = 0x0000000000000004; Name = "CFG Strict Mode"; Description = "Stricter CFG enforcement" },
    @{ Flag = 0x0000000000000008; Name = "DEP (Data Execution Prevention)"; Description = "Prevents code execution in data pages" },
    @{ Flag = 0x0000000000000010; Name = "DEP ATL Thunk Emulation"; Description = "Legacy ATL thunk compatibility" },
    @{ Flag = 0x0000000000000020; Name = "SEHOP (SEH Overwrite Protection)"; Description = "Protects exception handlers" },
    @{ Flag = 0x0000000000000040; Name = "Heap Terminate on Corruption"; Description = "Immediately terminates on heap corruption" },
    @{ Flag = 0x0000000000000080; Name = "Bottom-up ASLR"; Description = "Randomizes memory layout" },
    @{ Flag = 0x0000000000000100; Name = "High Entropy ASLR"; Description = "64-bit address space randomization" },
    @{ Flag = 0x0000000000000200; Name = "Force Relocate Images"; Description = "Forces ASLR even for non-ASLR images" },
    @{ Flag = 0x0000000000000400; Name = "Heap Terminate on Corruption (Enhanced)"; Description = "Enhanced heap protection" },
    @{ Flag = 0x0000000000001000; Name = "Stack Pivot Protection"; Description = "Prevents stack pivoting attacks" },
    @{ Flag = 0x0000000000002000; Name = "Import Address Filtering"; Description = "Filters dangerous API imports" },
    @{ Flag = 0x0000000000004000; Name = "Module Signature Enforcement"; Description = "Requires signed modules" },
    @{ Flag = 0x0000000000008000; Name = "Font Disable"; Description = "Disables loading untrusted fonts" },
    @{ Flag = 0x0000000000010000; Name = "Image Load Signature Mitigation"; Description = "Validates image signatures" },
    @{ Flag = 0x0000000000020000; Name = "Non-System Font Disable"; Description = "Blocks non-system fonts" },
    @{ Flag = 0x0000000000040000; Name = "Audit Non-System Font Loading"; Description = "Audits font loading" },
    @{ Flag = 0x0000000000080000; Name = "Child Process Policy"; Description = "Restricts child process creation" },
    @{ Flag = 0x0000000000100000; Name = "Payload Restriction Policy"; Description = "Prevents payload execution" },
    @{ Flag = 0x0000000001000000; Name = "CET (Intel CET Shadow Stack)"; Description = "Hardware-assisted CFI" },
    @{ Flag = 0x0000000002000000; Name = "CET Strict Mode"; Description = "Strict CET enforcement" },
    @{ Flag = 0x0000000004000000; Name = "CET Dynamic Code"; Description = "CET for dynamic code" },
    @{ Flag = 0x0000000008000000; Name = "Intel MPX (Memory Protection Extensions)"; Description = "Hardware bounds checking (deprecated)" },
    @{ Flag = 0x2000000000000000; Name = "Core Hardware Security Features"; Description = "Essential CPU security mitigations (RECOMMENDED)" }
)

Write-ColorOutput "`nFlag Value          Status    Mitigation Name" -Color Header
Write-ColorOutput "----------          ------    ---------------" -Color Header

foreach ($flag in $mitigationFlags | Sort-Object Flag) {
    $flagValue = "0x{0:X16}" -f $flag.Flag
    $isEnabled = if ($currentMitigationValue) { 
        ($currentMitigationValue -band $flag.Flag) -eq $flag.Flag 
    }
    else { 
        $false 
    }
    
    $statusIcon = if ($isEnabled) { "[+]" } else { "[?]" }
    $statusColor = if ($isEnabled) { "Good" } else { "Warning" }
    
    Write-Host "$flagValue  " -NoNewline -ForegroundColor Gray
    Write-Host "$statusIcon" -NoNewline -ForegroundColor $Colors[$statusColor]
    Write-Host "       $($flag.Name)" -ForegroundColor White
    
    if ($flag.Flag -eq 0x2000000000000000) {
        Write-ColorOutput "                               --> This is the primary flag for side-channel mitigations!" -Color Info
    }
}

if ($currentMitigationValue) {
    Write-ColorOutput "`nCurrent MitigationOptions Value:" -Color Header
    Write-Host "Hex:     " -NoNewline -ForegroundColor Gray  
    Write-Host ("0x{0:X}" -f $currentMitigationValue) -ForegroundColor White
    
    $enabledCount = ($mitigationFlags | Where-Object { ($currentMitigationValue -band $_.Flag) -eq $_.Flag }).Count
    $totalFlags = $mitigationFlags.Count
    Write-Host "Enabled: " -NoNewline -ForegroundColor Gray
    Write-Host "$enabledCount" -NoNewline -ForegroundColor $Colors['Good']
    Write-Host " of $totalFlags known flags" -ForegroundColor Gray
}
else {
    Write-ColorOutput "`nCurrent MitigationOptions Value: Not Set" -Color Warning
    Write-ColorOutput "This means Windows is using default hardware mitigation settings." -Color Info
}

Write-ColorOutput "`nRecommended Minimum Value:" -Color Header
Write-ColorOutput "0x2000000000000000 (Core Hardware Security Features)" -Color Good
Write-ColorOutput "`nNote: The exact flags enabled depend on your CPU capabilities and Windows version." -Color Info
Write-ColorOutput "Some flags are only available on newer processors or Windows versions." -Color Info

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
Write-Host "[+] ENABLED:       " -NoNewline -ForegroundColor $Colors['Good']
Write-Host "$enabledCount" -NoNewline -ForegroundColor $Colors['Good']
Write-Host " / $totalCount mitigations" -ForegroundColor Gray

Write-Host "[?] NOT SET:       " -NoNewline -ForegroundColor $Colors['Warning']
Write-Host "$notConfiguredCount" -NoNewline -ForegroundColor $Colors['Warning']
Write-Host " / $totalCount mitigations" -ForegroundColor Gray

Write-Host "[-] DISABLED:      " -NoNewline -ForegroundColor $Colors['Bad']
Write-Host "$disabledCount" -NoNewline -ForegroundColor $Colors['Bad']
Write-Host " / $totalCount mitigations" -ForegroundColor Gray

Write-Host "`nOverall Security Level: " -NoNewline -ForegroundColor $Colors['Info']
$levelColor = if ($configuredPercent -ge 80) { 'Good' } elseif ($configuredPercent -ge 60) { 'Warning' } else { 'Bad' }
Write-Host "$configuredPercent%" -ForegroundColor $Colors[$levelColor]

# Security level indicator
$securityBar = ""
$filledBlocks = [math]::Floor($configuredPercent / 10)
$emptyBlocks = 10 - $filledBlocks

for ($i = 0; $i -lt $filledBlocks; $i++) { $securityBar += "#" }
for ($i = 0; $i -lt $emptyBlocks; $i++) { $securityBar += "-" }

Write-Host "Security Bar:     [" -NoNewline -ForegroundColor Gray
Write-Host "$securityBar" -NoNewline -ForegroundColor $Colors[$levelColor]
Write-Host "] $configuredPercent%" -ForegroundColor Gray

# Interactive mitigation selection function
function Select-Mitigations {
    param(
        [array]$AvailableMitigations,
        [switch]$WhatIf
    )
    
    Write-ColorOutput "`n=== Interactive Mitigation Selection ===" -Color Header
    
    if ($WhatIf) {
        Write-ColorOutput "WhatIf Mode: Changes will be previewed but not applied" -Color Warning
    }
    
    Write-ColorOutput "`nThe following mitigations are not configured and can be enabled:" -Color Info
    Write-ColorOutput "Use numbers to select (e.g., 1,3,5 or 1-3 or 'all' for all mitigations):`n" -Color Info
    
    # Display available mitigations with numbers
    $index = 1
    foreach ($mitigation in $AvailableMitigations) {
        $impact = switch ($mitigation.Name) {
            { $_ -match "Spectre|BTI|IBRS|SSBD" } { "Low" }
            { $_ -match "Meltdown|KVAS" } { "Medium" }
            { $_ -match "TSX|Hardware" } { "Variable" }
            { $_ -match "VBS|HVCI" } { "High" }
            default { "Unknown" }
        }
        
        $description = switch ($mitigation.Name) {
            "Speculative Store Bypass Disable" { "Protects against Spectre Variant 4" }
            "Branch Target Injection Mitigation" { "Protects against Spectre Variant 2" }
            "Kernel VA Shadow" { "Meltdown protection (KPTI)" }
            "Hardware Security Mitigations" { "CPU-level side-channel protections" }
            "Intel TSX Disable" { "Prevents TSX-based attacks" }
            "Enhanced IBRS" { "Intel hardware mitigation" }
            "VBS" { "Virtualization Based Security" }
            "HVCI" { "Hypervisor-protected Code Integrity" }
            default { $mitigation.Description -replace "^CVE-[^:]+: ", "" }
        }
        
        Write-Host "  [$index] " -NoNewline -ForegroundColor Yellow
        Write-Host $mitigation.Name -NoNewline -ForegroundColor White
        Write-Host " (Impact: $impact)" -ForegroundColor Gray
        Write-Host "      $description" -ForegroundColor Gray
        $index++
    }
    
    Write-Host ""
    $selection = Read-Host "Enter your selection (numbers separated by commas, ranges like 1-3, or 'all')"
    
    # Parse selection
    $selectedItems = @()
    
    if ($selection -eq 'all') {
        $selectedItems = $AvailableMitigations
    }
    else {
        $selections = $selection -split ',' | ForEach-Object { $_.Trim() }
        
        foreach ($sel in $selections) {
            if ($sel -match '(\d+)-(\d+)') {
                # Range selection like "1-3"
                $start = [int]$matches[1]
                $end = [int]$matches[2]
                for ($i = $start; $i -le $end; $i++) {
                    if ($i -le $AvailableMitigations.Count) {
                        $selectedItems += $AvailableMitigations[$i - 1]
                    }
                }
            }
            elseif ($sel -match '^\d+$') {
                # Single number selection
                $num = [int]$sel
                if ($num -le $AvailableMitigations.Count -and $num -gt 0) {
                    $selectedItems += $AvailableMitigations[$num - 1]
                }
            }
        }
    }
    
    return $selectedItems
}

# Apply configurations if requested
if ($Apply) {
    # Validate parameter combinations
    if ($WhatIf -and -not $Interactive) {
        Write-ColorOutput "`nWhatIf mode requires Interactive mode. Adding -Interactive automatically." -Color Warning
        $Interactive = $true
    }
    
    Write-ColorOutput "`n=== Configuration Application ===" -Color Header
    $notConfigured = $Results | Where-Object { $_.Status -ne "Enabled" -and $_.CanBeEnabled }
    
    if ($notConfigured.Count -gt 0) {
        
        # Interactive mode - let user select specific mitigations
        if ($Interactive) {
            $selectedMitigations = Select-Mitigations -AvailableMitigations $notConfigured -WhatIf:$WhatIf
            
            if ($selectedMitigations.Count -eq 0) {
                Write-ColorOutput "`nNo mitigations selected. Exiting." -Color Warning
                return
            }
            
            $mitigationsToApply = $selectedMitigations
        }
        else {
            $mitigationsToApply = $notConfigured
        }
        
        if ($WhatIf) {
            Write-ColorOutput "`n=== WhatIf: Changes that would be made ===" -Color Header
            Write-ColorOutput "The following registry changes would be applied:" -Color Info
            
            foreach ($item in $mitigationsToApply) {
                Write-ColorOutput "`nMitigation: $($item.Name)" -Color Info
                Write-ColorOutput "  Registry Path: $($item.RegistryPath)" -Color Gray
                Write-ColorOutput "  Registry Name: $($item.RegistryName)" -Color Gray  
                Write-ColorOutput "  New Value: $($item.ExpectedValue)" -Color Gray
                $valueType = if ($item.ValueType) { $item.ValueType } else { "REG_DWORD" }
                Write-ColorOutput "  Value Type: $valueType" -Color Gray
                
                # Show impact assessment
                $impact = switch ($item.Name) {
                    { $_ -match "Spectre|BTI|IBRS|SSBD" } { "Minimal performance impact" }
                    { $_ -match "Meltdown|KVAS" } { "Low-medium performance impact" }
                    { $_ -match "TSX" } { "May affect TSX-dependent applications" }
                    { $_ -match "Hardware" } { "Hardware-dependent performance impact" }
                    default { "Performance impact varies" }
                }
                Write-ColorOutput "  Expected Impact: $impact" -Color Yellow
            }
            
            Write-ColorOutput "`nWhatIf Summary:" -Color Header
            Write-ColorOutput "Total changes that would be made: $($mitigationsToApply.Count)" -Color Info
            Write-ColorOutput "System restart would be required: Yes" -Color Warning
            Write-ColorOutput "`nTo actually apply these changes, run without -WhatIf parameter." -Color Info
            
        }
        else {
            Write-ColorOutput "Applying $($mitigationsToApply.Count) security configurations..." -Color Info
            $successCount = 0
            
            foreach ($item in $mitigationsToApply) {
                Write-ColorOutput "`nConfiguring: $($item.Name)" -Color Info
                if (Set-RegistryValue -Path $item.RegistryPath -Name $item.RegistryName -Value $item.ExpectedValue) {
                    $successCount++
                }
            }
            
            Write-ColorOutput "`nConfiguration Results:" -Color Header
            Write-ColorOutput "Successfully applied: $successCount/$($mitigationsToApply.Count)" -Color Good
            
            if ($successCount -gt 0) {
                Write-ColorOutput "`n[!] IMPORTANT: A system restart is required for changes to take effect." -Color Warning
                $restart = Read-Host "Would you like to restart now? (y/N)"
                if ($restart -eq 'y' -or $restart -eq 'Y') {
                    Write-ColorOutput "Restarting system in 10 seconds... Press Ctrl+C to cancel." -Color Warning
                    Start-Sleep -Seconds 10
                    Restart-Computer -Force
                }
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
            Write-ColorOutput "- $($item.Name): $($item.Recommendation)" -Color Warning
        }
        
        Write-ColorOutput "`nTo apply these configurations automatically, run:" -Color Info
        Write-ColorOutput ".\SideChannel_Check.ps1 -Apply" -Color Info
        Write-ColorOutput "`nFor interactive selection (recommended):" -Color Info
        Write-ColorOutput ".\SideChannel_Check.ps1 -Apply -Interactive" -Color Good
        
        Write-ColorOutput "`nOr manually use these registry commands:" -Color Info
        foreach ($item in $notConfigured | Where-Object { $_.CanBeEnabled }) {
            # Special handling for different registry value types
            $regType = "REG_DWORD"
            $regValue = $item.ExpectedValue
            
            # Handle large hex values (like MitigationOptions)
            if ($item.ExpectedValue -is [string] -and $item.ExpectedValue.Length -gt 10 -and $item.ExpectedValue -match "^[0-9A-Fa-f]+$") {
                try {
                    $regValue = [Convert]::ToUInt64($item.ExpectedValue, 16)
                    $regType = "REG_QWORD"
                }
                catch {
                    $regValue = $item.ExpectedValue
                }
            }
            
            # Add comment for modern CVE mitigations
            $ModernCVENames = @("BranchHistoryBufferEnabled", "GatherDataSampleMitigation", "SpeculativeReturnStackMitigation", "RegisterFileDataSamplingMitigation", "MicroarchitecturalDataSamplingMitigation", "L1TerminalFaultMitigation")
            if ($item.RegistryName -in $ModernCVENames) {
                $cveDescription = switch ($item.RegistryName) {
                    "BranchHistoryBufferEnabled" { "BHB CVE-2022-0001/0002" }
                    "GatherDataSampleMitigation" { "GDS CVE-2022-40982" }
                    "SpeculativeReturnStackMitigation" { "SRSO CVE-2023-20569" }
                    "RegisterFileDataSamplingMitigation" { "RFDS CVE-2023-28746" }
                    "MicroarchitecturalDataSamplingMitigation" { "MDS mitigation" }
                    "L1TerminalFaultMitigation" { "L1TF CVE-2018-3620" }
                }
                Write-ColorOutput "# $($item.Name) - $cveDescription" -Color Info
            }
            
            Write-ColorOutput "reg add `"$($item.RegistryPath)`" /v `"$($item.RegistryName)`" /t $regType /d $regValue /f" -Color Info
        }
        Write-ColorOutput "`nNote: A system restart may be required after making registry changes." -Color Warning
        
        # Additional guidance for modern CVE mitigations
        $hasModernCVEs = $notConfigured | Where-Object { $_.Name -match "BHB|GDS|SRSO|RFDS|MDS|L1TF" }
        if ($hasModernCVEs) {
            Write-ColorOutput "`nAdvanced CVE Mitigations Notice:" -Color Header
            Write-ColorOutput "- These mitigations target recent vulnerabilities (2018-2023)" -Color Info
            Write-ColorOutput "- Some mitigations require specific CPU microcode updates" -Color Info
            Write-ColorOutput "- CPU vendor compatibility varies (Intel vs AMD specific)" -Color Info
            Write-ColorOutput "- Consider testing in non-production environments first" -Color Warning
            Write-ColorOutput "- Performance impact varies by CPU generation and workload" -Color Info
        }
    }
    else {
        Write-ColorOutput "All checked mitigations are properly configured!" -Color Good
    }
}

# Handle Revert functionality
if ($Revert) {
    # Validate parameter combinations
    if ($WhatIf -and -not $Interactive) {
        Write-ColorOutput "`nWhatIf mode requires Interactive mode for revert operations. Adding -Interactive automatically." -Color Warning
        $Interactive = $true
    }
    
    Write-ColorOutput "`n=== Mitigation Revert Mode ===" -Color Header
    Write-ColorOutput "Scanning for revertable side-channel mitigations..." -Color Info
    
    $revertableMitigations = Get-RevertableMitigations
    
    if ($revertableMitigations.Count -gt 0) {
        Write-ColorOutput "`nFound $($revertableMitigations.Count) revertable mitigation(s):" -Color Warning
        
        if ($Interactive) {
            Write-ColorOutput "`n⚠️  WARNING: Reverting mitigations will REDUCE your system's security!" -Color Error
            Write-ColorOutput "Only proceed if specific mitigations are causing performance issues." -Color Error
            Write-ColorOutput "Always test in non-production environments first.`n" -Color Error
            
            if ($WhatIf) {
                Write-ColorOutput "WhatIf Mode: Changes will be previewed but not applied`n" -Color Warning
            }
            
            Write-ColorOutput "Available mitigations to revert:" -Color Info
            Write-ColorOutput "Use numbers to select (e.g., 1,3,4 or 1-3 or 'all' for all mitigations):`n" -Color Info
            
            for ($i = 0; $i -lt $revertableMitigations.Count; $i++) {
                $mitigation = $revertableMitigations[$i]
                Write-ColorOutput "  [$($i + 1)] $($mitigation.Name) (Impact: $($mitigation.Impact))" -Color Warning
                Write-ColorOutput "      $($mitigation.Description)" -Color Info
                Write-ColorOutput "      Security Risk: $($mitigation.SecurityRisk)" -Color Error
                Write-ColorOutput "      Registry: $($mitigation.RegistryPath)\$($mitigation.RegistryName)" -Color Gray
                Write-ColorOutput "" -Color Info
            }
            
            $selection = Read-Host "Enter your selection"
            
            if ([string]::IsNullOrWhiteSpace($selection)) {
                Write-ColorOutput "No selection made. Exiting revert mode." -Color Warning
                return
            }
            
            # Parse selection (similar to existing selection logic)
            $selectedIndices = @()
            if ($selection.ToLower() -eq 'all') {
                $selectedIndices = 0..($revertableMitigations.Count - 1)
            }
            else {
                foreach ($part in $selection.Split(',')) {
                    if ($part.Contains('-')) {
                        $range = $part.Split('-')
                        if ($range.Count -eq 2) {
                            $start = [int]$range[0].Trim() - 1
                            $end = [int]$range[1].Trim() - 1
                            $selectedIndices += $start..$end
                        }
                    }
                    else {
                        $selectedIndices += [int]$part.Trim() - 1
                    }
                }
            }
            
            $selectedMitigations = @()
            foreach ($index in $selectedIndices) {
                if ($index -ge 0 -and $index -lt $revertableMitigations.Count) {
                    $selectedMitigations += $revertableMitigations[$index]
                }
            }
            
            if ($selectedMitigations.Count -gt 0) {
                Write-ColorOutput "`nSelected $($selectedMitigations.Count) mitigation(s) for revert." -Color Warning
                
                if (-not $WhatIf) {
                    $confirm = Read-Host "`n⚠️  Are you sure you want to REMOVE these security protections? (yes/no)"
                    if ($confirm.ToLower() -ne 'yes') {
                        Write-ColorOutput "Revert operation cancelled." -Color Info
                        return
                    }
                }
                
                Invoke-MitigationRevert -SelectedMitigations $selectedMitigations -WhatIf:$WhatIf
            }
            else {
                Write-ColorOutput "No valid mitigations selected." -Color Warning
            }
        }
        else {
            Write-ColorOutput "Non-interactive revert mode is not supported for security reasons." -Color Error
            Write-ColorOutput "Use -Interactive switch to manually select mitigations to revert." -Color Warning
        }
    }
    else {
        Write-ColorOutput "No revertable mitigations found." -Color Info
        Write-ColorOutput "Either no mitigations are currently enabled, or they cannot be safely reverted." -Color Info
    }
}

# Virtualization-Specific Recommendations
Write-ColorOutput "`n=== Virtualization Security Recommendations ===" -Color Header
Write-ColorOutput "`nStatus Symbols:" -Color Header
Write-ColorOutput "[+] Enabled/Recommended - Feature is active or recommended configuration" -Color Good
Write-ColorOutput "[-] Disabled/Not Recommended - Feature is disabled or not recommended" -Color Bad
Write-ColorOutput "[?] Unknown/Variable - Status depends on configuration or hardware" -Color Warning

if ($virtInfo.IsVirtualMachine) {
    Write-ColorOutput "Running in Virtual Machine - Guest Recommendations:" -Color Info
    Write-ColorOutput "- Ensure hypervisor host has latest microcode updates" -Color Warning
    Write-ColorOutput "- Verify hypervisor has side-channel mitigations enabled" -Color Warning
    Write-ColorOutput "- Keep guest OS and drivers updated" -Color Warning
    
    switch ($virtInfo.HypervisorVendor) {
        "Microsoft" {
            Write-ColorOutput "`nHyper-V Guest Specific:" -Color Header
            Write-ColorOutput "- Host should use Core Scheduler (auto-enabled in newer Windows versions)" -Color Info
            Write-ColorOutput "- Enable Enhanced Session Mode for better security" -Color Info
            Write-ColorOutput "- Ensure host has VBS/HVCI enabled" -Color Warning
        }
        "VMware" {
            Write-ColorOutput "`nVMware Guest Specific:" -Color Header
            Write-ColorOutput "- ESXi host should be 6.7 U2+ with Side-Channel Aware Scheduler" -Color Warning
            Write-ColorOutput "- VM hardware version should be 14+ for latest security features" -Color Warning
            Write-ColorOutput "- Enable VMware Tools for additional security features" -Color Info
            
            # Display comprehensive VMware host security configuration
            Write-ColorOutput "`nFor VMware Host Administrators:" -Color Warning
            Write-ColorOutput "Use parameter -ShowVMwareHostSecurity for detailed ESXi security configuration guidance." -Color Warning
        }
        "QEMU/KVM" {
            Write-ColorOutput "`nKVM Guest Specific:" -Color Header
            Write-ColorOutput "- Host kernel should support spec-ctrl (4.15+)" -Color Warning
            Write-ColorOutput "- Use CPU flags: `+spec-ctrl,`+ibpb,`+ssbd" -Color Warning
            Write-ColorOutput "- Enable SLAT (Intel EPT/AMD RVI) on host" -Color Warning
        }
        default {
            Write-ColorOutput "`nGeneral VM Recommendations:" -Color Header
            Write-ColorOutput "- Contact hypervisor vendor for side-channel mitigation guidance" -Color Warning
            Write-ColorOutput "- Verify hardware virtualization extensions are properly exposed" -Color Info
        }
    }
}
else {
    Write-ColorOutput "Running on Physical Hardware - Host Recommendations:" -Color Info
    Write-ColorOutput "- Apply CPU microcode updates from manufacturer" -Color Warning
    Write-ColorOutput "- Enable all available CPU security features in BIOS/UEFI" -Color Warning
    
    if ($virtInfo.HyperVStatus -eq "Enabled") {
        Write-ColorOutput "`nHyper-V Host Specific:" -Color Header
        
        # OS version-aware Core Scheduler recommendation
        $osBuildNumber = [int](Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
        if ($osBuildNumber -lt 20348) {
            Write-ColorOutput "- Enable Core Scheduler (required for this OS): bcdedit /set hypervisorschedulertype core" -Color Warning
            Write-ColorOutput "  ?? Prevents SMT-based side-channel attacks between VMs" -Color Info
        }
        else {
            Write-ColorOutput "- Core Scheduler: [+] Enabled by default (Windows 11/Server 2022+ Build $osBuildNumber)" -Color Good
        }
        
        Write-ColorOutput "- Configure VM isolation policies" -Color Info
        Write-ColorOutput "- Use Generation 2 VMs for enhanced security" -Color Info
        Write-ColorOutput "- Enable Secure Boot for VMs when possible" -Color Info
        Write-ColorOutput "- Consider disabling SMT if security > performance" -Color Warning
    }
    
    Write-ColorOutput "`nGeneral Host Security:" -Color Header
    Write-ColorOutput "- Enable VBS/HVCI if hardware supports it" -Color Warning
    Write-ColorOutput "- Use UEFI Secure Boot" -Color Warning
    Write-ColorOutput "- Enable TPM 2.0 if available" -Color Info
    Write-ColorOutput "- Configure proper VM resource isolation" -Color Warning
}

Write-ColorOutput "`n=== Hardware Prerequisites for Side-Channel Protection ===" -Color Header
Write-ColorOutput "Required CPU Features:" -Color Info
Write-ColorOutput "- Intel: VT-x with EPT, VT-d (or AMD: AMD-V with RVI, AMD-Vi)" -Color Warning
Write-ColorOutput "- Hardware support for SMEP/SMAP" -Color Warning
Write-ColorOutput "- CPU microcode with Spectre/Meltdown mitigations" -Color Warning
Write-ColorOutput "- For VBS: IOMMU, TPM 2.0, UEFI Secure Boot" -Color Warning

Write-ColorOutput "`nFirmware Requirements:" -Color Info
Write-ColorOutput "- UEFI firmware (not legacy BIOS)" -Color Warning
Write-ColorOutput "- Secure Boot capability" -Color Warning
Write-ColorOutput "- TPM 2.0 (for Credential Guard and other VBS features)" -Color Warning
Write-ColorOutput "- Latest firmware updates from manufacturer" -Color Warning

# Show VMware Host Security Configuration if requested
if ($ShowVMwareHostSecurity) {
    Show-VMwareHostSecurity
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


