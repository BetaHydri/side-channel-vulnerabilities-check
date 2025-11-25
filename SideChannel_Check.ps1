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
    Basic security assessment
    
.EXAMPLE
    .\SideChannel_Check.ps1 -Detailed
    Detailed security assessment with registry paths
    
.EXAMPLE
    .\SideChannel_Check.ps1 -ShowVMwareHostSecurity
    Assessment with VMware ESXi host security guide
    
.EXAMPLE
    .\SideChannel_Check.ps1 -Detailed -ShowVMwareHostSecurity
    Detailed assessment with VMware guidance
    
.EXAMPLE
    .\SideChannel_Check.ps1 -Apply
    Apply all recommended mitigations automatically
    
.EXAMPLE
    .\SideChannel_Check.ps1 -Apply -Interactive
    Interactive mitigation selection and application
    
.EXAMPLE
    .\SideChannel_Check.ps1 -Apply -Interactive -WhatIf
    Preview changes in interactive mode without applying them
    
.EXAMPLE
    .\SideChannel_Check.ps1 -ExportPath "C:\temp\SideChannelReport.csv"
    Export assessment results to CSV file

.EXAMPLE
    .\SideChannel_Check.ps1 -Detailed -ExportPath "C:\temp\DetailedReport.csv"
    Detailed assessment with CSV export

.EXAMPLE
    .\SideChannel_Check.ps1 -Revert -Interactive
    Interactively revert specific mitigations
    
.EXAMPLE
    .\SideChannel_Check.ps1 -Revert -Interactive -WhatIf
    Preview what would be reverted without making changes
    
.NOTES
    Author: Jan Tiedemann
    Version: 2.8
    Requires: PowerShell 5.1+ and Administrator privileges
    Based on: Microsoft KB4073119
    GitHub: https://github.com/BetaHydri/side-channel-vulnerabilities-check
    
    PARAMETER SETS:
    - Assessment: Default, Detailed, VMware guide, Export combinations
    - Modification: Apply (automatic), ApplyInteractive (manual), Revert (interactive only)
    - Logical constraints: Interactive and WhatIf require Apply or Revert operations
#>

param(
    # Assessment Parameters (can be combined freely)
    [Parameter(ParameterSetName = 'Assessment')]
    [Parameter(ParameterSetName = 'Apply')]
    [Parameter(ParameterSetName = 'ApplyInteractive')]
    [Parameter(ParameterSetName = 'ApplyWhatIf')]
    [Parameter(ParameterSetName = 'RevertInteractive')]
    [Parameter(ParameterSetName = 'RevertWhatIf')]
    [switch]$Detailed,
    
    [Parameter(ParameterSetName = 'Assessment')]
    [Parameter(ParameterSetName = 'Apply')]
    [Parameter(ParameterSetName = 'ApplyInteractive')]
    [Parameter(ParameterSetName = 'ApplyWhatIf')]
    [Parameter(ParameterSetName = 'RevertInteractive')]
    [Parameter(ParameterSetName = 'RevertWhatIf')]
    [ValidateScript({
            if (-not (Test-Path (Split-Path $_ -Parent) -PathType Container)) {
                throw "Export directory does not exist: $(Split-Path $_ -Parent)"
            }
            if ($_ -notmatch '\.(csv|txt)$') {
                throw "Export file must have .csv or .txt extension"
            }
            return $true
        })]
    [string]$ExportPath,
    
    # VMware Security Guide (can be combined with assessment parameters)
    [Parameter(ParameterSetName = 'Assessment')]
    [Parameter(ParameterSetName = 'Apply')]
    [Parameter(ParameterSetName = 'ApplyInteractive')]
    [Parameter(ParameterSetName = 'ApplyWhatIf')]
    [Parameter(ParameterSetName = 'RevertInteractive')]
    [Parameter(ParameterSetName = 'RevertWhatIf')]
    [switch]$ShowVMwareHostSecurity,
    
    # Modification Parameters - Apply Operations
    [Parameter(ParameterSetName = 'Apply', Mandatory)]
    [Parameter(ParameterSetName = 'ApplyInteractive', Mandatory)]
    [Parameter(ParameterSetName = 'ApplyWhatIf', Mandatory)]
    [switch]$Apply,
    
    [Parameter(ParameterSetName = 'ApplyInteractive', Mandatory)]
    [Parameter(ParameterSetName = 'ApplyWhatIf', Mandatory)]
    [Parameter(ParameterSetName = 'RevertInteractive', Mandatory)]
    [Parameter(ParameterSetName = 'RevertWhatIf', Mandatory)]
    [switch]$Interactive,
    
    [Parameter(ParameterSetName = 'ApplyWhatIf', Mandatory)]
    [Parameter(ParameterSetName = 'RevertWhatIf', Mandatory)]
    [switch]$WhatIf,
    
    # Revert Operations (must use Interactive)
    [Parameter(ParameterSetName = 'RevertInteractive', Mandatory)]
    [Parameter(ParameterSetName = 'RevertWhatIf', Mandatory)]
    [switch]$Revert
)

# Initialize results array
$Results = @()

# PowerShell version compatibility detection
$PSVersion = $PSVersionTable.PSVersion.Major
$UseEmojis = $false  # Simplified approach for maximum compatibility

# Define simple, consistent category markers
$Emojis = @{
    Shield    = "[SW]"     # Software Mitigations
    Lock      = "[SF]"       # Security Features  
    Wrench    = "[HW]"     # Hardware Prerequisites
    Gear      = "[OT]"       # Other Mitigations
    Chart     = "[>>]"      # Summary/Progress
    Clipboard = "[--]"  # Status Legend
    Target    = "[>>]"     # Category Descriptions
}

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
    
    # Handle missing colors gracefully
    if ($Colors.ContainsKey($Color)) {
        Write-Host $Message -ForegroundColor $Colors[$Color]
    }
    elseif ($Color -in @('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White')) {
        # Direct color name
        Write-Host $Message -ForegroundColor $Color
    }
    else {
        # Fallback to white if color not found
        Write-Host $Message -ForegroundColor White
    }
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
    
    # Define categories for mitigation grouping
    $softwareMitigations = @(
        "Speculative Store Bypass Disable",
        "SSBD Feature Mask", 
        "Branch Target Injection Mitigation",
        "Kernel VA Shadow (Meltdown Protection)",
        "Enhanced IBRS",
        "Intel TSX Disable",
        "L1TF Mitigation",
        "MDS Mitigation",
        "CVE-2019-11135 Mitigation",
        "SBDR/SBDS Mitigation",
        "SRBDS Update Mitigation",
        "DRPW Mitigation"
    )
    
    $securityFeatures = @(
        "Hardware Security Mitigations",
        "Exception Chain Validation",
        "Supervisor Mode Access Prevention",
        "Windows Defender Exploit Guard ASLR",
        "Virtualization Based Security",
        "Hypervisor Code Integrity",
        "Credential Guard",
        "Windows Defender Application Guard"
    )
    
    $hardwarePrerequisites = @(
        "UEFI Firmware",
        "Secure Boot",
        "TPM 2.0",
        "Virtualization Technology",
        "IOMMU Support",
        "CPU Microcode"
    )
    
    # Helper function to categorize and format results
    function Get-CategorizedResults {
        param([array]$Results, [array]$CategoryNames, [string]$CategoryTitle, [string]$CategoryEmoji)
        
        $categoryResults = $Results | Where-Object { $_.Name -in $CategoryNames }
        if ($categoryResults.Count -gt 0) {
            Write-ColorOutput "`n$CategoryEmoji $CategoryTitle" -Color Header
            Write-ColorOutput ("=" * 60) -Color Header
            
            $tableData = @()
            foreach ($result in $categoryResults) {
                $status = switch ($result.Status) {
                    "Enabled" { "[+] Enabled" }
                    "Disabled" { "[-] Disabled" }
                    "Not Configured" { "[-] Not Set" }
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
            
            # Display the table for this category
            $tableData | Format-Table -AutoSize -Wrap
            
            # Category summary
            $enabled = ($categoryResults | Where-Object { $_.Status -eq "Enabled" }).Count
            $total = $categoryResults.Count
            $percentage = if ($total -gt 0) { [math]::Round(($enabled / $total) * 100, 1) } else { 0 }
            
            $summaryColor = switch ($percentage) {
                { $_ -ge 80 } { $Colors['Good'] }
                { $_ -ge 60 } { $Colors['Warning'] }
                default { $Colors['Bad'] }
            }
            
            Write-Host "Category Score: " -NoNewline
            $categoryText = "$enabled/$total enabled (" + [string]$percentage + "%)"
            Write-Host $categoryText -ForegroundColor $summaryColor
        }
    }
    
    # Display results by category
    Get-CategorizedResults -Results $Results -CategoryNames $softwareMitigations -CategoryTitle "SOFTWARE MITIGATIONS" -CategoryEmoji $Emojis.Shield
    Get-CategorizedResults -Results $Results -CategoryNames $securityFeatures -CategoryTitle "SECURITY FEATURES" -CategoryEmoji $Emojis.Lock
    Get-CategorizedResults -Results $Results -CategoryNames $hardwarePrerequisites -CategoryTitle "HARDWARE PREREQUISITES" -CategoryEmoji $Emojis.Wrench
    
    # Display any uncategorized results
    $allCategorized = $softwareMitigations + $securityFeatures + $hardwarePrerequisites
    $uncategorized = $Results | Where-Object { $_.Name -notin $allCategorized }
    if ($uncategorized.Count -gt 0) {
        Get-CategorizedResults -Results $uncategorized -CategoryNames ($uncategorized | Select-Object -ExpandProperty Name) -CategoryTitle "OTHER MITIGATIONS" -CategoryEmoji $Emojis.Gear
    }
    
    # Overall summary
    Write-ColorOutput ("`n" + $Emojis.Chart + " OVERALL SECURITY SUMMARY") -Color Header
    Write-ColorOutput ("=" * 60) -Color Header
    
    $totalEnabled = ($Results | Where-Object { $_.Status -eq "Enabled" }).Count
    $totalCount = $Results.Count
    $overallPercentage = if ($totalCount -gt 0) { [math]::Round(($totalEnabled / $totalCount) * 100, 1) } else { 0 }
    
    $overallColor = switch ($overallPercentage) {
        { $_ -ge 80 } { $Colors['Good'] }
        { $_ -ge 60 } { $Colors['Warning'] }
        default { $Colors['Bad'] }
    }
    
    Write-Host "Overall Protection Level: " -NoNewline
    $overallText = "$totalEnabled/$totalCount mitigations enabled (" + [string]$overallPercentage + "%)"
    Write-Host $overallText -ForegroundColor $overallColor
    
    # Create visual progress bar (PowerShell 5.1 compatible)
    $filledBlocks = [math]::Floor($overallPercentage / 10)
    $emptyBlocks = 10 - $filledBlocks
    $equalSigns = if ($filledBlocks -gt 0) { "=" * $filledBlocks } else { "" }
    $dashSigns = if ($emptyBlocks -gt 0) { "-" * $emptyBlocks } else { "" }
    $progressBar = "[" + $equalSigns + $dashSigns + "]"
    Write-Host "Security Level: " -NoNewline
    Write-Host $progressBar -ForegroundColor $overallColor
    
    # Display color-coded status legend
    Write-ColorOutput ("`n" + $Emojis.Clipboard + " STATUS LEGEND") -Color Header
    Write-Host "[+] Enabled" -ForegroundColor $Colors['Good'] -NoNewline
    Write-Host " - Mitigation is active and properly configured"
    Write-Host "[-] Disabled" -ForegroundColor $Colors['Bad'] -NoNewline  
    Write-Host " - Mitigation is explicitly disabled"
    Write-Host "[-] Not Set" -ForegroundColor $Colors['Warning'] -NoNewline
    Write-Host " - Registry value not configured (using defaults)"
    
    Write-ColorOutput ("`n" + $Emojis.Target + " CATEGORY DESCRIPTIONS") -Color Header
    Write-ColorOutput ($Emojis.Shield + "  SOFTWARE MITIGATIONS: OS-level protections against CPU vulnerabilities") -Color Info
    Write-ColorOutput ($Emojis.Lock + " SECURITY FEATURES: Advanced Windows security technologies") -Color Info
    Write-ColorOutput ($Emojis.Wrench + " HARDWARE PREREQUISITES: Required hardware security capabilities") -Color Info
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
        
        # Show appropriate configuration type based on RegistryPath
        if ($RegistryPath -match "^HKLM:|^HKCU:|^HKEY_") {
            Write-ColorOutput "Registry: $RegistryPath\$RegistryName" -Color Info
        }
        elseif ($RegistryPath -match "Hardware|UEFI|BIOS") {
            Write-ColorOutput "Hardware/UEFI: $RegistryName" -Color Info
        }
        elseif ($RegistryPath -match "Hyper-V") {
            Write-ColorOutput "Hyper-V: $RegistryName" -Color Info
        }
        elseif ($RegistryPath -match "VMware") {
            Write-ColorOutput "VMware: $RegistryName" -Color Info
        }
        else {
            Write-ColorOutput "Configuration: $RegistryPath\$RegistryName" -Color Info
        }
        
        Write-ColorOutput "Recommendation: $Recommendation" -Color Info
        Write-ColorOutput "Impact: $Impact" -Color Info
    }
    else {
        # Enhanced console output with clear status indicators
        $statusIndicator = switch ($status) {
            "Enabled" { "[+] ENABLED" }
            "Disabled" { "[-] DISABLED" }
            "Not Configured" { "[-] NOT SET" }
            default { $status }
        }
        
        $paddedName = $Name.PadRight(45)
        Write-Host "$paddedName : " -NoNewline
        Write-Host "$statusIndicator" -ForegroundColor $Colors[$statusColor] -NoNewline
        
        # Add current value for context
        if ($currentValue -ne $null -and $currentValue -ne "Not Set") {
            # Special formatting for Hardware Security Mitigations (MitigationOptions) to show hex
            if ($Name -eq "Hardware Security Mitigations" -and $currentValue -is [uint64]) {
                Write-Host " (Value: 0x$($currentValue.ToString('X16')))" -ForegroundColor Gray
            }
            else {
                Write-Host " (Value: $currentValue)" -ForegroundColor Gray
            }
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

function Get-HardwareRequirements {
    <#
    .SYNOPSIS
        Checks hardware requirements for security features like VBS, Secure Boot, TPM, UEFI
    .DESCRIPTION
        Detects and returns status of hardware security requirements
    #>
    
    $hwInfo = @{
        IsUEFI            = $false
        SecureBootEnabled = $false
        SecureBootCapable = $false
        TPMPresent        = $false
        TPMVersion        = "Not Available"
        IOMMUSupport      = "Unknown"
        VTxSupport        = $false
        SecureBootStatus  = "Not Available"
    }
    
    try {
        # Check for UEFI vs Legacy BIOS
        $firmwareType = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue
        if ($firmwareType -or (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "PEFirmwareType" -ErrorAction SilentlyContinue)) {
            $hwInfo.IsUEFI = $true
        }
        
        # Check Secure Boot status
        try {
            $secureBootState = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue
            if ($secureBootState) {
                $hwInfo.SecureBootEnabled = $secureBootState.UEFISecureBootEnabled -eq 1
                $hwInfo.SecureBootCapable = $true
                $hwInfo.SecureBootStatus = if ($hwInfo.SecureBootEnabled) { "Enabled" } else { "Available but Disabled" }
            }
            else {
                # Alternative check using PowerShell cmdlet if available
                try {
                    $secureBootUEFI = Get-SecureBootUEFI -ErrorAction SilentlyContinue
                    if ($secureBootUEFI) {
                        $hwInfo.SecureBootCapable = $true
                        $hwInfo.SecureBootStatus = "Capable (check UEFI settings)"
                    }
                }
                catch {
                    $hwInfo.SecureBootStatus = "Not Available"
                }
            }
        }
        catch {
            $hwInfo.SecureBootStatus = "Detection Failed"
        }
        
        # Check TPM
        try {
            $tpm = Get-CimInstance -Namespace "Root\cimv2\Security\MicrosoftTpm" -ClassName "Win32_Tpm" -ErrorAction SilentlyContinue
            if ($tpm) {
                $hwInfo.TPMPresent = $true
                $hwInfo.TPMVersion = "$($tpm.SpecVersion)"
            }
            else {
                # Alternative TPM check
                try {
                    $tpmWmi = Get-WmiObject -Namespace "Root\cimv2\Security\MicrosoftTpm" -Class "Win32_Tpm" -ErrorAction SilentlyContinue
                    if ($tpmWmi) {
                        $hwInfo.TPMPresent = $true
                        $hwInfo.TPMVersion = "Available"
                    }
                }
                catch {
                    # Try PowerShell TPM module
                    try {
                        $tpmInfo = Get-Tpm -ErrorAction SilentlyContinue
                        if ($tpmInfo) {
                            $hwInfo.TPMPresent = $tpmInfo.TmpPresent
                            $hwInfo.TPMVersion = if ($tmpInfo.TmpPresent) { "2.0" } else { "Not Available" }
                        }
                    }
                    catch {
                        $hwInfo.TPMVersion = "Detection Failed"
                    }
                }
            }
        }
        catch {
            $hwInfo.TPMVersion = "Detection Failed"
        }
        
        # Check CPU Virtualization Support (Enhanced Detection)
        try {
            $hwInfo.VTxSupport = $false
            $vtxStatus = "Not Detected"
            
            # Method 1: Check if Hyper-V is running (strong indicator of VT-x/AMD-V)
            try {
                $hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -ErrorAction SilentlyContinue
                if ($hyperv -and $hyperv.State -eq "Enabled") {
                    $hwInfo.VTxSupport = $true
                    $vtxStatus = "Enabled (Hyper-V Running)"
                }
            }
            catch { }
            
            # Method 2: Check Win32_Processor VirtualizationFirmwareEnabled
            if (-not $hwInfo.VTxSupport) {
                try {
                    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
                    if ($cpu.VirtualizationFirmwareEnabled -eq $true) {
                        $hwInfo.VTxSupport = $true
                        $vtxStatus = "Enabled (Firmware)"
                    }
                }
                catch { }
            }
            
            # Method 3: Check systeminfo command for virtualization
            if (-not $hwInfo.VTxSupport) {
                try {
                    $systemInfo = systeminfo.exe 2>$null | Out-String
                    if ($systemInfo -match "Virtualization Enabled In Firmware:\s*Yes") {
                        $hwInfo.VTxSupport = $true
                        $vtxStatus = "Enabled (System Info)"
                    }
                    elseif ($systemInfo -match "Hyper-V") {
                        $hwInfo.VTxSupport = $true
                        $vtxStatus = "Enabled (Hyper-V Detected)"
                    }
                }
                catch { }
            }
            
            # Method 4: Check CPU capabilities via WMI
            if (-not $hwInfo.VTxSupport) {
                try {
                    $cpuFeatures = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
                    # Intel VT-x detection
                    if ($cpuFeatures.Name -match "Intel") {
                        # Check if we can detect Intel VT-x flags
                        if ($cpuFeatures.Description -match "VT-x|Virtualization" -or 
                            $cpuFeatures.Characteristics -contains 32) {
                            # 32 = supports virtualization
                            $hwInfo.VTxSupport = $true
                            $vtxStatus = "Available (Intel VT-x)"
                        }
                    }
                    # AMD-V detection
                    elseif ($cpuFeatures.Name -match "AMD") {
                        if ($cpuFeatures.Description -match "AMD-V|SVM") {
                            $hwInfo.VTxSupport = $true
                            $vtxStatus = "Available (AMD-V)"
                        }
                    }
                }
                catch { }
            }
            
            # Method 5: Check if VMware Workstation/VirtualBox can run (indirect detection)
            if (-not $hwInfo.VTxSupport) {
                try {
                    # Check for virtualization-capable services
                    $vboxService = Get-Service -Name "VBoxSVC" -ErrorAction SilentlyContinue
                    $vmwareService = Get-Service -Name "VMware*" -ErrorAction SilentlyContinue
                    if ($vboxService -or $vmwareService) {
                        $hwInfo.VTxSupport = $true
                        $vtxStatus = "Likely Available (VM Software Installed)"
                    }
                }
                catch { }
            }
            
            # Method 6: Check WMIC for processor features (last resort)
            if (-not $hwInfo.VTxSupport) {
                try {
                    $wmicOutput = wmic cpu get Name, VirtualizationFirmwareEnabled /format:list 2>$null | Out-String
                    if ($wmicOutput -match "VirtualizationFirmwareEnabled=TRUE") {
                        $hwInfo.VTxSupport = $true
                        $vtxStatus = "Enabled (WMIC)"
                    }
                }
                catch { }
            }
            
            # Store detection method for debugging
            $hwInfo.VTxDetectionMethod = $vtxStatus
        }
        catch {
            $hwInfo.VTxSupport = $false
            $hwInfo.VTxDetectionMethod = "Detection Failed"
        }
        
        # Check IOMMU/VT-d support (basic detection)
        try {
            $vtdRegistry = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\iommu" -ErrorAction SilentlyContinue
            if ($vtdRegistry) {
                $hwInfo.IOMMUSupport = "Available"
            }
            else {
                # Check for Hyper-V IOMMU indicators
                $hvIommu = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -ErrorAction SilentlyContinue
                if ($hvIommu) {
                    $hwInfo.IOMMUSupport = "Available (Hyper-V)"
                }
                else {
                    $hwInfo.IOMMUSupport = "Unknown"
                }
            }
        }
        catch {
            $hwInfo.IOMMUSupport = "Detection Failed"
        }
    }
    catch {
        Write-Verbose "Error checking hardware requirements: $($_.Exception.Message)"
    }
    
    return $hwInfo
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
    
    Write-ColorOutput "[*] CRITICAL ESXi HOST SETTINGS:" -Color Header
    
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
    
    Write-ColorOutput "`n[*] VM-LEVEL CONFIGURATION:" -Color Header
    
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
    
    Write-ColorOutput "`n[*] VERIFICATION COMMANDS:" -Color Header
    
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
    
    Write-ColorOutput "`n[*] PERFORMANCE IMPACT SUMMARY:" -Color Header
    
    $performanceTable = @(
        @{ Mitigation = "Side-Channel Aware Scheduler"; Impact = "2-5%"; Recommendation = "Enable for multi-tenant environments" }
        @{ Mitigation = "L1TF Protection"; Impact = "5-15%"; Recommendation = "Critical for untrusted VMs" }
        @{ Mitigation = "Full Hyperthreading Disable"; Impact = "20-40%"; Recommendation = "Only for highest security requirements" }
        @{ Mitigation = "MDS Mitigation"; Impact = "3-8%"; Recommendation = "Enable for Intel hosts" }
        @{ Mitigation = "VM Memory Reservation"; Impact = "0% (more host memory usage)"; Recommendation = "For critical security workloads" }
    )
    
    $performanceTable | Format-Table -AutoSize
    
    Write-ColorOutput "`n[*] SECURITY CHECKLIST:" -Color Header
    
    Write-ColorOutput "`nHost Level (ESXi):" -Color Info
    Write-ColorOutput "   - Update ESXi to 6.7 U2+ or 7.0+" -Color Warning
    Write-ColorOutput "   - Apply latest CPU microcode updates" -Color Warning
    Write-ColorOutput "   - Enable Side-Channel Aware Scheduler" -Color Warning
    Write-ColorOutput "   - Configure L1TF protection" -Color Warning
    Write-ColorOutput "   - Enable MDS/TAA mitigations" -Color Warning
    Write-ColorOutput "   - Verify Spectre/Meltdown host protections" -Color Warning
    
    Write-ColorOutput "`nVM Level:" -Color Info
    Write-ColorOutput "   - Update to VM Hardware Version 14+" -Color Warning
    Write-ColorOutput "   - Install latest VMware Tools" -Color Warning
    Write-ColorOutput "   - Configure VM security parameters" -Color Warning
    Write-ColorOutput "   - Enable CPU performance counter virtualization" -Color Warning
    Write-ColorOutput "   - Reserve guest memory (for critical VMs)" -Color Warning
    Write-ColorOutput "   - Apply guest OS mitigations (using this script)" -Color Warning
    
    Write-ColorOutput "`nNetwork Security:" -Color Info
    Write-ColorOutput "   - Isolate management network" -Color Warning
    Write-ColorOutput "   - Use encrypted vMotion" -Color Warning
    Write-ColorOutput "   - Enable VM communication encryption" -Color Warning
    Write-ColorOutput "   - Configure distributed firewall rules" -Color Warning
    
    Write-ColorOutput "`n[*] Additional Resources:" -Color Header
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
    
    # 7. Windows Defender ASLR
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

    # 8. L1TF Mitigation - CVE-2018-3620/3646
    $l1tf = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "L1TFMitigationLevel"
    if ($l1tf -ne $null -and $l1tf -eq 1) {
        $revertableMitigations += @{
            Name          = "L1TF Mitigation"
            Description   = "Disable L1 Terminal Fault protection (CVE-2018-3620/3646)"
            RegistryPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
            RegistryName  = "L1TFMitigationLevel"
            CurrentValue  = $l1tf
            RevertValue   = 0
            Impact        = "High"
            CanBeReverted = $true
            SecurityRisk  = "High - Exposes VMs to L1TF attacks"
        }
    }

    # 9. MDS Mitigation - CVE-2018-11091/12126/12127/12130
    $mds = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "MDSMitigationLevel"
    if ($mds -ne $null -and $mds -eq 1) {
        $revertableMitigations += @{
            Name          = "MDS Mitigation"
            Description   = "Disable Microarchitectural Data Sampling protection"
            RegistryPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
            RegistryName  = "MDSMitigationLevel"
            CurrentValue  = $mds
            RevertValue   = 0
            Impact        = "High"
            CanBeReverted = $true
            SecurityRisk  = "High - Exposes Intel CPUs to MDS attacks"
        }
    }

    # 10. CVE-2019-11135 Mitigation
    $tsxAsync = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "TSXAsyncAbortLevel"
    if ($tsxAsync -ne $null -and $tsxAsync -eq 1) {
        $revertableMitigations += @{
            Name          = "CVE-2019-11135 Mitigation"
            Description   = "Disable Windows Kernel Information Disclosure protection"
            RegistryPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
            RegistryName  = "TSXAsyncAbortLevel"
            CurrentValue  = $tsxAsync
            RevertValue   = 0
            Impact        = "Medium"
            CanBeReverted = $true
            SecurityRisk  = "Medium - TSX-related vulnerability exposure"
        }
    }

    # 11. SBDR/SBDS Mitigation - CVE-2022-21123/21125
    $sbds = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "SBDRMitigationLevel"
    if ($sbds -ne $null -and $sbds -eq 1) {
        $revertableMitigations += @{
            Name          = "SBDR/SBDS Mitigation"
            Description   = "Disable Shared Buffer Data Read/Sampling protection"
            RegistryPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
            RegistryName  = "SBDRMitigationLevel"
            CurrentValue  = $sbds
            RevertValue   = 0
            Impact        = "Medium"
            CanBeReverted = $true
            SecurityRisk  = "Medium - Intel CPU vulnerability exposure"
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
    $hashSigns = if ($filledBlocks -gt 0) { "#" * $filledBlocks } else { "" }
    $dashSigns = if ($emptyBlocks -gt 0) { "-" * $emptyBlocks } else { "" }
    $barDisplay = "[" + $hashSigns + $dashSigns + "]"
    
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
    This function includes ALL the same checks as the main script to ensure accurate scoring.
    #>
    $currentResults = @()
    
    # Core side-channel mitigations (same as main script)
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

    $currentResults += Test-SideChannelMitigation -Name "Branch Target Injection Mitigation" `
        -Description "Mitigates Branch Target Injection (Variant 2) by disabling page combining" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "DisablePageCombining" `
        -ExpectedValue 0 `
        -Recommendation "Keep page combining disabled for Spectre V2 protection" `
        -Impact "Minimal performance impact on most modern systems"

    $currentResults += Test-SideChannelMitigation -Name "Kernel VA Shadow (Meltdown Protection)" `
        -Description "Kernel Virtual Address Shadowing mitigates Meltdown attacks" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
        -RegistryName "EnableKernelVaShadow" `
        -ExpectedValue 1 `
        -Recommendation "Enable to protect against Meltdown (CVE-2017-5754)" `
        -Impact "Moderate performance impact, but critical for security"

    $currentResults += Test-SideChannelMitigation -Name "Hardware Security Mitigations" `
        -Description "CPU-level hardware security mitigations" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "MitigationOptions" `
        -ExpectedValue "2000000000000000" `
        -Recommendation "Enable hardware-level CPU security mitigations" `
        -Impact "Hardware-dependent, modern CPUs have better performance"

    $currentResults += Test-SideChannelMitigation -Name "Exception Chain Validation" `
        -Description "Validates exception chain integrity" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "EnableCetUserShadowStack" `
        -ExpectedValue 1 `
        -Recommendation "Enable for enhanced exception handling security" `
        -Impact "Requires CPU support for CET (Intel Tiger Lake+)"

    $currentResults += Test-SideChannelMitigation -Name "Supervisor Mode Access Prevention" `
        -Description "SMAP prevents kernel access to user pages" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "EnableSmapUserShadowStack" `
        -ExpectedValue 1 `
        -Recommendation "Enable SMAP for kernel protection" `
        -Impact "Requires CPU support, minimal performance impact"

    $currentResults += Test-SideChannelMitigation -Name "Intel TSX Disable" `
        -Description "Disables Intel TSX to prevent TSX-based attacks" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "DisableTsx" `
        -ExpectedValue 1 `
        -Recommendation "Disable Intel TSX for security" `
        -Impact "May affect applications that rely on TSX, but improves security"

    $currentResults += Test-SideChannelMitigation -Name "Enhanced IBRS" `
        -Description "Enhanced Indirect Branch Restricted Speculation" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "EnabledIBRS" `
        -ExpectedValue 1 `
        -Recommendation "Enable Enhanced IBRS if CPU supports it" `
        -Impact "Modern feature with lower performance impact than legacy IBRS"

    # CVE-specific mitigations  
    $currentResults += Test-SideChannelMitigation -Name "L1TF Mitigation" `
        -Description "L1 Terminal Fault protection (CVE-2018-3620/3646)" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "L1TFMitigationLevel" `
        -ExpectedValue 1 `
        -Recommendation "Enable L1TF protection" `
        -Impact "*** PERFORMANCE IMPACT WARNING *** High impact in virtualized environments"

    $currentResults += Test-SideChannelMitigation -Name "MDS Mitigation" `
        -Description "Microarchitectural Data Sampling protection (CVE-2018-11091/12126/12127/12130)" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "MDSMitigationLevel" `
        -ExpectedValue 1 `
        -Recommendation "Enable MDS protection" `
        -Impact "*** PERFORMANCE IMPACT WARNING *** Moderate performance impact on Intel CPUs"

    $currentResults += Test-SideChannelMitigation -Name "CVE-2019-11135 Mitigation" `
        -Description "Windows Kernel Information Disclosure protection (CVE-2019-11135)" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "TSXAsyncAbortLevel" `
        -ExpectedValue 1 `
        -Recommendation "Enable CVE-2019-11135 protection" `
        -Impact "Minimal performance impact"

    $currentResults += Test-SideChannelMitigation -Name "SBDR/SBDS Mitigation" `
        -Description "Shared Buffer Data Read/Sampling protection (CVE-2022-21123/21125)" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "SBDRMitigationLevel" `
        -ExpectedValue 1 `
        -Recommendation "Enable SBDR/SBDS protection" `
        -Impact "Intel CPU-specific, minimal performance impact"

    $currentResults += Test-SideChannelMitigation -Name "SRBDS Update Mitigation" `
        -Description "Special Register Buffer Data Sampling protection (CVE-2022-21127)" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "SRBDSMitigationLevel" `
        -ExpectedValue 1 `
        -Recommendation "Enable SRBDS protection" `
        -Impact "Intel CPU-specific, minimal performance impact"

    $currentResults += Test-SideChannelMitigation -Name "DRPW Mitigation" `
        -Description "Data Register Partial Write protection (CVE-2022-21166)" `
        -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -RegistryName "DRPWMitigationLevel" `
        -ExpectedValue 1 `
        -Recommendation "Enable DRPW protection" `
        -Impact "Intel CPU-specific, minimal performance impact"

    # Hardware and virtualization features (simplified checks for scoring)
    try {
        $hwInfo = Get-HardwareRequirements
        
        # UEFI Secure Boot
        $currentResults += [PSCustomObject]@{
            Name           = "UEFI Secure Boot"
            Description    = "Hardware-verified boot process"
            Status         = if ($hwInfo.SecureBootEnabled) { "Enabled" } else { "Not Configured" }
            CurrentValue   = $hwInfo.SecureBootStatus
            ExpectedValue  = "Enabled"
            RegistryPath   = "Hardware Feature"
            RegistryName   = "SecureBoot"
            Recommendation = "Enable Secure Boot in UEFI firmware settings"
            Impact         = "Protects boot process from tampering"
            CanBeEnabled   = $hwInfo.SecureBootCapable
        }

        # TPM 2.0
        $currentResults += [PSCustomObject]@{
            Name           = "TPM 2.0"
            Description    = "Trusted Platform Module for cryptographic operations"
            Status         = if ($hwInfo.TPMPresent -and $hwInfo.TPMVersion -match "2\.0") { "Enabled" } else { "Not Configured" }
            CurrentValue   = $hwInfo.TPMVersion
            ExpectedValue  = "2.0"
            RegistryPath   = "Hardware Feature"
            RegistryName   = "TPM"
            Recommendation = "Ensure TPM 2.0 is enabled in firmware"
            Impact         = "Required for advanced Windows security features"
            CanBeEnabled   = $true
        }

        # VBS and HVCI (from virtualization info)
        $virtInfo = Get-VirtualizationInfo
        
        $currentResults += [PSCustomObject]@{
            Name           = "Virtualization Based Security (VBS)"
            Description    = "Hardware-isolated Windows security subsystem"
            Status         = if ($virtInfo.VBSStatus -eq "Running") { "Enabled" } else { "Not Configured" }
            CurrentValue   = $virtInfo.VBSStatus
            ExpectedValue  = "Running"
            RegistryPath   = "Hardware Feature"
            RegistryName   = "VBS"
            Recommendation = "Enable VBS in Windows Features"
            Impact         = "Provides hardware isolation for security features"
            CanBeEnabled   = $hwInfo.IsUEFI -and $hwInfo.TPMPresent
        }

        $currentResults += [PSCustomObject]@{
            Name           = "Hypervisor-protected Code Integrity (HVCI)"
            Description    = "Hardware-enforced code integrity"
            Status         = if ($virtInfo.HVCIStatus -eq "Enforced") { "Enabled" } else { "Not Configured" }
            CurrentValue   = $virtInfo.HVCIStatus
            ExpectedValue  = "Enforced"
            RegistryPath   = "Hardware Feature"
            RegistryName   = "HVCI"
            Recommendation = "Enable Device Guard and HVCI"
            Impact         = "Prevents kernel code injection attacks"
            CanBeEnabled   = $virtInfo.VBSStatus -ne "Not Available"
        }

        # Windows Defender Exploit Guard ASLR
        $aslrValue = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Exploit Protection\System" -Name "ASLR_ForceRelocateImages"
        $currentResults += [PSCustomObject]@{
            Name           = "Windows Defender Exploit Guard ASLR"
            Description    = "Address Space Layout Randomization enforcement"
            Status         = if ($aslrValue -eq 1) { "Enabled" } else { "Not Configured" }
            CurrentValue   = if ($null -ne $aslrValue) { $aslrValue } else { "Not Set" }
            ExpectedValue  = 1
            RegistryPath   = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Exploit Protection\System"
            RegistryName   = "ASLR_ForceRelocateImages"
            Recommendation = "Enable Windows Defender Exploit Guard ASLR"
            Impact         = "Hardens memory layout randomization"
            CanBeEnabled   = $true
        }

        # Nested Virtualization Check
        try {
            $vmProcessor = Get-VMProcessor -VMName * -ErrorAction SilentlyContinue 2>$null
            $nestedEnabled = ($vmProcessor | Where-Object { $_.ExposeVirtualizationExtensions -eq $true }).Count -gt 0
            $currentResults += [PSCustomObject]@{
                Name           = "Nested Virtualization Security"
                Description    = "Virtualization extensions in virtual machines"
                Status         = if ($nestedEnabled) { "Enabled" } else { "Not Configured" }
                CurrentValue   = if ($nestedEnabled) { "Exposed" } else { "Not Exposed" }
                ExpectedValue  = "Exposed (with security considerations)"
                RegistryPath   = "Hyper-V Feature"
                RegistryName   = "ExposeVirtualizationExtensions"
                Recommendation = "Configure nested virtualization securely if needed"
                Impact         = "Enables VMs to run hypervisors, requires careful security setup"
                CanBeEnabled   = $virtInfo.HyperVStatus -eq "Enabled"
            }
        }
        catch {
            # No Hyper-V or VMs - add placeholder for consistent counting
            $currentResults += [PSCustomObject]@{
                Name           = "Nested Virtualization Security"
                Description    = "Virtualization extensions in virtual machines"
                Status         = "Not Configured"
                CurrentValue   = "Hyper-V not available"
                ExpectedValue  = "Proper configuration if needed"
                RegistryPath   = "Hyper-V Feature"
                RegistryName   = "ExposeVirtualizationExtensions"
                Recommendation = "Install Hyper-V if nested virtualization is required"
                Impact         = "N/A - Hyper-V not installed"
                CanBeEnabled   = $false
            }
        }
    }
    catch {
        Write-Warning "Error getting hardware info for scoring: $($_.Exception.Message)"
    }

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
    $beforeScoreNum = $beforeScore.Percentage
    $beforeScoreText = 'Current Security Score: ' + [string]$beforeScoreNum + ' of 100'
    Write-ColorOutput $beforeScoreText -Color $(if ($beforeScore.Percentage -ge 80) { 'Good' } elseif ($beforeScore.Percentage -ge 60) { 'Warning' } else { 'Bad' })
    $barDisplay = $beforeScore.BarDisplay
    $barPercent = $beforeScore.Percentage
    $securityBarText = 'Security Bar: ' + [string]$barDisplay + ' ' + [string]$barPercent + ' of 100' + "`n"
    Write-ColorOutput $securityBarText -Color Info
    
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
                        Write-ColorOutput "  + Disabled nested virtualization for VM: $vmName" -Color Good
                    }
                }
                elseif ($mitigation.RegistryPath -eq "VMware ESXi") {
                    # Handle VMware guidance
                    Write-ColorOutput "  ! VMware Configuration Required:" -Color Warning
                    Write-ColorOutput "    This change requires ESXi host access" -Color Warning
                    Write-ColorOutput "    Commands to run on ESXi host:" -Color Info
                    if ($mitigation.ESXiCommands) {
                        foreach ($cmd in $mitigation.ESXiCommands) {
                            if ($cmd.StartsWith("#")) {
                                Write-ColorOutput "    $cmd" -Color Good
                            }
                            else {
                                Write-ColorOutput "    $cmd" -Color Warning
                            }
                        }
                    }
                    else {
                        Write-ColorOutput "    # Access ESXi host via vSphere Client or SSH" -Color Good
                        Write-ColorOutput "    # Power off VM and edit hardware settings" -Color Good
                        Write-ColorOutput "    # Disable 'Expose hardware assisted virtualization'" -Color Warning
                        Write-ColorOutput "    # Or use PowerCLI for advanced configuration" -Color Good
                    }
                    Write-ColorOutput "  ! Cannot execute automatically from Windows guest" -Color Error
                }
                elseif ($mitigation.RevertValue -eq "Remove registry value") {
                    # Remove the registry value entirely
                    if (Test-Path $mitigation.RegistryPath) {
                        Remove-ItemProperty -Path $mitigation.RegistryPath -Name $mitigation.RegistryName -ErrorAction SilentlyContinue
                        Write-ColorOutput "  + Registry value removed: $($mitigation.RegistryName)" -Color Good
                    }
                }
                else {
                    # Set to revert value
                    Set-RegistryValue -Path $mitigation.RegistryPath -Name $mitigation.RegistryName -Value $mitigation.RevertValue -Type "DWORD"
                    Write-ColorOutput "  + Reverted: $($mitigation.Name) = $($mitigation.RevertValue)" -Color Good
                }
                $successCount++
            }
            catch {
                Write-ColorOutput "  - Failed to revert $($mitigation.Name): $($_.Exception.Message)" -Color Bad
                $errorCount++
            }
        }
    }
    
    Write-ColorOutput "`nRevert Results:" -Color Header
    Write-ColorOutput "Successfully reverted: $successCount/$($selectedMitigations.Count)" -Color Good
    
    if ($errorCount -gt 0) {
        Write-ColorOutput "Errors encountered: $errorCount" -Color Bad
    }
    
    if ($successCount -gt 0) {
        Write-ColorOutput "`n[!] IMPORTANT: A system restart may be required for changes to take effect." -Color Warning
        
        if (-not $WhatIf) {
            # Calculate security score after revert (for actual revert operations)
            Write-ColorOutput "`nRecalculating security score..." -Color Info
            $afterResults = Get-CurrentSecurityResults
            $afterScore = Calculate-SecurityScore -Results $afterResults
            $scoreDifference = $beforeScore.Percentage - $afterScore.Percentage
            
            Write-ColorOutput "`nSecurity Impact Assessment:" -Color Header
            $beforePercent = $beforeScore.Percentage
            $beforeBar = $beforeScore.BarDisplay
            $beforeRevertText = '  Before Revert:  ' + [string]$beforePercent + ' of 100 ' + [string]$beforeBar
            Write-ColorOutput $beforeRevertText -Color $(if ($beforeScore.Percentage -ge 80) { 'Good' } elseif ($beforeScore.Percentage -ge 60) { 'Warning' } else { 'Bad' })
            $afterPercent = $afterScore.Percentage
            $afterBar = $afterScore.BarDisplay
            $afterRevertText = '  After Revert:   ' + [string]$afterPercent + ' of 100 ' + [string]$afterBar
            Write-ColorOutput $afterRevertText -Color $(if ($afterScore.Percentage -ge 80) { 'Good' } elseif ($afterScore.Percentage -ge 60) { 'Warning' } else { 'Bad' })
            $scoreDiff = [math]::Round($scoreDifference, 1)
            $scoreChangeText = '  Score Change:   -' + [string]$scoreDiff + ' of 100 (Security Reduced)'
            Write-ColorOutput $scoreChangeText -Color Error
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
        $currentPercent = $beforeScore.Percentage
        $currentBar = $beforeScore.BarDisplay
        $currentScoreText = '  Current Score:   ' + [string]$currentPercent + ' of 100 ' + [string]$currentBar
        Write-ColorOutput $currentScoreText -Color $(if ($beforeScore.Percentage -ge 80) { 'Good' } elseif ($beforeScore.Percentage -ge 60) { 'Warning' } else { 'Bad' })
        $projectedPercent = $projectedScore.Percentage
        $projectedBar = $projectedScore.BarDisplay
        $projectedScoreText = '  After Revert:    ' + [string]$projectedPercent + ' of 100 ' + [string]$projectedBar
        Write-ColorOutput $projectedScoreText -Color $(if ($projectedScore.Percentage -ge 80) { 'Good' } elseif ($projectedScore.Percentage -ge 60) { 'Warning' } else { 'Bad' })
        $projectedDiff = [math]::Round($scoreDifference, 1)
        $projectedChangeText = '  Score Change:    -' + [string]$projectedDiff + ' of 100 (Security Reduction)'
        Write-ColorOutput $projectedChangeText -Color Error
        Write-ColorOutput "`nTo actually revert these mitigations, run without -WhatIf switch." -Color Info
    }
    
    # Add VMware-specific guidance if VMware mitigations were selected
    $vmwareMitigations = $SelectedMitigations | Where-Object { $_.RegistryPath -eq "VMware ESXi" }
    if ($vmwareMitigations.Count -gt 0) {
        Write-ColorOutput "`n[!] IMPORTANT: ESXi host configuration required for VMware environments!" -Color Warning
        Write-ColorOutput "VMware nested virtualization changes require direct ESXi host access." -Color Warning
        Write-ColorOutput "Contact your VMware infrastructure administrator to apply changes." -Color Info
    }
}

# Main execution
Write-ColorOutput "`n=== Side-Channel Vulnerability Configuration Check ===" -Color Header
Write-ColorOutput "Based on Microsoft KB4073119 + Extended Modern CVE Coverage`n" -Color Info

# Parameter validation (simplified with ParameterSets)
Write-ColorOutput "IMPORTANT: This script checks KB4073119 + modern CVEs (2018-2023) with enterprise features." -Color Warning
Write-ColorOutput "For additional hardware-level analysis, also consider running:" -Color Info
Write-ColorOutput "   Install-Module SpeculationControl; Get-SpeculationControlSettings`n" -Color Good

# Performance Impact Warning
Write-ColorOutput "*** PERFORMANCE IMPACT WARNING ***" -Color Error
Write-ColorOutput "Some mitigations may significantly impact system performance:" -Color Warning
Write-ColorOutput "- L1TF & MDS Mitigations: May require disabling hyperthreading" -Color Warning
Write-ColorOutput "- Older Hyper-V (pre-2016): Higher performance impact" -Color Warning
Write-ColorOutput "- VBS/Credential Guard: Requires UEFI, Secure Boot, TPM 2.0" -Color Warning
Write-ColorOutput "- Build servers/shared hosting: May need SMT disabled" -Color Warning
Write-ColorOutput "Test performance impact in non-production first!`n" -Color Error

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
    -RegistryName "DisablePageCombining" `
    -ExpectedValue 0 `
    -Recommendation "Enable BTI mitigation to protect against Spectre V2 attacks" `
    -Impact "Minimal performance impact on modern CPUs"

# 4. Kernel VA Shadow (KVAS) for Meltdown Protection
$Results += Test-SideChannelMitigation -Name "Kernel VA Shadow (Meltdown Protection)" `
    -Description "Kernel Virtual Address Shadowing to mitigate Meltdown attacks" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
    -RegistryName "EnableKernelVaShadow" `
    -ExpectedValue 1 `
    -Recommendation "Enable KVAS to protect against Meltdown (CVE-2017-5754)" `
    -Impact "Medium performance impact, essential for Meltdown protection"

# 5. Hardware Mitigations
$Results += Test-SideChannelMitigation -Name "Hardware Security Mitigations" `
    -Description "Enable hardware-based security mitigations when available" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "MitigationOptions" `
    -ExpectedValue "2000000000000000" `
    -Recommendation "Hardware mitigations are enabled. The core mitigation flag (0x2000000000000000) is set with additional options." `
    -Impact "Hardware-dependent, modern CPUs have better performance"

# 6. Exception Chain Validation
$Results += Test-SideChannelMitigation -Name "Exception Chain Validation" `
    -Description "Validates exception handler chains to prevent SEH exploitation" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "DisableExceptionChainValidation" `
    -ExpectedValue 0 `
    -Recommendation "Ensure exception chain validation is enabled (value = 0)" `
    -Impact "Prevents SEH (Structured Exception Handler) exploitation techniques"

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

# 9. Retpoline Support Check (Informational)
$Results += [PSCustomObject]@{
    Name           = "Retpoline Support"
    Description    = "Compiler-based mitigation for indirect branch speculation"
    Status         = "Information"
    CurrentValue   = "Check with compiler and application vendors"
    ExpectedValue  = "Enabled in compiled binaries"
    RegistryPath   = "N/A - Compiler Feature"
    RegistryName   = "N/A"
    Recommendation = "Ensure applications are compiled with retpoline support"
    Impact         = "Compiler and application dependent"
    CanBeEnabled   = $false
}

# 10. Enhanced IBRS (Indirect Branch Restricted Speculation)
$Results += Test-SideChannelMitigation -Name "Enhanced IBRS" `
    -Description "Enhanced Indirect Branch Restricted Speculation" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "IbrsEnabled" `
    -ExpectedValue 1 `
    -Recommendation "Enable Enhanced IBRS for Spectre V2 protection on supported CPUs" `
    -Impact "Minimal performance impact on CPUs with Enhanced IBRS support"

# ===================================================================
# ADDITIONAL CVE MITIGATIONS - HIGH PERFORMANCE IMPACT WARNING
# ===================================================================
Write-ColorOutput "`nChecking Additional CVE Mitigations (Performance Impact Warning)..." -Color Warning

# 11. L1 Terminal Fault (L1TF) - CVE-2018-3620, CVE-2018-3646
$Results += Test-SideChannelMitigation -Name "L1TF Mitigation" `
    -Description "L1 Terminal Fault protection (CVE-2018-3620/3646)" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "L1TFMitigationLevel" `
    -ExpectedValue 1 `
    -Recommendation "Enable L1TF protection. WARNING: High performance impact in virtualized environments" `
    -Impact "HIGH - May require disabling hyperthreading on older Hyper-V versions"

# 12. MDS Mitigation - CVE-2018-11091, CVE-2018-12126, CVE-2018-12127, CVE-2018-12130
$Results += Test-SideChannelMitigation -Name "MDS Mitigation" `
    -Description "Microarchitectural Data Sampling protection (CVE-2018-11091/12126/12127/12130)" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "MDSMitigationLevel" `
    -ExpectedValue 1 `
    -Recommendation "Enable MDS protection. WARNING: Moderate performance impact on Intel CPUs" `
    -Impact "MODERATE-HIGH - 3-8% performance impact, may require SMT disable"

# 13. Windows Kernel Information Disclosure - CVE-2019-11135  
$Results += Test-SideChannelMitigation -Name "CVE-2019-11135 Mitigation" `
    -Description "Windows Kernel Information Disclosure Vulnerability protection" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "TSXAsyncAbortLevel" `
    -ExpectedValue 1 `
    -Recommendation "Enable TAA/TSX mitigation. Performance impact varies by workload" `
    -Impact "MODERATE - Application-dependent performance impact"

# 14. SBDR/SBDS Mitigation - CVE-2022-21123, CVE-2022-21125
$Results += Test-SideChannelMitigation -Name "SBDR/SBDS Mitigation" `
    -Description "Shared Buffer Data Read/Sampling protection (CVE-2022-21123/21125)" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "SBDRMitigationLevel" `
    -ExpectedValue 1 `
    -Recommendation "Enable SBDR/SBDS protection for recent Intel CPUs" `
    -Impact "LOW-MODERATE - Performance impact varies by CPU generation"

# 15. SRBDS Update - CVE-2022-21127
$Results += Test-SideChannelMitigation -Name "SRBDS Update Mitigation" `
    -Description "Special Register Buffer Data Sampling Update protection (CVE-2022-21127)" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "SRBDSMitigationLevel" `
    -ExpectedValue 1 `
    -Recommendation "Enable SRBDS Update protection for affected Intel CPUs" `
    -Impact "LOW - Minimal performance impact on most workloads"

# 16. DRPW Mitigation - CVE-2022-21166
$Results += Test-SideChannelMitigation -Name "DRPW Mitigation" `
    -Description "Device Register Partial Write protection (CVE-2022-21166)" `
    -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -RegistryName "DRPWMitigationLevel" `
    -ExpectedValue 1 `
    -Recommendation "Enable DRPW protection for Intel CPUs with affected components" `
    -Impact "LOW - Typically minimal performance impact"

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

# Get hardware requirements info
$hwRequirements = Get-HardwareRequirements

# 1a. UEFI Firmware Check
$uefiStatus = "Unknown - Check System Information"
$uefiValue = "Manual verification required"
$uefiRecommendation = "Check system information or BIOS settings to determine firmware type"

if ($hwRequirements.IsUEFI) {
    $uefiStatus = "UEFI Firmware Active"
    $uefiValue = "Modern UEFI firmware"
    $uefiRecommendation = "UEFI firmware is active - supports modern security features"
}
else {
    $uefiStatus = "Legacy BIOS Mode"
    $uefiValue = "Legacy BIOS or CSM mode"
    $uefiRecommendation = "Upgrade to UEFI mode for advanced security (may require OS reinstall in UEFI mode)"
}

$Results += [PSCustomObject]@{
    Name           = "UEFI Firmware (not Legacy BIOS)"
    Description    = "Modern firmware interface required for advanced security features"
    Status         = $uefiStatus
    CurrentValue   = $uefiValue
    ExpectedValue  = "UEFI Firmware Active"
    RegistryPath   = "System Firmware (Hardware)"
    RegistryName   = "Firmware Type"
    Recommendation = $uefiRecommendation
    Impact         = "Required for Secure Boot, VBS, and other security features"
    CanBeEnabled   = $false
}

# 1b. Secure Boot Check
$secureBootStatus = "Unknown - Check UEFI Settings"
$secureBootValue = "Manual verification required"
$secureBootRecommendation = "Access UEFI firmware settings to verify Secure Boot status"
$canEnableSecureBoot = $false

if ($hwRequirements.SecureBootEnabled) {
    $secureBootStatus = "Enabled"
    $secureBootValue = "Active"
    $secureBootRecommendation = "Secure Boot is properly enabled - no action required"
    $canEnableSecureBoot = $true
}
elseif ($hwRequirements.SecureBootCapable) {
    $secureBootStatus = "Available but Disabled"
    $secureBootValue = "Hardware supports but not enabled"
    $secureBootRecommendation = "Enable Secure Boot in UEFI firmware settings (requires UEFI mode, not Legacy BIOS)"
    $canEnableSecureBoot = $true
}
elseif ($hwRequirements.IsUEFI) {
    $secureBootStatus = "UEFI Present - Secure Boot Unknown"
    $secureBootValue = "Check UEFI firmware manually"
    $secureBootRecommendation = "Access UEFI setup during boot to enable Secure Boot if available"
    $canEnableSecureBoot = $true
}
else {
    $secureBootStatus = "Not Available (Legacy BIOS)"
    $secureBootValue = "Requires UEFI firmware"
    $secureBootRecommendation = "Upgrade to UEFI firmware to support Secure Boot (requires reinstall in UEFI mode)"
    $canEnableSecureBoot = $false
}

$Results += [PSCustomObject]@{
    Name           = "Secure Boot"
    Description    = "Prevents unauthorized bootloaders and ensures boot integrity"
    Status         = $secureBootStatus
    CurrentValue   = $secureBootValue
    ExpectedValue  = "Enabled"
    RegistryPath   = "UEFI Firmware Setting"
    RegistryName   = "Secure Boot"
    Recommendation = $secureBootRecommendation
    Impact         = "Essential for VBS and prevents boot-level malware"
    CanBeEnabled   = $canEnableSecureBoot
}

# 1c. TPM 2.0 Check
$tpmStatus = "Unknown - Check Hardware"
$tpmValue = "Manual verification required"
$tpmRecommendation = "Check BIOS/UEFI for TPM settings or hardware installation"
$canEnableTPM = $false

if ($hwRequirements.TPMPresent) {
    if ($hwRequirements.TPMVersion -match "2\.0") {
        $tpmStatus = "TPM 2.0 Enabled"
        $tpmValue = "Version $($hwRequirements.TPMVersion) - Active"
        $tpmRecommendation = "TPM 2.0 is properly enabled and functioning"
        $canEnableTPM = $true
    }
    elseif ($hwRequirements.TPMVersion -match "1\.") {
        $tpmStatus = "TPM 1.x Present (Upgrade Needed)"
        $tpmValue = "Version $($hwRequirements.TPMVersion) - Insufficient"
        $tpmRecommendation = "TPM 1.x detected - upgrade to TPM 2.0 chip or enable TPM 2.0 mode in UEFI if available"
        $canEnableTPM = $false
    }
    else {
        $tpmStatus = "TPM Present (Version Unknown)"
        $tpmValue = "Version: $($hwRequirements.TPMVersion)"
        $tpmRecommendation = "TPM detected but version unclear - verify TPM 2.0 compatibility"
        $canEnableTPM = $true
    }
}
else {
    $tpmStatus = "Not Detected"
    $tpmValue = "No TPM found"
    $tpmRecommendation = "Enable TPM in BIOS/UEFI if available, or install TPM 2.0 hardware module"
    $canEnableTPM = $false
}

$Results += [PSCustomObject]@{
    Name           = "TPM 2.0 (Trusted Platform Module)"
    Description    = "Hardware security chip for cryptographic operations and key storage"
    Status         = $tpmStatus
    CurrentValue   = $tpmValue
    ExpectedValue  = "TPM 2.0 Enabled"
    RegistryPath   = "Hardware/UEFI Setting"
    RegistryName   = "TPM 2.0"
    Recommendation = $tpmRecommendation
    Impact         = "Required for Credential Guard, BitLocker, and VBS features"
    CanBeEnabled   = $canEnableTPM
}

# 1d. CPU Virtualization Support Check
$vtxStatus = "Unknown - Manual BIOS Check Required"
$vtxValue = "Check BIOS/UEFI Settings"
$vtxRecommendation = "Verify VT-x (Intel) or AMD-V (AMD) is enabled in BIOS/UEFI firmware settings"

if ($hwRequirements.VTxSupport) {
    # Additional check to see if Hyper-V is actually working
    if ($virtInfo.HyperVStatus -eq "Enabled" -or (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue).State -eq "Enabled") {
        $vtxStatus = "Enabled and Active"
        $vtxValue = "Hardware virtualization active"
        $vtxRecommendation = "CPU virtualization is enabled and functioning properly"
    }
    else {
        $vtxStatus = "Hardware Available but Inactive"
        $vtxValue = "Enable Hyper-V to verify full functionality"
        $vtxRecommendation = "CPU virtualization detected - enable Hyper-V role to verify complete functionality"
    }
}
else {
    $vtxStatus = "Not Detected or Disabled"
    $vtxValue = "Enable in BIOS/UEFI"
    $vtxRecommendation = "Enable VT-x (Intel) or AMD-V (AMD) in BIOS/UEFI firmware settings - required for VBS/HVCI"
}

$Results += [PSCustomObject]@{
    Name           = "CPU Virtualization Support (VT-x/AMD-V)"
    Description    = "Hardware virtualization extensions required for hypervisor-based security"
    Status         = $vtxStatus
    CurrentValue   = $vtxValue
    ExpectedValue  = "Enabled and Active"
    RegistryPath   = "BIOS/UEFI Setting (Hardware Feature)"
    RegistryName   = "Intel VT-x / AMD-V"
    Recommendation = $vtxRecommendation
    Impact         = "Essential for Hyper-V, VBS, and virtualization-based security"
    CanBeEnabled   = $true
}

# 1e. IOMMU/VT-d Support Check
$Results += [PSCustomObject]@{
    Name           = "IOMMU/VT-d Support"
    Description    = "Input/Output Memory Management Unit for secure DMA isolation"
    Status         = if ($hwRequirements.IOMMUSupport -match "Available.*Hyper-V") { "Enabled" } elseif ($hwRequirements.IOMMUSupport -match "Available") { "Not Configured" } else { "Not Configured" }
    CurrentValue   = $hwRequirements.IOMMUSupport
    ExpectedValue  = "Enabled and Active"
    RegistryPath   = "Hardware Feature (BIOS/UEFI Setting)"
    RegistryName   = "Intel VT-d / AMD IOMMU"
    Recommendation = if ($hwRequirements.IOMMUSupport -match "Available.*Hyper-V") { "IOMMU/VT-d is enabled and being used by Hyper-V - optimal configuration" } else { "Enable VT-d (Intel) or AMD-Vi (AMD) in BIOS/UEFI for enhanced DMA protection" }
    Impact         = "Provides DMA isolation and enhanced security for VBS"
    CanBeEnabled   = $false
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
            Status         = if ($vmToolsVersion) { "Enabled" } else { "Not Configured" }
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
    Write-ColorOutput "Checking host-level virtualization security features..." -Color Info
    
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
            "Enabled"  # Newer OS versions have it enabled by default - mark as Enabled to exclude from recommendations
        }
        
        $coreSchedulerRecommendation = if ($needsCoreSchedulerConfig) {
            "Enable Core Scheduler for SMT security: bcdedit /set hypervisorschedulertype core"
        }
        else {
            "Core Scheduler is enabled by default in this Windows version (Build $osBuildNumber) - no action required"
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
            Description    = "Enable nested virtualization on Hyper-V VMs"
            Status         = if ($virtInfo.NestedVirtualizationEnabled) { "Enabled" } else { "Not Configured" }
            CurrentValue   = if ($virtInfo.NestedVirtualizationEnabled) { "Enabled" } else { "Disabled" }
            ExpectedValue  = "Enabled (with security considerations)"
            RegistryPath   = "Hyper-V Feature"
            RegistryName   = "ExposeVirtualizationExtensions"
            Recommendation = "Enable nested virtualization if required for development"
            Impact         = "Reduces security score but enables nested hypervisors in VMs"
            CanBeEnabled   = $virtInfo.HyperVStatus -eq "Enabled"
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
    $vbsHwReadyText = if ($vbsHwReady) { "+ Yes" } else { "- No" }
    $vbsHwReadyColor = if ($vbsHwReady) { $Colors['Good'] } else { $Colors['Warning'] }
    Write-Host $vbsHwReadyText -ForegroundColor $vbsHwReadyColor
    Write-Host "  Currently Active: " -NoNewline -ForegroundColor Gray
    $vbsRunningText = if ($vbsRunning) { "+ Yes" } else { "- No" }
    $vbsRunningColor = if ($vbsRunning) { $Colors['Good'] } else { $Colors['Warning'] }
    Write-Host $vbsRunningText -ForegroundColor $vbsRunningColor
    
    Write-ColorOutput "`nHVCI (Hypervisor-protected Code Integrity):" -Color Info
    Write-Host "  Hardware Ready:  " -NoNewline -ForegroundColor Gray
    $hvciHwReadyText = if ($hvciHwReady) { "+ Yes" } else { "- No" }
    $hvciHwReadyColor = if ($hvciHwReady) { $Colors['Good'] } else { $Colors['Warning'] }
    Write-Host $hvciHwReadyText -ForegroundColor $hvciHwReadyColor
    Write-Host "  Currently Active: " -NoNewline -ForegroundColor Gray
    $hvciRunningText = if ($hvciRunning) { "+ Yes" } else { "- No" }
    $hvciRunningColor = if ($hvciRunning) { $Colors['Good'] } else { $Colors['Warning'] }
    Write-Host $hvciRunningText -ForegroundColor $hvciRunningColor
    
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
    
    $statusIcon = if ($isEnabled) { "+" } else { "-" }
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

# Categorize results into different types
$softwareMitigations = $Results | Where-Object { 
    $_.Status -in @("Enabled", "Not Configured", "Disabled") -and
    $_.Name -notmatch "UEFI|TPM|CPU Virtualization|Retpoline Support|Information"
}

$hardwarePrerequisites = $Results | Where-Object { 
    $_.Name -match "UEFI|TPM|CPU Virtualization" -or $_.Status -eq "Information"
}

$securityFeatures = $Results | Where-Object {
    $_.Status -in @("Enabled", "Not Configured", "Disabled") -and
    $_.Name -match "VBS|HVCI|Credential Guard|Windows Defender|Hyper-V Core Scheduler"
}

# Count software mitigations for scoring (the main security score)
$enabledMitigations = ($softwareMitigations | Where-Object { $_.Status -eq "Enabled" }).Count
$notConfiguredMitigations = ($softwareMitigations | Where-Object { $_.Status -eq "Not Configured" }).Count  
$disabledMitigations = ($softwareMitigations | Where-Object { $_.Status -eq "Disabled" }).Count
$totalMitigations = $softwareMitigations.Count

# Count security features separately  
$enabledFeatures = ($securityFeatures | Where-Object { $_.Status -eq "Enabled" }).Count
$totalFeatures = $securityFeatures.Count

# Count hardware prerequisites (informational)
$readyHardware = ($hardwarePrerequisites | Where-Object { 
        $_.Status -match "Enabled|Active|2\.0 Enabled|UEFI Firmware Active" 
    }).Count
$totalHardware = $hardwarePrerequisites.Count

# Show breakdown
Write-ColorOutput "`nSecurity Assessment Categories:" -Color Info
Write-ColorOutput "- Software Mitigations: $enabledMitigations/$totalMitigations enabled" -Color Info
Write-ColorOutput "- Security Features: $enabledFeatures/$totalFeatures enabled" -Color Info  
Write-ColorOutput "- Hardware Prerequisites: $readyHardware/$totalHardware ready" -Color Info

# Calculate primary security score based on software mitigations only
$mitigationPercent = if ($totalMitigations -gt 0) { [math]::Round(($enabledMitigations / $totalMitigations) * 100, 1) } else { 0 }

$configuredPercent = $mitigationPercent

# Visual status breakdown - focus on software mitigations for primary score
Write-Host "`nSecurity Status Overview:" -ForegroundColor $Colors['Header']
Write-Host "=========================" -ForegroundColor $Colors['Header']

Write-Host ("`n" + $Emojis.Shield + "  SOFTWARE MITIGATIONS (Primary Score):") -ForegroundColor $Colors['Header']
Write-Host "[+] ENABLED:       " -NoNewline -ForegroundColor $Colors['Good']
Write-Host "$enabledMitigations" -NoNewline -ForegroundColor $Colors['Good']
Write-Host " / $totalMitigations mitigations" -ForegroundColor Gray

Write-Host "[-] NOT SET:       " -NoNewline -ForegroundColor $Colors['Warning']
Write-Host "$notConfiguredMitigations" -NoNewline -ForegroundColor $Colors['Warning']
Write-Host " / $totalMitigations mitigations" -ForegroundColor Gray

Write-Host "[-] DISABLED:      " -NoNewline -ForegroundColor $Colors['Bad']
Write-Host "$disabledMitigations" -NoNewline -ForegroundColor $Colors['Bad']
Write-Host " / $totalMitigations mitigations" -ForegroundColor Gray

if ($totalFeatures -gt 0) {
    Write-Host ("`n" + $Emojis.Lock + " SECURITY FEATURES:") -ForegroundColor $Colors['Header'] 
    Write-Host "[+] ENABLED:       " -NoNewline -ForegroundColor $Colors['Good']
    Write-Host "$enabledFeatures" -NoNewline -ForegroundColor $Colors['Good']
    Write-Host " / $totalFeatures features" -ForegroundColor Gray
}

if ($totalHardware -gt 0) {
    Write-Host ("`n" + $Emojis.Wrench + " HARDWARE PREREQUISITES:") -ForegroundColor $Colors['Header']
    Write-Host "[+] READY:         " -NoNewline -ForegroundColor $Colors['Good']
    Write-Host "$readyHardware" -NoNewline -ForegroundColor $Colors['Good']
    Write-Host " / $totalHardware components" -ForegroundColor Gray
}

Write-Host "`nOverall Mitigation Score: " -NoNewline -ForegroundColor $Colors['Info']
$levelColor = if ($configuredPercent -ge 80) { 'Good' } elseif ($configuredPercent -ge 60) { 'Warning' } else { 'Bad' }
Write-Host "$configuredPercent%" -ForegroundColor $Colors[$levelColor]

# Security level indicator
$securityBar = ""
$filledBlocks = [math]::Floor($configuredPercent / 10)
$emptyBlocks = 10 - $filledBlocks

for ($i = 0; $i -lt $filledBlocks; $i++) { $securityBar += "#" }
for ($i = 0; $i -lt $emptyBlocks; $i++) { $securityBar += "-" }

Write-Host "Mitigation Progress: [" -NoNewline -ForegroundColor Gray
Write-Host "$securityBar" -NoNewline -ForegroundColor $Colors[$levelColor]
Write-Host "] $configuredPercent%" -ForegroundColor Gray

# Show what the score means
Write-Host "`nScore Explanation:" -ForegroundColor $Colors['Info']
Write-Host "* Mitigation Score: Based on registry-configurable side-channel protections" -ForegroundColor Gray
Write-Host "* Security Features: Windows security services (VBS, HVCI, etc.)" -ForegroundColor Gray  
Write-Host "* Hardware Prerequisites: Platform readiness for advanced security" -ForegroundColor Gray

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
    
    # Display CPU compatibility info
    Write-ColorOutput "`nCPU Detected: $($cpuInfo.Manufacturer) - $($cpuInfo.Name)" -Color Info
    Write-ColorOutput "Note: Only CPU-compatible mitigations are shown." -Color Info
    
    Write-ColorOutput "`nThe following mitigations are not configured and can be enabled:" -Color Info
    Write-ColorOutput "Use numbers to select (for example: 1,3,5 or 1-3 or all for all mitigations):" -Color Info
    Write-ColorOutput "Enter 0 to apply no mitigations and exit:`n" -Color Info
    
    # Display available mitigations with numbers
    $index = 1
    foreach ($mitigation in $AvailableMitigations) {
        $impact = switch ($mitigation.Name) {
            { $_ -match "Spectre|BTI|IBRS|SSBD|SRBDS|DRPW" } { "Low" }
            { $_ -match "Meltdown|KVAS|SBDR|SBDS|CVE-2019-11135" } { "Medium" }
            { $_ -match "L1TF|MDS" } { "High" }
            { $_ -match "TSX|Hardware" } { "Variable" }
            { $_ -match "VBS|HVCI" } { "High" }
            { $_ -eq "Nested Virtualization Security" } { "Security Risk" }
            default { "Unknown" }
        }
        
        $description = switch ($mitigation.Name) {
            "Speculative Store Bypass Disable" { "Protects against Spectre Variant 4" }
            "Branch Target Injection Mitigation" { "Protects against Spectre Variant 2" }
            "Kernel VA Shadow" { "Meltdown protection (KPTI)" }
            "Hardware Security Mitigations" { "CPU-level side-channel protections" }
            "Intel TSX Disable" { "Prevents TSX-based attacks" }
            "Enhanced IBRS" { "Intel hardware mitigation" }
            "L1TF Mitigation" { "L1 Terminal Fault protection (may require SMT disable)" }
            "MDS Mitigation" { "Microarchitectural Data Sampling protection (Intel)" }
            "CVE-2019-11135 Mitigation" { "Windows Kernel Information Disclosure protection" }
            "SBDR/SBDS Mitigation" { "Shared Buffer Data protection (Intel)" }
            "SRBDS Update Mitigation" { "Special Register Buffer protection (Intel)" }
            "DRPW Mitigation" { "Device Register Partial Write protection (Intel)" }
            "VBS" { "Virtualization Based Security" }
            "HVCI" { "Hypervisor-protected Code Integrity" }
            "Nested Virtualization Security" { "Enable nested virtualization (reduces security score)" }
            default { $mitigation.Description -replace "^CVE-[^:]+: ", "" }
        }
        
        Write-Host "  [$index] " -NoNewline -ForegroundColor Yellow
        Write-Host $mitigation.Name -NoNewline -ForegroundColor White
        Write-Host " (Impact: $impact)" -ForegroundColor $(if ($impact -eq "Security Risk") { "Red" } else { "Gray" })
        Write-Host "      $description" -ForegroundColor $(if ($mitigation.Name -eq "Nested Virtualization Security") { "Yellow" } else { "Gray" })
        
        # Special warning for nested virtualization
        if ($mitigation.Name -eq "Nested Virtualization Security") {
            Write-Host "      WARNING: This will REDUCE your security score by enabling attack surface" -ForegroundColor Red
        }
        
        $index++
    }
    
    Write-Host ""
    $selection = Read-Host "Enter your selection (numbers separated by commas, ranges like 1-3, or 'all', or 0 for none)"
    
    # Parse selection
    $selectedItems = @()
    
    if ($selection -eq '0') {
        # User selected 0 - apply no mitigations
        Write-ColorOutput "`nNo mitigations selected. Exiting without applying any changes." -Color Info
        return @()
    }
    elseif ($selection -eq 'all') {
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

function Filter-CPUSpecificMitigations {
    <#
    .SYNOPSIS
    Filters mitigations based on CPU manufacturer compatibility.
    
    .DESCRIPTION
    Removes CPU-specific mitigations that don't apply to the current CPU manufacturer,
    preventing unnecessary or incompatible mitigations from being applied.
    #>
    param(
        [array]$Mitigations,
        [string]$CPUManufacturer
    )
    
    # Define CPU-specific mitigation mappings
    $intelSpecificMitigations = @(
        "GDS Mitigation",
        "RFDS Mitigation", 
        "L1TF Mitigation",
        "MDS Mitigation",
        "Intel TSX Disable",
        "CVE-2019-11135 Mitigation",
        "SBDR/SBDS Mitigation", 
        "SRBDS Update Mitigation",
        "DRPW Mitigation"
    )
    
    $amdSpecificMitigations = @(
        "SRSO Mitigation"
    )
    
    $filteredMitigations = @()
    $skippedCount = 0
    
    foreach ($mitigation in $Mitigations) {
        $shouldInclude = $true
        $reason = ""
        
        # Skip Intel-specific mitigations on non-Intel CPUs
        if ($mitigation.Name -in $intelSpecificMitigations -and $CPUManufacturer -ne "GenuineIntel") {
            $shouldInclude = $false
            $reason = "Intel-specific mitigation not applicable on $($CPUManufacturer -replace 'Genuine|Authentic','')"
        }
        # Skip AMD-specific mitigations on non-AMD CPUs
        elseif ($mitigation.Name -in $amdSpecificMitigations -and $CPUManufacturer -ne "AuthenticAMD") {
            $shouldInclude = $false
            $reason = "AMD-specific mitigation not applicable on $($CPUManufacturer -replace 'Genuine|Authentic','')"
        }
        
        if ($shouldInclude) {
            $filteredMitigations += $mitigation
        }
        else {
            $skippedCount++
            Write-ColorOutput "  [SKIPPED] $($mitigation.Name) - $reason" -Color Info
        }
    }
    
    if ($skippedCount -gt 0) {
        Write-ColorOutput "`nFiltered out $skippedCount CPU-incompatible mitigation(s) because you have a $CPUManufacturer CPU." -Color Info
    }
    
    return $filteredMitigations
}

# Apply configurations if requested
if ($Apply) {
    Write-ColorOutput "`n=== Configuration Application ===" -Color Header
    $notConfigured = $Results | Where-Object { $_.Status -ne "Enabled" -and $_.CanBeEnabled }
    
    # Filter CPU-specific mitigations
    if ($notConfigured.Count -gt 0) {
        Write-ColorOutput "Filtering mitigations for CPU compatibility..." -Color Info
        $notConfigured = Filter-CPUSpecificMitigations -Mitigations $notConfigured -CPUManufacturer $cpuInfo.Manufacturer
    }
    
    # Handle nested virtualization as a special case and filter out other hardware/firmware settings
    if ($notConfigured.Count -gt 0) {
        Write-ColorOutput "Filtering hardware/firmware settings..." -Color Info
        
        # Extract nested virtualization for special handling
        $nestedVirtualization = $notConfigured | Where-Object { $_.Name -eq "Nested Virtualization Security" }
        
        # Filter out other hardware settings but keep registry-configurable ones
        $notConfigured = $notConfigured | Where-Object { 
            $_.RegistryPath -notmatch "Hardware/UEFI|BIOS/UEFI" -and
            $_.RegistryPath -notmatch "Hardware Feature" -and
            $_.Name -ne "Nested Virtualization Security"
        }
        
        # Add nested virtualization back as a configurable option if available
        if ($nestedVirtualization -and $nestedVirtualization.CanBeEnabled) {
            $notConfigured = @($notConfigured) + $nestedVirtualization
        }
        
        # Show which hardware settings were filtered out (excluding nested virtualization)
        $hardwareSettings = $Results | Where-Object { 
            $_.Status -ne "Enabled" -and 
            $_.CanBeEnabled -and 
            ($_.RegistryPath -match "Hardware/UEFI|BIOS/UEFI" -or $_.RegistryPath -match "Hardware Feature") -and
            $_.Name -ne "Nested Virtualization Security"
        }
        
        if ($hardwareSettings.Count -gt 0) {
            Write-ColorOutput "`nNote: The following settings require hardware/firmware configuration and cannot be applied via registry:" -Color Warning
            foreach ($setting in $hardwareSettings) {
                Write-ColorOutput "  - $($setting.Name): $($setting.Recommendation)" -Color Info
            }
        }
    }
    
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
            Write-ColorOutput "The following changes would be applied:" -Color Info
            
            foreach ($item in $mitigationsToApply) {
                Write-ColorOutput "`nMitigation: $($item.Name)" -Color Info
                
                # Special display for nested virtualization
                if ($item.Name -eq "Nested Virtualization Security") {
                    Write-ColorOutput "  Action: Enable nested virtualization on Hyper-V VMs" -Color Gray
                    Write-ColorOutput "  Method: Set-VMProcessor -ExposeVirtualizationExtensions $true" -Color Gray
                    Write-ColorOutput "  Scope: All VMs (will be stopped if running)" -Color Gray
                    Write-ColorOutput "  Security Impact: REDUCES security score - enables VM attack surface" -Color Red
                }
                else {
                    # Regular registry changes
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
                    Write-ColorOutput "  Expected Impact: $impact" -Color Warning
                }
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
                
                # Special handling for nested virtualization
                if ($item.Name -eq "Nested Virtualization Security") {
                    try {
                        # Get all VMs
                        $vms = Get-VM -ErrorAction Stop
                        if ($vms.Count -eq 0) {
                            Write-ColorOutput "  No VMs found to configure" -Color Warning
                            continue
                        }
                        
                        Write-ColorOutput "  Found $($vms.Count) VMs. Enabling nested virtualization..." -Color Info
                        $vmSuccessCount = 0
                        
                        foreach ($vm in $vms) {
                            try {
                                # Only enable on stopped VMs
                                if ($vm.State -eq "Running") {
                                    Write-ColorOutput "  Stopping VM '$($vm.Name)' to enable nested virtualization..." -Color Warning
                                    Stop-VM -Name $vm.Name -Force -ErrorAction Stop
                                    # Wait a moment for VM to fully stop
                                    Start-Sleep -Seconds 3
                                }
                                
                                # Enable nested virtualization
                                Set-VMProcessor -VMName $vm.Name -ExposeVirtualizationExtensions $true -ErrorAction Stop
                                Write-ColorOutput "  Enabled nested virtualization for VM '$($vm.Name)'" -Color Good
                                $vmSuccessCount++
                            }
                            catch {
                                Write-ColorOutput "  Failed to configure VM '$($vm.Name)': $($_.Exception.Message)" -Color Bad
                            }
                        }
                        
                        if ($vmSuccessCount -eq $vms.Count) {
                            Write-ColorOutput "  Successfully enabled nested virtualization on all $vmSuccessCount VMs" -Color Good
                            $successCount++
                        }
                        else {
                            Write-ColorOutput "  Enabled nested virtualization on $vmSuccessCount of $($vms.Count) VMs" -Color Warning
                        }
                    }
                    catch {
                        Write-ColorOutput "  Failed to configure nested virtualization: $($_.Exception.Message)" -Color Bad
                    }
                }
                else {
                    # Regular registry-based configuration
                    if (Set-RegistryValue -Path $item.RegistryPath -Name $item.RegistryName -Value $item.ExpectedValue) {
                        $successCount++
                    }
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
    
    # Filter out items that are already properly configured
    # This includes "Enabled", but also hardware features that are working properly
    $notConfigured = $Results | Where-Object { 
        $status = $_.Status
        $canBeEnabled = $_.CanBeEnabled
        
        # Exclude if already enabled/working properly OR if it's an informational item that can't be configured
        -not ($status -eq "Enabled" -or 
            $status -match "^UEFI Firmware Active" -or
            $status -match "^TPM 2.0 Enabled" -or
            $status -match "^Enabled and Active" -or
            $status -match "Running" -or
            $status -match "Enforced" -or
            ($status -eq "Information" -and $canBeEnabled -eq $false))
    }
    
    # Filter CPU-specific mitigations in recommendations too
    if ($notConfigured.Count -gt 0) {
        $notConfigured = Filter-CPUSpecificMitigations -Mitigations $notConfigured -CPUManufacturer $cpuInfo.Manufacturer
    }
    
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
        Write-ColorOutput "(Filtered for $($cpuInfo.Manufacturer) CPU compatibility)" -Color Info
        foreach ($item in $notConfigured | Where-Object { $_.CanBeEnabled }) {
            # Only show registry commands for actual registry configurations
            if ($item.RegistryPath -match "^HKLM:|^HKCU:|^HKEY_") {
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
                
                Write-ColorOutput "reg add `"$($item.RegistryPath)`" /v `"$($item.RegistryName)`" /t $regType /d $regValue /f" -Color Info
            }
            elseif ($item.RegistryPath -match "Hardware|UEFI|BIOS") {
                Write-ColorOutput "# Hardware/UEFI: $($item.Name) - Configure in BIOS/UEFI settings" -Color Warning
            }
            elseif ($item.RegistryPath -match "Hyper-V") {
                Write-ColorOutput "# Hyper-V: $($item.Name) - Use Hyper-V PowerShell commands or GUI" -Color Warning
            }
            elseif ($item.RegistryPath -match "VMware") {
                Write-ColorOutput "# VMware: $($item.Name) - Configure on ESXi host" -Color Warning
            }
            else {
                Write-ColorOutput "# Configuration: $($item.Name) - Manual configuration required" -Color Warning
            }
        }
        Write-ColorOutput "`nNote: A system restart may be required after making registry changes." -Color Warning
        Write-ColorOutput "These are the core KB4073119 documented mitigations. For additional modern CVE mitigations," -Color Info
        Write-ColorOutput "use Microsoft's official SpeculationControl PowerShell module." -Color Info
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
    Write-ColorOutput "`n=== Mitigation Revert Mode ===" -Color Header
    Write-ColorOutput "Scanning for revertable side-channel mitigations..." -Color Info
    
    $revertableMitigations = Get-RevertableMitigations
    
    if ($revertableMitigations.Count -gt 0) {
        Write-ColorOutput "`nFound $($revertableMitigations.Count) revertable mitigation(s):" -Color Warning
        
        if ($Interactive) {
            Write-ColorOutput "`n!  WARNING: Reverting mitigations will REDUCE your system's security!" -Color Error
            Write-ColorOutput "Only proceed if specific mitigations are causing performance issues." -Color Error
            Write-ColorOutput "Always test in non-production environments first.`n" -Color Error
            
            if ($WhatIf) {
                Write-ColorOutput "WhatIf Mode: Changes will be previewed but not applied`n" -Color Warning
            }
            
            Write-ColorOutput "Available mitigations to revert:" -Color Info
            Write-ColorOutput "Use numbers to select (e.g., 1,3,4 or 1-3 or all for all mitigations):" -Color Info
            Write-ColorOutput "Enter 0 to revert no mitigations and exit:`n" -Color Info
            
            for ($i = 0; $i -lt $revertableMitigations.Count; $i++) {
                $mitigation = $revertableMitigations[$i]
                Write-ColorOutput "  [$($i + 1)] $($mitigation.Name) (Impact: $($mitigation.Impact))" -Color Warning
                Write-ColorOutput "      $($mitigation.Description)" -Color Info
                Write-ColorOutput "      Security Risk: $($mitigation.SecurityRisk)" -Color Error
                
                # Show appropriate configuration location
                if ($mitigation.Name -eq "Nested Virtualization Security") {
                    Write-ColorOutput "      Configuration: Hyper-V VM Processor Settings" -Color Gray
                }
                elseif ($mitigation.Name -match "VMware.*Nested.*Virtualization") {
                    Write-ColorOutput "      Configuration: VMware ESXi Host Settings" -Color Gray
                }
                elseif ($mitigation.RegistryPath -match "^HKLM:|^HKCU:|^HKEY_") {
                    Write-ColorOutput "      Registry: $($mitigation.RegistryPath)\$($mitigation.RegistryName)" -Color Gray
                }
                elseif ($mitigation.RegistryPath -match "Hardware|UEFI|BIOS") {
                    Write-ColorOutput "      Hardware/UEFI: $($mitigation.RegistryName)" -Color Gray
                }
                elseif ($mitigation.RegistryPath -match "Hyper-V") {
                    Write-ColorOutput "      Hyper-V: $($mitigation.RegistryName)" -Color Gray
                }
                elseif ($mitigation.RegistryPath -match "VMware") {
                    Write-ColorOutput "      VMware: $($mitigation.RegistryName)" -Color Gray
                }
                else {
                    Write-ColorOutput "      Configuration: $($mitigation.RegistryPath)\$($mitigation.RegistryName)" -Color Gray
                }
                
                Write-ColorOutput "" -Color Info
            }
            
            $selection = Read-Host "Enter your selection (numbers separated by commas, ranges like 1-3, 'all', or 0 for none)"
            
            if ([string]::IsNullOrWhiteSpace($selection)) {
                Write-ColorOutput "No selection made. Exiting revert mode." -Color Warning
                return
            }
            
            if ($selection -eq '0') {
                Write-ColorOutput "No mitigations selected for revert. Exiting without making any changes." -Color Info
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
                    $confirm = Read-Host "`n!  Are you sure you want to REMOVE these security protections? (yes/no)"
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

# Get current hardware status
$hwStatus = Get-HardwareRequirements

Write-ColorOutput "Hardware Security Assessment:" -Color Info
Write-ColorOutput "(Symbols: [+] Enabled/Good, [?] Needs Verification, [-] Disabled/Missing)" -Color Info

# Get updated hardware status from our Results array for consistency
$uefiResult = $Results | Where-Object { $_.Name -match "UEFI Firmware" }
$secureBootResult = $Results | Where-Object { $_.Name -eq "Secure Boot" }
$tpmResult = $Results | Where-Object { $_.Name -match "TPM 2.0" }
$vtxResult = $Results | Where-Object { $_.Name -match "CPU Virtualization" }
$iommuResult = $Results | Where-Object { $_.Name -match "IOMMU" }

# UEFI Status
Write-Host "- UEFI Firmware: " -NoNewline -ForegroundColor Gray
$uefiStatusIcon = if ($uefiResult.Status -match "Active") { "+" } else { "-" }
$uefiColor = if ($uefiResult.Status -match "Active") { $Colors['Good'] } else { $Colors['Bad'] }
Write-Host "$uefiStatusIcon $($uefiResult.Status)" -ForegroundColor $uefiColor

# Secure Boot Status
Write-Host "- Secure Boot: " -NoNewline -ForegroundColor Gray
$sbStatusIcon = if ($secureBootResult.Status -eq "Enabled") { "+" } elseif ($secureBootResult.Status -match "Available|Unknown") { "-" } else { "-" }
$sbColor = if ($secureBootResult.Status -eq "Enabled") { $Colors['Good'] } elseif ($secureBootResult.Status -match "Available|Unknown") { $Colors['Warning'] } else { $Colors['Bad'] }
Write-Host "$sbStatusIcon $($secureBootResult.Status)" -ForegroundColor $sbColor

# TPM Status
Write-Host "- TPM 2.0: " -NoNewline -ForegroundColor Gray
$tpmStatusIcon = if ($tpmResult.Status -match "TPM 2.0 Enabled") { "[+]" } elseif ($tpmResult.Status -match "Present|Unknown") { "[-]" } else { "[-]" }
$tpmColor = if ($tpmResult.Status -match "TPM 2.0 Enabled") { $Colors['Good'] } elseif ($tpmResult.Status -match "Present|Unknown") { $Colors['Warning'] } else { $Colors['Bad'] }
Write-Host "$tpmStatusIcon $($tpmResult.Status)" -ForegroundColor $tpmColor
                
# CPU Virtualization Status
Write-Host "- CPU Virtualization (VT-x/AMD-V): " -NoNewline -ForegroundColor Gray
$vtxStatusIcon = if ($vtxResult.Status -match "Enabled and Active") { "+" } elseif ($vtxResult.Status -match "Available|Unknown") { "-" } else { "-" }
$vtxColor = if ($vtxResult.Status -match "Enabled and Active") { $Colors['Good'] } elseif ($vtxResult.Status -match "Available|Unknown") { $Colors['Warning'] } else { $Colors['Bad'] }
Write-Host "$vtxStatusIcon $($vtxResult.Status)" -ForegroundColor $vtxColor

# IOMMU Status
Write-Host "- IOMMU/VT-d Support: " -NoNewline -ForegroundColor Gray
$iommuStatusIcon = if ($iommuResult.Status -match "Enabled and Active") { "+" } else { "-" }
$iommuColor = if ($iommuResult.Status -match "Enabled and Active") { $Colors['Good'] } else { $Colors['Warning'] }
Write-Host "$iommuStatusIcon $($iommuResult.Status)" -ForegroundColor $iommuColor

Write-ColorOutput "`nRequired CPU Features:" -Color Info
Write-ColorOutput "- Intel: VT-x with EPT, VT-d (or AMD: AMD-V with RVI, AMD-Vi)" -Color $(if ($hwStatus.VTxSupport) { 'Good' } else { 'Warning' })
Write-ColorOutput "- Hardware support for SMEP/SMAP" -Color Info
Write-ColorOutput "- CPU microcode with Spectre/Meltdown mitigations" -Color Warning
Write-ColorOutput "- For VBS: IOMMU, TPM 2.0, UEFI Secure Boot" -Color $(if ($hwStatus.TPMPresent -and $hwStatus.SecureBootEnabled -and $hwStatus.IsUEFI) { 'Good' } else { 'Warning' })

Write-ColorOutput "`nAdministrator Action Items:" -Color Header
Write-ColorOutput "===========================" -Color Header

# Generate specific action items based on current status
$actionItems = @()

if (!$hwStatus.IsUEFI) {
    $actionItems += "- CRITICAL: Convert from Legacy BIOS to UEFI mode (may require OS reinstall)"
}

if ($hwStatus.IsUEFI -and !$hwStatus.SecureBootEnabled) {
    $actionItems += "- Access UEFI firmware settings and enable Secure Boot"
}

if (!$hwStatus.TPMPresent) {
    $actionItems += "- Enable TPM 2.0 in BIOS/UEFI or install TPM hardware module"
}
elseif ($hwStatus.TPMVersion -notmatch "2\.0") {
    $actionItems += "- Upgrade TPM to version 2.0 or enable TPM 2.0 mode in UEFI"
}

if (!$hwStatus.VTxSupport) {
    $actionItems += "- Enable VT-x (Intel) or AMD-V (AMD) virtualization in BIOS/UEFI"
}

if ($hwStatus.IOMMUSupport -notmatch "Available.*Hyper-V") {
    $actionItems += "- Enable VT-d (Intel) or AMD-Vi (AMD) IOMMU in BIOS/UEFI for DMA protection"
}

# Always include firmware update recommendation
$actionItems += "- Update system firmware/BIOS to latest version for security fixes"
$actionItems += "- Update CPU microcode through Windows Update or vendor tools"

if ($actionItems.Count -gt 0) {
    Write-ColorOutput "`nRequired Actions for Optimal Security:" -Color Warning
    foreach ($item in $actionItems) {
        Write-ColorOutput $item -Color Warning
    }
}
else {
    Write-ColorOutput "`nHardware Security Status: All critical components properly configured!" -Color Good
}

Write-ColorOutput "`nManual Verification Steps:" -Color Info
Write-ColorOutput "- Boot into UEFI/BIOS setup to verify settings" -Color Info
Write-ColorOutput "- Run 'msinfo32.exe' and check 'System Summary' for Secure Boot State" -Color Info
Write-ColorOutput "- Use `'tpm.msc`' to verify TPM status and version" -Color Info
Write-ColorOutput "- Check Windows Event Logs for Hyper-V and VBS initialization" -Color Info

Write-ColorOutput "`nFirmware Requirements Status:" -Color Info
$uefiStatusText = if ($hwStatus.IsUEFI) { "[+] Met" } else { "[-] Not Met" }
$uefiStatusColor = if ($hwStatus.IsUEFI) { "Good" } else { "Bad" }
Write-ColorOutput "- UEFI firmware (not legacy BIOS): $uefiStatusText" -Color $uefiStatusColor
$secureBootStatusText = if ($hwStatus.SecureBootCapable) { "[+] Available" } else { "[-] Not Available" }
$secureBootStatusColor = if ($hwStatus.SecureBootCapable) { "Good" } else { "Bad" }
Write-ColorOutput "- Secure Boot capability: $secureBootStatusText" -Color $secureBootStatusColor
$tpmStatusText = if ($hwStatus.TPMPresent) { "[+] Present" } else { "[-] Missing" }
$tpmStatusColor = if ($hwStatus.TPMPresent) { "Good" } else { "Bad" }
Write-ColorOutput "- TPM 2.0: $tpmStatusText" -Color $tpmStatusColor
Write-ColorOutput "- Latest firmware updates: [?] Check with manufacturer" -Color Warning

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





