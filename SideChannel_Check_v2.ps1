<#
.SYNOPSIS
    Side-Channel Vulnerability Mitigation Assessment and Remediation Tool - Version 2.0

.DESCRIPTION
    Enterprise-grade tool for assessing and configuring Windows side-channel vulnerability
    mitigations (Spectre, Meltdown, L1TF, MDS, and related CVEs).
    
    Version 2.0 features a redesigned architecture with:
    - Modular function-based design (PowerShell 5.1 & 7.x compatible)
    - Kernel runtime state detection via native Windows API  
    - Platform-aware recommendations (Physical/Hyper-V/VMware)
    - Simplified output focused on actionable intelligence
    - Interactive apply mode with automatic rollback capability
    - Comprehensive change tracking and audit logging

.PARAMETER Mode
    Operation mode: 'Assess' (default), 'Apply', 'Revert'

.PARAMETER Interactive
    Enable interactive mode for Apply operations (recommended)

.PARAMETER ShowDetails
    Display detailed technical information

.PARAMETER ExportPath
    Path to export assessment results (CSV format). Can be used with any mode to save results.

.PARAMETER LogPath
    Path to write detailed operation logs

.EXAMPLE
    .\SideChannel_Check_v2.ps1
    Run assessment and display current mitigation status

.EXAMPLE
    .\SideChannel_Check_v2.ps1 -Mode Apply -Interactive
    Interactively select and apply mitigations

.EXAMPLE
    .\SideChannel_Check_v2.ps1 -Mode Revert
    Restore previously saved configuration

.EXAMPLE
    .\SideChannel_Check_v2.ps1 -ExportPath "results.csv"
    Run assessment and export results to CSV

.NOTES
    Version:        2.0.0
    Requires:       PowerShell 5.1 or higher, Administrator privileges
    Platform:       Windows 10/11, Windows Server 2016+
    Compatible:     PowerShell 5.1, 7.x
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Assess', 'Apply', 'Revert')]
    [string]$Mode = 'Assess',
    
    [Parameter()]
    [switch]$Interactive,
    
    [Parameter()]
    [switch]$ShowDetails,
    
    [Parameter()]
    [string]$ExportPath,
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\Logs\SideChannelCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

# ============================================================================
# SCRIPT INITIALIZATION
# ============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Script metadata
$script:Version = '2.0.0'
$script:BackupPath = "$PSScriptRoot\Backups"
$script:ConfigPath = "$PSScriptRoot\Config"

# Runtime state storage
$script:RuntimeState = @{
    APIAvailable = $false
    Flags = @{}
}

$script:PlatformInfo = @{
    Type = 'Unknown'
    Details = @{}
}

# Ensure required directories exist
@($script:BackupPath, $script:ConfigPath, (Split-Path $LogPath -Parent)) | ForEach-Object {
    if ($_ -and -not (Test-Path $_)) {
        New-Item -Path $_ -ItemType Directory -Force | Out-Null
    }
}

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info',
        
        [Parameter()]
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    try {
        Add-Content -Path $LogPath -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Silently continue if log write fails
    }
    
    # Write to console
    if (-not $NoConsole) {
        $color = switch ($Level) {
            'Success' { 'Green' }
            'Warning' { 'Yellow' }
            'Error' { 'Red' }
            'Debug' { 'Gray' }
            default { 'Cyan' }
        }
        
        Write-Host "[$Level] $Message" -ForegroundColor $color
    }
}

function Initialize-Log {
    $header = @"
================================================================================
Side-Channel Vulnerability Mitigation Tool - Version $script:Version
Session Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
User: $env:USERNAME
Computer: $env:COMPUTERNAME
PowerShell Version: $($PSVersionTable.PSVersion)
================================================================================

"@
    try {
        Set-Content -Path $LogPath -Value $header -Encoding UTF8 -Force
    } catch {
        Write-Warning "Could not initialize log file: $($_.Exception.Message)"
    }
}

# ============================================================================
# KERNEL RUNTIME DETECTION
# ============================================================================

function Initialize-RuntimeDetection {
    <#
    .SYNOPSIS
    Detects real-time kernel mitigation state via Windows API
    #>
    
    Write-Log "Initializing kernel runtime state detection..." -Level Debug
    
    try {
        # Check if type already exists
        $ntApiType = 'Kernel32.NtApi' -as [type]
        
        if (-not $ntApiType) {
            # P/Invoke setup for NtQuerySystemInformation
            $signature = @'
[DllImport("ntdll.dll", SetLastError = true)]
public static extern int NtQuerySystemInformation(
    uint SystemInformationClass,
    IntPtr SystemInformation,
    uint SystemInformationLength,
    out uint ReturnLength);
'@
            Add-Type -MemberDefinition $signature -Name 'NtApi' -Namespace 'Kernel32'
            $ntApiType = 'Kernel32.NtApi' -as [type]
        }
        
        # Query system information (class 201 = SystemSpeculationControlInformation)
        $infoSize = 256
        $infoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($infoSize)
        
        try {
            $returnLength = 0
            $result = $ntApiType::NtQuerySystemInformation(
                201,  # SystemSpeculationControlInformation
                $infoPtr,
                $infoSize,
                [ref]$returnLength
            )
            
            if ($result -eq 0) {
                # Parse the returned structure
                $flags = [System.Runtime.InteropServices.Marshal]::ReadInt32($infoPtr, 0)
                
                # Extract individual mitigation states
                $script:RuntimeState.Flags['BTIEnabled'] = ($flags -band 0x01) -ne 0
                $script:RuntimeState.Flags['SSBDSystemWide'] = ($flags -band 0x10) -ne 0
                $script:RuntimeState.Flags['EnhancedIBRS'] = ($flags -band 0x100) -ne 0
                $script:RuntimeState.Flags['RetpolineEnabled'] = ($flags -band 0x200) -ne 0
                $script:RuntimeState.Flags['MBClearEnabled'] = ($flags -band 0x1000) -ne 0
                $script:RuntimeState.Flags['L1DFlushSupported'] = ($flags -band 0x2000) -ne 0
                $script:RuntimeState.Flags['RDCLHardwareProtected'] = ($flags -band 0x4000) -ne 0
                $script:RuntimeState.Flags['MDSHardwareProtected'] = ($flags -band 0x8000) -ne 0
                
                # KVAS detection
                $kvasReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
                    -Name "EnableKernelVaShadow" -ErrorAction SilentlyContinue
                $script:RuntimeState.Flags['KVAShadowEnabled'] = ($null -ne $kvasReg) -and (-not $script:RuntimeState.Flags['RDCLHardwareProtected'])
                
                $script:RuntimeState.APIAvailable = $true
                Write-Log "Kernel runtime state detection: Operational" -Level Success
            } else {
                Write-Log "NtQuerySystemInformation returned error: 0x$($result.ToString('X8'))" -Level Warning
            }
        } finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($infoPtr)
        }
        
    } catch {
        Write-Log "Kernel runtime detection not available: $($_.Exception.Message)" -Level Warning
        $script:RuntimeState.APIAvailable = $false
    }
}

function Get-RuntimeMitigationStatus {
    param(
        [Parameter(Mandatory)]
        [string]$MitigationId
    )
    
    if (-not $script:RuntimeState.APIAvailable) {
        return 'N/A'
    }
    
    switch ($MitigationId) {
        'BTI' {
            if ($script:RuntimeState.Flags['EnhancedIBRS']) { return 'Active (Enhanced IBRS)' }
            if ($script:RuntimeState.Flags['RetpolineEnabled']) { return 'Active (Retpoline)' }
            if ($script:RuntimeState.Flags['BTIEnabled']) { return 'Active' }
            return 'Inactive'
        }
        'SSBD' {
            if ($script:RuntimeState.Flags['SSBDSystemWide']) { return 'Active' }
            return 'Inactive'
        }
        'KVAS' {
            if ($script:RuntimeState.Flags['RDCLHardwareProtected']) { return 'Not Needed (HW Immune)' }
            if ($script:RuntimeState.Flags['KVAShadowEnabled']) { return 'Active' }
            return 'Inactive'
        }
        'MDS' {
            if ($script:RuntimeState.Flags['MDSHardwareProtected']) { return 'Not Needed (HW Immune)' }
            if ($script:RuntimeState.Flags['MBClearEnabled']) { return 'Active' }
            return 'Inactive'
        }
        'L1TF' {
            if ($script:RuntimeState.Flags['L1DFlushSupported']) { return 'Supported' }
            return 'Not Supported'
        }
        default { return 'N/A' }
    }
}

# ============================================================================
# PLATFORM DETECTION
# ============================================================================

function Initialize-PlatformDetection {
    <#
    .SYNOPSIS
    Detects platform type and hardware capabilities
    #>
    
    Write-Log "Detecting platform type..." -Level Debug
    
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    
    # Detect if virtual machine
    $isVM = $computerSystem.Model -match 'Virtual|VMware|Hyper-V'
    
    if ($isVM) {
        if ($computerSystem.Model -match 'VMware') {
            $script:PlatformInfo.Type = 'VMwareGuest'
            $script:PlatformInfo.Details['Hypervisor'] = 'VMware'
        } elseif ($computerSystem.Model -match 'Virtual|Hyper-V') {
            $script:PlatformInfo.Type = 'HyperVGuest'
            $script:PlatformInfo.Details['Hypervisor'] = 'Hyper-V'
        } else {
            $script:PlatformInfo.Type = 'VirtualMachine'
        }
    } else {
        # Check for Hyper-V role
        $hyperV = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction SilentlyContinue
        if ($hyperV -and $hyperV.State -eq 'Enabled') {
            $script:PlatformInfo.Type = 'HyperVHost'
        } else {
            $script:PlatformInfo.Type = 'Physical'
        }
    }
    
    $script:PlatformInfo.Details['CPUVendor'] = $cpu.Manufacturer
    $script:PlatformInfo.Details['CPUModel'] = $cpu.Name
    $script:PlatformInfo.Details['OSVersion'] = $os.Caption
    $script:PlatformInfo.Details['OSBuild'] = $os.BuildNumber
    
    Write-Log "Platform detected: $($script:PlatformInfo.Type)" -Level Info
}

function Test-PlatformApplicability {
    param(
        [Parameter(Mandatory)]
        [string]$TargetPlatform
    )
    
    switch ($TargetPlatform) {
        'All' { return $true }
        'Physical' { return $script:PlatformInfo.Type -in @('Physical', 'HyperVHost') }
        'HyperVHost' { return $script:PlatformInfo.Type -eq 'HyperVHost' }
        'HyperVGuest' { return $script:PlatformInfo.Type -eq 'HyperVGuest' }
        'VMwareGuest' { return $script:PlatformInfo.Type -eq 'VMwareGuest' }
        'VirtualMachine' { return $script:PlatformInfo.Type -match 'Guest$|VirtualMachine' }
        default { return $true }
    }
}

# ============================================================================
# MITIGATION REGISTRY
# ============================================================================

function Get-MitigationDefinitions {
    <#
    .SYNOPSIS
    Returns centralized registry of all mitigation definitions
    #>
    
    return @(
        # Critical - Spectre/Meltdown core mitigations
        @{
            Id = 'SSBD'
            Name = 'Speculative Store Bypass Disable'
            CVE = 'CVE-2018-3639'
            Category = 'Critical'
            RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            RegistryName = 'FeatureSettingsOverride'
            EnabledValue = 72
            Description = 'Prevents Speculative Store Bypass (Variant 4) attacks'
            Impact = 'Low'
            Platform = 'All'
            RuntimeDetection = 'SSBD'
            Recommendation = 'Enable to protect against speculative execution vulnerabilities'
        },
        @{
            Id = 'SSBD_Mask'
            Name = 'SSBD Feature Mask'
            CVE = 'CVE-2018-3639'
            Category = 'Critical'
            RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            RegistryName = 'FeatureSettingsOverrideMask'
            EnabledValue = 3
            Description = 'Required companion setting for SSBD'
            Impact = 'Low'
            Platform = 'All'
            RuntimeDetection = $null
            Recommendation = 'Must be enabled for SSBD to function'
        },
        @{
            Id = 'BTI'
            Name = 'Branch Target Injection Mitigation'
            CVE = 'CVE-2017-5715'
            Category = 'Critical'
            RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName = 'DisablePageCombining'
            EnabledValue = 0
            Description = 'Mitigates Spectre Variant 2 attacks'
            Impact = 'Low'
            Platform = 'All'
            RuntimeDetection = 'BTI'
            Recommendation = 'Essential protection against Spectre v2'
        },
        @{
            Id = 'KVAS'
            Name = 'Kernel VA Shadow (Meltdown Protection)'
            CVE = 'CVE-2017-5754'
            Category = 'Critical'
            RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            RegistryName = 'EnableKernelVaShadow'
            EnabledValue = 1
            Description = 'Page table isolation to prevent Meltdown attacks'
            Impact = 'Medium'
            Platform = 'All'
            RuntimeDetection = 'KVAS'
            Recommendation = 'Critical for Meltdown protection; modern CPUs have hardware immunity'
        },
        @{
            Id = 'EnhancedIBRS'
            Name = 'Enhanced IBRS'
            CVE = 'CVE-2017-5715'
            Category = 'Critical'
            RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName = 'IbrsEnabled'
            EnabledValue = 1
            Description = 'Hardware-based Spectre v2 protection'
            Impact = 'Low'
            Platform = 'All'
            RuntimeDetection = $null
            Recommendation = 'Enable on CPUs with Enhanced IBRS support'
        },
        @{
            Id = 'TSXDisable'
            Name = 'Intel TSX Disable'
            CVE = 'CVE-2019-11135'
            Category = 'Recommended'
            RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName = 'DisableTsx'
            EnabledValue = 1
            Description = 'Disable Intel TSX to prevent TAA vulnerabilities'
            Impact = 'Low'
            Platform = 'All'
            RuntimeDetection = $null
            Recommendation = 'Disable unless specifically required by applications'
        },
        
        # High-impact mitigations
        @{
            Id = 'L1TF'
            Name = 'L1 Terminal Fault Mitigation'
            CVE = 'CVE-2018-3620'
            Category = 'Optional'
            RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName = 'L1TFMitigationLevel'
            EnabledValue = 1
            Description = 'Protects against L1 Terminal Fault (Foreshadow)'
            Impact = 'High'
            Platform = 'HyperVHost'
            RuntimeDetection = 'L1TF'
            Recommendation = 'High performance impact; for multi-tenant virtualization only'
        },
        @{
            Id = 'MDS'
            Name = 'MDS Mitigation (ZombieLoad)'
            CVE = 'CVE-2018-12130'
            Category = 'Recommended'
            RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName = 'MDSMitigationLevel'
            EnabledValue = 1
            Description = 'Protects against MDS attacks'
            Impact = 'Medium'
            Platform = 'All'
            RuntimeDetection = 'MDS'
            Recommendation = 'Moderate performance impact; modern CPUs have hardware immunity'
        },
        @{
            Id = 'TAA'
            Name = 'TSX Asynchronous Abort Mitigation'
            CVE = 'CVE-2019-11135'
            Category = 'Recommended'
            RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName = 'TSXAsyncAbortLevel'
            EnabledValue = 1
            Description = 'Protects against TAA vulnerabilities'
            Impact = 'Medium'
            Platform = 'All'
            RuntimeDetection = $null
            Recommendation = 'Enable if TSX cannot be disabled'
        },
        @{
            Id = 'HWMitigations'
            Name = 'Hardware Security Mitigations'
            CVE = 'Multiple'
            Category = 'Critical'
            RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName = 'MitigationOptions'
            EnabledValue = 0x2000000000000000
            Description = 'Core hardware-based security features'
            Impact = 'Low'
            Platform = 'All'
            RuntimeDetection = $null
            Recommendation = 'Enable core hardware mitigation features'
        }
    )
}

# ============================================================================
# ASSESSMENT ENGINE
# ============================================================================

function Invoke-MitigationAssessment {
    <#
    .SYNOPSIS
    Runs assessment of all applicable mitigations
    #>
    
    Write-Log "Starting mitigation assessment..." -Level Info
    
    $mitigations = Get-MitigationDefinitions
    $results = @()
    
    foreach ($mitigation in $mitigations) {
        # Check platform applicability
        if (-not (Test-PlatformApplicability -TargetPlatform $mitigation.Platform)) {
            Write-Log "Skipping $($mitigation.Name) - not applicable to $($script:PlatformInfo.Type)" -Level Debug
            continue
        }
        
        $result = Test-Mitigation -Mitigation $mitigation
        $results += $result
    }
    
    Write-Log "Assessment complete: $($results.Count) mitigations evaluated" -Level Success
    return $results
}

function Test-Mitigation {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Mitigation
    )
    
    # Get current registry value
    $currentValue = $null
    $registryStatus = 'Not Configured'
    
    try {
        $regItem = Get-ItemProperty -Path $Mitigation.RegistryPath -Name $Mitigation.RegistryName -ErrorAction Stop
        $currentValue = $regItem.($Mitigation.RegistryName)
        
        # Compare values
        if (Compare-MitigationValue -Current $currentValue -Expected $Mitigation.EnabledValue -RegistryName $Mitigation.RegistryName) {
            $registryStatus = 'Enabled'
        } else {
            $registryStatus = 'Disabled'
        }
    } catch {
        $registryStatus = 'Not Configured'
    }
    
    # Get runtime status
    $runtimeStatus = 'N/A'
    if ($Mitigation.RuntimeDetection) {
        $runtimeStatus = Get-RuntimeMitigationStatus -MitigationId $Mitigation.RuntimeDetection
    }
    
    # Determine overall status
    $overallStatus = Get-OverallStatus -RegistryStatus $registryStatus -RuntimeStatus $runtimeStatus
    
    # Determine action needed
    $actionNeeded = Get-ActionNeeded -Category $Mitigation.Category -OverallStatus $overallStatus
    
    return [PSCustomObject]@{
        Id = $Mitigation.Id
        Name = $Mitigation.Name
        CVE = $Mitigation.CVE
        Category = $Mitigation.Category
        RegistryStatus = $registryStatus
        RuntimeStatus = $runtimeStatus
        OverallStatus = $overallStatus
        ActionNeeded = $actionNeeded
        CurrentValue = $currentValue
        ExpectedValue = $Mitigation.EnabledValue
        Impact = $Mitigation.Impact
        Description = $Mitigation.Description
        Recommendation = $Mitigation.Recommendation
        RegistryPath = $Mitigation.RegistryPath
        RegistryName = $Mitigation.RegistryName
    }
}

function Compare-MitigationValue {
    param(
        [object]$Current,
        [object]$Expected,
        [string]$RegistryName
    )
    
    if ($null -eq $Current) { return $false }
    
    # Handle hex string comparisons for large values
    if ($Expected -is [long] -or $Expected -is [uint64]) {
        # For MitigationOptions, check if core flag is set
        if ($RegistryName -eq 'MitigationOptions' -and $Current -is [uint64]) {
            $coreFlagPresent = ($Current -band $Expected) -eq $Expected
            return $coreFlagPresent
        }
        return $Current -eq $Expected
    }
    
    return $Current -eq $Expected
}

function Get-OverallStatus {
    param(
        [string]$RegistryStatus,
        [string]$RuntimeStatus
    )
    
    # Priority: Runtime status > Registry status
    if ($RuntimeStatus -ne 'N/A') {
        if ($RuntimeStatus -match 'Active|Immune|Supported|Not Needed') {
            return 'Protected'
        } else {
            return 'Vulnerable'
        }
    }
    
    # Fallback to registry
    switch ($RegistryStatus) {
        'Enabled' { return 'Protected' }
        'Disabled' { return 'Vulnerable' }
        default { return 'Unknown' }
    }
}

function Get-ActionNeeded {
    param(
        [string]$Category,
        [string]$OverallStatus
    )
    
    if ($OverallStatus -eq 'Protected') {
        return 'No'
    }
    
    switch ($Category) {
        'Critical' { return 'Yes - Critical' }
        'Recommended' { return 'Yes - Recommended' }
        'Optional' { return 'Consider' }
        default { return 'No' }
    }
}

# ============================================================================
# OUTPUT FORMATTING
# ============================================================================

function Show-Header {
    $header = @"

================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version $script:Version
================================================================================

"@
    Write-Host $header -ForegroundColor Cyan
}

function Show-PlatformInfo {
    Write-Host "`n--- Platform Information ---" -ForegroundColor Yellow
    Write-Host "Type:        " -NoNewline
    Write-Host $script:PlatformInfo.Type -ForegroundColor White
    Write-Host "CPU:         " -NoNewline
    Write-Host $script:PlatformInfo.Details['CPUModel'] -ForegroundColor White
    Write-Host "OS:          " -NoNewline
    Write-Host "$($script:PlatformInfo.Details['OSVersion']) (Build $($script:PlatformInfo.Details['OSBuild']))" -ForegroundColor White
    
    if ($script:PlatformInfo.Details['Hypervisor']) {
        Write-Host "Hypervisor:  " -NoNewline
        Write-Host $script:PlatformInfo.Details['Hypervisor'] -ForegroundColor White
    }
}

function Show-AssessmentSummary {
    param([array]$Results)
    
    Write-Host "`n--- Security Assessment Summary ---" -ForegroundColor Yellow
    
    $protected = @($Results | Where-Object { $_.OverallStatus -eq 'Protected' }).Count
    $vulnerable = @($Results | Where-Object { $_.OverallStatus -eq 'Vulnerable' }).Count
    $unknown = @($Results | Where-Object { $_.OverallStatus -eq 'Unknown' }).Count
    $total = $Results.Count
    
    $protectionPercent = if ($total -gt 0) { [math]::Round(($protected / $total) * 100, 1) } else { 0 }
    
    Write-Host "Total Mitigations Evaluated:  " -NoNewline
    Write-Host $total -ForegroundColor White
    
    Write-Host "Protected:                    " -NoNewline
    Write-Host "$protected " -ForegroundColor Green -NoNewline
    Write-Host "($protectionPercent%)"
    
    if ($vulnerable -gt 0) {
        Write-Host "Vulnerable:                   " -NoNewline
        Write-Host $vulnerable -ForegroundColor Red
    }
    
    if ($unknown -gt 0) {
        Write-Host "Unknown Status:               " -NoNewline
        Write-Host $unknown -ForegroundColor Gray
    }
    
    # Visual progress bar
    Write-Host "`nSecurity Score: " -NoNewline
    $barLength = 40
    $filledLength = [math]::Round(($protectionPercent / 100) * $barLength)
    $emptyLength = $barLength - $filledLength
    
    # Determine color based on percentage
    $barColor = if ($protectionPercent -ge 90) { 'Green' }
                elseif ($protectionPercent -ge 75) { 'Cyan' }
                elseif ($protectionPercent -ge 50) { 'Yellow' }
                else { 'Red' }
    
    # Build progress bar using block characters (PS 5.1 compatible)
    Write-Host "[" -NoNewline
    Write-Host ("=" * $filledLength) -ForegroundColor $barColor -NoNewline
    Write-Host (" " * $emptyLength) -NoNewline
    Write-Host "] " -NoNewline
    Write-Host "$protectionPercent%" -ForegroundColor $barColor
    
    # Security level
    Write-Host "Security Level: " -NoNewline
    if ($protectionPercent -ge 90) {
        Write-Host "Excellent" -ForegroundColor Green
    } elseif ($protectionPercent -ge 75) {
        Write-Host "Good" -ForegroundColor Cyan
    } elseif ($protectionPercent -ge 50) {
        Write-Host "Fair" -ForegroundColor Yellow
    } else {
        Write-Host "Poor - Action Required" -ForegroundColor Red
    }
}

function Show-MitigationTable {
    param(
        [array]$Results,
        [bool]$Detailed
    )
    
    Write-Host "`n--- Mitigation Status ---" -ForegroundColor Yellow
    
    if ($Detailed) {
        $Results | Format-Table -Property Name, OverallStatus, RuntimeStatus, RegistryStatus, ActionNeeded, Impact, CVE -AutoSize
    } else {
        # Simplified view
        Write-Host ("{0,-45} {1,-15} {2,-20} {3,-10}" -f "Mitigation", "Status", "Action Needed", "Impact") -ForegroundColor Gray
        Write-Host ("{0,-45} {1,-15} {2,-20} {3,-10}" -f ("-" * 44), ("-" * 14), ("-" * 19), ("-" * 9)) -ForegroundColor DarkGray
        
        foreach ($result in $Results) {
            $statusColor = switch ($result.OverallStatus) {
                'Protected' { 'Green' }
                'Vulnerable' { 'Red' }
                default { 'Gray' }
            }
            
            $actionColor = switch -Wildcard ($result.ActionNeeded) {
                '*Critical*' { 'Red' }
                '*Recommended*' { 'Yellow' }
                'Consider' { 'Cyan' }
                default { 'Green' }
            }
            
            Write-Host ("{0,-45}" -f $result.Name) -NoNewline
            Write-Host ("{0,-15}" -f $result.OverallStatus) -ForegroundColor $statusColor -NoNewline
            Write-Host ("{0,-20}" -f $result.ActionNeeded) -ForegroundColor $actionColor -NoNewline
            Write-Host ("{0,-10}" -f $result.Impact) -ForegroundColor Gray
        }
    }
}

function Show-Recommendations {
    param([array]$Results)
    
    $actionable = @($Results | Where-Object { $_.ActionNeeded -match 'Yes|Consider' })
    
    if ($actionable.Count -eq 0) {
        Write-Host "`n✓ All critical mitigations are properly configured!" -ForegroundColor Green
        return
    }
    
    Write-Host "`n--- Recommendations ---" -ForegroundColor Yellow
    
    $critical = @($actionable | Where-Object { $_.ActionNeeded -match 'Critical' })
    $recommended = @($actionable | Where-Object { $_.ActionNeeded -match 'Recommended' })
    $optional = @($actionable | Where-Object { $_.ActionNeeded -eq 'Consider' })
    
    if ($critical.Count -gt 0) {
        Write-Host "`n🔴 CRITICAL - Apply immediately:" -ForegroundColor Red
        foreach ($item in $critical) {
            Write-Host "   • $($item.Name)" -ForegroundColor White
            Write-Host "     $($item.Recommendation)" -ForegroundColor Gray
            if ($item.Impact -eq 'High') {
                Write-Host "     ⚠ Performance Impact: HIGH" -ForegroundColor Yellow
            }
        }
    }
    
    if ($recommended.Count -gt 0) {
        Write-Host "`n🟡 RECOMMENDED - Apply for enhanced security:" -ForegroundColor Yellow
        foreach ($item in $recommended) {
            Write-Host "   • $($item.Name)" -ForegroundColor White
            Write-Host "     $($item.Recommendation)" -ForegroundColor Gray
        }
    }
    
    if ($optional.Count -gt 0) {
        Write-Host "`n🟢 OPTIONAL - Evaluate based on environment:" -ForegroundColor Cyan
        foreach ($item in $optional) {
            Write-Host "   • $($item.Name)" -ForegroundColor White
            Write-Host "     $($item.Recommendation)" -ForegroundColor Gray
        }
    }
    
    Write-Host "`nTo apply mitigations, run:" -ForegroundColor Cyan
    Write-Host "   .\SideChannel_Check_v2.ps1 -Mode Apply -Interactive" -ForegroundColor White
}

# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

function New-ConfigurationBackup {
    param([array]$Mitigations)
    
    Write-Log "Creating configuration backup..." -Level Info
    
    $backupFile = Join-Path $script:BackupPath "Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    
    $backupData = @{
        Timestamp = Get-Date -Format 'o'
        Computer = $env:COMPUTERNAME
        User = $env:USERNAME
        Mitigations = @()
    }
    
    foreach ($mitigation in $Mitigations) {
        try {
            $regItem = Get-ItemProperty -Path $mitigation.RegistryPath -Name $mitigation.RegistryName -ErrorAction Stop
            $value = $regItem.($mitigation.RegistryName)
        } catch {
            $value = $null
        }
        
        $backupData.Mitigations += @{
            Id = $mitigation.Id
            Name = $mitigation.Name
            RegistryPath = $mitigation.RegistryPath
            RegistryName = $mitigation.RegistryName
            Value = $value
        }
    }
    
    $backupData | ConvertTo-Json -Depth 10 | Set-Content -Path $backupFile -Encoding UTF8
    Write-Log "Backup created: $backupFile" -Level Success
    return $backupFile
}

function Get-LatestBackup {
    $backupFiles = @(Get-ChildItem -Path $script:BackupPath -Filter "Backup_*.json" -ErrorAction SilentlyContinue)
    
    if ($backupFiles.Count -eq 0) {
        return $null
    }
    
    $latest = $backupFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    return Get-Content -Path $latest.FullName -Raw | ConvertFrom-Json
}

function Set-MitigationValue {
    param(
        [hashtable]$Mitigation
    )
    
    Write-Log "Applying: $($Mitigation.Name)" -Level Info
    
    try {
        # Ensure registry path exists
        if (-not (Test-Path $Mitigation.RegistryPath)) {
            New-Item -Path $Mitigation.RegistryPath -Force | Out-Null
        }
        
        # Determine value type
        $valueType = 'DWord'
        if ($Mitigation.EnabledValue -is [uint64] -or $Mitigation.EnabledValue -gt 0xFFFFFFFF) {
            $valueType = 'QWord'
        }
        
        Set-ItemProperty -Path $Mitigation.RegistryPath `
            -Name $Mitigation.RegistryName `
            -Value $Mitigation.EnabledValue `
            -Type $valueType -Force
        
        Write-Log "Applied: $($Mitigation.Name)" -Level Success
        return $true
    } catch {
        Write-Log "Failed to apply $($Mitigation.Name): $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Restore-Configuration {
    param([object]$Backup)
    
    Write-Log "Restoring configuration from $($Backup.Timestamp)" -Level Info
    
    $success = 0
    $failed = 0
    
    foreach ($item in $Backup.Mitigations) {
        try {
            if ($null -eq $item.Value) {
                Remove-ItemProperty -Path $item.RegistryPath -Name $item.RegistryName -ErrorAction SilentlyContinue
                Write-Log "Removed: $($item.Name)" -Level Info
            } else {
                Set-ItemProperty -Path $item.RegistryPath -Name $item.RegistryName -Value $item.Value -Force
                Write-Log "Restored: $($item.Name)" -Level Info
            }
            $success++
        } catch {
            Write-Log "Could not restore $($item.Name): $($_.Exception.Message)" -Level Warning
            $failed++
        }
    }
    
    Write-Host "`n=== Restore Summary ===" -ForegroundColor Cyan
    Write-Host "Successfully restored: $success" -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host "Failed: $failed" -ForegroundColor Red
    }
    
    Write-Log "Configuration restored: $success successful, $failed failed" -Level Success
}

# ============================================================================
# INTERACTIVE APPLY MODE
# ============================================================================

function Invoke-InteractiveApply {
    param([array]$Results)
    
    Write-Host "`n=== Interactive Mitigation Application ===" -ForegroundColor Cyan
    Write-Host "Select mitigations to apply (or 'all' for recommended, 'critical' for critical only)`n"
    
    $actionable = @($Results | Where-Object { $_.ActionNeeded -match 'Yes|Consider' })
    
    if ($actionable.Count -eq 0) {
        Write-Host "No mitigations require configuration!" -ForegroundColor Green
        return
    }
    
    # Display options
    for ($i = 0; $i -lt $actionable.Count; $i++) {
        $item = $actionable[$i]
        $statusColor = switch -Wildcard ($item.ActionNeeded) {
            '*Critical*' { 'Red' }
            '*Recommended*' { 'Yellow' }
            default { 'Cyan' }
        }
        
        Write-Host "[$($i+1)] " -NoNewline
        Write-Host $item.Name -ForegroundColor $statusColor
        Write-Host "    $($item.Recommendation)" -ForegroundColor Gray
        Write-Host "    Impact: $($item.Impact) | CVE: $($item.CVE)" -ForegroundColor DarkGray
    }
    
    Write-Host "`nEnter selections (e.g., '1,2,5' or '1-3' or 'all' or 'critical'): " -NoNewline -ForegroundColor Cyan
    $selection = Read-Host
    
    # Parse selection
    $selectedItems = @()
    
    if ($selection -eq 'all') {
        $selectedItems = $actionable
    } elseif ($selection -eq 'critical') {
        $selectedItems = @($actionable | Where-Object { $_.ActionNeeded -match 'Critical' })
    } else {
        # Parse numbers
        $indices = @()
        foreach ($part in ($selection -split ',')) {
            if ($part -match '(\d+)-(\d+)') {
                $start = [int]$Matches[1]
                $end = [int]$Matches[2]
                $indices += $start..$end
            } elseif ($part -match '^\d+$') {
                $indices += [int]$part
            }
        }
        
        $selectedItems = $indices | ForEach-Object {
            if ($_ -ge 1 -and $_ -le $actionable.Count) {
                $actionable[$_ - 1]
            }
        }
    }
    
    if ($selectedItems.Count -eq 0) {
        Write-Host "No items selected. Exiting." -ForegroundColor Yellow
        return
    }
    
    # Confirm
    Write-Host "`nYou have selected $($selectedItems.Count) mitigation(s):" -ForegroundColor Cyan
    $selectedItems | ForEach-Object { Write-Host "  • $($_.Name)" -ForegroundColor White }
    
    Write-Host "`nA backup will be created before applying changes."
    Write-Host "Do you want to proceed? (Y/N): " -NoNewline -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -ne 'Y') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        return
    }
    
    # Create backup
    $mitigations = Get-MitigationDefinitions
    $backupFile = New-ConfigurationBackup -Mitigations $mitigations
    
    # Apply
    Write-Host "`nApplying mitigations..." -ForegroundColor Cyan
    
    $success = 0
    $failed = 0
    
    foreach ($item in $selectedItems) {
        $mitigation = $mitigations | Where-Object { $_.Id -eq $item.Id }
        if ($mitigation) {
            if (Set-MitigationValue -Mitigation $mitigation) {
                $success++
            } else {
                $failed++
            }
        }
    }
    
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Successfully applied: $success" -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host "Failed: $failed" -ForegroundColor Red
    }
    Write-Host "Backup saved: $backupFile" -ForegroundColor Gray
    
    Write-Host "`n⚠ A system restart is required for changes to take effect." -ForegroundColor Yellow
}

# ============================================================================
# EXPORT FUNCTIONALITY
# ============================================================================

function Export-AssessmentResults {
    param(
        [array]$Results,
        [string]$Path
    )
    
    try {
        $Results | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        Write-Log "Assessment exported to: $Path" -Level Success
        Write-Host "`n✓ Assessment exported successfully to: $Path" -ForegroundColor Green
    } catch {
        Write-Log "Export failed: $($_.Exception.Message)" -Level Error
        Write-Host "✗ Export failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-SideChannelCheck {
    try {
        # Initialize log
        Initialize-Log
        
        # Display header
        Show-Header
        
        # Initialize components
        Initialize-PlatformDetection
        Initialize-RuntimeDetection
        
        # Display platform info
        Show-PlatformInfo
        
        # Execute based on mode
        switch ($Mode) {
            'Assess' {
                $results = Invoke-MitigationAssessment
                Show-AssessmentSummary -Results $results
                Show-MitigationTable -Results $results -Detailed $ShowDetails
                Show-Recommendations -Results $results
                
                # Export if path provided
                if ($ExportPath) {
                    Export-AssessmentResults -Results $results -Path $ExportPath
                }
            }
            
            'Apply' {
                $results = Invoke-MitigationAssessment
                if ($Interactive) {
                    Invoke-InteractiveApply -Results $results
                } else {
                    Write-Host "`n⚠ Non-interactive apply mode requires -Interactive flag." -ForegroundColor Yellow
                    Write-Host "Use: .\SideChannel_Check_v2.ps1 -Mode Apply -Interactive" -ForegroundColor Cyan
                }
                
                # Export if path provided
                if ($ExportPath) {
                    Export-AssessmentResults -Results $results -Path $ExportPath
                }
            }
            
            'Revert' {
                $backup = Get-LatestBackup
                if ($null -eq $backup) {
                    Write-Host "`n✗ No backup found. Cannot revert." -ForegroundColor Red
                    return
                }
                
                Write-Host "`nFound backup from: $($backup.Timestamp)" -ForegroundColor Cyan
                Write-Host "Computer: $($backup.Computer)" -ForegroundColor Gray
                Write-Host "`nDo you want to restore this backup? (Y/N): " -NoNewline -ForegroundColor Yellow
                $confirm = Read-Host
                
                if ($confirm -eq 'Y') {
                    Restore-Configuration -Backup $backup
                    Write-Host "`n✓ Configuration restored." -ForegroundColor Green
                    Write-Host "⚠ A system restart is required." -ForegroundColor Yellow
                } else {
                    Write-Host "Revert cancelled." -ForegroundColor Yellow
                }
            }
        }
        
        Write-Host "`n"
        
    } catch {
        Write-Log "Fatal error: $($_.Exception.Message)" -Level Error
        Write-Host "`n✗ An error occurred: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "See log file: $LogPath" -ForegroundColor Gray
        throw
    }
}

# Execute
Start-SideChannelCheck
