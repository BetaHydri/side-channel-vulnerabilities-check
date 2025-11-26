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
    Operation mode: 'Assess' (default), 'ApplyInteractive', 'RevertInteractive', 'Backup', 'Restore'

.PARAMETER WhatIf
    Preview changes without applying them (available with ApplyInteractive, RevertInteractive, and Backup modes)

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
    .\SideChannel_Check_v2.ps1 -Mode ApplyInteractive
    Interactively select and apply mitigations

.EXAMPLE
    .\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf
    Preview mitigation changes without applying them

.EXAMPLE
    .\SideChannel_Check_v2.ps1 -Mode RevertInteractive
    Interactively restore most recent backup

.EXAMPLE
    .\SideChannel_Check_v2.ps1 -Mode Backup
    Create a backup of current mitigation settings

.EXAMPLE
    .\SideChannel_Check_v2.ps1 -Mode Restore
    Interactively select and restore from available backups

.EXAMPLE
    .\SideChannel_Check_v2.ps1 -ExportPath "results.csv"
    Run assessment and export results to CSV

.NOTES
    Version:        2.1.0
    Requires:       PowerShell 5.1 or higher, Administrator privileges
    Platform:       Windows 10/11, Windows Server 2016+
    Compatible:     PowerShell 5.1, 7.x
#>

[CmdletBinding(DefaultParameterSetName = 'Assess', SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidateSet('Assess', 'ApplyInteractive', 'RevertInteractive', 'Backup', 'Restore')]
    [string]$Mode = 'Assess',
    
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

# Validate parameter combinations
if ($ShowDetails -and $Mode -notin @('Assess', 'ApplyInteractive')) {
    Write-Warning "The -ShowDetails parameter only applies to Assess and ApplyInteractive modes. It will be ignored for $Mode mode."
}
$ProgressPreference = 'SilentlyContinue'

# Script metadata
$script:Version = '2.1.0'
$script:BackupPath = "$PSScriptRoot\Backups"
$script:ConfigPath = "$PSScriptRoot\Config"

# Runtime state storage
$script:RuntimeState = @{
    APIAvailable = $false
    Flags        = @{}
}

$script:PlatformInfo = @{
    Type    = 'Unknown'
    Details = @{}
}

$script:HardwareInfo = @{
    IsUEFI            = $false
    SecureBootEnabled = $false
    SecureBootCapable = $false
    TPMPresent        = $false
    TPMVersion        = 'Unknown'
    VTxEnabled        = $false
    IOMMUSupport      = $false
    VBSCapable        = $false
    HVCICapable       = $false
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
    }
    catch {
        # Silently continue if log write fails
    }
    
    # Write to console (skip Debug messages unless $DebugPreference is set)
    if (-not $NoConsole) {
        # Skip Debug messages unless explicitly enabled
        if ($Level -eq 'Debug' -and $DebugPreference -eq 'SilentlyContinue') {
            return
        }
        
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
    }
    catch {
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
            }
            else {
                Write-Log "NtQuerySystemInformation returned error: 0x$($result.ToString('X8'))" -Level Warning
            }
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($infoPtr)
        }
        
    }
    catch {
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
        }
        elseif ($computerSystem.Model -match 'Virtual|Hyper-V') {
            $script:PlatformInfo.Type = 'HyperVGuest'
            $script:PlatformInfo.Details['Hypervisor'] = 'Hyper-V'
        }
        else {
            $script:PlatformInfo.Type = 'VirtualMachine'
        }
    }
    else {
        # Check for Hyper-V role
        $hyperV = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction SilentlyContinue
        if ($hyperV -and $hyperV.State -eq 'Enabled') {
            $script:PlatformInfo.Type = 'HyperVHost'
        }
        else {
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

function Initialize-HardwareDetection {
    <#
    .SYNOPSIS
    Detects hardware security capabilities and prerequisites
    #>
    
    Write-Log "Detecting hardware security features..." -Level Debug
    
    # Check UEFI
    try {
        $firmwareType = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue
        $script:HardwareInfo.IsUEFI = $null -ne $firmwareType
    }
    catch {
        $script:HardwareInfo.IsUEFI = $false
    }
    
    # Check Secure Boot
    try {
        $secureBootState = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue
        if ($secureBootState) {
            $script:HardwareInfo.SecureBootEnabled = $secureBootState.UEFISecureBootEnabled -eq 1
            $script:HardwareInfo.SecureBootCapable = $true
        }
    }
    catch {
        $script:HardwareInfo.SecureBootEnabled = $false
    }
    
    # Check TPM
    try {
        $tpm = Get-CimInstance -Namespace "Root\cimv2\Security\MicrosoftTpm" -ClassName "Win32_Tpm" -ErrorAction SilentlyContinue
        if ($tpm) {
            $script:HardwareInfo.TPMPresent = $true
            $script:HardwareInfo.TPMVersion = $tpm.SpecVersion
        }
        else {
            # Fallback check
            $tpmWmi = Get-WmiObject -Namespace "Root\cimv2\Security\MicrosoftTpm" -Class "Win32_Tpm" -ErrorAction SilentlyContinue
            if ($tpmWmi) {
                $script:HardwareInfo.TPMPresent = $true
                $script:HardwareInfo.TPMVersion = "Available"
            }
        }
    }
    catch {
        $script:HardwareInfo.TPMPresent = $false
    }
    
    # Check CPU Virtualization (VT-x/AMD-V)
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        if ($cpu.VirtualizationFirmwareEnabled -eq $true) {
            $script:HardwareInfo.VTxEnabled = $true
        }
        else {
            # Check if Hyper-V is running
            $hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -ErrorAction SilentlyContinue
            if ($hyperv -and $hyperv.State -eq 'Enabled') {
                $script:HardwareInfo.VTxEnabled = $true
            }
        }
    }
    catch {
        $script:HardwareInfo.VTxEnabled = $false
    }
    
    # Check IOMMU/VT-d
    try {
        $iommuRegistry = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\iommu" -ErrorAction SilentlyContinue
        if ($iommuRegistry) {
            $script:HardwareInfo.IOMMUSupport = $true
        }
        else {
            # Check VBS properties
            $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
            if ($deviceGuard -and $deviceGuard.AvailableSecurityProperties -contains 7) {
                $script:HardwareInfo.IOMMUSupport = $true
            }
        }
    }
    catch {
        $script:HardwareInfo.IOMMUSupport = $false
    }
    
    # Check VBS capability
    try {
        $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        if ($deviceGuard) {
            # VBS requires: UEFI, Secure Boot, VT-x, IOMMU
            $script:HardwareInfo.VBSCapable = $script:HardwareInfo.IsUEFI -and 
            $script:HardwareInfo.SecureBootCapable -and 
            $script:HardwareInfo.VTxEnabled -and 
            $script:HardwareInfo.IOMMUSupport
            
            # HVCI additionally requires VBS
            $script:HardwareInfo.HVCICapable = $script:HardwareInfo.VBSCapable
        }
    }
    catch {
        $script:HardwareInfo.VBSCapable = $false
        $script:HardwareInfo.HVCICapable = $false
    }
    
    Write-Log "Hardware detection complete" -Level Success
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
            Id               = 'SSBD'
            Name             = 'Speculative Store Bypass Disable'
            CVE              = 'CVE-2018-3639'
            Category         = 'Critical'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            RegistryName     = 'FeatureSettingsOverride'
            EnabledValue     = 72
            Description      = 'Prevents Speculative Store Bypass (Variant 4) attacks'
            Impact           = 'Low'
            Platform         = 'All'
            RuntimeDetection = 'SSBD'
            Recommendation   = 'Enable to protect against speculative execution vulnerabilities'
            URL              = 'https://nvd.nist.gov/vuln/detail/CVE-2018-3639'
        },
        @{
            Id               = 'SSBD_Mask'
            Name             = 'SSBD Feature Mask'
            CVE              = 'CVE-2018-3639'
            Category         = 'Critical'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            RegistryName     = 'FeatureSettingsOverrideMask'
            EnabledValue     = 3
            Description      = 'Required companion setting for SSBD'
            Impact           = 'Low'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Must be enabled for SSBD to function'
            URL              = 'https://nvd.nist.gov/vuln/detail/CVE-2018-3639'
        },
        @{
            Id               = 'BTI'
            Name             = 'Branch Target Injection Mitigation'
            CVE              = 'CVE-2017-5715'
            Category         = 'Critical'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName     = 'DisablePageCombining'
            EnabledValue     = 0
            Description      = 'Mitigates Spectre Variant 2 attacks'
            Impact           = 'Low'
            Platform         = 'All'
            RuntimeDetection = 'BTI'
            Recommendation   = 'Essential protection against Spectre v2'
            URL              = 'https://nvd.nist.gov/vuln/detail/CVE-2017-5715'
        },
        @{
            Id               = 'KVAS'
            Name             = 'Kernel VA Shadow (Meltdown Protection)'
            CVE              = 'CVE-2017-5754'
            Category         = 'Critical'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            RegistryName     = 'EnableKernelVaShadow'
            EnabledValue     = 1
            Description      = 'Page table isolation to prevent Meltdown attacks'
            Impact           = 'Medium'
            Platform         = 'All'
            RuntimeDetection = 'KVAS'
            Recommendation   = 'Critical for Meltdown protection; modern CPUs have hardware immunity'
            URL              = 'https://nvd.nist.gov/vuln/detail/CVE-2017-5754'
        },
        @{
            Id               = 'EnhancedIBRS'
            Name             = 'Enhanced IBRS'
            CVE              = 'CVE-2017-5715'
            Category         = 'Critical'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName     = 'IbrsEnabled'
            EnabledValue     = 1
            Description      = 'Hardware-based Spectre v2 protection'
            Impact           = 'Low'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Enable on CPUs with Enhanced IBRS support'
            URL              = 'https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/indirect-branch-restricted-speculation.html'
        },
        @{
            Id               = 'TSXDisable'
            Name             = 'Intel TSX Disable'
            CVE              = 'CVE-2019-11135'
            Category         = 'Recommended'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName     = 'DisableTsx'
            EnabledValue     = 1
            Description      = 'Disable Intel TSX to prevent TAA vulnerabilities'
            Impact           = 'Low'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Disable unless specifically required by applications'
            URL              = 'https://nvd.nist.gov/vuln/detail/CVE-2019-11135'
        },
        
        # High-impact mitigations
        @{
            Id               = 'L1TF'
            Name             = 'L1 Terminal Fault Mitigation'
            CVE              = 'CVE-2018-3620'
            Category         = 'Optional'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName     = 'L1TFMitigationLevel'
            EnabledValue     = 1
            Description      = 'Protects against L1 Terminal Fault (Foreshadow)'
            Impact           = 'High'
            Platform         = 'HyperVHost'
            RuntimeDetection = 'L1TF'
            Recommendation   = 'High performance impact; for multi-tenant virtualization only'
            URL              = 'https://nvd.nist.gov/vuln/detail/CVE-2018-3620'
        },
        @{
            Id               = 'MDS'
            Name             = 'MDS Mitigation (ZombieLoad)'
            CVE              = 'CVE-2018-12130'
            Category         = 'Recommended'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName     = 'MDSMitigationLevel'
            EnabledValue     = 1
            Description      = 'Protects against MDS attacks'
            Impact           = 'Medium'
            Platform         = 'All'
            RuntimeDetection = 'MDS'
            Recommendation   = 'Moderate performance impact; modern CPUs have hardware immunity'
            URL              = 'https://nvd.nist.gov/vuln/detail/CVE-2018-12130'
        },
        @{
            Id               = 'TAA'
            Name             = 'TSX Asynchronous Abort Mitigation'
            CVE              = 'CVE-2019-11135'
            Category         = 'Recommended'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName     = 'TSXAsyncAbortLevel'
            EnabledValue     = 1
            Description      = 'Protects against TAA vulnerabilities'
            Impact           = 'Medium'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Enable if TSX cannot be disabled'
            URL              = 'https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/intel-tsx-asynchronous-abort.html'
        },
        @{
            Id               = 'HWMitigations'
            Name             = 'Hardware Security Mitigations'
            CVE              = 'Multiple'
            Category         = 'Critical'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName     = 'MitigationOptions'
            EnabledValue     = 0x2000000000000000
            Description      = 'Core hardware-based security features'
            Impact           = 'Low'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Enable core hardware mitigation features'
        },
        
        # Additional Side-Channel Mitigations (2022+)
        @{
            Id               = 'SBDR'
            Name             = 'SBDR/SBDS Mitigation'
            CVE              = 'CVE-2022-21123, CVE-2022-21125'
            Category         = 'Recommended'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName     = 'SBDRMitigationLevel'
            EnabledValue     = 1
            Description      = 'Shared Buffer Data Read/Sampling protection'
            Impact           = 'Low'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Enable to protect against SBDR/SBDS attacks'
            URL              = 'https://nvd.nist.gov/vuln/detail/CVE-2022-21123'
        },
        @{
            Id               = 'SRBDS'
            Name             = 'SRBDS Update Mitigation'
            CVE              = 'CVE-2022-21127'
            Category         = 'Recommended'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName     = 'SRBDSMitigationLevel'
            EnabledValue     = 1
            Description      = 'Special Register Buffer Data Sampling protection'
            Impact           = 'Low'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Enable to protect against SRBDS attacks'
            URL              = 'https://nvd.nist.gov/vuln/detail/CVE-2022-21127'
        },
        @{
            Id               = 'DRPW'
            Name             = 'DRPW Mitigation'
            CVE              = 'CVE-2022-21166'
            Category         = 'Recommended'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName     = 'DRPWMitigationLevel'
            EnabledValue     = 1
            Description      = 'Device Register Partial Write protection'
            Impact           = 'Low'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Enable to protect against DRPW attacks'
            URL              = 'https://nvd.nist.gov/vuln/detail/CVE-2022-21166'
        },
        
        # Security Features
        @{
            Id               = 'ExceptionChainValidation'
            Name             = 'Exception Chain Validation'
            CVE              = 'General SEH Protection'
            Category         = 'Recommended'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            RegistryName     = 'DisableExceptionChainValidation'
            EnabledValue     = 0
            Description      = 'Validates exception handler chains (SEH protection)'
            Impact           = 'Low'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Enable to prevent SEH exploitation'
            URL              = 'https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard'
        },
        @{
            Id               = 'SMAP'
            Name             = 'Supervisor Mode Access Prevention'
            CVE              = 'Privilege Escalation Protection'
            Category         = 'Recommended'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            RegistryName     = 'MoveImages'
            EnabledValue     = 1
            Description      = 'Prevents kernel access to user-mode pages'
            Impact           = 'Low'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Enable to prevent privilege escalation attacks'
            URL              = 'https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/secure-coding/supervisor-mode-access-prevention.html'
        },
        @{
            Id               = 'VBS'
            Name             = 'Virtualization Based Security'
            CVE              = 'Kernel Isolation'
            Category         = 'Optional'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
            RegistryName     = 'EnableVirtualizationBasedSecurity'
            EnabledValue     = 1
            Description      = 'Hardware-based security isolation using virtualization'
            Impact           = 'Low'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Enable for enhanced kernel isolation (requires hardware support)'
            HardwareRequired = 'VBS'
            URL              = 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs'
        },
        @{
            Id               = 'HVCI'
            Name             = 'Hypervisor-protected Code Integrity'
            CVE              = 'Code Injection Protection'
            Category         = 'Optional'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
            RegistryName     = 'Enabled'
            EnabledValue     = 1
            Description      = 'Hardware-enforced code integrity using hypervisor'
            Impact           = 'Low'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Enable for kernel code integrity enforcement (requires VBS)'
            HardwareRequired = 'HVCI'
            URL              = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity'
        },
        @{
            Id               = 'CredentialGuard'
            Name             = 'Credential Guard'
            CVE              = 'Credential Theft Protection'
            Category         = 'Optional'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            RegistryName     = 'LsaCfgFlags'
            EnabledValue     = 1
            Description      = 'Protects domain credentials using VBS'
            Impact           = 'Low'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Enable for domain credential protection (requires VBS)'
            HardwareRequired = 'VBS'
            URL              = 'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard'
        },
        @{
            Id               = 'HyperVCoreScheduler'
            Name             = 'Hyper-V Core Scheduler'
            CVE              = 'SMT Side-Channel Protection'
            Category         = 'Optional'
            RegistryPath     = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization'
            RegistryName     = 'CoreSchedulerType'
            EnabledValue     = 1
            Description      = 'Prevents SMT-based side-channel attacks between VMs'
            Impact           = 'Medium'
            Platform         = 'HyperVHost'
            RuntimeDetection = $null
            Recommendation   = 'Enable on Hyper-V hosts for multi-tenant environments'
            URL              = 'https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-scheduler-types'
        },
        
        # Hardware Prerequisites (Informational)
        @{
            Id               = 'UEFI'
            Name             = 'UEFI Firmware'
            CVE              = 'Boot Security Prerequisite'
            Category         = 'Prerequisite'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
            RegistryName     = 'UEFISecureBootEnabled'
            EnabledValue     = $null
            Description      = 'UEFI firmware mode (required for Secure Boot and modern security)'
            Impact           = 'None'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'UEFI mode required for Secure Boot, VBS, and HVCI'
            IsPrerequisite   = $true
            URL              = 'https://uefi.org/specifications'
        },
        @{
            Id               = 'SecureBoot'
            Name             = 'Secure Boot'
            CVE              = 'Boot Malware Protection'
            Category         = 'Prerequisite'
            RegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
            RegistryName     = 'UEFISecureBootEnabled'
            EnabledValue     = 1
            Description      = 'Prevents unauthorized bootloaders and boot-level malware'
            Impact           = 'None'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Enable in UEFI firmware settings for boot security'
            IsPrerequisite   = $true
            URL              = 'https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot'
        },
        @{
            Id               = 'TPM'
            Name             = 'TPM 2.0'
            CVE              = 'Hardware Cryptographic Security'
            Category         = 'Prerequisite'
            RegistryPath     = $null
            RegistryName     = $null
            EnabledValue     = $null
            Description      = 'Trusted Platform Module for hardware-based cryptography'
            Impact           = 'None'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'TPM 2.0 required for BitLocker, Credential Guard, and VBS'
            IsPrerequisite   = $true
            URL              = 'https://trustedcomputinggroup.org/resource/tpm-library-specification/'
        },
        @{
            Id               = 'VTx'
            Name             = 'CPU Virtualization (VT-x/AMD-V)'
            CVE              = 'Virtualization Prerequisite'
            Category         = 'Prerequisite'
            RegistryPath     = $null
            RegistryName     = $null
            EnabledValue     = $null
            Description      = 'Hardware virtualization support for Hyper-V and VBS'
            Impact           = 'None'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Enable in BIOS/UEFI for Hyper-V and VBS support'
            IsPrerequisite   = $true
            URL              = 'https://www.intel.com/content/www/us/en/virtualization/virtualization-technology/intel-virtualization-technology.html'
        },
        @{
            Id               = 'IOMMU'
            Name             = 'IOMMU/VT-d Support'
            CVE              = 'DMA Protection'
            Category         = 'Prerequisite'
            RegistryPath     = $null
            RegistryName     = $null
            EnabledValue     = $null
            Description      = 'I/O Memory Management Unit for DMA protection'
            Impact           = 'None'
            Platform         = 'All'
            RuntimeDetection = $null
            Recommendation   = 'Required for HVCI and advanced VBS features'
            IsPrerequisite   = $true
            URL              = 'https://www.intel.com/content/www/us/en/virtualization/virtualization-technology/intel-virtualization-technology-for-directed-io.html'
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
    
    # Handle prerequisites separately
    if ($Mitigation.ContainsKey('IsPrerequisite') -and $Mitigation.IsPrerequisite) {
        return Test-Prerequisite -Mitigation $Mitigation
    }
    
    # Check hardware requirements
    if ($Mitigation.ContainsKey('HardwareRequired') -and $Mitigation.HardwareRequired) {
        $hwCapable = Test-HardwareCapability -Requirement $Mitigation.HardwareRequired
        if (-not $hwCapable) {
            return [PSCustomObject]@{
                Id             = $Mitigation.Id
                Name           = $Mitigation.Name
                CVE            = $Mitigation.CVE
                Category       = $Mitigation.Category
                RegistryStatus = 'N/A'
                RuntimeStatus  = 'Hardware Not Supported'
                OverallStatus  = 'Not Applicable'
                ActionNeeded   = 'No'
                CurrentValue   = $null
                ExpectedValue  = $Mitigation.EnabledValue
                Impact         = $Mitigation.Impact
                Description    = $Mitigation.Description
                Recommendation = "Hardware prerequisites not met: $($Mitigation.HardwareRequired)"
                RegistryPath   = $Mitigation.RegistryPath
                RegistryName   = $Mitigation.RegistryName
                URL            = if ($Mitigation.ContainsKey('URL')) { $Mitigation.URL } else { $null }
            }
        }
    }
    
    # Get current registry value
    $currentValue = $null
    $registryStatus = 'Not Configured'
    
    try {
        $regItem = Get-ItemProperty -Path $Mitigation.RegistryPath -Name $Mitigation.RegistryName -ErrorAction Stop
        $currentValue = $regItem.($Mitigation.RegistryName)
        
        # Compare values
        if (Compare-MitigationValue -Current $currentValue -Expected $Mitigation.EnabledValue -RegistryName $Mitigation.RegistryName) {
            $registryStatus = 'Enabled'
        }
        else {
            $registryStatus = 'Disabled'
        }
    }
    catch {
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
        Id             = $Mitigation.Id
        Name           = $Mitigation.Name
        CVE            = $Mitigation.CVE
        Category       = $Mitigation.Category
        RegistryStatus = $registryStatus
        RuntimeStatus  = $runtimeStatus
        OverallStatus  = $overallStatus
        ActionNeeded   = $actionNeeded
        CurrentValue   = $currentValue
        ExpectedValue  = $Mitigation.EnabledValue
        Impact         = $Mitigation.Impact
        Description    = $Mitigation.Description
        Recommendation = $Mitigation.Recommendation
        RegistryPath   = $Mitigation.RegistryPath
        RegistryName   = $Mitigation.RegistryName
        URL            = if ($Mitigation.ContainsKey('URL')) { $Mitigation.URL } else { $null }
    }
}

function Test-HardwareCapability {
    param([string]$Requirement)
    
    switch ($Requirement) {
        'VBS' { return $script:HardwareInfo.VBSCapable }
        'HVCI' { return $script:HardwareInfo.HVCICapable }
        default { return $true }
    }
}

function Test-Prerequisite {
    param([hashtable]$Mitigation)
    
    $status = 'Not Met'
    $currentValue = $null
    $overallStatus = 'Missing'
    
    switch ($Mitigation.Id) {
        'UEFI' {
            $status = if ($script:HardwareInfo.IsUEFI) { 'Active' } else { 'Not Present' }
            $overallStatus = if ($script:HardwareInfo.IsUEFI) { 'Active' } else { 'Missing' }
            $currentValue = $script:HardwareInfo.IsUEFI
        }
        'SecureBoot' {
            if ($script:HardwareInfo.SecureBootEnabled) {
                $status = 'Enabled'
                $overallStatus = 'Protected'
            }
            elseif ($script:HardwareInfo.SecureBootCapable) {
                $status = 'Disabled (Capable)'
                $overallStatus = 'Vulnerable'
            }
            else {
                $status = 'Not Supported'
                $overallStatus = 'Missing'
            }
            $currentValue = $script:HardwareInfo.SecureBootEnabled
        }
        'TPM' {
            if ($script:HardwareInfo.TPMPresent) {
                $status = "Active ($($script:HardwareInfo.TPMVersion))"
                $overallStatus = 'Protected'
            }
            else {
                $status = 'Not Present'
                $overallStatus = 'Missing'
            }
            $currentValue = $script:HardwareInfo.TPMVersion
        }
        'VTx' {
            if ($script:HardwareInfo.VTxEnabled) {
                $status = 'Enabled'
                $overallStatus = 'Protected'
            }
            else {
                $status = 'Disabled or Not Supported'
                $overallStatus = 'Missing'
            }
            $currentValue = $script:HardwareInfo.VTxEnabled
        }
        'IOMMU' {
            if ($script:HardwareInfo.IOMMUSupport) {
                $status = 'Active'
                $overallStatus = 'Protected'
            }
            else {
                $status = 'Not Detected'
                $overallStatus = 'Missing'
            }
            $currentValue = $script:HardwareInfo.IOMMUSupport
        }
    }
    
    return [PSCustomObject]@{
        Id             = $Mitigation.Id
        Name           = $Mitigation.Name
        CVE            = $Mitigation.CVE
        Category       = 'Prerequisite'
        RegistryStatus = 'N/A'
        RuntimeStatus  = $status
        OverallStatus  = $overallStatus
        ActionNeeded   = if ($overallStatus -eq 'Protected' -or $overallStatus -eq 'Active') { 'No' } else { 'Configure in Firmware' }
        CurrentValue   = $currentValue
        ExpectedValue  = $Mitigation.EnabledValue
        Impact         = 'None'
        Description    = $Mitigation.Description
        Recommendation = $Mitigation.Recommendation
        RegistryPath   = $Mitigation.RegistryPath
        RegistryName   = $Mitigation.RegistryName
        URL            = if ($Mitigation.ContainsKey('URL')) { $Mitigation.URL } else { $null }
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
        }
        else {
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

function Get-StatusIcon {
    <#
    .SYNOPSIS
        Returns Unicode icons for status display (PS 5.1 compatible)
    #>
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'Success', 'Error', 'Warning', 'Info',
            'Check', 'Cross', 'Bullet',
            'RedCircle', 'YellowCircle', 'GreenCircle',
            'BlockFull', 'BlockLight'
        )]
        [string]$Name
    )
    
    switch ($Name) {
        'Success' { [System.Char]::ConvertFromUtf32([System.Convert]::toInt32("2713", 16)) }  # ✓
        'Error' { [System.Char]::ConvertFromUtf32([System.Convert]::toInt32("2717", 16)) }  # ✗
        'Warning' { [System.Char]::ConvertFromUtf32([System.Convert]::toInt32("26A0", 16)) }  # $(Get-StatusIcon -Name Warning)
        'Info' { [System.Char]::ConvertFromUtf32([System.Convert]::toInt32("2139", 16)) }  # ℹ
        'Check' { [System.Char]::ConvertFromUtf32([System.Convert]::toInt32("2713", 16)) }  # ✓
        'Cross' { [System.Char]::ConvertFromUtf32([System.Convert]::toInt32("2717", 16)) }  # ✗
        'Bullet' { [System.Char]::ConvertFromUtf32([System.Convert]::toInt32("2022", 16)) }  # $(Get-StatusIcon -Name Bullet)
        'RedCircle' { [System.Char]::ConvertFromUtf32([System.Convert]::toInt32("1F534", 16)) }  # $(Get-StatusIcon -Name RedCircle)
        'YellowCircle' { [System.Char]::ConvertFromUtf32([System.Convert]::toInt32("1F7E1", 16)) }  # $(Get-StatusIcon -Name YellowCircle)
        'GreenCircle' { [System.Char]::ConvertFromUtf32([System.Convert]::toInt32("1F7E2", 16)) }  # $(Get-StatusIcon -Name GreenCircle)
        'BlockFull' { [System.Char]::ConvertFromUtf32([System.Convert]::toInt32("2588", 16)) }  # █
        'BlockLight' { [System.Char]::ConvertFromUtf32([System.Convert]::toInt32("2591", 16)) }  # ░
    }
}

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
    
    # Separate prerequisites from actual mitigations
    $prerequisites = @($Results | Where-Object { $_.Category -eq 'Prerequisite' })
    $mitigations = @($Results | Where-Object { $_.Category -ne 'Prerequisite' })
    
    # Calculate for mitigations only (exclude N/A)
    $applicableMitigations = @($mitigations | Where-Object { $_.OverallStatus -ne 'Not Applicable' })
    $protected = @($applicableMitigations | Where-Object { $_.OverallStatus -eq 'Protected' }).Count
    $vulnerable = @($applicableMitigations | Where-Object { $_.OverallStatus -eq 'Vulnerable' }).Count
    $unknown = @($applicableMitigations | Where-Object { $_.OverallStatus -eq 'Unknown' }).Count
    $notApplicable = @($mitigations | Where-Object { $_.OverallStatus -eq 'Not Applicable' }).Count
    $total = $applicableMitigations.Count
    
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
    
    # Visual progress bar with block characters
    Write-Host "`nSecurity Score: " -NoNewline
    $barLength = 40
    $filledLength = [math]::Round(($protectionPercent / 100) * $barLength)
    $emptyLength = $barLength - $filledLength
    
    # Determine color based on percentage
    $barColor = if ($protectionPercent -ge 90) { 'Green' }
    elseif ($protectionPercent -ge 75) { 'Cyan' }
    elseif ($protectionPercent -ge 50) { 'Yellow' }
    else { 'Red' }
    
    # Get block characters
    $blockFull = Get-StatusIcon -Name BlockFull
    $blockLight = Get-StatusIcon -Name BlockLight
    
    # Build progress bar using filled/empty blocks
    Write-Host "[" -NoNewline
    if ($filledLength -gt 0) {
        Write-Host ($blockFull * $filledLength) -ForegroundColor $barColor -NoNewline
    }
    if ($emptyLength -gt 0) {
        Write-Host ($blockLight * $emptyLength) -ForegroundColor DarkGray -NoNewline
    }
    Write-Host "] " -NoNewline
    Write-Host "$protectionPercent%" -ForegroundColor $barColor
    
    # Security level
    Write-Host "Security Level: " -NoNewline
    if ($protectionPercent -ge 90) {
        Write-Host "Excellent" -ForegroundColor Green
    }
    elseif ($protectionPercent -ge 75) {
        Write-Host "Good" -ForegroundColor Cyan
    }
    elseif ($protectionPercent -ge 50) {
        Write-Host "Fair" -ForegroundColor Yellow
    }
    else {
        Write-Host "Poor - Action Required" -ForegroundColor Red
    }
    
    # Show hardware prerequisites status
    if ($prerequisites.Count -gt 0) {
        Write-Host "`n--- Hardware Prerequisites ---" -ForegroundColor Yellow
        $prereqEnabled = @($prerequisites | Where-Object { $_.OverallStatus -in @('Protected', 'Active') }).Count
        $prereqMissing = @($prerequisites | Where-Object { $_.OverallStatus -eq 'Missing' }).Count
        $prereqVulnerable = @($prerequisites | Where-Object { $_.OverallStatus -eq 'Vulnerable' }).Count
        
        Write-Host "Prerequisites Enabled: " -NoNewline
        Write-Host "$prereqEnabled" -ForegroundColor Green -NoNewline
        Write-Host " / $($prerequisites.Count)"
        
        if ($prereqVulnerable -gt 0) {
            Write-Host "Capable but Disabled:  " -NoNewline
            Write-Host "$prereqVulnerable" -ForegroundColor Yellow
        }
        
        if ($prereqMissing -gt 0) {
            Write-Host "Not Available:         " -NoNewline
            Write-Host "$prereqMissing" -ForegroundColor Red
        }
    }
    
    if ($notApplicable -gt 0) {
        Write-Host "`nNote: $notApplicable mitigation(s) not applicable (hardware requirements not met)" -ForegroundColor Gray
    }
}

function Show-MitigationTable {
    param(
        [array]$Results,
        [bool]$Detailed
    )
    
    Write-Host "`n--- Mitigation Status ---" -ForegroundColor Yellow
    
    if ($Detailed) {
        # Enhanced detailed view with educational information
        foreach ($result in $Results) {
            $statusColor = switch ($result.OverallStatus) {
                'Protected' { 'Green' }
                'Vulnerable' { 'Red' }
                'Active' { 'Cyan' }
                default { 'Gray' }
            }
            
            Write-Host "`n$(Get-StatusIcon -Name Bullet) " -NoNewline -ForegroundColor Cyan
            Write-Host $result.Name -ForegroundColor White -NoNewline
            Write-Host " [" -NoNewline -ForegroundColor DarkGray
            Write-Host $result.OverallStatus -ForegroundColor $statusColor -NoNewline
            Write-Host "]" -ForegroundColor DarkGray
            
            # Show CVE if available
            if ($result.CVE -and $result.CVE -ne 'N/A') {
                Write-Host "  CVE:          " -NoNewline -ForegroundColor Gray
                Write-Host $result.CVE -ForegroundColor Yellow
            }
            
            # Show URL if available
            if ($result.PSObject.Properties.Name -contains 'URL' -and $result.URL) {
                Write-Host "  Reference:    " -NoNewline -ForegroundColor Gray
                Write-Host $result.URL -ForegroundColor Blue
            }
            
            # Show Description if available
            if ($result.Description) {
                Write-Host "  Description:  " -NoNewline -ForegroundColor Gray
                Write-Host $result.Description -ForegroundColor Cyan
            }
            
            # Show Runtime vs Registry Status
            if ($result.RuntimeStatus -and $result.RuntimeStatus -ne 'N/A') {
                Write-Host "  Runtime:      " -NoNewline -ForegroundColor Gray
                Write-Host $result.RuntimeStatus -ForegroundColor Cyan
            }
            
            if ($result.RegistryStatus -and $result.RegistryStatus -ne 'N/A') {
                Write-Host "  Registry:     " -NoNewline -ForegroundColor Gray
                Write-Host $result.RegistryStatus -ForegroundColor Gray
            }
            
            # Show Performance Impact
            Write-Host "  Impact:       " -NoNewline -ForegroundColor Gray
            $impactColor = switch ($result.Impact) {
                'High' { 'Red' }
                'Medium' { 'Yellow' }
                'Low' { 'Green' }
                default { 'Gray' }
            }
            Write-Host $result.Impact -ForegroundColor $impactColor
            
            # Show Recommendation if action needed
            if ($result.ActionNeeded -match 'Yes|Consider' -and $result.Recommendation) {
                Write-Host "  Action:       " -NoNewline -ForegroundColor Gray
                Write-Host $result.Recommendation -ForegroundColor Yellow
            }
        }
        
        # Add educational note about runtime vs registry
        if ($script:RuntimeState.APIAvailable) {
            Write-Host "`n$(Get-StatusIcon -Name Info) " -NoNewline -ForegroundColor Cyan
            Write-Host "Runtime Status Guide:" -ForegroundColor White
            Write-Host "  $(Get-StatusIcon -Name Success) Active" -ForegroundColor Green -NoNewline
            Write-Host " - Protection is running (you are protected)" -ForegroundColor Gray
            Write-Host "  $(Get-StatusIcon -Name Cross) Inactive" -ForegroundColor Red -NoNewline
            Write-Host " - Protection is NOT running (you are vulnerable)" -ForegroundColor Gray
            Write-Host "  $(Get-StatusIcon -Name Info) Not Needed" -ForegroundColor Cyan -NoNewline
            Write-Host " - Hardware protection supersedes software mitigation" -ForegroundColor Gray
            Write-Host "  $(Get-StatusIcon -Name Info) HW Immune" -ForegroundColor Cyan -NoNewline
            Write-Host " - CPU has hardware immunity (no mitigation needed)" -ForegroundColor Gray
        }
    }
    else {
        # Simplified table view with colors
        Write-Host ("{0,-45} {1,-20} {2,-26} {3}" -f "Mitigation", "Status", "Action Needed", "Impact") -ForegroundColor Gray
        Write-Host ("{0,-45} {1,-20} {2,-26} {3}" -f ("-" * 44), ("-" * 19), ("-" * 25), ("-" * 9)) -ForegroundColor DarkGray
        
        # Check PowerShell version for ANSI support
        $useAnsi = $PSVersionTable.PSVersion.Major -ge 6
        
        if ($useAnsi) {
            # PowerShell 7+ with ANSI color codes
            $ansiReset = "`e[0m"
            $ansiGreen = "`e[32m"
            $ansiRed = "`e[31m"
            $ansiCyan = "`e[36m"
            $ansiYellow = "`e[33m"
            $ansiGray = "`e[90m"
            
            foreach ($result in $Results) {
                # Determine ANSI color for status
                $statusAnsi = switch ($result.OverallStatus) {
                    'Protected' { $ansiGreen }
                    'Vulnerable' { $ansiRed }
                    'Active' { $ansiCyan }
                    default { $ansiGray }
                }
                
                # Determine ANSI color for action
                $actionAnsi = switch -Wildcard ($result.ActionNeeded) {
                    '*Critical*' { $ansiRed }
                    '*Recommended*' { $ansiYellow }
                    'Consider' { $ansiCyan }
                    default { $ansiGreen }
                }
                
                # Format columns with exact widths
                $nameCol = "{0,-45}" -f $result.Name
                $statusCol = "{0,-20}" -f $result.OverallStatus
                $actionCol = "{0,-26}" -f $result.ActionNeeded
                $impactCol = $result.Impact
                
                # Build line with ANSI colors embedded
                $line = "$nameCol $statusAnsi$statusCol$ansiReset $actionAnsi$actionCol$ansiReset $impactCol"
                
                # Output with colors
                Write-Host $line
            }
        }
        else {
            # PowerShell 5.1 fallback - use VT100 if available or plain text
            foreach ($result in $Results) {
                # Format the entire line as a single string
                $line = "{0,-45} {1,-20} {2,-26} {3}" -f $result.Name, $result.OverallStatus, $result.ActionNeeded, $result.Impact
                
                # Determine color for the line based on status
                $lineColor = switch ($result.OverallStatus) {
                    'Protected' { 'White' }
                    'Vulnerable' { 'Yellow' }
                    'Active' { 'Cyan' }
                    default { 'Gray' }
                }
                
                Write-Host $line -ForegroundColor $lineColor
            }
        }
    }
}

function Show-Recommendations {
    param([array]$Results)
    
    $actionable = @($Results | Where-Object { $_.ActionNeeded -match 'Yes|Consider' })
    
    if ($actionable.Count -eq 0) {
        Write-Host "`n$(Get-StatusIcon -Name Success) All critical mitigations are properly configured!" -ForegroundColor Green
        return
    }
    
    Write-Host "`n--- Recommendations ---" -ForegroundColor Yellow
    
    $critical = @($actionable | Where-Object { $_.ActionNeeded -match 'Critical' })
    $recommended = @($actionable | Where-Object { $_.ActionNeeded -match 'Recommended' })
    $optional = @($actionable | Where-Object { $_.ActionNeeded -eq 'Consider' })
    
    if ($critical.Count -gt 0) {
        Write-Host "`n$(Get-StatusIcon -Name RedCircle) CRITICAL - Apply immediately:" -ForegroundColor Red
        foreach ($item in $critical) {
            Write-Host "   $(Get-StatusIcon -Name Bullet) $($item.Name)" -ForegroundColor White
            Write-Host "     $($item.Recommendation)" -ForegroundColor Gray
            if ($item.Impact -eq 'High') {
                Write-Host "     $(Get-StatusIcon -Name Warning) Performance Impact: HIGH" -ForegroundColor Yellow
            }
        }
    }
    
    if ($recommended.Count -gt 0) {
        Write-Host "`n$(Get-StatusIcon -Name YellowCircle) RECOMMENDED - Apply for enhanced security:" -ForegroundColor Yellow
        foreach ($item in $recommended) {
            Write-Host "   $(Get-StatusIcon -Name Bullet) $($item.Name)" -ForegroundColor White
            Write-Host "     $($item.Recommendation)" -ForegroundColor Gray
        }
    }
    
    if ($optional.Count -gt 0) {
        Write-Host "`n$(Get-StatusIcon -Name GreenCircle) OPTIONAL - Evaluate based on environment:" -ForegroundColor Cyan
        foreach ($item in $optional) {
            Write-Host "   $(Get-StatusIcon -Name Bullet) $($item.Name)" -ForegroundColor White
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
        Timestamp   = Get-Date -Format 'o'
        Computer    = $env:COMPUTERNAME
        User        = $env:USERNAME
        Mitigations = @()
    }
    
    foreach ($mitigation in $Mitigations) {
        try {
            $regItem = Get-ItemProperty -Path $mitigation.RegistryPath -Name $mitigation.RegistryName -ErrorAction Stop
            $value = $regItem.($mitigation.RegistryName)
        }
        catch {
            $value = $null
        }
        
        $backupData.Mitigations += @{
            Id           = $mitigation.Id
            Name         = $mitigation.Name
            RegistryPath = $mitigation.RegistryPath
            RegistryName = $mitigation.RegistryName
            Value        = $value
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

function Get-AllBackups {
    $backupFiles = @(Get-ChildItem -Path $script:BackupPath -Filter "Backup_*.json" -ErrorAction SilentlyContinue)
    
    if ($backupFiles.Count -eq 0) {
        return @()
    }
    
    $backups = @()
    foreach ($file in ($backupFiles | Sort-Object LastWriteTime -Descending)) {
        try {
            $backup = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
            $backups += [PSCustomObject]@{
                File            = $file.FullName
                FileName        = $file.Name
                Timestamp       = $backup.Timestamp
                Computer        = $backup.Computer
                User            = $backup.User
                MitigationCount = $backup.Mitigations.Count
                FileSize        = $file.Length
                Data            = $backup
            }
        }
        catch {
            Write-Log "Could not parse backup file $($file.Name): $($_.Exception.Message)" -Level Warning
        }
    }
    
    return $backups
}

function Set-MitigationValue {
    param(
        [hashtable]$Mitigation
    )
    
    if ($WhatIfPreference) {
        Write-Log "[WhatIf] Would apply: $($Mitigation.Name)" -Level Info
        Write-Host "  [WhatIf] Would set: $($Mitigation.RegistryPath)\$($Mitigation.RegistryName) = $($Mitigation.EnabledValue)" -ForegroundColor Cyan
        return $true
    }
    
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
    }
    catch {
        Write-Log "Failed to apply $($Mitigation.Name): $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Restore-Configuration {
    param([object]$Backup)
    
    if ($WhatIfPreference) {
        Write-Host "`n=== WhatIf: Configuration Restore Preview ===" -ForegroundColor Cyan
        Write-Host "Would restore configuration from: $($Backup.Timestamp)" -ForegroundColor Yellow
        Write-Host "`nChanges that would be made:" -ForegroundColor White
        
        foreach ($item in $Backup.Mitigations) {
            if ($null -eq $item.Value) {
                Write-Host "  [-] Would remove: $($item.RegistryPath)\$($item.RegistryName)" -ForegroundColor Red
            }
            else {
                Write-Host "  [+] Would set: $($item.RegistryPath)\$($item.RegistryName) = $($item.Value)" -ForegroundColor Green
            }
        }
        
        Write-Host "`nTotal changes that would be made: $($Backup.Mitigations.Count)" -ForegroundColor Cyan
        Write-Host "System restart would be required: Yes" -ForegroundColor Yellow
        return
    }
    
    Write-Log "Restoring configuration from $($Backup.Timestamp)" -Level Info
    
    $success = 0
    $failed = 0
    $skipped = 0
    
    # Filter out hardware-only items (no registry path)
    $restorableItems = @($Backup.Mitigations | Where-Object { -not [string]::IsNullOrEmpty($_.RegistryPath) })
    
    foreach ($item in $restorableItems) {
        try {
            if ($null -eq $item.Value) {
                Remove-ItemProperty -Path $item.RegistryPath -Name $item.RegistryName -ErrorAction SilentlyContinue
                Write-Log "Removed: $($item.Name)" -Level Info
            }
            else {
                Set-ItemProperty -Path $item.RegistryPath -Name $item.RegistryName -Value $item.Value -Force
                Write-Log "Restored: $($item.Name)" -Level Info
            }
            $success++
        }
        catch {
            Write-Log "Could not restore $($item.Name): $($_.Exception.Message)" -Level Warning
            $failed++
        }
    }
    
    # Count skipped hardware items
    $skipped = $Backup.Mitigations.Count - $restorableItems.Count
    
    Write-Host "`n=== Restore Summary ===" -ForegroundColor Cyan
    Write-Host "Successfully restored: $success" -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host "Failed: $failed" -ForegroundColor Red
    }
    if ($skipped -gt 0) {
        Write-Host "Skipped (hardware-only): $skipped" -ForegroundColor Gray
    }
    
    Write-Log "Configuration restored: $success successful, $failed failed, $skipped skipped" -Level Success
}

function Invoke-InteractiveRestore {
    param([object]$Backup)
    
    Write-Host "`n=== Interactive Restore ===" -ForegroundColor Cyan
    if ($WhatIfPreference) {
        Write-Host "[WhatIf Mode] Changes will be previewed but not applied`n" -ForegroundColor Yellow
    }
    Write-Host "Select mitigations to restore (or 'all' for all settings)`n"
    
    # Filter to only restorable items (exclude hardware-only)
    $restorableItems = @($Backup.Mitigations | Where-Object { -not [string]::IsNullOrEmpty($_.RegistryPath) })
    
    if ($restorableItems.Count -eq 0) {
        Write-Host "No restorable mitigations found in backup (hardware-only items)." -ForegroundColor Yellow
        return
    }
    
    # Display restorable mitigations from backup
    for ($i = 0; $i -lt $restorableItems.Count; $i++) {
        $item = $restorableItems[$i]
        $valueDisplay = if ($null -eq $item.Value) { "[DELETE]" } else { $item.Value }
        
        Write-Host "[$($i+1)] " -NoNewline -ForegroundColor Cyan
        Write-Host "$($item.Name)" -ForegroundColor White -NoNewline
        Write-Host " = $valueDisplay" -ForegroundColor Gray
    }
    
    Write-Host "`nEnter numbers (comma-separated), 'all', or 'Q' to quit: " -NoNewline -ForegroundColor Yellow
    $selection = Read-Host
    
    if ($selection -eq 'Q' -or $selection -eq 'q') {
        Write-Host "Restore cancelled." -ForegroundColor Yellow
        return
    }
    
    $selectedItems = @()
    
    if ($selection -eq 'all' -or $selection -eq 'All') {
        $selectedItems = $restorableItems
    }
    else {
        $numbers = $selection -split ',' | ForEach-Object { $_.Trim() }
        $tempItems = foreach ($num in $numbers) {
            $index = $null
            if ([int]::TryParse($num, [ref]$index) -and $index -ge 1 -and $index -le $restorableItems.Count) {
                $restorableItems[$index - 1]
            }
        }
        $selectedItems = @($tempItems)
    }
    
    if ($selectedItems.Count -eq 0) {
        Write-Host "No valid selections made. Restore cancelled." -ForegroundColor Red
        return
    }
    
    # Show what will be restored
    Write-Host "`nSelected mitigations to restore:" -ForegroundColor Cyan
    foreach ($item in $selectedItems) {
        $valueDisplay = if ($null -eq $item.Value) { "[DELETE]" } else { $item.Value }
        Write-Host "  $(Get-StatusIcon -Name Bullet) $($item.Name) = $valueDisplay" -ForegroundColor White
    }
    
    Write-Host "`nRestore these $($selectedItems.Count) mitigation(s)? (Y/N): " -NoNewline -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "Restore cancelled." -ForegroundColor Yellow
        return
    }
    
    # Perform the restore
    if ($WhatIfPreference) {
        Write-Host "`n=== WhatIf: Would restore these settings ===" -ForegroundColor Cyan
        foreach ($item in $selectedItems) {
            if ($null -eq $item.Value) {
                Write-Host "  [-] Would remove: $($item.RegistryPath)\$($item.RegistryName)" -ForegroundColor Red
            }
            else {
                Write-Host "  [+] Would set: $($item.RegistryPath)\$($item.RegistryName) = $($item.Value)" -ForegroundColor Green
            }
        }
        Write-Host "`nTotal changes that would be made: $($selectedItems.Count)" -ForegroundColor Cyan
        Write-Host "System restart would be required: Yes" -ForegroundColor Yellow
        return
    }
    
    Write-Log "Restoring $($selectedItems.Count) selected mitigation(s) from $($Backup.Timestamp)" -Level Info
    
    $success = 0
    $failed = 0
    
    foreach ($item in $selectedItems) {
        try {
            if ($null -eq $item.Value) {
                Remove-ItemProperty -Path $item.RegistryPath -Name $item.RegistryName -ErrorAction SilentlyContinue
                Write-Log "Removed: $($item.Name)" -Level Info
            }
            else {
                Set-ItemProperty -Path $item.RegistryPath -Name $item.RegistryName -Value $item.Value -Force
                Write-Log "Restored: $($item.Name)" -Level Info
            }
            $success++
        }
        catch {
            Write-Log "Could not restore $($item.Name): $($_.Exception.Message)" -Level Warning
            $failed++
        }
    }
    
    Write-Host "`n=== Restore Summary ===" -ForegroundColor Cyan
    Write-Host "Successfully restored: $success" -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host "Failed: $failed" -ForegroundColor Red
    }
    
    Write-Host "`n$(Get-StatusIcon -Name Success) Selected mitigations restored from backup." -ForegroundColor Green
    Write-Host "$(Get-StatusIcon -Name Warning) A system restart is required." -ForegroundColor Yellow
    
    Write-Log "Interactive restore complete: $success successful, $failed failed" -Level Success
}

# ============================================================================
# INTERACTIVE APPLY MODE
# ============================================================================

function Invoke-InteractiveApply {
    param([array]$Results)
    
    Write-Host "`n=== Interactive Mitigation Application ===" -ForegroundColor Cyan
    if ($WhatIfPreference) {
        Write-Host "[WhatIf Mode] Changes will be previewed but not applied`n" -ForegroundColor Yellow
    }
    
    # Ask if user wants to see only actionable items or all mitigations
    Write-Host "Selection mode:" -ForegroundColor Yellow
    Write-Host "  [R] Show only recommended/actionable mitigations" -ForegroundColor White
    Write-Host "  [A] Show all available mitigations (for selective hardening)" -ForegroundColor White
    Write-Host "`nYour choice (R/A) [Default: R]: " -NoNewline -ForegroundColor Yellow
    $viewMode = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($viewMode)) {
        $viewMode = 'R'
    }
    
    $itemsToShow = @()
    
    if ($viewMode -eq 'A' -or $viewMode -eq 'a') {
        # Show ALL mitigations, allowing user to enable anything
        $itemsToShow = @($Results)
        Write-Host "`nShowing all $($itemsToShow.Count) available mitigations:`n" -ForegroundColor Cyan
    }
    else {
        # Show only actionable items (original behavior)
        $itemsToShow = @($Results | Where-Object { $_.ActionNeeded -match 'Yes|Consider' })
        
        if ($itemsToShow.Count -eq 0) {
            Write-Host "`nNo mitigations require configuration!" -ForegroundColor Green
            Write-Host "Tip: Use selection mode [A] to see all available mitigations." -ForegroundColor Gray
            return
        }
        
        Write-Host "`nShowing $($itemsToShow.Count) recommended/actionable mitigations:`n" -ForegroundColor Cyan
    }
    
    # Display options
    for ($i = 0; $i -lt $itemsToShow.Count; $i++) {
        $item = $itemsToShow[$i]
        
        # Determine color based on current status and action needed
        $statusColor = if ($item.OverallStatus -eq 'Protected') {
            'Green'
        }
        else {
            switch -Wildcard ($item.ActionNeeded) {
                '*Critical*' { 'Red' }
                '*Recommended*' { 'Yellow' }
                default { 'Cyan' }
            }
        }
        
        $statusIndicator = if ($item.OverallStatus -eq 'Protected') { "$(Get-StatusIcon -Name Success) " } else { "" }
        
        Write-Host "[$($i+1)] " -NoNewline
        Write-Host "$statusIndicator$($item.Name)" -ForegroundColor $statusColor
        Write-Host "    Status: $($item.OverallStatus) | Impact: $($item.Impact)" -ForegroundColor Gray
        if ($item.Recommendation) {
            Write-Host "    $($item.Recommendation)" -ForegroundColor DarkGray
        }
    }
    
    $bullet = Get-StatusIcon -Name Bullet
    Write-Host "`nSelection options:" -ForegroundColor Cyan
    Write-Host "  $bullet Enter numbers (e.g., '1,2,5' or '1-3')" -ForegroundColor White
    Write-Host "  $bullet Type 'all' to select all shown mitigations" -ForegroundColor White
    Write-Host "  $bullet Type 'critical' to select only critical items" -ForegroundColor White
    Write-Host "  $bullet Type 'Q' to quit" -ForegroundColor White
    Write-Host "`nYour selection: " -NoNewline -ForegroundColor Yellow
    $selection = Read-Host
    
    if ($selection -eq 'Q' -or $selection -eq 'q') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        return
    }
    
    # Parse selection
    $selectedItems = @()
    
    if ($selection -eq 'all') {
        $selectedItems = $itemsToShow
    }
    elseif ($selection -eq 'critical') {
        $selectedItems = @($itemsToShow | Where-Object { $_.ActionNeeded -match 'Critical' })
        if ($selectedItems.Count -eq 0) {
            Write-Host "No critical items found in current view." -ForegroundColor Yellow
            return
        }
    }
    else {
        # Parse numbers
        $indices = @()
        foreach ($part in ($selection -split ',')) {
            if ($part -match '(\d+)-(\d+)') {
                $start = [int]$Matches[1]
                $end = [int]$Matches[2]
                $indices += $start..$end
            }
            elseif ($part -match '^\d+$') {
                $indices += [int]$part
            }
        }
        
        $selectedItems = @($indices | ForEach-Object {
                if ($_ -ge 1 -and $_ -le $itemsToShow.Count) {
                    $itemsToShow[$_ - 1]
                }
            })
    }
    
    if ($selectedItems.Count -eq 0) {
        Write-Host "No items selected. Exiting." -ForegroundColor Yellow
        return
    }
    
    # Confirm
    Write-Host "`nYou have selected $($selectedItems.Count) mitigation(s):" -ForegroundColor Cyan
    $selectedItems | ForEach-Object { Write-Host "  $(Get-StatusIcon -Name Bullet) $($_.Name)" -ForegroundColor White }
    
    if ($WhatIfPreference) {
        Write-Host "`n=== WhatIf: Changes Preview ===" -ForegroundColor Cyan
        Write-Host "The following changes would be made:`n" -ForegroundColor Yellow
        
        $mitigations = Get-MitigationDefinitions
        foreach ($item in $selectedItems) {
            $mitigation = $mitigations | Where-Object { $_.Id -eq $item.Id }
            if ($mitigation) {
                Write-Host "[$($mitigation.Id)] $($mitigation.Name)" -ForegroundColor White
                Write-Host "  Registry Path: $($mitigation.RegistryPath)" -ForegroundColor Gray
                Write-Host "  Registry Name: $($mitigation.RegistryName)" -ForegroundColor Gray
                Write-Host "  New Value: $($mitigation.EnabledValue)" -ForegroundColor Green
                Write-Host "  Impact: $($mitigation.Impact)`n" -ForegroundColor Gray
            }
        }
        
        Write-Host "WhatIf Summary:" -ForegroundColor Cyan
        Write-Host "Total changes that would be made: $($selectedItems.Count)" -ForegroundColor White
        Write-Host "Backup would be created: Yes" -ForegroundColor White
        Write-Host "System restart would be required: Yes" -ForegroundColor Yellow
        return
    }
    
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
            }
            else {
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
    
    Write-Host "`n$(Get-StatusIcon -Name Warning) A system restart is required for changes to take effect." -ForegroundColor Yellow
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
        Write-Host "`n$(Get-StatusIcon -Name Success) Assessment exported successfully to: $Path" -ForegroundColor Green
    }
    catch {
        Write-Log "Export failed: $($_.Exception.Message)" -Level Error
        Write-Host "$(Get-StatusIcon -Name Error) Export failed: $($_.Exception.Message)" -ForegroundColor Red
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
        Initialize-HardwareDetection
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
            
            'ApplyInteractive' {
                $results = Invoke-MitigationAssessment
                Invoke-InteractiveApply -Results $results
                
                # Export if path provided
                if ($ExportPath) {
                    Export-AssessmentResults -Results $results -Path $ExportPath
                }
            }
            
            'RevertInteractive' {
                $backup = Get-LatestBackup
                if ($null -eq $backup) {
                    Write-Host "`n$(Get-StatusIcon -Name Error) No backup found. Cannot revert." -ForegroundColor Red
                    Write-Host "Tip: Use -Mode Restore to select from available backups." -ForegroundColor Gray
                    return
                }
                
                Write-Host "`n=== Revert to Most Recent Backup ===" -ForegroundColor Cyan
                Write-Host "`nFound most recent backup:" -ForegroundColor Yellow
                Write-Host "Timestamp: $($backup.Timestamp)" -ForegroundColor Gray
                Write-Host "Computer:  $($backup.Computer)" -ForegroundColor Gray
                Write-Host "User:      $($backup.User)" -ForegroundColor Gray
                Write-Host "`nDo you want to restore this backup? (Y/N): " -NoNewline -ForegroundColor Yellow
                $confirm = Read-Host
                
                if ($confirm -eq 'Y') {
                    Restore-Configuration -Backup $backup
                    Write-Host "`n$(Get-StatusIcon -Name Success) Configuration restored." -ForegroundColor Green
                    Write-Host "$(Get-StatusIcon -Name Warning) A system restart is required." -ForegroundColor Yellow
                }
                else {
                    Write-Host "Revert cancelled." -ForegroundColor Yellow
                }
            }
            
            'Backup' {
                Write-Host "`n=== Create Configuration Backup ===" -ForegroundColor Cyan
                
                if ($WhatIfPreference) {
                    Write-Host "`n[WhatIf Mode] Would create backup of current mitigation settings..." -ForegroundColor Yellow
                    $mitigations = Get-MitigationDefinitions
                    $applicableMitigations = @($mitigations | Where-Object { $_.RegistryPath -and $_.RegistryName })
                    
                    Write-Host "`nBackup would include:" -ForegroundColor Cyan
                    Write-Host "Computer:    $env:COMPUTERNAME" -ForegroundColor White
                    Write-Host "User:        $env:USERNAME" -ForegroundColor White
                    Write-Host "Mitigations: $($applicableMitigations.Count)" -ForegroundColor White
                    Write-Host "`nWould save to: $script:BackupPath\Backup_<timestamp>.json" -ForegroundColor Gray
                    return
                }
                
                Write-Host "`nCreating backup of current mitigation settings..." -ForegroundColor Yellow
                
                $mitigations = Get-MitigationDefinitions
                $backupFile = New-ConfigurationBackup -Mitigations $mitigations
                
                Write-Host "`n$(Get-StatusIcon -Name Success) Backup created successfully!" -ForegroundColor Green
                Write-Host "Location: $backupFile" -ForegroundColor Gray
                
                # Show backup details
                $backupData = Get-Content -Path $backupFile -Raw | ConvertFrom-Json
                Write-Host "`nBackup Details:" -ForegroundColor Cyan
                Write-Host "Timestamp:   $($backupData.Timestamp)" -ForegroundColor White
                Write-Host "Computer:    $($backupData.Computer)" -ForegroundColor White
                Write-Host "User:        $($backupData.User)" -ForegroundColor White
                Write-Host "Mitigations: $($backupData.Mitigations.Count)" -ForegroundColor White
            }
            
            'Restore' {
                $backups = @(Get-AllBackups)
                if ($backups.Count -eq 0) {
                    Write-Host "`n$(Get-StatusIcon -Name Error) No backups found." -ForegroundColor Red
                    Write-Host "Create a backup first using: .\SideChannel_Check_v2.ps1 -Mode Backup" -ForegroundColor Gray
                    return
                }
                
                Write-Host "`n=== Restore from Backup ===" -ForegroundColor Cyan
                Write-Host "Found $($backups.Count) backup(s):`n" -ForegroundColor Yellow
                
                for ($i = 0; $i -lt $backups.Count; $i++) {
                    $backup = $backups[$i]
                    
                    # Parse timestamp - try as DateTime first, then as string
                    try {
                        if ($backup.Timestamp -is [DateTime]) {
                            $timestamp = $backup.Timestamp
                        }
                        else {
                            # Try parsing as ISO 8601 format or culture-invariant
                            $timestamp = [DateTime]::Parse($backup.Timestamp, [System.Globalization.CultureInfo]::InvariantCulture)
                        }
                    }
                    catch {
                        # Fallback: try to parse using current culture
                        try {
                            $timestamp = [DateTime]$backup.Timestamp
                        }
                        catch {
                            # Last resort: use file timestamp
                            $timestamp = (Get-Item $backup.File).LastWriteTime
                            Write-Log "Could not parse timestamp for $($backup.FileName), using file date" -Level Warning
                        }
                    }
                    
                    $age = (Get-Date) - $timestamp
                    $ageStr = if ($age.Days -gt 0) { "$($age.Days)d ago" } 
                    elseif ($age.Hours -gt 0) { "$($age.Hours)h ago" } 
                    else { "$($age.Minutes)m ago" }
                    
                    Write-Host "[$($i+1)] " -NoNewline -ForegroundColor White
                    Write-Host "$($timestamp.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan -NoNewline
                    Write-Host " ($ageStr)" -ForegroundColor DarkGray
                    Write-Host "    Computer: $($backup.Computer) | User: $($backup.User) | Mitigations: $($backup.MitigationCount)" -ForegroundColor Gray
                }
                
                Write-Host "`nSelect backup to restore (1-$($backups.Count)) or 'Q' to quit: " -NoNewline -ForegroundColor Yellow
                $selection = Read-Host
                
                if ($selection -eq 'Q' -or $selection -eq 'q') {
                    Write-Host "Restore cancelled." -ForegroundColor Yellow
                    return
                }
                
                $index = $null
                if ([int]::TryParse($selection, [ref]$index) -and $index -ge 1 -and $index -le $backups.Count) {
                    $selectedBackup = $backups[$index - 1]
                    
                    Write-Host "`nSelected backup:" -ForegroundColor Cyan
                    Write-Host "Timestamp: $($selectedBackup.Timestamp)" -ForegroundColor Gray
                    Write-Host "Computer:  $($selectedBackup.Computer)" -ForegroundColor Gray
                    Write-Host "User:      $($selectedBackup.User)" -ForegroundColor Gray
                    
                    # Ask if user wants to restore all or select individual mitigations
                    Write-Host "`nRestore options:" -ForegroundColor Yellow
                    Write-Host "  [A] All mitigations ($($selectedBackup.MitigationCount) total)" -ForegroundColor White
                    Write-Host "  [S] Select individual mitigations" -ForegroundColor White
                    Write-Host "  [Q] Cancel" -ForegroundColor White
                    Write-Host "`nYour choice (A/S/Q): " -NoNewline -ForegroundColor Yellow
                    $restoreChoice = Read-Host
                    
                    if ($restoreChoice -eq 'Q' -or $restoreChoice -eq 'q') {
                        Write-Host "Restore cancelled." -ForegroundColor Yellow
                        return
                    }
                    
                    if ($restoreChoice -eq 'S' -or $restoreChoice -eq 's') {
                        # Interactive selection mode
                        Invoke-InteractiveRestore -Backup $selectedBackup.Data
                    }
                    elseif ($restoreChoice -eq 'A' -or $restoreChoice -eq 'a') {
                        # Restore all
                        Write-Host "`nDo you want to restore ALL mitigations? (Y/N): " -NoNewline -ForegroundColor Yellow
                        $confirm = Read-Host
                        
                        if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                            Restore-Configuration -Backup $selectedBackup.Data
                            Write-Host "`n$(Get-StatusIcon -Name Success) Configuration restored from backup." -ForegroundColor Green
                            Write-Host "$(Get-StatusIcon -Name Warning) A system restart is required." -ForegroundColor Yellow
                        }
                        else {
                            Write-Host "Restore cancelled." -ForegroundColor Yellow
                        }
                    }
                    else {
                        Write-Host "Invalid choice. Restore cancelled." -ForegroundColor Red
                    }
                }
                else {
                    Write-Host "Invalid selection. Restore cancelled." -ForegroundColor Red
                }
            }
        }
        
        Write-Host "`n"
        
    }
    catch {
        Write-Log "Fatal error: $($_.Exception.Message)" -Level Error
        Write-Host "`n$(Get-StatusIcon -Name Error) An error occurred: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "See log file: $LogPath" -ForegroundColor Gray
        throw
    }
}

# Execute
Start-SideChannelCheck
