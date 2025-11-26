<#
.SYNOPSIS
    Side-Channel Vulnerability Mitigation Assessment and Remediation Tool - Version 2.0

.DESCRIPTION
    Enterprise-grade tool for assessing and configuring Windows side-channel vulnerability
    mitigations (Spectre, Meltdown, L1TF, MDS, and related CVEs). Version 2.0 features
    a completely redesigned architecture with:
    
    - Modular design with clear separation of concerns
    - Kernel runtime state detection via native Windows API
    - Platform-aware recommendations (Physical/Hyper-V/VMware)
    - Simplified output focused on actionable intelligence
    - Interactive apply mode with rollback capability
    - Comprehensive change tracking and audit logging

.PARAMETER Mode
    Operation mode: 'Assess' (default), 'Apply', 'Revert', 'Export'

.PARAMETER Interactive
    Enable interactive mode for Apply operations (recommended)

.PARAMETER ConfigFile
    Path to configuration file for batch apply operations

.PARAMETER ShowDetails
    Display detailed technical information

.PARAMETER ExportPath
    Path to export assessment results (CSV format)

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
    .\SideChannel_Check_v2.ps1 -Mode Export -ExportPath ".\assessment.csv"
    Export detailed assessment to CSV

.NOTES
    Version:        2.0.0
    Author:         Side-Channel Security Project
    Creation Date:  November 2025
    Requires:       PowerShell 5.1 or higher, Administrator privileges
    Platform:       Windows 10/11, Windows Server 2016+

.LINK
    https://github.com/BetaHydri/side-channel-vulnerabilities-check
#>

[CmdletBinding(DefaultParameterSetName = 'Assess')]
param(
    [Parameter(ParameterSetName = 'Assess')]
    [Parameter(ParameterSetName = 'Apply')]
    [Parameter(ParameterSetName = 'Revert')]
    [Parameter(ParameterSetName = 'Export')]
    [ValidateSet('Assess', 'Apply', 'Revert', 'Export')]
    [string]$Mode = 'Assess',
    
    [Parameter(ParameterSetName = 'Apply')]
    [switch]$Interactive,
    
    [Parameter(ParameterSetName = 'Apply')]
    [string]$ConfigFile,
    
    [Parameter(ParameterSetName = 'Assess')]
    [Parameter(ParameterSetName = 'Export')]
    [switch]$ShowDetails,
    
    [Parameter(ParameterSetName = 'Export')]
    [string]$ExportPath,
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\Logs\SideChannelCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Script metadata
$script:Version = '2.0.0'
$script:BackupPath = "$PSScriptRoot\Backups"
$script:ConfigPath = "$PSScriptRoot\Config"

# Ensure required directories exist
@($script:BackupPath, $script:ConfigPath, (Split-Path $LogPath -Parent)) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -Path $_ -ItemType Directory -Force | Out-Null
    }
}

# ============================================================================
# LOGGING MODULE
# ============================================================================

class Logger {
    [string]$LogFile
    [bool]$EnableConsole
    
    Logger([string]$logPath, [bool]$consoleOutput) {
        $this.LogFile = $logPath
        $this.EnableConsole = $consoleOutput
        $this.Initialize()
    }
    
    [void] Initialize() {
        $header = @"
================================================================================
Side-Channel Vulnerability Mitigation Tool - Version $($script:Version)
Session Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
User: $env:USERNAME
Computer: $env:COMPUTERNAME
================================================================================

"@
        Add-Content -Path $this.LogFile -Value $header -Encoding UTF8
    }
    
    [void] Info([string]$message) {
        $this.Write('INFO', $message, 'Cyan')
    }
    
    [void] Success([string]$message) {
        $this.Write('SUCCESS', $message, 'Green')
    }
    
    [void] Warning([string]$message) {
        $this.Write('WARNING', $message, 'Yellow')
    }
    
    [void] Error([string]$message) {
        $this.Write('ERROR', $message, 'Red')
    }
    
    [void] Debug([string]$message) {
        if ($script:VerbosePreference -ne 'SilentlyContinue') {
            $this.Write('DEBUG', $message, 'Gray')
        }
    }
    
    [void] Write([string]$level, [string]$message, [string]$color) {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $logEntry = "[$timestamp] [$level] $message"
        
        # Write to log file
        Add-Content -Path $this.LogFile -Value $logEntry -Encoding UTF8
        
        # Write to console if enabled
        if ($this.EnableConsole) {
            $consoleMessage = "[$level] $message"
            if ($color) {
                Write-Host $consoleMessage -ForegroundColor $color
            } else {
                Write-Host $consoleMessage
            }
        }
    }
}

# Initialize global logger
$script:Logger = [Logger]::new($LogPath, $true)

# ============================================================================
# KERNEL RUNTIME DETECTION MODULE
# ============================================================================

class KernelRuntimeDetector {
    [hashtable]$State
    [bool]$APIAvailable
    
    KernelRuntimeDetector() {
        $this.State = @{}
        $this.APIAvailable = $false
        $this.DetectRuntimeState()
    }
    
    [void] DetectRuntimeState() {
        try {
            $script:Logger.Debug("Initializing kernel runtime state detection...")
            
            # P/Invoke setup for NtQuerySystemInformation
            if (-not ('Kernel32.NtApi' -as [type])) {
                $signature = @'
[DllImport("ntdll.dll", SetLastError = true)]
public static extern int NtQuerySystemInformation(
    uint SystemInformationClass,
    IntPtr SystemInformation,
    uint SystemInformationLength,
    out uint ReturnLength);
'@
                Add-Type -MemberDefinition $signature -Name 'NtApi' -Namespace 'Kernel32'
            }
            
            # Query system information (class 201 = SystemSpeculationControlInformation)
            $infoSize = 256
            $infoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($infoSize)
            
            try {
                $returnLength = 0
                $ntApi = 'Kernel32.NtApi' -as [type]
                $result = $ntApi::NtQuerySystemInformation(
                    201,  # SystemSpeculationControlInformation
                    $infoPtr,
                    $infoSize,
                    [ref]$returnLength
                )
                
                if ($result -eq 0) {
                    # Parse the returned structure
                    $flags = [System.Runtime.InteropServices.Marshal]::ReadInt32($infoPtr, 0)
                    
                    # Extract individual mitigation states from flags
                    $this.State['BTIEnabled'] = ($flags -band 0x01) -ne 0
                    $this.State['BTIDisabledBySystemPolicy'] = ($flags -band 0x02) -ne 0
                    $this.State['BTIDisabledByNoHardwareSupport'] = ($flags -band 0x04) -ne 0
                    $this.State['SSBDSystemWide'] = ($flags -band 0x10) -ne 0
                    $this.State['SSBDUserMode'] = ($flags -band 0x20) -ne 0
                    $this.State['EnhancedIBRS'] = ($flags -band 0x100) -ne 0
                    $this.State['RetpolineEnabled'] = ($flags -band 0x200) -ne 0
                    $this.State['MBClearEnabled'] = ($flags -band 0x1000) -ne 0
                    $this.State['L1DFlushSupported'] = ($flags -band 0x2000) -ne 0
                    $this.State['RDCLHardwareProtected'] = ($flags -band 0x4000) -ne 0
                    $this.State['MDSHardwareProtected'] = ($flags -band 0x8000) -ne 0
                    
                    $this.APIAvailable = $true
                    $script:Logger.Success("Kernel runtime state detection: Operational")
                } else {
                    $script:Logger.Warning("NtQuerySystemInformation returned error: 0x$($result.ToString('X8'))")
                }
            } finally {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($infoPtr)
            }
            
            # Additional detection: KVAShadow state
            $this.DetectKVAShadowState()
            
        } catch {
            $script:Logger.Warning("Kernel runtime detection not available: $($_.Exception.Message)")
            $this.APIAvailable = $false
        }
    }
    
    [void] DetectKVAShadowState() {
        try {
            # Check if KVAS is active via performance counter
            $kvasShadowEnabled = $false
            
            # Method 1: Check via registry value that reflects actual state
            $kvasValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
                -Name "FeatureSettingsOverride" -ErrorAction SilentlyContinue
            
            if ($null -ne $kvasValue) {
                # If KVAS is configured, assume it's active unless hardware immunity
                $kvasShadowEnabled = -not $this.State['RDCLHardwareProtected']
            }
            
            $this.State['KVAShadowEnabled'] = $kvasShadowEnabled
            
        } catch {
            $script:Logger.Debug("Could not detect KVAShadow state: $($_.Exception.Message)")
            $this.State['KVAShadowEnabled'] = $false
        }
    }
    
    [string] GetMitigationStatus([string]$mitigationName) {
        if (-not $this.APIAvailable) {
            return 'Unknown'
        }
        
        $result = switch ($mitigationName) {
            'BTI' { 
                if ($this.State['EnhancedIBRS']) { 'Active (Enhanced IBRS)' }
                elseif ($this.State['RetpolineEnabled']) { 'Active (Retpoline)' }
                elseif ($this.State['BTIEnabled']) { 'Active' }
                else { 'Inactive' }
            }
            'SSBD' {
                if ($this.State['SSBDSystemWide']) { 'Active' }
                else { 'Inactive' }
            }
            'KVAS' {
                if ($this.State['RDCLHardwareProtected']) { 'Not Needed (Hardware Immune)' }
                elseif ($this.State['KVAShadowEnabled']) { 'Active' }
                else { 'Inactive' }
            }
            'MDS' {
                if ($this.State['MDSHardwareProtected']) { 'Not Needed (Hardware Immune)' }
                elseif ($this.State['MBClearEnabled']) { 'Active' }
                else { 'Inactive' }
            }
            'L1DFlush' {
                if ($this.State['L1DFlushSupported']) { 'Supported' }
                else { 'Not Supported' }
            }
            default { 'Unknown' }
        }
        
        return $result
    }
}

# ============================================================================
# PLATFORM DETECTION MODULE
# ============================================================================

class PlatformDetector {
    [string]$Type  # Physical, HyperVHost, HyperVGuest, VMwareHost, VMwareGuest
    [hashtable]$Details
    
    PlatformDetector() {
        $this.Details = @{}
        $this.DetectPlatform()
    }
    
    [void] DetectPlatform() {
        $script:Logger.Debug("Detecting platform type...")
        
        # Check if running in a VM
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $isVM = $computerSystem.Model -match 'Virtual|VMware|Hyper-V'
        
        if ($isVM) {
            # Determine hypervisor type
            if ($computerSystem.Model -match 'VMware') {
                $this.Type = 'VMwareGuest'
                $this.Details['Hypervisor'] = 'VMware'
            } elseif ($computerSystem.Model -match 'Virtual|Hyper-V') {
                $this.Type = 'HyperVGuest'
                $this.Details['Hypervisor'] = 'Hyper-V'
            } else {
                $this.Type = 'Unknown'
            }
        } else {
            # Physical hardware - check if Hyper-V role is installed
            $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction SilentlyContinue
            
            if ($hyperVFeature -and $hyperVFeature.State -eq 'Enabled') {
                $this.Type = 'HyperVHost'
                $this.Details['Role'] = 'Hypervisor Host'
            } else {
                $this.Type = 'Physical'
                $this.Details['Role'] = 'Standalone Server/Workstation'
            }
        }
        
        # Detect CPU and OS information
        $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        
        $this.Details['CPUVendor'] = $cpu.Manufacturer
        $this.Details['CPUModel'] = $cpu.Name
        $this.Details['OSVersion'] = $os.Caption
        $this.Details['OSBuild'] = $os.BuildNumber
        
        $script:Logger.Info("Platform detected: $($this.Type)")
    }
    
    [bool] IsApplicable([string]$mitigationPlatform) {
        # Check if mitigation applies to this platform
        $result = switch ($mitigationPlatform) {
            'All' { $true }
            'Physical' { $this.Type -eq 'Physical' -or $this.Type -eq 'HyperVHost' }
            'HyperVHost' { $this.Type -eq 'HyperVHost' }
            'HyperVGuest' { $this.Type -eq 'HyperVGuest' }
            'VMwareHost' { $false }  # Not typically applicable for Windows
            'VMwareGuest' { $this.Type -eq 'VMwareGuest' }
            'VirtualMachine' { $this.Type -match 'Guest$' }
            default { $true }
        }
        return $result
    }
}

# ============================================================================
# MITIGATION DEFINITION MODULE
# ============================================================================

class MitigationDefinition {
    [string]$Id
    [string]$Name
    [string]$CVE
    [string]$Category  # Critical, Recommended, Optional
    [string]$RegistryPath
    [string]$RegistryName
    [object]$EnabledValue
    [object]$DisabledValue
    [string]$Description
    [string]$Impact  # Low, Medium, High
    [string]$Platform  # All, Physical, HyperVHost, HyperVGuest, VMwareGuest
    [string]$KernelDetection  # Name for kernel runtime detection, or null
    [string[]]$Dependencies
    [string]$Recommendation
    
    MitigationDefinition(
        [string]$id,
        [string]$name,
        [string]$cve,
        [string]$category,
        [string]$registryPath,
        [string]$registryName,
        [object]$enabledValue,
        [string]$description,
        [string]$impact,
        [string]$platform,
        [string]$kernelDetection,
        [string[]]$dependencies,
        [string]$recommendation
    ) {
        $this.Id = $id
        $this.Name = $name
        $this.CVE = $cve
        $this.Category = $category
        $this.RegistryPath = $registryPath
        $this.RegistryName = $registryName
        $this.EnabledValue = $enabledValue
        $this.DisabledValue = $null  # Will be determined by registry check
        $this.Description = $description
        $this.Impact = $impact
        $this.Platform = $platform
        $this.KernelDetection = $kernelDetection
        $this.Dependencies = $dependencies
        $this.Recommendation = $recommendation
    }
}

# ============================================================================
# MITIGATION REGISTRY (CENTRALIZED DEFINITIONS)
# ============================================================================

function Get-MitigationRegistry {
    <#
    .SYNOPSIS
    Returns centralized registry of all side-channel mitigations
    #>
    
    return @(
        # Critical mitigations - Always recommended
        [MitigationDefinition]::new(
            'SSBD',
            'Speculative Store Bypass Disable',
            'CVE-2018-3639',
            'Critical',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',
            'FeatureSettingsOverride',
            72,
            'Prevents Speculative Store Bypass (Variant 4) attacks',
            'Low',
            'All',
            'SSBD',
            @(),
            'Enable to protect against speculative execution vulnerabilities with minimal performance impact'
        ),
        
        [MitigationDefinition]::new(
            'SSBD_Mask',
            'SSBD Feature Mask',
            'CVE-2018-3639',
            'Critical',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',
            'FeatureSettingsOverrideMask',
            3,
            'Feature mask for Speculative Store Bypass Disable',
            'Low',
            'All',
            $null,
            @('SSBD'),
            'Required companion setting for SSBD to function properly'
        ),
        
        [MitigationDefinition]::new(
            'BTI',
            'Branch Target Injection Mitigation',
            'CVE-2017-5715',
            'Critical',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel',
            'DisablePageCombining',
            0,
            'Mitigates Spectre Variant 2 (Branch Target Injection) attacks',
            'Low',
            'All',
            'BTI',
            @(),
            'Essential protection against Spectre v2 with minimal performance impact on modern CPUs'
        ),
        
        [MitigationDefinition]::new(
            'KVAS',
            'Kernel VA Shadow',
            'CVE-2017-5754',
            'Critical',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',
            'EnableKernelVaShadow',
            1,
            'Page table isolation to prevent Meltdown attacks',
            'Medium',
            'All',
            'KVAS',
            @(),
            'Critical for Meltdown protection; modern CPUs have hardware immunity'
        ),
        
        [MitigationDefinition]::new(
            'EnhancedIBRS',
            'Enhanced IBRS',
            'CVE-2017-5715',
            'Critical',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel',
            'IbrsEnabled',
            1,
            'Enhanced Indirect Branch Restricted Speculation (hardware-based Spectre v2 protection)',
            'Low',
            'All',
            $null,
            @(),
            'Enable on CPUs with Enhanced IBRS support for optimal Spectre v2 protection'
        ),
        
        [MitigationDefinition]::new(
            'TSXDisable',
            'Intel TSX Disable',
            'CVE-2019-11135',
            'Recommended',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel',
            'DisableTsx',
            1,
            'Disable Intel TSX to prevent TAA vulnerabilities',
            'Low',
            'All',
            $null,
            @(),
            'Disable TSX unless specifically required by applications'
        ),
        
        # High-impact mitigations - Evaluate carefully
        [MitigationDefinition]::new(
            'L1TF',
            'L1 Terminal Fault Mitigation',
            'CVE-2018-3620',
            'Optional',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel',
            'L1TFMitigationLevel',
            1,
            'Protects against L1 Terminal Fault (Foreshadow) attacks',
            'High',
            'HyperVHost',
            'L1DFlush',
            @(),
            'High performance impact; primarily for multi-tenant virtualization environments'
        ),
        
        [MitigationDefinition]::new(
            'MDS',
            'Microarchitectural Data Sampling Mitigation',
            'CVE-2018-12130',
            'Recommended',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel',
            'MDSMitigationLevel',
            1,
            'Protects against MDS (RIDL, Fallout, ZombieLoad) attacks',
            'Medium',
            'All',
            'MDS',
            @(),
            'Moderate performance impact; modern CPUs have hardware immunity'
        ),
        
        [MitigationDefinition]::new(
            'TAA',
            'TSX Asynchronous Abort Mitigation',
            'CVE-2019-11135',
            'Recommended',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel',
            'TSXAsyncAbortLevel',
            1,
            'Protects against TAA vulnerabilities in Intel TSX',
            'Medium',
            'All',
            $null,
            @('TSXDisable'),
            'Enable if TSX cannot be disabled; moderate performance impact'
        ),
        
        # Hardware-based mitigations
        [MitigationDefinition]::new(
            'HWMitigations',
            'Hardware Security Mitigations',
            'Multiple',
            'Critical',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel',
            'MitigationOptions',
            0x2000000000000000,
            'Core hardware-based security mitigation flags',
            'Low',
            'All',
            $null,
            @(),
            'Enable core hardware mitigation features; essential baseline protection'
        )
    )
}

# ============================================================================
# ASSESSMENT ENGINE
# ============================================================================

class AssessmentEngine {
    [PlatformDetector]$Platform
    [KernelRuntimeDetector]$Runtime
    [array]$Mitigations
    [array]$Results
    
    AssessmentEngine([PlatformDetector]$platform, [KernelRuntimeDetector]$runtime) {
        $this.Platform = $platform
        $this.Runtime = $runtime
        $this.Mitigations = Get-MitigationRegistry
        $this.Results = @()
    }
    
    [void] RunAssessment() {
        $script:Logger.Info("Starting mitigation assessment...")
        
        foreach ($mitigation in $this.Mitigations) {
            # Skip if not applicable to this platform
            if (-not $this.Platform.IsApplicable($mitigation.Platform)) {
                $script:Logger.Debug("Skipping $($mitigation.Name) - not applicable to $($this.Platform.Type)")
                continue
            }
            
            $result = $this.AssessMitigation($mitigation)
            $this.Results += $result
        }
        
        $script:Logger.Success("Assessment complete: $($this.Results.Count) mitigations evaluated")
    }
    
    [PSCustomObject] AssessMitigation([MitigationDefinition]$mitigation) {
        # Get current registry value
        $currentValue = $null
        $registryStatus = 'Not Configured'
        
        try {
            $regItem = Get-ItemProperty -Path $mitigation.RegistryPath -Name $mitigation.RegistryName -ErrorAction Stop
            $currentValue = $regItem.($mitigation.RegistryName)
            
            # Compare with expected value
            if ($this.CompareValues($currentValue, $mitigation.EnabledValue)) {
                $registryStatus = 'Enabled'
            } else {
                $registryStatus = 'Disabled'
            }
        } catch {
            $registryStatus = 'Not Configured'
        }
        
        # Get kernel runtime status if available
        $runtimeStatus = 'N/A'
        if ($mitigation.KernelDetection -and $this.Runtime.APIAvailable) {
            $runtimeStatus = $this.Runtime.GetMitigationStatus($mitigation.KernelDetection)
        }
        
        # Determine overall status and action needed
        $overallStatus = $this.DetermineOverallStatus($registryStatus, $runtimeStatus)
        $actionNeeded = $this.DetermineActionNeeded($mitigation.Category, $overallStatus)
        
        # Build result object
        return [PSCustomObject]@{
            Id                = $mitigation.Id
            Name              = $mitigation.Name
            CVE               = $mitigation.CVE
            Category          = $mitigation.Category
            RegistryStatus    = $registryStatus
            RuntimeStatus     = $runtimeStatus
            OverallStatus     = $overallStatus
            ActionNeeded      = $actionNeeded
            CurrentValue      = $currentValue
            ExpectedValue     = $mitigation.EnabledValue
            Impact            = $mitigation.Impact
            Platform          = $mitigation.Platform
            Description       = $mitigation.Description
            Recommendation    = $mitigation.Recommendation
            RegistryPath      = $mitigation.RegistryPath
            RegistryName      = $mitigation.RegistryName
        }
    }
    
    [bool] CompareValues([object]$current, [object]$expected) {
        if ($null -eq $current) { return $false }
        
        # Handle hex string comparisons
        if ($expected -is [string] -and $expected -match '^0x') {
            try {
                $expectedInt = [Convert]::ToUInt64($expected, 16)
                return $current -eq $expectedInt
            } catch {
                return $current.ToString() -eq $expected
            }
        }
        
        return $current -eq $expected
    }
    
    [string] DetermineOverallStatus([string]$registryStatus, [string]$runtimeStatus) {
        # Priority: Runtime status > Registry status
        if ($runtimeStatus -ne 'N/A') {
            if ($runtimeStatus -match 'Active|Immune|Supported') {
                return 'Protected'
            } elseif ($runtimeStatus -match 'Not Needed') {
                return 'Not Required'
            } else {
                return 'Vulnerable'
            }
        }
        
        # Fallback to registry status
        if ($registryStatus -eq 'Enabled') {
            return 'Protected'
        } elseif ($registryStatus -eq 'Disabled') {
            return 'Vulnerable'
        } else {
            return 'Unknown'
        }
    }
    
    [string] DetermineActionNeeded([string]$category, [string]$overallStatus) {
        if ($overallStatus -eq 'Protected' -or $overallStatus -eq 'Not Required') {
            return 'No'
        }
        
        switch ($category) {
            'Critical' { return 'Yes - Critical' }
            'Recommended' { return 'Yes - Recommended' }
            'Optional' { return 'Consider' }
            default { return 'No' }
        }
    }
}

# ============================================================================
# OUTPUT FORMATTER
# ============================================================================

class OutputFormatter {
    
    static [void] DisplayHeader() {
        $header = @"

================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version $($script:Version)
================================================================================

"@
        Write-Host $header -ForegroundColor Cyan
    }
    
    static [void] DisplayPlatformInfo([PlatformDetector]$platform) {
        Write-Host "`n--- Platform Information ---" -ForegroundColor Yellow
        Write-Host "Type:        " -NoNewline; Write-Host $platform.Type -ForegroundColor White
        Write-Host "CPU:         " -NoNewline; Write-Host $platform.Details['CPUModel'] -ForegroundColor White
        Write-Host "OS:          " -NoNewline; Write-Host "$($platform.Details['OSVersion']) (Build $($platform.Details['OSBuild']))" -ForegroundColor White
        
        if ($platform.Details.ContainsKey('Hypervisor')) {
            Write-Host "Hypervisor:  " -NoNewline; Write-Host $platform.Details['Hypervisor'] -ForegroundColor White
        }
    }
    
    static [void] DisplayAssessmentSummary([array]$results) {
        Write-Host "`n--- Security Assessment Summary ---" -ForegroundColor Yellow
        
        $protected = ($results | Where-Object { $_.OverallStatus -eq 'Protected' }).Count
        $vulnerable = ($results | Where-Object { $_.OverallStatus -eq 'Vulnerable' }).Count
        $unknown = ($results | Where-Object { $_.OverallStatus -eq 'Unknown' }).Count
        $total = $results.Count
        
        $protectionPercent = if ($total -gt 0) { [math]::Round(($protected / $total) * 100, 1) } else { 0 }
        
        Write-Host "Total Mitigations Evaluated:  " -NoNewline
        Write-Host $total -ForegroundColor White
        
        Write-Host "Protected:                    " -NoNewline
        Write-Host "$protected " -ForegroundColor Green -NoNewline
        Write-Host "($protectionPercent%)"
        
        Write-Host "Vulnerable:                   " -NoNewline
        Write-Host $vulnerable -ForegroundColor Red
        
        if ($unknown -gt 0) {
            Write-Host "Unknown Status:               " -NoNewline
            Write-Host $unknown -ForegroundColor Gray
        }
        
        # Security level indicator
        Write-Host "`nSecurity Level: " -NoNewline
        if ($protectionPercent -ge 90) {
            Write-Host "Excellent" -ForegroundColor Green
        } elseif ($protectionPercent -ge 75) {
            Write-Host "Good" -ForegroundColor Cyan
        } elseif ($protectionPercent -ge 50) {
            Write-Host "Fair" -ForegroundColor Yellow
        } else {
            Write-Host "Poor" -ForegroundColor Red
        }
    }
    
    static [void] DisplayMitigationTable([array]$results, [bool]$showDetails) {
        Write-Host "`n--- Mitigation Status ---" -ForegroundColor Yellow
        
        if ($showDetails) {
            # Detailed view with all columns
            $results | Format-Table -Property `
                Name,
                OverallStatus,
                RuntimeStatus,
                RegistryStatus,
                ActionNeeded,
                Impact,
                CVE `
                -AutoSize
        } else {
            # Simplified view - only essential information
            $displayResults = $results | Select-Object `
                @{Name='Mitigation'; Expression={$_.Name}},
                @{Name='Status'; Expression={$_.OverallStatus}},
                @{Name='Action Needed'; Expression={$_.ActionNeeded}},
                @{Name='Impact'; Expression={$_.Impact}}
            
            # Color-code the output
            foreach ($result in $results) {
                $statusColor = switch ($result.OverallStatus) {
                    'Protected' { 'Green' }
                    'Vulnerable' { 'Red' }
                    'Not Required' { 'Cyan' }
                    default { 'Gray' }
                }
                
                $actionColor = switch -Wildcard ($result.ActionNeeded) {
                    '*Critical*' { 'Red' }
                    '*Recommended*' { 'Yellow' }
                    'No' { 'Green' }
                    default { 'Gray' }
                }
                
                Write-Host ("{0,-45}" -f $result.Name) -NoNewline
                Write-Host ("{0,-15}" -f $result.OverallStatus) -ForegroundColor $statusColor -NoNewline
                Write-Host ("{0,-20}" -f $result.ActionNeeded) -ForegroundColor $actionColor -NoNewline
                Write-Host ("{0,-10}" -f $result.Impact) -ForegroundColor Gray
            }
        }
    }
    
    static [void] DisplayRecommendations([array]$results) {
        $actionable = $results | Where-Object { $_.ActionNeeded -match 'Yes' -or $_.ActionNeeded -eq 'Consider' }
        
        if ($actionable.Count -eq 0) {
            Write-Host "`n✓ All critical mitigations are properly configured!" -ForegroundColor Green
            return
        }
        
        Write-Host "`n--- Recommendations ---" -ForegroundColor Yellow
        
        # Group by priority
        $critical = $actionable | Where-Object { $_.ActionNeeded -match 'Critical' }
        $recommended = $actionable | Where-Object { $_.ActionNeeded -match 'Recommended' }
        $optional = $actionable | Where-Object { $_.ActionNeeded -eq 'Consider' }
        
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
}

# ============================================================================
# CONFIGURATION MANAGER
# ============================================================================

class ConfigurationManager {
    [string]$BackupPath
    
    ConfigurationManager([string]$backupPath) {
        $this.BackupPath = $backupPath
    }
    
    [void] CreateBackup([array]$mitigations) {
        $script:Logger.Info("Creating configuration backup...")
        
        $backupFile = Join-Path $this.BackupPath "Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        
        $backupData = @{
            Timestamp = Get-Date -Format 'o'
            Computer = $env:COMPUTERNAME
            User = $env:USERNAME
            Mitigations = @()
        }
        
        foreach ($mitigation in $mitigations) {
            try {
                $currentValue = Get-ItemProperty -Path $mitigation.RegistryPath -Name $mitigation.RegistryName -ErrorAction Stop
                
                $backupData.Mitigations += @{
                    Name = $mitigation.Name
                    RegistryPath = $mitigation.RegistryPath
                    RegistryName = $mitigation.RegistryName
                    Value = $currentValue.($mitigation.RegistryName)
                }
            } catch {
                # Value doesn't exist - record as null
                $backupData.Mitigations += @{
                    Name = $mitigation.Name
                    RegistryPath = $mitigation.RegistryPath
                    RegistryName = $mitigation.RegistryName
                    Value = $null
                }
            }
        }
        
        $backupData | ConvertTo-Json -Depth 10 | Set-Content -Path $backupFile -Encoding UTF8
        $script:Logger.Success("Backup created: $backupFile")
    }
    
    [object] GetLatestBackup() {
        $backupFiles = Get-ChildItem -Path $this.BackupPath -Filter "Backup_*.json" -ErrorAction SilentlyContinue
        
        if ($backupFiles.Count -eq 0) {
            return $null
        }
        
        $latestBackup = $backupFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        return Get-Content -Path $latestBackup.FullName -Raw | ConvertFrom-Json
    }
    
    [void] ApplyMitigation([MitigationDefinition]$mitigation) {
        $script:Logger.Info("Applying: $($mitigation.Name)")
        
        try {
            # Ensure registry path exists
            if (-not (Test-Path $mitigation.RegistryPath)) {
                New-Item -Path $mitigation.RegistryPath -Force | Out-Null
            }
            
            # Determine value type
            $valueType = 'DWord'
            if ($mitigation.EnabledValue -is [uint64] -or $mitigation.EnabledValue -gt 0xFFFFFFFF) {
                $valueType = 'QWord'
            }
            
            # Set the registry value
            Set-ItemProperty -Path $mitigation.RegistryPath `
                -Name $mitigation.RegistryName `
                -Value $mitigation.EnabledValue `
                -Type $valueType -Force
            
            $script:Logger.Success("Applied: $($mitigation.Name)")
        } catch {
            $script:Logger.Error("Failed to apply $($mitigation.Name): $($_.Exception.Message)")
            throw
        }
    }
    
    [void] RevertConfiguration([object]$backup) {
        $script:Logger.Info("Reverting to backup from $($backup.Timestamp)")
        
        foreach ($item in $backup.Mitigations) {
            try {
                if ($null -eq $item.Value) {
                    # Remove the value if it didn't exist in backup
                    Remove-ItemProperty -Path $item.RegistryPath -Name $item.RegistryName -ErrorAction SilentlyContinue
                    $script:Logger.Info("Removed: $($item.Name)")
                } else {
                    # Restore the original value
                    Set-ItemProperty -Path $item.RegistryPath -Name $item.RegistryName -Value $item.Value -Force
                    $script:Logger.Info("Restored: $($item.Name)")
                }
            } catch {
                $script:Logger.Warning("Could not revert $($item.Name): $($_.Exception.Message)")
            }
        }
        
        $script:Logger.Success("Configuration reverted successfully")
    }
}

# ============================================================================
# INTERACTIVE MODE HANDLER
# ============================================================================

function Invoke-InteractiveApply {
    param(
        [array]$Results,
        [ConfigurationManager]$ConfigManager
    )
    
    Write-Host "`n=== Interactive Mitigation Application ===" -ForegroundColor Cyan
    Write-Host "Select mitigations to apply (or 'all' for automatic selection)`n"
    
    # Filter actionable items
    $actionable = $Results | Where-Object { $_.ActionNeeded -match 'Yes|Consider' }
    
    if ($actionable.Count -eq 0) {
        Write-Host "No mitigations require configuration!" -ForegroundColor Green
        return
    }
    
    # Display options
    for ($i = 0; $i -lt $actionable.Count; $i++) {
        $item = $actionable[$i]
        $statusColor = if ($item.ActionNeeded -match 'Critical') { 'Red' } 
                      elseif ($item.ActionNeeded -match 'Recommended') { 'Yellow' }
                      else { 'Cyan' }
        
        Write-Host "[$($i+1)] " -NoNewline
        Write-Host $item.Name -ForegroundColor $statusColor
        Write-Host "    $($item.Recommendation)" -ForegroundColor Gray
        Write-Host "    Impact: $($item.Impact) | CVE: $($item.CVE)" -ForegroundColor DarkGray
    }
    
    Write-Host "`nEnter selections (e.g., '1,2,5' or '1-3' or 'all' or 'critical'): " -NoNewline
    $selection = Read-Host
    
    # Parse selection
    $selectedItems = @()
    
    if ($selection -eq 'all') {
        $selectedItems = $actionable
    } elseif ($selection -eq 'critical') {
        $selectedItems = $actionable | Where-Object { $_.ActionNeeded -match 'Critical' }
    } else {
        # Parse number selections
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
    
    # Confirm selection
    Write-Host "`nYou have selected $($selectedItems.Count) mitigation(s):" -ForegroundColor Cyan
    $selectedItems | ForEach-Object { Write-Host "  • $($_.Name)" -ForegroundColor White }
    
    Write-Host "`nA backup will be created before applying changes."
    Write-Host "Do you want to proceed? (Y/N): " -NoNewline
    $confirm = Read-Host
    
    if ($confirm -ne 'Y') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        return
    }
    
    # Create backup
    $mitigations = Get-MitigationRegistry
    $ConfigManager.CreateBackup($mitigations)
    
    # Apply selected mitigations
    Write-Host "`nApplying mitigations..." -ForegroundColor Cyan
    
    $success = 0
    $failed = 0
    
    foreach ($item in $selectedItems) {
        try {
            $mitigation = $mitigations | Where-Object { $_.Id -eq $item.Id } | Select-Object -First 1
            if ($mitigation) {
                $ConfigManager.ApplyMitigation($mitigation)
                $success++
            }
        } catch {
            $failed++
        }
    }
    
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Successfully applied: $success" -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host "Failed: $failed" -ForegroundColor Red
    }
    
    Write-Host "`n⚠ A system restart is required for changes to take effect." -ForegroundColor Yellow
}

# ============================================================================
# EXPORT HANDLER
# ============================================================================

function Export-Assessment {
    param(
        [array]$Results,
        [string]$ExportPath
    )
    
    try {
        $Results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        $script:Logger.Success("Assessment exported to: $ExportPath")
        Write-Host "`n✓ Assessment exported successfully to: $ExportPath" -ForegroundColor Green
    } catch {
        $script:Logger.Error("Export failed: $($_.Exception.Message)")
        Write-Host "✗ Export failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================================================
# MAIN EXECUTION FLOW
# ============================================================================

function Start-SideChannelCheck {
    param(
        [string]$Mode,
        [bool]$Interactive,
        [bool]$ShowDetails,
        [string]$ExportPath
    )
    
    try {
        # Display header
        [OutputFormatter]::DisplayHeader()
        
        # Initialize components
        $script:Logger.Info("Initializing platform detection...")
        $platform = [PlatformDetector]::new()
        
        $script:Logger.Info("Initializing kernel runtime detection...")
        $runtime = [KernelRuntimeDetector]::new()
        
        $script:Logger.Info("Initializing configuration manager...")
        $configManager = [ConfigurationManager]::new($script:BackupPath)
        
        # Display platform info
        [OutputFormatter]::DisplayPlatformInfo($platform)
        
        switch ($Mode) {
            'Assess' {
                # Run assessment
                $engine = [AssessmentEngine]::new($platform, $runtime)
                $engine.RunAssessment()
                
                # Display results
                [OutputFormatter]::DisplayAssessmentSummary($engine.Results)
                [OutputFormatter]::DisplayMitigationTable($engine.Results, $ShowDetails)
                [OutputFormatter]::DisplayRecommendations($engine.Results)
            }
            
            'Apply' {
                # Run assessment first
                $engine = [AssessmentEngine]::new($platform, $runtime)
                $engine.RunAssessment()
                
                if ($Interactive) {
                    Invoke-InteractiveApply -Results $engine.Results -ConfigManager $configManager
                } else {
                    Write-Host "`n⚠ Non-interactive apply mode not yet implemented." -ForegroundColor Yellow
                    Write-Host "Please use -Interactive flag for guided mitigation application." -ForegroundColor Cyan
                }
            }
            
            'Revert' {
                # Get latest backup
                $backup = $configManager.GetLatestBackup()
                
                if ($null -eq $backup) {
                    Write-Host "`n✗ No backup found. Cannot revert." -ForegroundColor Red
                    return
                }
                
                Write-Host "`nFound backup from: $($backup.Timestamp)" -ForegroundColor Cyan
                Write-Host "Computer: $($backup.Computer)" -ForegroundColor Gray
                Write-Host "`nDo you want to restore this backup? (Y/N): " -NoNewline
                $confirm = Read-Host
                
                if ($confirm -eq 'Y') {
                    $configManager.RevertConfiguration($backup)
                    Write-Host "`n✓ Configuration restored successfully." -ForegroundColor Green
                    Write-Host "⚠ A system restart is required for changes to take effect." -ForegroundColor Yellow
                } else {
                    Write-Host "Revert cancelled." -ForegroundColor Yellow
                }
            }
            
            'Export' {
                if (-not $ExportPath) {
                    $ExportPath = Join-Path $PSScriptRoot "SideChannel_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                }
                
                # Run assessment
                $engine = [AssessmentEngine]::new($platform, $runtime)
                $engine.RunAssessment()
                
                # Export results
                Export-Assessment -Results $engine.Results -ExportPath $ExportPath
            }
        }
        
        Write-Host "`n" # Spacing
        
    } catch {
        $script:Logger.Error("Fatal error: $($_.Exception.Message)")
        Write-Host "`n✗ An error occurred: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "See log file for details: $LogPath" -ForegroundColor Gray
        throw
    }
}

# ============================================================================
# SCRIPT ENTRY POINT
# ============================================================================

# Execute main function
Start-SideChannelCheck -Mode $Mode -Interactive $Interactive -ShowDetails $ShowDetails -ExportPath $ExportPath

# End of script
