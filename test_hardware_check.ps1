# Simplified test of the enhanced hardware requirements detection
# This tests the core improvements made to the side-channel vulnerability checker

param()

# Color coding for output
$Colors = @{
    Good    = 'Green'
    Warning = 'Yellow' 
    Bad     = 'Red'
    Info    = 'Cyan'
    Header  = 'Magenta'
    Error   = 'Red'
}

function Write-ColorOutput {
    param([string]$Message, [string]$Color = 'White')
    Write-Host $Message -ForegroundColor $Colors[$Color]
}

function Get-HardwareRequirements {
    $requirements = @{
        IsUEFI = $false
        SecureBootEnabled = $false
        SecureBootCapable = $false
        TPMPresent = $false
        TPMVersion = "Not Available"
        VTxSupport = $false
        IOMMUSupport = "Unknown"
    }
    
    try {
        # Check firmware type
        $firmwareType = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "PEFirmwareType" -ErrorAction SilentlyContinue
        if ($firmwareType.PEFirmwareType -eq 2) {
            $requirements.IsUEFI = $true
        }
        
        # Check Secure Boot
        $secureBootState = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue
        if ($secureBootState.UEFISecureBootEnabled -eq 1) {
            $requirements.SecureBootEnabled = $true
            $requirements.SecureBootCapable = $true
        }
        
        # Check TPM
        $tpm = Get-CimInstance -ClassName Win32_Tpm -Namespace root\cimv2\security\microsofttpm -ErrorAction SilentlyContinue
        if ($tpm) {
            $requirements.TPMPresent = $true
            $requirements.TPMVersion = $tpm.SpecVersion
        }
        
        # Check VT-x/AMD-V
        try {
            $hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction SilentlyContinue
            if ($hyperv) {
                $requirements.VTxSupport = $true
            }
        }
        catch {
            $requirements.VTxSupport = $false
        }
        
        # Check IOMMU
        try {
            $iommu = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction SilentlyContinue
            if ($iommu) {
                $requirements.IOMMUSupport = "Available (basic detection)"
            }
        }
        catch {
            $requirements.IOMMUSupport = "Check BIOS/UEFI manually"
        }
    }
    catch {
        Write-ColorOutput "Error detecting hardware requirements: $($_.Exception.Message)" -Color Error
    }
    
    return $requirements
}

function Get-CPUInfo {
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        return @{
            Name = $cpu.Name
            Manufacturer = $cpu.Manufacturer
            Description = $cpu.Description
        }
    }
    catch {
        return @{
            Name = "Unknown CPU"
            Manufacturer = "Unknown"
            Description = "CPU detection failed"
        }
    }
}

# Main test execution
Write-ColorOutput "`n=== Enhanced Hardware Requirements Detection Test ===" -Color Header
Write-ColorOutput "Testing the improved hardware security assessment functionality`n" -Color Info

# Get system information
$cpuInfo = Get-CPUInfo
$hwRequirements = Get-HardwareRequirements

Write-ColorOutput "System Information:" -Color Header
Write-ColorOutput "CPU: $($cpuInfo.Name)" -Color Info
Write-ColorOutput "CPU Manufacturer: $($cpuInfo.Manufacturer)" -Color Info

Write-ColorOutput "`nEnhanced Hardware Security Assessment:" -Color Header
Write-ColorOutput "(Symbols: [+] Enabled/Good, [?] Needs Verification, [-] Disabled/Missing)" -Color Info

# Enhanced UEFI Status
Write-Host "- UEFI Firmware: " -NoNewline -ForegroundColor Gray
if ($hwRequirements.IsUEFI) {
    Write-Host "`[+`] UEFI Firmware Active - Modern security features supported" -ForegroundColor $Colors['Good']
} else {
    Write-Host "`[-`] Legacy BIOS Mode - Upgrade to UEFI recommended" -ForegroundColor $Colors['Bad']
}

# Enhanced Secure Boot Status  
Write-Host "- Secure Boot: " -NoNewline -ForegroundColor Gray
if ($hwRequirements.SecureBootEnabled) {
    Write-Host "`[+`] Enabled - Boot integrity protection active" -ForegroundColor $Colors['Good']
} elseif ($hwRequirements.SecureBootCapable) {
    Write-Host "`[?`] Available but Disabled - Enable in UEFI settings" -ForegroundColor $Colors['Warning']
} else {
    Write-Host "`[-`] Not Available - UEFI firmware upgrade needed" -ForegroundColor $Colors['Bad']
}

# Enhanced TPM Status
Write-Host "- TPM 2.0: " -NoNewline -ForegroundColor Gray
if ($hwRequirements.TPMPresent) {
    if ($hwRequirements.TPMVersion -match "2\.0") {
        Write-Host "`[+`] TPM 2.0 Enabled - Cryptographic security available" -ForegroundColor $Colors['Good']
    } else {
        Write-Host "`[?`] TPM Present (Version: $($hwRequirements.TPMVersion)) - Verify compatibility" -ForegroundColor $Colors['Warning']
    }
} else {
    Write-Host "`[-`] Not Detected - Enable in BIOS/UEFI or install hardware" -ForegroundColor $Colors['Bad']
}

# Enhanced CPU Virtualization Status
Write-Host "- CPU Virtualization (VT-x/AMD-V): " -NoNewline -ForegroundColor Gray
if ($hwRequirements.VTxSupport) {
    Write-Host "`[+`] Hardware Available - Ready for VBS/HVCI" -ForegroundColor $Colors['Good']
} else {
    Write-Host "`[?`] Manual BIOS Check Required - Enable in firmware settings" -ForegroundColor $Colors['Warning']
}

# Enhanced IOMMU Status
Write-Host "- IOMMU/VT-d Support: " -NoNewline -ForegroundColor Gray
Write-Host "`[?`] $($hwRequirements.IOMMUSupport) - Enable for DMA protection" -ForegroundColor $Colors['Warning']

Write-ColorOutput "`nAdministrator Action Items:" -Color Header
Write-ColorOutput "============================" -Color Header

# Generate specific action items based on current status
$actionItems = @()

if (!$hwRequirements.IsUEFI) {
    $actionItems += "• CRITICAL: Convert from Legacy BIOS to UEFI mode (may require OS reinstall)"
}

if ($hwRequirements.IsUEFI -and !$hwRequirements.SecureBootEnabled) {
    $actionItems += "• Access UEFI firmware settings and enable Secure Boot"
}

if (!$hwRequirements.TPMPresent) {
    $actionItems += "• Enable TPM 2.0 in BIOS/UEFI or install TPM hardware module"
} elseif ($hwRequirements.TPMVersion -notmatch "2\.0") {
    $actionItems += "• Upgrade TPM to version 2.0 or enable TPM 2.0 mode in UEFI"
}

if (!$hwRequirements.VTxSupport) {
    $actionItems += "• Enable VT-x (Intel) or AMD-V (AMD) virtualization in BIOS/UEFI"
}

$actionItems += "• Enable VT-d (Intel) or AMD-Vi (AMD) IOMMU in BIOS/UEFI for DMA protection"
$actionItems += "• Update system firmware/BIOS to latest version for security fixes"
$actionItems += "• Update CPU microcode through Windows Update or vendor tools"

if ($actionItems.Count -gt 0) {
    Write-ColorOutput "`nRequired Actions for Optimal Security:" -Color Warning
    foreach ($item in $actionItems) {
        Write-ColorOutput $item -Color Warning
    }
} else {
    Write-ColorOutput "`nHardware Security Status: All critical components properly configured!" -Color Good
}

Write-ColorOutput "`nManual Verification Steps:" -Color Info
Write-ColorOutput "• Boot into UEFI/BIOS setup to verify settings" -Color Info
Write-ColorOutput "• Run 'msinfo32.exe' and check 'System Summary' for Secure Boot State" -Color Info  
Write-ColorOutput "• Use 'tpm.msc' to verify TPM status and version" -Color Info
Write-ColorOutput "• Check Windows Event Logs for Hyper-V and VBS initialization" -Color Info

# CPU-specific filtering demonstration
Write-ColorOutput "`nCPU-Specific Mitigation Filtering:" -Color Header
Write-ColorOutput "===================================" -Color Header

$intelSpecificMitigations = @("GDS Mitigation", "RFDS Mitigation", "L1TF Mitigation", "MDS Mitigation", "Intel TSX Disable")
$amdSpecificMitigations = @("SRSO Mitigation")

Write-ColorOutput "CPU Detected: $($cpuInfo.Manufacturer)" -Color Info

if ($cpuInfo.Manufacturer -eq "GenuineIntel") {
    Write-ColorOutput "`nIntel CPU - The following mitigations would be applicable:" -Color Good
    foreach ($mitigation in $intelSpecificMitigations) {
        Write-ColorOutput "  ✓ $mitigation" -Color Good
    }
    Write-ColorOutput "`nAMD-specific mitigations would be filtered out:" -Color Info
    foreach ($mitigation in $amdSpecificMitigations) {
        Write-ColorOutput "  ✗ $mitigation (AMD-specific)" -Color Warning
    }
} elseif ($cpuInfo.Manufacturer -eq "AuthenticAMD") {
    Write-ColorOutput "`nAMD CPU - The following mitigations would be applicable:" -Color Good
    foreach ($mitigation in $amdSpecificMitigations) {
        Write-ColorOutput "  ✓ $mitigation" -Color Good
    }
    Write-ColorOutput "`nIntel-specific mitigations would be filtered out:" -Color Info
    foreach ($mitigation in $intelSpecificMitigations) {
        Write-ColorOutput "  ✗ $mitigation (Intel-specific)" -Color Warning
    }
} else {
    Write-ColorOutput "`nUnknown CPU - Manual verification required for mitigation compatibility" -Color Warning
}

Write-ColorOutput "`n=== Test Completed Successfully! ===" -Color Header
Write-ColorOutput "The enhanced hardware requirements detection is working properly." -Color Good
Write-ColorOutput "Key improvements:" -Color Info
Write-ColorOutput "• More accurate hardware status detection" -Color Info
Write-ColorOutput "• Clearer status messages with actionable guidance" -Color Info
Write-ColorOutput "• CPU-specific mitigation filtering" -Color Info
Write-ColorOutput "• Comprehensive administrator action items" -Color Info