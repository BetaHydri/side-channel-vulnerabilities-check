# Detection Logic Comparison: SpeculationControl vs SideChannel_Check.ps1

## Overview

This document compares the detection methods used by Microsoft's official **SpeculationControl** module (v1.0.19) versus the custom **SideChannel_Check.ps1** tool.

---

## Key Architectural Differences

### Microsoft SpeculationControl Module
- **Primary Method**: Uses `NtQuerySystemInformation` Win32 API calls
- **Information Class**: SystemSpeculationControlInformation (201)
- **Advantages**: 
  - Direct access to kernel-level mitigation state
  - Most authoritative source (Windows kernel reports actual runtime state)
  - Includes hardware vulnerability flags from CPU microcode
- **Limitations**:
  - Read-only assessment (no remediation guidance)
  - Limited hardware prerequisite checking
  - No dependency matrix or detailed recommendations

### SideChannel_Check.ps1
- **Primary Method**: Registry-based detection + WMI/CIM queries
- **Information Sources**: 
  - Registry keys (`HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`)
  - WMI/CIM classes (`Win32_OperatingSystem`, `Win32_Processor`, `Get-ComputerInfo`)
  - DeviceGuard properties (`Get-CimInstance -ClassName Win32_DeviceGuard`)
- **Advantages**:
  - Actionable remediation steps with registry changes
  - Comprehensive hardware prerequisite validation
  - Dependency matrix showing relationships
  - Mitigation flag breakdown with detailed explanations
- **Limitations**:
  - Registry values may not reflect runtime state in all cases
  - Requires administrative privileges for full detection

---

## Detection Method Comparison by Vulnerability

### CVE-2017-5715 (Spectre Variant 2 - Branch Target Injection)

#### SpeculationControl Module
```powershell
# Uses NtQuerySystemInformation with SystemInformationClass = 201
$flags = NtQuerySystemInformation(201, ...)

# Detection via bitflags:
$btiHardwarePresent = (($flags -band $scfSpecCtrlEnumerated) -ne 0) -or 
                      (($flags -band $scfSpecCmdEnumerated) -ne 0)
$btiWindowsSupportEnabled = ($flags -band $scfBpbEnabled) -ne 0
$btiRetpolineEnabled = ($flags -band $scfSpecCtrlRetpolineEnabled) -ne 0
$btiImportOptimizationEnabled = ($flags -band $scfSpecCtrlImportOptimizationEnabled) -ne 0

# Bitflag values:
$scfBpbEnabled = 0x01
$scfSpecCtrlEnumerated = 0x08
$scfSpecCmdEnumerated = 0x10
$scfIbrsPresent = 0x20
$scfStibpPresent = 0x40
$scfSpecCtrlRetpolineEnabled = 0x4000
$scfSpecCtrlImportOptimizationEnabled = 0x8000
```

#### SideChannel_Check.ps1
```powershell
# Registry path: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"

# Detection via registry value:
$featureSettingsOverride = Get-RegistryValue -Path $regPath -Name "FeatureSettingsOverride"
$featureSettingsOverrideMask = Get-RegistryValue -Path $regPath -Name "FeatureSettingsOverrideMask"

# Mitigation enabled if:
# - FeatureSettingsOverride bit is SET (mitigation disabled flag NOT set)
# - FeatureSettingsOverrideMask bit is SET (flag is active)
# Uses Test-MitigationFlag function to check specific bits

# Primary flags checked:
# 0x0000000000000001 - BTI (Branch Target Injection) - CVE-2017-5715
# 0x0000000000000002 - KPTI (Kernel Page Table Isolation) - CVE-2017-5754
```

**Key Difference**: 
- SpeculationControl queries **runtime kernel state** (most accurate)
- SideChannel_Check reads **configuration registry** (persistent settings)
- **Verdict**: SpeculationControl is more accurate for current state; SideChannel_Check shows configured policy

---

### CVE-2017-5754 (Meltdown - Rogue Data Cache Load)

#### SpeculationControl Module
```powershell
# Uses NtQuerySystemInformation with SystemInformationClass = 196 (KVA Shadow)
$flags = NtQuerySystemInformation(196, ...)

# Detection:
$kvaShadowEnabled = ($flags -band $kvaShadowEnabledFlag) -ne 0
$kvaShadowRequired = ($flags -band $kvaShadowRequiredFlag) -ne 0
$kvaShadowPcidEnabled = (($flags -band $kvaShadowPcidFlag) -ne 0) -and 
                        (($flags -band $kvaShadowInvpcidFlag) -ne 0)

# Hardware vulnerability determined by:
# - Intel CPU model/family/stepping lookup table
# - $rdclHardwareProtected flag (newer CPUs report immunity)
```

#### SideChannel_Check.ps1
```powershell
# Registry detection:
$featureSettingsOverride bit 0x0000000000000002 (KPTI flag)

# Additional verification:
$kvaStatus = Get-RegistryValue -Path $regPath -Name "KVAShadowEnabled"
# 0 = Disabled, 1 = Enabled

# Hardware vulnerability check:
$cpu = Get-WmiObject Win32_Processor
# Manual CPU family/model lookup against known vulnerable processors
```

**Key Difference**: 
- Both use similar vulnerability lists for Intel CPUs
- SpeculationControl has more complete CPU model database
- **Verdict**: SpeculationControl CPU detection is more comprehensive

---

### CVE-2018-3639 (Spectre Variant 4 - Speculative Store Bypass)

#### SpeculationControl Module
```powershell
# From NtQuerySystemInformation (201):
$ssbdAvailable = ($flags -band $scfSsbdAvailable) -ne 0
$ssbdHardwarePresent = ($flags -band $scfSsbdSupported) -ne 0
$ssbdSystemWide = ($flags -band $scfSsbdSystemWide) -ne 0
$ssbdRequired = ($flags -band $scfSsbdRequired) -ne 0

# Bitflags:
$scfSsbdAvailable = 0x100
$scfSsbdSupported = 0x200
$scfSsbdSystemWide = 0x400
$scfSsbdRequired = 0x1000
```

#### SideChannel_Check.ps1
```powershell
# Registry detection:
$featureSettingsOverride bit 0x0000000000000008 (SSB flag)

# Alternative registry check:
$ssbdValue = Get-RegistryValue -Path $regPath -Name "SSBDAvailable"
```

**Key Difference**: 
- SpeculationControl distinguishes between "available", "hardware support", "enabled system-wide"
- SideChannel_Check checks binary enabled/disabled state
- **Verdict**: SpeculationControl provides more granular information

---

### CVE-2018-3620 (L1 Terminal Fault / Foreshadow)

#### SpeculationControl Module
```powershell
# From NtQuerySystemInformation (196):
$l1tfInvalidPteBit = [math]::Floor(($flags -band $l1tfInvalidPteBitMask) * [math]::Pow(2,-$l1tfInvalidPteBitShift))
$l1tfMitigationEnabled = (($l1tfInvalidPteBit -ne 0) -and ($kvaShadowEnabled -eq $true))
$l1tfFlushSupported = ($flags -band $l1tfFlushSupportedFlag) -ne 0

# Hardware vulnerability via CPU model lookup table
$l1tfVulnerableCpus = @(
    [tuple]::Create(6, 26, 4), [tuple]::Create(6, 26, 5), 
    [tuple]::Create(6, 142, 9), [tuple]::Create(6, 158, 12)
    # ... extensive list
)
```

#### SideChannel_Check.ps1
```powershell
# Registry detection:
$featureSettingsOverride bit 0x0000000000000010 (L1TF flag)

# Hypervisor L1TF settings:
$hypervisorCheck = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_DeviceGuard"
# Checks AvailableSecurityProperties for hypervisor support
```

**Key Difference**: 
- SpeculationControl has comprehensive Intel CPU model database for L1TF
- SideChannel_Check relies on registry configuration
- **Verdict**: SpeculationControl hardware detection is superior

---

### MDS Vulnerabilities (RIDL, Fallout, ZombieLoad)

#### SpeculationControl Module
```powershell
# From NtQuerySystemInformation (201):
$mdsHardwareProtected = ($flags -band $scfMdsHardwareProtected) -ne 0
$mdsMbClearEnabled = ($flags -band $scfMbClearEnabled) -ne 0
$mdsMbClearReported = ($flags -band $scfMbClearReported) -ne 0

# Bitflags:
$scfMdsHardwareProtected = 0x1000000
$scfMbClearEnabled = 0x2000000
$scfMbClearReported = 0x4000000

# AMD/ARM assumed protected:
if ($manufacturer -eq "AuthenticAMD" -or $isArmCpu -eq $true) {
    $mdsHardwareProtected = $true
}
```

#### SideChannel_Check.ps1
```powershell
# Registry detection:
$featureSettingsOverride bit 0x0000000000000100 (MDS flag)

# Alternative check via DeviceGuard:
$vbsStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard"
# Checks for VBS properties that indicate MDS protections
```

**Key Difference**: 
- SpeculationControl directly queries MBClear (Memory Buffer Clear) support
- SideChannel_Check uses registry + VBS status as proxy
- **Verdict**: SpeculationControl is more direct and accurate

---

### TAA (TSX Asynchronous Abort) - CVE-2019-11135

#### SpeculationControl Module
```powershell
# Uses TAA-specific flags in flags2:
$sbdrSsdpHardwareProtected = ($flags2 -band $scf2SbdrSsdpHardwareProtected) -ne 0
$fbClearEnabled = ($flags2 -band $scf2FbClearEnabled) -ne 0
$fbClearReported = ($flags2 -band $scf2FbClearReported) -ne 0

# Bitflags (flags2):
$scf2SbdrSsdpHardwareProtected = 0x01
$scf2FbClearEnabled = 0x08
$scf2FbClearReported = 0x10
```

#### SideChannel_Check.ps1
```powershell
# Registry detection:
$featureSettingsOverride bit 0x0000000000000400 (TAA flag)

# CPU feature check:
$cpuInfo = Get-WmiObject Win32_Processor
# Checks for TSX (Transactional Synchronization Extensions) support
```

**Key Difference**: 
- SpeculationControl checks FBClear (Fill Buffer Clear) capability
- SideChannel_Check checks registry configuration + TSX presence
- **Verdict**: SpeculationControl is more accurate for mitigation state

---

## Registry vs API Comparison Summary

| Detection Method | SpeculationControl | SideChannel_Check.ps1 |
|------------------|--------------------|-----------------------|
| **Primary Source** | Win32 API (`NtQuerySystemInformation`) | Registry + WMI/CIM |
| **Accuracy** | ✅ **Runtime kernel state** (most accurate) | ⚠️ **Configuration state** (may differ from runtime) |
| **Hardware Detection** | ✅ **Direct CPU microcode queries** | ⚠️ **WMI processor info + manual lookups** |
| **Vulnerability Lists** | ✅ **Comprehensive Intel CPU database** | ⚠️ **Limited CPU model checking** |
| **Mitigation Flags** | ✅ **Kernel bitflags (0x01-0x4000000)** | ✅ **Registry FeatureSettingsOverride bits** |
| **Hypervisor State** | ✅ **Direct HvL1tf flags** | ✅ **DeviceGuard CIM queries** |
| **Remediation** | ❌ None | ✅ **Detailed registry fixes + reboot** |
| **Prerequisites** | ❌ None | ✅ **UEFI, TPM, VT-x, IOMMU checks** |

---

## Detected Discrepancies & Recommendations

### 1. **FeatureSettingsOverride Interpretation**

**Issue**: SideChannel_Check.ps1 uses registry `FeatureSettingsOverride` and `FeatureSettingsOverrideMask`, but these represent **configuration policy**, not runtime state.

**Recommendation**: 
```powershell
# Add Win32 API call for runtime verification (similar to SpeculationControl):
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class NtQuerySystem {
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(
        uint SystemInformationClass,
        IntPtr SystemInformation,
        uint SystemInformationLength,
        IntPtr ReturnLength);
}
"@

# Query system information class 201 (speculation control)
$systemInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)
$returnLengthPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
$result = [NtQuerySystem]::NtQuerySystemInformation(201, $systemInfoPtr, 8, $returnLengthPtr)

if ($result -eq 0) {
    $flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInfoPtr)
    
    # Check BTI enabled at runtime:
    $btiEnabled = ($flags -band 0x01) -ne 0
    Write-Host "BTI Runtime State: $btiEnabled"
}
```

### 2. **CPU Vulnerability Detection**

**Issue**: SideChannel_Check.ps1 lacks comprehensive CPU model database for hardware vulnerability detection.

**Recommendation**: Adopt SpeculationControl's CPU lookup tables:
```powershell
# Example: L1TF vulnerable CPUs
$l1tfVulnerableCpus = @(
    @{Family=6; Model=26; Stepping=4},
    @{Family=6; Model=142; Stepping=9},
    @{Family=6; Model=158; Stepping=12}
    # ... complete list from SpeculationControl
)

$cpu = Get-WmiObject Win32_Processor
$cpuDescription = $cpu.Description
if ($cpuDescription -match 'Family (\d+) Model (\d+) Stepping (\d+)') {
    $cpuFamily = [int]$matches[1]
    $cpuModel = [int]$matches[2]
    $cpuStepping = [int]$matches[3]
    
    $isVulnerable = $l1tfVulnerableCpus | Where-Object {
        $_.Family -eq $cpuFamily -and 
        $_.Model -eq $cpuModel -and 
        $_.Stepping -eq $cpuStepping
    }
}
```

### 3. **MBClear / FBClear Detection**

**Issue**: SideChannel_Check.ps1 doesn't verify MBClear (MDS) or FBClear (TAA) capabilities.

**Recommendation**: Add runtime checks:
```powershell
# Check if MBClear is enabled (bit 0x2000000 in flags)
$mbClearEnabled = ($runtimeFlags -band 0x2000000) -ne 0

# Check if FBClear is enabled (bit 0x08 in flags2)
$fbClearEnabled = ($runtimeFlags2 -band 0x08) -ne 0
```

### 4. **Retpoline Detection**

**Issue**: SideChannel_Check.ps1 doesn't detect retpoline usage (important for Spectre v2).

**Recommendation**: Add retpoline check from SpeculationControl:
```powershell
# Retpoline flag: 0x4000 in flags
$retpolineEnabled = ($runtimeFlags -band 0x4000) -ne 0

if ($retpolineEnabled) {
    Write-Host "✓ Kernel retpoline enabled (software mitigation for Spectre v2)" -ForegroundColor Green
} else {
    Write-Host "✗ Kernel retpoline not enabled" -ForegroundColor Yellow
}
```

---

## Validation Testing

### Test 1: BTI (Spectre v2) Detection Comparison

```powershell
# Microsoft SpeculationControl
$specControl = Get-SpeculationControlSettings
$specControl.BTIWindowsSupportEnabled  # Expected: True

# SideChannel_Check.ps1
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
$override = Get-ItemProperty -Path $regPath -Name "FeatureSettingsOverride"
$mask = Get-ItemProperty -Path $regPath -Name "FeatureSettingsOverrideMask"

# Check BTI bit (0x01):
$btiBit = 0x01
$btiDisabled = ($override.FeatureSettingsOverride -band $btiBit) -eq $btiBit
$btiMaskSet = ($mask.FeatureSettingsOverrideMask -band $btiBit) -eq $btiBit
$btiEnabled = -not $btiDisabled -and $btiMaskSet

Write-Host "SpeculationControl BTI: $($specControl.BTIWindowsSupportEnabled)"
Write-Host "SideChannel_Check BTI:  $btiEnabled"
# Should match in most cases
```

### Test 2: MDS Detection Comparison

```powershell
# Microsoft SpeculationControl
$specControl = Get-SpeculationControlSettings
$mdsMitigated = $specControl.MDSWindowsSupportEnabled  # Expected: True/False
$mdsImmune = -not $specControl.MDSHardwareVulnerable   # Expected: True for AMD/new Intel

# SideChannel_Check.ps1
# Would need to add NtQuerySystemInformation call for accurate comparison
```

---

## Conclusions

### SpeculationControl Module Strengths:
1. ✅ **Most accurate** - queries runtime kernel state
2. ✅ **Comprehensive CPU database** for hardware vulnerability detection
3. ✅ **Detailed flag breakdown** (retpoline, import optimization, etc.)
4. ✅ **Microcode-level** hardware protection flags

### SideChannel_Check.ps1 Strengths:
1. ✅ **Actionable remediation** - provides registry fixes
2. ✅ **Hardware prerequisites** - UEFI, TPM, VT-x, IOMMU validation
3. ✅ **Dependency matrix** - shows relationships between features
4. ✅ **Assessment mode** - non-intrusive scanning
5. ✅ **Detailed recommendations** - step-by-step guidance

### Recommendations for SideChannel_Check.ps1:
1. **Add NtQuerySystemInformation API calls** for runtime verification
2. **Adopt SpeculationControl's CPU vulnerability database**
3. **Cross-reference** registry configuration with runtime state
4. **Add MBClear/FBClear detection**
5. **Add retpoline detection**
6. **Display discrepancies** when registry config differs from runtime state

---

## Example: Enhanced Detection Function

```powershell
function Get-EnhancedSpeculationControl {
    # Combine registry (policy) with runtime (actual state)
    
    # 1. Get runtime state via API
    Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        public class NtQuery {
            [DllImport("ntdll.dll")]
            public static extern int NtQuerySystemInformation(uint c, IntPtr p, uint l, IntPtr r);
        }
"@
    
    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)
    $retPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
    
    try {
        $result = [NtQuery]::NtQuerySystemInformation(201, $ptr, 8, $retPtr)
        
        if ($result -eq 0) {
            $flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($ptr)
            $flags2 = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($ptr, 4)
            
            # 2. Get registry configuration
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            $override = (Get-ItemProperty -Path $regPath -Name "FeatureSettingsOverride" -ErrorAction SilentlyContinue).FeatureSettingsOverride
            $mask = (Get-ItemProperty -Path $regPath -Name "FeatureSettingsOverrideMask" -ErrorAction SilentlyContinue).FeatureSettingsOverrideMask
            
            # 3. Compare runtime vs configuration
            $btiRuntimeEnabled = ($flags -band 0x01) -ne 0
            $btiConfigDisabled = ($override -band 0x01) -eq 0x01
            $btiMaskSet = ($mask -band 0x01) -eq 0x01
            
            [PSCustomObject]@{
                Feature = "BTI (Spectre v2)"
                RuntimeState = if ($btiRuntimeEnabled) { "Enabled" } else { "Disabled" }
                ConfiguredState = if ($btiConfigDisabled -and $btiMaskSet) { "Disabled" } else { "Enabled" }
                Discrepancy = $btiRuntimeEnabled -ne (-not $btiConfigDisabled)
                Retpoline = ($flags -band 0x4000) -ne 0
            }
        }
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($retPtr)
    }
}
```

---

## Final Verdict

**For accuracy**: Use **SpeculationControl module** - it queries kernel runtime state directly.

**For remediation**: Use **SideChannel_Check.ps1** - it provides actionable fixes and comprehensive hardware validation.

**Best practice**: **Combine both approaches** - use SideChannel_Check.ps1 but enhance it with NtQuerySystemInformation API calls to validate that registry changes have actually taken effect at the kernel level.
