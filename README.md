# Side-Channel Vulnerability Configuration Checker

A PowerShell tool for checking, applying, and reverting Windows side-channel vulnerability mitigations with VMware ESXi and Hyper-V integration.

## 🎯 What This Tool Does

- **Checks** your system for side-channel vulnerability protections (Spectre, Meltdown, L1TF, MDS)
- **Applies** missing security mitigations with interactive selection
- **Reverts** problematic mitigations causing performance issues  
- **Provides VMware ESXi** host security configuration guidance
- **Exports results** to CSV for compliance reporting

## 🚀 Quick Start

### Basic Security Check
```powershell
.\SideChannel_Check.ps1
```

### Apply Security Mitigations
```powershell
# Interactive selection (recommended)
.\SideChannel_Check.ps1 -Apply -Interactive

# Preview changes first
.\SideChannel_Check.ps1 -Apply -Interactive -WhatIf
```

### Remove Problematic Mitigations
```powershell
# Safe revert with preview
.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf

# Revert specific mitigations
.\SideChannel_Check.ps1 -Revert -Interactive
```

## 🖥️ Execution Order for Virtualized Environments

### **Step 1: Secure the Hypervisor Host FIRST** 🏗️

**For VMware ESXi:**
```powershell
# Get ESXi configuration commands from Windows VM
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity
```

**Apply on ESXi host (SSH/console):**
```bash
# Enable Side-Channel Aware Scheduler
esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigation -i true
esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigationIntraVM -i true

# Enable L1TF protection  
esxcli system settings advanced set -o /VMkernel/Boot/mitigateL1TF -i true

# Enable MDS protection
esxcli system settings advanced set -o /VMkernel/Boot/ignoreMsrLoad -i false
```

**For Hyper-V Host:**
```powershell
# Run on Hyper-V host system
.\SideChannel_Check.ps1 -Apply -Interactive
```

### **Step 2: Secure Guest VMs SECOND** 🖥️

**Run inside each Windows VM:**
```powershell
# 1. Check current security status
.\SideChannel_Check.ps1

# 2. Apply guest-level mitigations
.\SideChannel_Check.ps1 -Apply -Interactive

# 3. Export compliance report
.\SideChannel_Check.ps1 -ExportPath "VM_Security_Report.csv"
```

### **Step 3: Performance Optimization (If Needed)** ⚡

```powershell
# If performance issues occur, selectively revert mitigations:
.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf
.\SideChannel_Check.ps1 -Revert -Interactive
```

## 📊 Sample Output

### Basic Security Assessment
```
=== Side-Channel Vulnerability Configuration Check ===
Based on Microsoft KB4073119 + Extended Modern CVE Coverage

System Information:
CPU: 11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
OS: Microsoft Windows 11 Enterprise Build 26200
Architecture: 64-bit

Virtualization Environment:
Running in VM: No
Hyper-V Status: Enabled
VBS Status: Running
HVCI Status: Enforced
Nested Virtualization: Enabled

🛡️ SOFTWARE MITIGATIONS
============================================================
Speculative Store Bypass Disable              : [+] ENABLED (Value: 72)
SSBD Feature Mask                             : [+] ENABLED (Value: 3)
Branch Target Injection Mitigation            : [+] ENABLED (Value: 0)
Kernel VA Shadow (Meltdown Protection)        : [+] ENABLED (Value: 1)
Enhanced IBRS                                 : [+] ENABLED (Value: 1)
Intel TSX Disable                             : [+] ENABLED (Value: 1)
L1TF Mitigation                               : [-] NOT SET
MDS Mitigation                                : [-] NOT SET
CVE-2019-11135 Mitigation                     : [+] ENABLED (Value: 1)
SBDR/SBDS Mitigation                          : [+] ENABLED (Value: 1)
SRBDS Update Mitigation                       : [+] ENABLED (Value: 1)
DRPW Mitigation                               : [+] ENABLED (Value: 1)

Category Score: 10/12 enabled (83.3%)

🔐 SECURITY FEATURES
============================================================
Hardware Security Mitigations                 : [+] ENABLED (Value: 0x2000000000000100)
Exception Chain Validation                    : [+] ENABLED (Value: 0)
Supervisor Mode Access Prevention             : [+] ENABLED (Value: 1)
Windows Defender Exploit Guard ASLR           : [-] NOT SET
Virtualization Based Security                 : [+] ENABLED
Hypervisor Code Integrity                     : [+] ENABLED
Credential Guard                              : [+] ENABLED
Windows Defender Application Guard            : [-] NOT CONFIGURED

Category Score: 4/5 enabled (80%)

🔧 HARDWARE PREREQUISITES
============================================================
UEFI Firmware                                 : [+] UEFI Firmware Active
Secure Boot                                   : [+] Enabled
TPM 2.0                                       : [+] TPM 2.0 Enabled
CPU Virtualization (VT-x/AMD-V)               : [+] Enabled and Active
IOMMU/VT-d Support                            : [-] Enabled
CPU Microcode                                 : [+] Up to date

Category Score: 5/6 ready (83.3%)

📊 OVERALL SECURITY SUMMARY
============================================================
Overall Protection Level: 15/18 mitigations enabled (83.3%)
Security Level: [========--]

Security Assessment Categories:
- Software Mitigations: 10/12 enabled
- Security Features: 4/5 enabled
- Hardware Prerequisites: 1/1 ready

Overall Mitigation Score: 83.3%

=== Recommendations ===
The following mitigations should be configured:
- L1TF Mitigation: Enable L1TF protection. WARNING: High performance impact in virtualized environments
- MDS Mitigation: Enable MDS protection. WARNING: Moderate performance impact on Intel CPUs

To apply these configurations:
.\SideChannel_Check.ps1 -Apply -Interactive
```

### Interactive Apply Session
```
=== Interactive Mitigation Selection ===
WhatIf Mode: Changes will be previewed but not applied

The following mitigations are not configured and can be enabled:
Use numbers to select (e.g., 1,3,4 or 1-3 or all for all mitigations):
Enter 0 to apply no mitigations and exit:

  [1] L1TF Mitigation (Impact: HIGH)
      L1 Terminal Fault protection for Intel CPUs
      Registry: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\L1TFMitigationLevel
      WARNING: High performance impact in virtualized environments

  [2] MDS Mitigation (Impact: MODERATE) 
      Microarchitectural Data Sampling protection
      Registry: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\MDSMitigationLevel
      Performance impact: 3-8%

  [3] Windows Defender ASLR (Impact: LOW)
      Enhanced memory protection against exploitation
      Registry: HKLM:\SOFTWARE\Microsoft\Windows Defender\...\ASLR_ForceRelocateImages

Enter your selection: 2,3

=== WhatIf Preview ===
The following changes would be made:

[2] MDS Mitigation
  Registry Path: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel
  Registry Name: MDSMitigationLevel
  New Value: 1
  Value Type: DWORD

[3] Windows Defender ASLR
  Registry Path: HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Exploit Protection\System
  Registry Name: ASLR_ForceRelocateImages
  New Value: 1
  Value Type: DWORD

WhatIf Summary:
Total changes that would be made: 2
System restart would be required: Yes

To apply these changes, run without -WhatIf switch
```

### VMware ESXi Security Guide Output
```
=== VMware ESXi Host Security Configuration Guide ===
ESXi/vSphere Security Hardening for Side-Channel Vulnerability Protection

[*] CRITICAL ESXi HOST SETTINGS:

1. Side-Channel Aware Scheduler (SCAS):
   # Enable Side-Channel Aware Scheduler (ESXi 6.7 U2+)
   esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigation -i true
   esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigationIntraVM -i true

2. L1 Terminal Fault (L1TF) Protection:
   # Enable L1D cache flush for VMs
   esxcli system settings advanced set -o /VMkernel/Boot/mitigateL1TF -i true
   esxcli system settings advanced set -o /VMkernel/Boot/runToCompletionOnly -i true

3. MDS/TAA Microcode Mitigations:
   # Enable CPU microcode updates
   esxcli system settings advanced set -o /VMkernel/Boot/ignoreMsrLoad -i false

[*] VM-LEVEL CONFIGURATION:

VM Hardware Requirements:
   - VM Hardware Version: 14+ (required for CPU security features)
   - CPU Configuration: Enable 'Expose hardware assisted virtualization'
   - Memory: Enable 'Reserve all guest memory' for critical VMs

VM Advanced Parameters (.vmx file):
   # Disable vulnerable features
   vmx.allowNonVPID = "FALSE"
   vmx.allowVpid = "TRUE"

   # Enable security features
   vpmc.enable = "TRUE"
   featMask.vm.hv.capable = "Min:1"

[*] PERFORMANCE IMPACT SUMMARY:

Mitigation                    Impact    Recommendation
---------                    ------    --------------
Side-Channel Aware Scheduler  2-5%     Enable for multi-tenant environments
L1TF Protection              5-15%     Critical for untrusted VMs
Full Hyperthreading Disable 20-40%    Only for highest security requirements
MDS Mitigation               3-8%      Enable for Intel hosts
VM Memory Reservation        0%        For critical security workloads (uses more host memory)

IMPORTANT: Test performance impact in non-production environment first!
Some mitigations may significantly impact performance.
```

### Revert Session Example
```
=== Mitigation Revert Mode ===
⚠️  WARNING: Reverting mitigations will REDUCE your system's security!

Available mitigations to revert:
Use numbers to select (e.g., 1,3 or 1-2 or 'all'):
Enter 0 to revert no mitigations and exit:

  [1] Intel TSX Disable (Impact: Application-dependent)
      Re-enable Intel TSX (Transactional Synchronization Extensions)
      Security Risk: Medium - May expose TSX-related vulnerabilities
      Registry: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableTsx

  [2] Hardware Security Mitigations (Impact: Variable)
      Reset CPU-level security mitigations to default
      Security Risk: High - Removes multiple CPU security features
      Registry: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\MitigationOptions

  [3] VMware Nested Virtualization (Information Only) (Impact: High)
      VMware nested virtualization detected - requires ESXi host configuration
      Security Risk: Info - Cannot be controlled from Windows guest. Requires ESXi host access.
      VMware: VT-x/AMD-V Passthrough

Enter your selection: 1

Are you sure you want to REMOVE these security protections? (yes/no): yes

=== Mitigation Revert Operation ===
Processing: Intel TSX Disable
  + Reverted: Intel TSX Disable = 0

Revert Results:
Successfully reverted: 1/1

[!] IMPORTANT: A system restart may be required for changes to take effect.
```

## 🔄 Tool Comparison

This tool complements Microsoft's official assessment tool:

| Feature | This Tool | Microsoft SpeculationControl |
|---------|-----------|-------------------------------|
| **CVE Coverage** | ✅ KB4073119 + Extended CVE Coverage (2018-2023) | ✅ Complete (2017-2023) |
| **Virtualization** | ✅ VMware/Hyper-V/Nested Detection & Integration | ❌ None |
| **Auto-Configuration** | ✅ `-Apply` with Interactive Mode | ❌ Assessment only |
| **Revert Functionality** | ✅ **Interactive Revert with WhatIf** | ❌ None |
| **Performance Warnings** | ✅ **L1TF/MDS Impact Warnings** | ⚠️ Basic |
| **CPU-Specific Filtering** | ✅ **Intel/AMD Automatic Detection** | ⚠️ Basic |
| **Categorized Scoring** | ✅ **Software/Security/Hardware Categories** | ⚠️ Combined |
| **Enterprise Features** | ✅ CSV Export, Interactive, WhatIf | ⚠️ Basic text |
| **OS Version-Awareness** | ✅ Automatic | ⚠️ Basic |
| **Hardware Analysis** | ⚠️ Registry-based + Hardware Detection | ✅ Native APIs |

**Recommended Usage:**
```powershell
# Use both tools for comprehensive assessment
.\SideChannel_Check.ps1                    # This tool - configuration management
Install-Module SpeculationControl          # Microsoft tool - detailed analysis
Get-SpeculationControlSettings              # Hardware-level verification
```

## 🏢 Enterprise Workflows

### New VM Deployment
```powershell
# 1. Assess baseline security
.\SideChannel_Check.ps1

# 2. Apply mitigations selectively  
.\SideChannel_Check.ps1 -Apply -Interactive

# 3. Document configuration
.\SideChannel_Check.ps1 -ExportPath "VM_$(hostname)_Security.csv"
```

### Performance Troubleshooting
```powershell
# 1. Identify problematic mitigations
.\SideChannel_Check.ps1 -Detailed

# 2. Preview removal impact
.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf

# 3. Selectively remove mitigations
.\SideChannel_Check.ps1 -Revert -Interactive

# 4. Verify performance improvement
.\SideChannel_Check.ps1
```

### Security Audit
```powershell
# Complete environment assessment
.\SideChannel_Check.ps1 -Detailed -ShowVMwareHostSecurity -ExportPath "Security_Audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

### Large VM Fleet Management
```powershell
# PowerCLI script for multiple VMs
Connect-VIServer -Server vcenter.company.com
$VMs = Get-VM | Where-Object {$_.PowerState -eq "PoweredOn" -and $_.Guest.OSFullName -like "*Windows*"}

foreach ($VM in $VMs) {
    Write-Host "Assessing VM: $($VM.Name)"
    $Result = Invoke-VMScript -VM $VM -ScriptText ".\SideChannel_Check.ps1" -GuestUser $GuestCred
    $Result.ScriptOutput | Out-File "Reports\$($VM.Name)_Security.txt"
}
```

## ⚠️ Important Warnings

### **CRITICAL Performance Considerations:**
- **L1TF & MDS mitigations** may require disabling hyperthreading/SMT
- **Test in non-production first** - some mitigations have high performance impact
- **VMware environments** require both host AND guest configuration
- **Backup registry** or create system restore point before making changes

### **Security vs Performance Balance:**
```powershell
# Apply low-impact mitigations first (recommended approach)
.\SideChannel_Check.ps1 -Apply -Interactive
# Select: Low-impact mitigations (typically 1,4,7,9)

# Apply medium-impact after testing performance
# Select: Medium-impact mitigations (typically 2,5,8)

# Apply high-impact mitigations in maintenance window
# Select: High-impact mitigations (typically 3,6,10)
```

### **Revert Safety:**
- Always use `-WhatIf` first to preview changes
- Revert mode requires `-Interactive` for safety - this is intentional
- Some mitigations cannot be reverted if they're OS/hardware enforced
- Always restart system after reverting mitigations for changes to take effect

## 🛠️ Requirements

- **Windows 10/11** or **Windows Server 2016+**
- **PowerShell 5.1+** (fully compatible with Windows Server defaults)
- **Administrator privileges** required
- **System restart** required after applying changes

## 📋 Command Reference

| Command | Purpose |
|---------|---------|
| `.\SideChannel_Check.ps1` | Basic security assessment |
| `.\SideChannel_Check.ps1 -Detailed` | Comprehensive analysis with registry paths |
| `.\SideChannel_Check.ps1 -Apply -Interactive` | Apply selected mitigations interactively |
| `.\SideChannel_Check.ps1 -Apply -Interactive -WhatIf` | Preview changes before applying |
| `.\SideChannel_Check.ps1 -Revert -Interactive` | Remove specific mitigations |
| `.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf` | Preview what would be reverted |
| `.\SideChannel_Check.ps1 -ShowVMwareHostSecurity` | VMware ESXi security guide |
| `.\SideChannel_Check.ps1 -ExportPath "report.csv"` | Export results to CSV |

## 🔍 Troubleshooting

**Access Denied:** Run PowerShell as Administrator

**Performance Issues:** Use revert functionality to remove problematic mitigations:
```powershell
.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf
.\SideChannel_Check.ps1 -Revert -Interactive
```

**VMware Issues:** Ensure both ESXi host AND Windows guest are configured properly

**Registry Errors:** Use `-WhatIf` to preview changes before applying

**Interactive Selection Issues:**
- Use ranges like "1-3" (no spaces around dash)
- Use 'all' (lowercase) to select all mitigations
- Use '0' to exit without changes

## 📊 Security Feature Dependency Matrix

The script includes an **intelligent dependency matrix** that analyzes your hardware capabilities and shows which security features are available with or without specific hardware requirements.

### Feature Overview

| Security Feature | Strict Hardware Required | Software Fallback Available | Impact Without Hardware |
|-----------------|-------------------------|----------------------------|------------------------|
| **Secure Boot** | UEFI firmware + Secure Boot capability | ❌ No | Bootloader attacks possible, rootkit persistence |
| **TPM 2.0** | Trusted Platform Module 2.0 chip | ⚠️ Partial (BitLocker with password/USB) | Reduced cryptographic key security, vulnerable to physical attacks |
| **VBS** (Virtualization Based Security) | CPU virtualization (VT-x/AMD-V) + SLAT/EPT | ✅ Yes (software mode) | Weaker kernel isolation, reduced protection |
| **HVCI** (Hypervisor-protected Code Integrity) | CPU virtualization + IOMMU (VT-d/AMD-Vi) | ✅ Yes (compatible mode) | Less driver protection, higher performance impact |
| **Credential Guard** | VBS + TPM 2.0 (recommended) | ✅ Yes (VBS without TPM) | Less secure credential storage, mimikatz risk |
| **BitLocker** Drive Encryption | TPM 2.0 (recommended) | ✅ Yes (password/USB key) | Vulnerable to physical attacks, evil maid attacks |
| **DRTM** (Dynamic Root of Trust) | Intel TXT / AMD Secure Startup | ❌ No | Vulnerable to bootkit persistence, firmware attacks |
| **Kernel DMA Protection** | IOMMU with pre-boot support | ❌ No | DMA attacks via Thunderbolt/USB4/FireWire possible |
| **Hardware Stack Protection** | Intel CET / AMD Shadow Stack | ❌ No | ROP/JOP attacks easier to execute |
| **Microsoft Pluton** | Integrated Pluton security processor | N/A (optional enhancement) | Falls back to discrete TPM (still secure) |

### Matrix Display in Script Output

The script displays a **real-time analysis** of your system's security capabilities:

```
╔═══════════════════════════════════════════════════════════════════════════╗
║          SECURITY FEATURE DEPENDENCY MATRIX                               ║
╠═══════════════════════════════════════════════════════════════════════════╣

FEATURE                                  FALLBACK   HARDWARE REQUIREMENT
────────────────────────────────────────────────────────────────────────────
Secure Boot                              [✗ No ]    UEFI firmware with Secure Boot capability
TPM 2.0                                  [~ Part]   Trusted Platform Module 2.0 chip
VBS (Virtualization Based Security)      [✓ Yes]    CPU virtualization (VT-x/AMD-V) + SLAT/EPT
HVCI (Hypervisor-protected Code Integrity) [✓ Yes] CPU virtualization + IOMMU (VT-d/AMD-Vi)
Credential Guard                         [✓ Yes]    VBS + TPM 2.0 (recommended)
BitLocker Drive Encryption               [✓ Yes]    TPM 2.0 (recommended)
DRTM (Dynamic Root of Trust)             [✗ No ]    Intel TXT or AMD Secure Startup
Kernel DMA Protection                    [✗ No ]    IOMMU (VT-d/AMD-Vi) with pre-boot protection
Hardware Stack Protection                [✗ No ]    Intel CET or AMD Shadow Stack
Microsoft Pluton                         [  N/A ]   Integrated Pluton security processor

╔═══════════════════════════════════════════════════════════════════════════╗
║          YOUR SYSTEM CAPABILITIES                                         ║
╠═══════════════════════════════════════════════════════════════════════════╣

Hardware Features Detected:
  Secure Boot:      ✓ Enabled
  TPM 2.0:          ✓ Present & Ready (Version 2.0)
  Virtualization:   ✓ Enabled (Intel VT-x / AMD-V active)
  IOMMU (VT-d/Vi):  ✗ Not Detected

Security Features Status:
  VBS:              ✓ Running
  HVCI:             ⚠️  Compatible Mode (IOMMU not available)
  Credential Guard: ✓ Enabled
  Kernel DMA Prot:  ✗ Not Available (IOMMU required)

╔═══════════════════════════════════════════════════════════════════════════╗
║          RECOMMENDATIONS FOR YOUR SYSTEM                                  ║
╠═══════════════════════════════════════════════════════════════════════════╣

  ⚠️  IOMMU (VT-d/AMD-Vi) not detected or disabled
      Impact: HVCI running in compatible mode (reduced protection + higher overhead)
      Action: Enable VT-d (Intel) or AMD-Vi in BIOS/UEFI settings
      Benefit: Full DMA protection + optimized HVCI performance

  ℹ️  All critical security features are active
      Your system has strong baseline protection despite missing IOMMU
```

### Fallback Symbol Legend

The script uses intelligent symbols to show fallback availability:

- **[✓ Yes]** - Full software fallback available (feature works without hardware)
- **[~ Part]** - Partial fallback available (reduced security/functionality)
- **[✗ No ]** - No fallback (hardware absolutely required)
- **[ N/A ]** - Not applicable (optional enhancement feature)

### Key Insights

**✅ Good News:**
- Most critical Windows security features have software fallbacks
- VBS, HVCI, Credential Guard, and BitLocker work on older hardware
- Missing IOMMU doesn't prevent security - it reduces optimization

**⚠️ Performance Trade-offs:**
- Software fallbacks may have higher CPU overhead
- HVCI without IOMMU uses "compatible mode" (more performance impact)
- BitLocker without TPM requires password/USB key (user friction)

**❌ Hardware-Only Features:**
- DRTM (Intel TXT/AMD Secure Startup) - absolute hardware requirement
- Kernel DMA Protection - needs IOMMU with pre-boot support
- Hardware Stack Protection - Intel CET or AMD Shadow Stack CPUs

**📊 Intelligent Analysis:**
- The script detects your actual hardware configuration
- Provides specific recommendations based on what's missing
- Explains real-world security impact, not just technical specs
- Helps prioritize BIOS settings or hardware upgrades

### Use Cases

**System Purchase Planning:**
```powershell
# Check if new hardware meets security requirements
.\SideChannel_Check.ps1
# Review dependency matrix - identify missing hardware features
```

**BIOS Configuration:**
```powershell
# After enabling VT-d/AMD-Vi in BIOS
.\SideChannel_Check.ps1
# Verify IOMMU detection and HVCI mode upgrade
```

**Security Audit:**
```powershell
# Understand security posture and hardware dependencies
.\SideChannel_Check.ps1 -Detailed
# Export matrix data for compliance documentation
```

**Upgrade Justification:**
```powershell
# Show management the security benefit of enabling IOMMU
.\SideChannel_Check.ps1
# Matrix shows: "HVCI Compatible Mode → Full Protection" upgrade path
```

### Technical Implementation

The dependency matrix in the script:

1. **Detects Hardware Features** (4-tier detection system):
   - UEFI/Legacy BIOS detection
   - TPM 2.0 presence and version
   - CPU virtualization (VT-x/AMD-V) via multiple methods
   - IOMMU (VT-d/AMD-Vi) via VBS, Hyper-V, and registry checks

2. **Analyzes Security Features** (cross-reference):
   - Checks VBS/HVCI/Credential Guard actual status
   - Determines operating mode (full vs compatible vs software)
   - Identifies hardware dependencies for each feature

3. **Provides Contextual Recommendations**:
   - Specific to your detected hardware configuration
   - Prioritized by security impact
   - Includes BIOS setting names and expected benefits

4. **Handles Edge Cases**:
   - Virtualized environments (Hyper-V, VMware, nested)
   - AMD vs Intel CPU differences
   - Windows 10 vs 11 vs Server variations
   - Pre-boot vs runtime security feature availability

This matrix transforms complex Microsoft security documentation into **actionable, system-specific guidance**

## 📚 Quick Reference

### Covered Vulnerabilities
- **Spectre** (CVE-2017-5753, CVE-2017-5715) - Branch prediction attacks
- **Meltdown** (CVE-2017-5754) - Kernel memory disclosure
- **L1TF** (CVE-2018-3620/3646) - L1 Terminal Fault (HIGH performance impact)
- **MDS** (CVE-2018-11091-12130) - Microarchitectural Data Sampling (MODERATE performance impact)
- **TSX** vulnerabilities - Transactional Synchronization Extensions
- **Modern CVEs** (2019-2023) with performance impact ratings

### Security Categories
- **🛡️ Software Mitigations**: CPU side-channel protections (Spectre, Meltdown, L1TF, MDS, etc.) - **12 mitigations on Intel, 13 on AMD**
- **🔐 Security Features**: Windows security technologies (VBS, HVCI, Credential Guard, ASLR, etc.) - **8 features**
- **🔧 Hardware Prerequisites**: Platform security capabilities (UEFI, TPM 2.0, VT-x/AMD-V, IOMMU) - **6 components**

**Note:** Counts are CPU-specific - AMD systems include SRSO mitigation, Intel systems include TSX and Enhanced IBRS mitigations.

### Selection Syntax
- **Individual**: `1,3,5` - Apply specific mitigations
- **Ranges**: `1-3` - Apply consecutive mitigations  
- **Mixed**: `1,3-5,7` - Combination of individual and ranges
- **All**: `all` - Apply all available mitigations
- **None**: `0` - Exit without applying changes

---

**Version:** 2.8  
**Author:** Jan Tiedemann  
**Compatibility:** Windows 10/11, Server 2016+  
**PowerShell:** 5.1+ (fully compatible)  
**Repository:** [GitHub - BetaHydri/side-channel-vulnerabilities-check](https://github.com/BetaHydri/side-channel-vulnerabilities-check)
