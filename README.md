# Side-Channel Vulnerability Configuration Checker

A comprehensive PowerShell tool for checking and configuring Windows side-channel vulnerability mitigations according to Microsoft's security guidance (KB4073119), enhanced with modern CVE support and enterprise features.

## 🔒 Overview

This tool helps system administrators assess and configure their Windows systems against CPU-based side-channel attacks with **full PowerShell 5.1+ compatibility** and **enterprise-grade interactive features**.

### 🛡️ Classic Vulnerabilities (2017-2018):
- **Spectre** (Variants 1, 2, and 4) - CVE-2017-5753, CVE-2017-5715
- **Meltdown** attacks - CVE-2017-5754
- **Intel TSX** vulnerabilities
- **Branch Target Injection** (BTI)
- **Speculative Store Bypass** (SSB) - CVE-2018-3639

### 🆕 Modern CVEs (2018-2023):
- **L1TF** (L1 Terminal Fault) - CVE-2018-3620
- **BHB** (Branch History Buffer) - CVE-2022-0001/0002
- **GDS** (Gather Data Sample) - CVE-2022-40982
- **SRSO** (Speculative Return Stack Overflow) - CVE-2023-20569
- **RFDS** (Register File Data Sampling) - CVE-2023-28746
- **MDS** (Microarchitectural Data Sampling) mitigation

### 🎯 NEW Enterprise Features:
- **🎮 Interactive Mode** - Choose specific mitigations with user-friendly interface
- **🔍 WhatIf Preview** - See changes before applying them
- **🎯 Granular Control** - Select individual, ranges, or all mitigations
- **🖥️ PowerShell 5.1 Compatibility** - Works seamlessly on Windows Server default installations

## 🏢 Enterprise Features

**Advanced Security Management**: Professional-grade features for enterprise environments:

### 🎮 Interactive Apply Mode
- **Granular Control** - Select specific mitigations to apply using numbered interface
- **Impact Assessment** - Shows performance impact for each mitigation (Low/Medium/High)
- **Smart Selection** - Individual numbers, ranges (1-3), or 'all' options
- **CVE Mapping** - Links mitigations to specific vulnerabilities
- **Safe Operation** - Preview changes before applying with WhatIf integration

### 🔄 Intelligent Revert System
- **Selective Revert** - Remove specific mitigations causing performance issues
- **Security Risk Assessment** - Clear warnings about security implications
- **WhatIf Preview** - See what would be reverted before making changes
- **Interactive Safety** - Requires confirmation for each revert operation
- **Performance Recovery** - Targeted removal of problematic mitigations

### 🔍 Advanced Analysis
- **Hardware Mitigation Matrix** - Decode complex registry values in human-readable format
- **Hardware Requirements Detection** - **NEW**: Automatically detects and displays UEFI, Secure Boot, TPM 2.0, CPU virtualization, and IOMMU status
- **OS Version Intelligence** - Automatic adaptation to Windows capabilities
- **CSV Export** - Professional reporting for compliance and documentation
- **Detailed Diagnostics** - Comprehensive security assessment with recommendations

## 🖥️ Virtualization Support

**Enhanced support for virtualized environments:**

- ✅ **VM Detection** - Automatic identification of host/guest systems
- ✅ **Hypervisor-specific Checks** - Special checks for Hyper-V, VMware, KVM
- ✅ **Host Recommendations** - Security guidance for virtualization hosts
- ✅ **Guest Recommendations** - VM-specific security configuration
- ✅ **Hardware Requirements** - Detailed requirements for secure virtualization

## 🚀 Enterprise Features

### 🎮 **Interactive Apply System** - **FLAGSHIP FEATURE**
- **Smart Selection Interface** - Choose specific mitigations with numbered menu (1,3,5 or 1-3 or 'all')
- **Impact Assessment** - Performance impact ratings (Low/Medium/High) for informed decisions
- **WhatIf Integration** - Preview all registry changes before applying
- **CVE Mapping** - Clear links between mitigations and specific vulnerabilities
- **Granular Control** - Apply individual, ranges, or all mitigations with precision

### 🔄 **Intelligent Revert System** - **ENTERPRISE EXCLUSIVE**
- **Selective Mitigation Removal** - Safely remove specific mitigations causing performance issues
- **Security Risk Warnings** - Clear assessment of security implications for each revert
- **Interactive Safety Mode** - Requires confirmation with detailed impact analysis
- **WhatIf Preview** - See exactly what would be reverted before making changes
- **Performance Recovery** - Targeted approach to resolve application compatibility issues

### 🔍 **Advanced Analysis & Reporting**
- **Comprehensive Security Assessment** - Checks 27+ critical security mitigations including modern CVEs (2018-2023)
- **Hardware Requirements Detection** - **NEW**: Automatically detects UEFI, Secure Boot, TPM 2.0, VT-x/AMD-V, and IOMMU status
- **Hardware Mitigation Matrix** - Decodes complex MitigationOptions registry values in human-readable format
- **OS Version Intelligence** - Automatic adaptation to Windows capabilities with intelligent Core Scheduler detection (Build 20348+)
- **Professional CSV Export** - Enterprise reporting for documentation and compliance
- **Virtualization-Aware** - Detects VM/host environment with specific recommendations

### 🛡️ **Security & Compatibility**
- **Extended CVE Support** - Based on Microsoft's SpeculationControl tool analysis (2017-2023)
- **CPU-specific Validation** - Intel vs AMD specific mitigation recommendations
- **Safe Operation** - Read-only by default, only modifies system on explicit request
- **PowerShell 5.1+ Compatible** - **Full compatibility** with Windows Server default PowerShell
- **VBS/HVCI Support** - Comprehensive virtualization-based security features
- **VMware Host Security** - Complete ESXi security configuration guide

## 📋 Requirements

- **Windows**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Version 5.1+ (**Fully Compatible**) or PowerShell 7+
- **Privileges**: Administrator rights required
- **Architecture**: x64 systems (Intel/AMD processors)

### ✅ PowerShell Compatibility:
- **PowerShell 5.1**: ✅ **Fully Supported** - All features work perfectly
- **PowerShell 7+**: ✅ **Fully Supported** - Enhanced performance and features
- **Cross-Version Tested**: Both versions display identical output and functionality
- **Windows Server Default**: PowerShell 5.1 compatibility ensures seamless operation

## 🔄 Compatibility with Microsoft Tools

This tool has been **extended based on Microsoft's official SpeculationControl module analysis**:

```powershell
# For comprehensive assessment use both tools:
.\SideChannel_Check.ps1                    # This extended enterprise tool
Install-Module SpeculationControl          # Microsoft's official assessment
Get-SpeculationControlSettings             # Hardware-level analysis
```

### Tool Comparison:
| Feature | This Tool | Microsoft SpeculationControl |
|---------|-----------|-------------------------------|
| **CVE Coverage** | ✅ Complete (2017-2023) | ✅ Complete (2017-2023) |
| **Virtualization** | ✅ Comprehensive | ❌ None |
| **Auto-Configuration** | ✅ `-Apply` Switch | ❌ Assessment only |
| **Revert Functionality** | ✅ **Interactive Revert** | ❌ None |
| **Enterprise Features** | ✅ CSV Export, Tables, WhatIf | ⚠️ Basic text |
| **OS Version-Awareness** | ✅ Automatic | ⚠️ Basic |
| **Hardware Analysis** | ⚠️ Registry-based | ✅ Native APIs |

## 🔧 Installation

1. Download the script:
   ```powershell
   git clone <repository-url>
   cd side-channel-vulnerabilities-check
   ```

2. Ensure you're running as Administrator:
   ```powershell
   # Right-click PowerShell and "Run as Administrator"
   ```

3. Set execution policy if needed:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## 📖 Usage

> **🏢 ENTERPRISE HIGHLIGHT**: This tool features advanced **Interactive Apply** and **Intelligent Revert** systems for professional security management. Use `-Apply -Interactive` for granular control and `-Revert -Interactive` for safe mitigation removal.

### Basic Security Assessment
```powershell
.\SideChannel_Check.ps1
```
Shows a formatted table with current mitigation status.

### Detailed Information
```powershell
.\SideChannel_Check.ps1 -Detailed
```
Displays comprehensive details about each security check including registry paths and recommendations.

### Apply Security Configurations
```powershell
.\SideChannel_Check.ps1 -Apply
```
Automatically configures all missing security mitigations. **System restart required after changes.**

### 🎯 Interactive Mode - Choose Specific Mitigations
```powershell
.\SideChannel_Check.ps1 -Apply -Interactive
```
**NEW**: Allows you to select which specific mitigations to apply using a user-friendly numbered menu with impact assessment and detailed descriptions.

### 🔍 WhatIf Mode - Preview Changes
```powershell
.\SideChannel_Check.ps1 -Apply -Interactive -WhatIf
```
**NEW**: Shows exactly what registry changes would be made without actually applying them. Must be combined with `-Interactive` mode for security.

### 🎮 **Combined Interactive WhatIf** (Enterprise Standard)
```powershell
.\SideChannel_Check.ps1 -Apply -Interactive -WhatIf
```
**🏢 ENTERPRISE WORKFLOW**: Select specific mitigations, see detailed registry changes, and apply only after careful review.

## 🏢 Enterprise Workflows

### 📋 **Standard Enterprise Deployment**
```powershell
# 1. Assess current security posture
.\SideChannel_Check.ps1 -Detailed

# 2. Plan changes with WhatIf preview
.\SideChannel_Check.ps1 -Apply -Interactive -WhatIf

# 3. Apply selected mitigations
.\SideChannel_Check.ps1 -Apply -Interactive

# 4. Export compliance report
.\SideChannel_Check.ps1 -ExportPath "C:\Reports\SecurityCompliance.csv"
```

### 🔄 **Performance Issue Resolution**
```powershell
# 1. Identify problematic mitigations
.\SideChannel_Check.ps1 -Detailed

# 2. Preview revert options with risk assessment
.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf

# 3. Selectively remove problematic mitigations
.\SideChannel_Check.ps1 -Revert -Interactive

# 4. Verify system performance and security
.\SideChannel_Check.ps1
```

### 📊 **Hardware Requirements Assessment** - **INTELLIGENT DETECTION**

The tool now automatically detects and properly color-codes hardware security requirements:

**Real-Time Hardware Detection:**
- **🟢 UEFI Firmware**: Detects UEFI vs Legacy BIOS automatically
- **🟢 Secure Boot**: Shows actual enablement status with registry detection
- **🟢 TPM 2.0**: Queries hardware directly via WMI/CIM for real TPM status
- **🟡 CPU Virtualization**: Detects VT-x/AMD-V availability and configuration
- **🟢 IOMMU/VT-d**: Identifies DMA isolation capabilities

**Smart Status Display:**
```
=== Hardware Prerequisites for Side-Channel Protection ===
Hardware Security Assessment:
- UEFI Firmware: [+] Present
- Secure Boot: [+] Enabled  
- TPM 2.0: [+] TPM 2.0 Present
- CPU Virtualization (VT-x/AMD-V): [-] Not Detected - Enable in BIOS/UEFI
- IOMMU/VT-d Support: [+] Available (Hyper-V)
```

**No More Guesswork**: Instead of generic warnings, see **actual hardware status** with actionable guidance.

## 🎯 **Granular Security Management**
```powershell
# Apply only low-impact mitigations first
.\SideChannel_Check.ps1 -Apply -Interactive
# Select: 1,4,7,9 (low-impact options)

# Later, apply medium-impact after testing
.\SideChannel_Check.ps1 -Apply -Interactive
# Select: 2,5,8 (medium-impact options)

# Finally, apply high-impact in maintenance window
.\SideChannel_Check.ps1 -Apply -Interactive
# Select: 3,6,10 (high-impact options)
```

### Export Results
```powershell
.\SideChannel_Check.ps1 -ExportPath "C:\Reports\SecurityReport.csv"
```
Exports detailed results to CSV file for documentation and compliance reporting.

### Combined Usage
```powershell
.\SideChannel_Check.ps1 -Detailed -ExportPath "C:\Reports\DetailedReport.csv"
```

### VMware Host Security Guide
```powershell
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity
```
**For VMware Administrators**: Displays comprehensive ESXi host security configuration guide with specific commands and settings for protecting VMs against side-channel attacks.

### 🔄 **Enterprise Revert System** - Safely Remove Mitigations
```powershell
.\SideChannel_Check.ps1 -Revert -Interactive
```
**🏢 ENTERPRISE FEATURE**: Intelligently remove specific side-channel mitigations causing performance issues. Interactive mode provides safety confirmations with detailed security impact analysis.

### 🔍 **Preview Revert Changes** - Risk-Free Planning
```powershell
.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf
```
**🎯 RECOMMENDED ENTERPRISE WORKFLOW**: Preview which mitigations would be reverted, their security implications, and registry changes before making any modifications.

## 🎯 Interactive Mitigation Selection

**NEW Enterprise Feature**: Granular control over which security mitigations to apply.

### 🎮 Interactive Mode Features:
- **📋 Smart Selection Interface** - Choose mitigations with numbered menu
- **🎯 Impact Assessment** - Shows performance impact for each mitigation (Low/Medium/High)
- **🔍 WhatIf Integration** - Preview registry changes before applying
- **📖 Clear Descriptions** - Explains what each mitigation protects against
- **⚡ Smart Defaults** - Automatic type detection and error handling
- **🛡️ CVE Mapping** - Links mitigations to specific vulnerabilities
- **🎛️ Flexible Selection** - Individual numbers, ranges, or 'all'
- **📍 Accurate Registry Paths** - Properly formatted registry paths without formatting errors

### 🎛️ Selection Methods:
- **Individual Numbers**: `1,3,5` - Apply specific numbered mitigations (e.g., only mitigation 1, 3, and 5)
- **Individual with Gaps**: `2,4,7,9` - Apply non-consecutive mitigations
- **Range Selection**: `1-3` - Apply consecutive mitigations 1 through 3 (equivalent to `1,2,3`)
- **Range with Gaps**: `1-3,6-8` - Apply multiple ranges (mitigations 1,2,3,6,7,8)
- **Mixed Selection**: `1,3-5,7` - Combination of individual and ranges (mitigations 1,3,4,5,7)
- **Apply All**: `all` - Apply all available mitigations at once

### 📋 Selection Examples:
| Input | Applies Mitigations | Description |
|-------|-------------------|-------------|
| `1` | 1 | Single mitigation |
| `1,3,4` | 1, 3, 4 | Specific individual mitigations |
| `2,5,7,10` | 2, 5, 7, 10 | Multiple individual mitigations |
| `1-3` | 1, 2, 3 | Range of consecutive mitigations |
| `1-3,6` | 1, 2, 3, 6 | Range plus individual |
| `1,3-5,8` | 1, 3, 4, 5, 8 | Individual, range, and individual |
| `1-2,4-6,9` | 1, 2, 4, 5, 6, 9 | Multiple ranges plus individual |
| `all` | All available | Every available mitigation |

### Example Interactive Session:
```
=== Interactive Mitigation Selection ===
WhatIf Mode: Changes will be previewed but not applied

The following mitigations are not configured and can be enabled:
Use numbers to select (e.g., 1,3,4 or 1-3 or 2,5-7,9 or 'all' for all mitigations):

  [1] SRSO Mitigation (Impact: Low)
      Speculative Return Stack Overflow mitigation for AMD CPUs (CVE-2023-20569)
      Registry: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\SpeculativeReturnStackMitigation
      
  [2] Windows Defender Exploit Guard ASLR (Impact: Medium)
      Address Space Layout Randomization force relocate images
      Registry: HKLM:\SOFTWARE\Microsoft\Windows Defender\...\ASLR_ForceRelocateImages
      
  [3] Hardware Security Mitigations (Impact: Variable)
      CPU-level side-channel protections
      Registry: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\MitigationOptions

  [4] BHB Mitigation (Impact: Low)
      Branch History Buffer injection mitigation (CVE-2022-0001/0002)
      Registry: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\BranchHistoryBufferEnabled

Enter your selection: 1,3,4

=== WhatIf Preview ===
The following changes would be made:

[1] SRSO Mitigation
  Registry Path: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel
  Registry Name: SpeculativeReturnStackMitigation
  New Value: 1
  Value Type: DWORD

[3] Hardware Security Mitigations  
  Registry Path: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel
  Registry Name: MitigationOptions
  New Value: 2000000000000000
  Value Type: QWORD

[4] BHB Mitigation
  Registry Path: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel
  Registry Name: BranchHistoryBufferEnabled
  New Value: 1
  Value Type: DWORD

WhatIf Summary:
Total changes that would be made: 3
System restart would be required: Yes

To apply these changes, run without -WhatIf switch
```

## 🔄 Mitigation Revert Functionality

**NEW Enterprise Feature**: Safely remove individual side-channel mitigations when they cause performance issues.

### 🛡️ Revert Mode Features:
- **🔒 Interactive Safety** - Requires interactive mode for safety confirmation
- **⚠️ Security Warnings** - Clear warnings about security implications of each revert
- **🔍 WhatIf Integration** - Preview what would be reverted before making changes
- **📊 Impact Assessment** - Shows security risk level for each mitigation removal
- **🎯 Selective Revert** - Choose specific mitigations to remove, not all-or-nothing
- **📋 Current Value Tracking** - Shows current and target values for transparency

### 🚨 Important Revert Considerations:
- **Security Risk**: Reverting mitigations reduces your system's security posture
- **Performance vs Security**: Only revert when specific mitigations cause measurable performance issues
- **Testing Required**: Always test revert impact in non-production environments first
- **Monitoring**: Monitor system security and performance after reverting mitigations
- **Re-enable When Possible**: Consider re-enabling mitigations when performance allows

### 🎛️ Revertable Mitigations:

| Mitigation | Security Risk | Typical Reason to Revert |
|------------|---------------|---------------------------|
| **Intel TSX Disable** | Medium | Application compatibility issues |
| **Hardware Security Mitigations** | High | Overall system performance impact |
| **L1TF Mitigation** | High | Virtualization performance issues |
| **BHB/GDS/SRSO Mitigations** | Medium | CPU-specific performance impact |
| **Speculative Store Bypass** | Medium | Application-specific performance |
| **Windows Defender ASLR** | Medium | Legacy application compatibility |
| **Nested Virtualization (Hyper-V)** | Medium | Enhanced security by reducing attack surface |
| **Nested Virtualization (VMware)** | Info | Guidance provided for ESXi host configuration |

### 📋 Example Revert Session:
```
=== Mitigation Revert Mode ===
⚠️  WARNING: Reverting mitigations will REDUCE your system's security!

Available mitigations to revert:
Use numbers to select (e.g., 1,3 or 1-2 or 'all'):

  [1] Intel TSX Disable (Impact: Application-dependent)
      Re-enable Intel TSX (Transactional Synchronization Extensions)
      Security Risk: Medium - May expose TSX-related vulnerabilities
      Registry: HKLM:\SYSTEM\...\kernel\DisableTsx

  [2] Hardware Security Mitigations (Impact: Variable)
      Reset CPU-level security mitigations to default
      Security Risk: High - Removes multiple CPU security features
      Registry: HKLM:\SYSTEM\...\kernel\MitigationOptions

  [3] VMware Nested Virtualization (Information Only) (Impact: High)
      VMware nested virtualization detected - requires ESXi host configuration
      Security Risk: Info - Cannot be controlled from Windows guest. Requires ESXi host access.
      Registry: VMware ESXi\VT-x/AMD-V Passthrough

Enter your selection: 3

=== Mitigation Revert Operation ===
Processing: VMware Nested Virtualization (Information Only)
  ⚠️ VMware Configuration Required:
    This change requires ESXi host access
    Commands to run on ESXi host:
    # Disable VT-x/AMD-V passthrough (run on ESXi host):
    esxcli hardware cpu set --vhv 0
    # Or edit VM .vmx file:
    vhv.enable = "FALSE"
    featMask.vm.hv.capable = "Min:0"
  ⚠️ Cannot execute automatically from Windows guest

Revert Summary:
  Successfully reverted: 0 (Information provided)
  Failed: 0

⚠️ IMPORTANT: ESXi host configuration required for VMware environments!
For VMware nested virtualization changes, access the ESXi host directly.
```

**NEW in Version 2.0**: The `-Detailed` mode now includes a comprehensive **Hardware Security Mitigation Value Matrix** that decodes the cryptic MitigationOptions registry values.

### What the Matrix shows:
```powershell
.\SideChannel_Check.ps1 -Detailed
```

```
HARDWARE SECURITY MITIGATION VALUE MATRIX
==========================================

Flag Value          Status    Mitigation Name
----------          ------    ---------------
0x0000000000000001  [?]       CFG (Control Flow Guard)
0x0000000000000100  [+]       High Entropy ASLR
0x2000000000000000  [+]       Core Hardware Security Features
                               --> This is the primary flag for side-channel mitigations!

Current MitigationOptions Value:
Hex:     0x2000000000000100
Enabled: 2 of 25 known flags
```

### Benefits for Administrators:
- **🔍 Decode Hex Values**: Understand what `0x2000000000000100` means
- **🛡️ Security Audit**: Clear overview of active hardware mitigations
- **📋 Compliance**: Easy verification of specific security flags
- **🔧 Troubleshooting**: Identification of missing security configurations
- **🎓 Education**: Learn about Windows security architecture

### Available Hardware Mitigations:
- **CFG** (Control Flow Guard) - ROP/JOP attack prevention
- **DEP** (Data Execution Prevention) - Prevent code execution in data areas
- **ASLR** (Address Space Layout Randomization) - Memory layout randomization
- **CET** (Intel Control-flow Enforcement Technology) - Hardware-assisted CFI
- **Core Hardware Security Features** - Essential CPU security mitigations
- **25+ additional flags** - Complete list in detailed output

## 🎨 Interpreting Terminal Output

### 📊 Status Symbols & Color Guide

The tool uses **color-coded status symbols** for quick visual assessment:

| Symbol | Color | Meaning | Action Required |
|--------|-------|---------|----------------|
| **[+]** | 🟢 **GREEN** | ✅ **Enabled/Secure** | None - properly configured |
| **[-]** | 🔴 **RED** | ❌ **Disabled/Vulnerable** | **URGENT** - Enable protection |
| **[?]** | 🟡 **YELLOW** | ⚠️ **Unknown/Default** | **REVIEW** - May need configuration |

### 🖥️ Terminal Color Scheme:
- **🟢 GREEN Text**: Successful/secure configurations
- **🔴 RED Text**: Critical issues requiring immediate attention  
- **🟡 YELLOW Text**: Warnings and items needing review
- **🔵 BLUE Text**: Informational messages and system details
- **🟣 MAGENTA Text**: Section headers and important summaries
- **🟠 CYAN Text**: Virtualization-specific guidance and recommendations

### 📈 Security Summary Colors:
- **High Security (>85%)**: Predominantly GREEN output
- **Medium Security (70-85%)**: Mix of GREEN and YELLOW
- **Low Security (<70%)**: Significant RED and YELLOW items

### 🎯 Quick Assessment Tips:
1. **Scan for RED [-] symbols** - These are your highest priority items
2. **Review YELLOW [?] symbols** - These may need configuration based on your environment
3. **GREEN [+] symbols** - These are properly configured and secure
4. **Check the Security Bar** - Visual representation of overall security level

### 🏢 Enterprise Dashboard Reading:
```
=== SECURITY CONFIGURATION SUMMARY ===

Security Status Overview:
=========================
[+] ENABLED:       20 / 22 mitigations  (GREEN - Good)
[?] NOT SET:       2 / 22 mitigations   (YELLOW - Review needed)
[-] DISABLED:      0 / 22 mitigations   (RED - Critical if present)

Overall Security Level: 90.9%            (GREEN - Excellent)
Security Bar:     [#########-] 90.9%     (Visual progress indicator)
```

### 🖥️ Virtualization Recommendations Color Guide:
At the end of the output, **Virtualization Security Recommendations** use the same color system:
- **🟢 [+] Enabled/Recommended**: Feature is active or recommended configuration
- **🔴 [-] Disabled/Not Recommended**: Feature is disabled or not recommended  
- **🟡 [?] Unknown/Variable**: Status depends on configuration or hardware

**Example Interpretation**:
```
=== Virtualization Security Recommendations ===
Hyper-V Host Specific:
- Core Scheduler: [+] Enabled by default (Windows 11/Server 2022+ Build 26200)
- Configure VM isolation policies
- Use Generation 2 VMs for enhanced security
```
This means the Core Scheduler is properly enabled (GREEN [+]) and no action is needed.

## 📊 Example Output

```
=== Side-Channel Vulnerability Configuration Check ===
Based on Microsoft KB4073119

Enhanced with additional CVEs from Microsoft's SpeculationControl tool analysis

System Information:
CPU: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz
OS: Microsoft Windows 11 Enterprise Build 22621
Architecture: 64-bit

Virtualization Environment:
Running in VM: No
Hyper-V Status: Enabled
VBS Status: Running
HVCI Status: Enforced

Checking Side-Channel Vulnerability Mitigations...

=== Side-Channel Vulnerability Mitigation Status ===

Mitigation Name                          Status         Current Value    Expected Value    Impact
---------------                          ------         -------------    --------------    ------
Speculative Store Bypass Disable        [+] Enabled               72                72    Minimal performance impact
SSBD Feature Mask                       [+] Enabled                3                 3    Works in conjunction with FeatureSettingsOverride
Branch Target Injection Mitigation      [?] Not Set          Not Set                 0    Required for proper security policy
Hardware Security Mitigations           [+] Enabled    0x2000000000000100  0x2000000000000000    Hardware-dependent, modern CPUs
Intel TSX Disable                       [+] Enabled                1                 1    May affect applications that rely on TSX
BHB Mitigation                          [+] Enabled                1                 1    Minimal performance impact on recent CPUs
GDS Mitigation                          [+] Enabled                1                 1    Performance impact varies by workload
SRSO Mitigation                         [?] Not Set          Not Set                 1    Minor performance impact on AMD Zen
RFDS Mitigation                         [+] Enabled                1                 1    Minimal performance overhead
L1TF Mitigation                         [+] Enabled                1                 1    High performance impact in virtualized environments
MDS Mitigation                          [+] Enabled                1                 1    Moderate performance impact on Intel CPUs
Windows Defender Exploit Guard ASLR     [?] Not Set          Not Set                 1    Improves resistance to memory corruption
Virtualization Based Security (VBS)     [+] Enabled                1                 1    Requires UEFI, Secure Boot
UEFI Firmware (not Legacy BIOS)         [+] Enabled             UEFI              UEFI    Required for Secure Boot, VBS
Secure Boot                             [+] Enabled          Enabled           Enabled    Essential for VBS and prevents boot malware  
TPM 2.0 (Trusted Platform Module)       [+] Enabled  Present (Version: 2.0)      TPM 2.0    Required for Credential Guard, BitLocker
CPU Virtualization Support (VT-x/AMD-V) [-] Not Detected   Not Available        Enabled    Essential for Hyper-V, VBS
IOMMU/VT-d Support                      [+] Available   Available (Hyper-V)    Available    Provides DMA isolation for VBS
Hypervisor-protected Code Integrity     [+] Enabled                1                 1    May cause compatibility issues
Credential Guard                        [+] Enabled                1                 1    Requires VBS and may affect applications
Hyper-V Core Scheduler                  [+] Enabled         OS Default             Built-in No action needed - already optimized

Status Legend:
[+] Enabled - Mitigation is active and properly configured (GREEN in terminal)
[-] Disabled - Mitigation is explicitly disabled (RED in terminal)
[?] Not Set - Registry value not configured (using defaults) (YELLOW in terminal)

### 🎨 Color Coding in Terminal Output:
- **🟢 GREEN [+]**: Security feature is properly enabled and working
- **🔴 RED [-]**: Security feature is disabled or not working (requires attention)
- **🟡 YELLOW [?]**: Security feature status is unknown or using default values (may need configuration)
- **🔵 BLUE**: Informational messages and system details
- **🟣 MAGENTA**: Section headers and important status summaries
- **🟠 CYAN**: Virtualization-specific recommendations and host security guidance

### 📋 Understanding the Output:
**Main Security Table**: Each mitigation shows its current status with color-coded symbols for quick visual assessment.

**Virtualization Security Recommendations**: 
- Use the status symbols and colors to quickly identify which features need attention
- GREEN items are properly configured and secure
- YELLOW/RED items may require configuration or updates
- Follow the specific recommendations provided for your environment type

=== SECURITY CONFIGURATION SUMMARY ===

Security Status Overview:
=========================
[+] ENABLED:       23 / 27 mitigations
[?] NOT SET:       2 / 27 mitigations
[-] DISABLED:      2 / 27 mitigations

Overall Security Level: 85.2%
Security Bar:     [########--] 85.2%

DETAILED SECURITY ANALYSIS
================================================================================

Virtualization Based Security Detailed Status:
=================================================

VBS (Virtualization Based Security):
  Hardware Ready:   [+] Yes
  Currently Active: [+] Yes

HVCI (Hypervisor-protected Code Integrity):
  Hardware Ready:   [+] Yes
  Currently Active: [+] Yes

Security Services Details:
Running Services: 1, 2
Configured Services: 1, 2

Active Security Services:
  - Credential Guard
  - HVCI (Hypervisor-protected Code Integrity)

HARDWARE SECURITY MITIGATION VALUE MATRIX
================================================================================

Flag Value          Status    Mitigation Name
----------          ------    ---------------
0x0000000000000001  [?]       CFG (Control Flow Guard)
0x0000000000000100  [+]       High Entropy ASLR  
0x2000000000000000  [+]       Core Hardware Security Features
                               --> This is the primary flag for side-channel mitigations!

Current MitigationOptions Value:
Hex:     0x2000000000000100
Enabled: 2 of 25 known flags
```

## 🛡️ Checked Security Measures

### Classic Side-Channel Mitigations:

| Protection Measure | Description | Registry Path | Impact |
|----------------|--------------|---------------|------------|
| **Speculative Store Bypass Disable (SSBD)** | Protection against Spectre Variant 4 | `HKLM:\SYSTEM\...\Memory Management` | Minimal |
| **Branch Target Injection (BTI)** | Protection against Spectre Variant 2 | `HKLM:\SYSTEM\...\kernel` | Low-Medium |
| **Kernel VA Shadow (KVAS)** | Meltdown protection | `HKLM:\SYSTEM\...\Memory Management` | Medium |
| **Enhanced IBRS** | Intel hardware mitigation | `HKLM:\SYSTEM\...\Memory Management` | Low |
| **Intel TSX Disable** | Prevents TSX-based attacks | `HKLM:\SYSTEM\...\kernel` | Application-dependent |
| **Hardware Mitigations** | CPU-level protection | `HKLM:\SYSTEM\...\kernel` | Hardware-dependent |

### Modern CVE Mitigations (2018-2023):

| CVE | Mitigation | Target CPUs | Description |
|-----|------------|-----------|-------------|
| **CVE-2018-3620** | L1TF Mitigation | Intel (Virtualization) | L1 Terminal Fault protection |
| **CVE-2022-0001/0002** | BHB Mitigation | Intel/AMD (Modern) | Branch History Buffer |
| **CVE-2022-40982** | GDS Mitigation | Intel (Server/Datacenter) | Gather Data Sample |
| **CVE-2023-20569** | SRSO Mitigation | AMD Zen | Speculative Return Stack Overflow |
| **CVE-2023-28746** | RFDS Mitigation | Intel (Modern) | Register File Data Sampling |
| **MDS** | MDS Mitigation | Intel (Affected) | Microarchitectural Data Sampling |

### Hardware Requirements & Platform Security:

| Protection Measure | Description | Detection Method | Status Display |
|----------------|--------------|-----------------|----------------|
| **UEFI Firmware** | Modern firmware interface vs Legacy BIOS | Registry Detection | 🟢 **[+] Present** or 🔴 **[-] Legacy BIOS** |
| **Secure Boot** | Boot integrity protection | Registry + PowerShell | 🟢 **[+] Enabled** or 🟡 **[?] Available** |
| **TPM 2.0** | Trusted Platform Module hardware | WMI + CIM Queries | 🟢 **[+] TPM 2.0 Present** or 🔴 **[-] Missing** |
| **CPU Virtualization (VT-x/AMD-V)** | Hardware virtualization extensions | CPU Feature Detection | 🟢 **[+] Available** or 🔴 **[-] Not Detected** |
| **IOMMU/VT-d Support** | DMA isolation capabilities | Service + Registry Detection | 🟢 **[+] Available** or 🟡 **[?] Unknown** |

### Windows Security Features:

| Protection Measure | Description | Registry Path | Impact |
|----------------|--------------|---------------|------------|
| **VBS (Virtualization Based Security)** | Hardware-based security | `HKLM:\SYSTEM\...\DeviceGuard` | Requires UEFI/TPM |
| **HVCI (Hypervisor Code Integrity)** | Hypervisor-protected code integrity | `HKLM:\SYSTEM\...\HypervisorEnforcedCodeIntegrity` | Driver compatibility |
| **Credential Guard** | Protection against credential theft | `HKLM:\SYSTEM\...\Lsa` | VBS required |
| **Windows Defender ASLR** | Address Space Layout Randomization | Windows Defender Exploit Guard | Application compatibility |

## 🖥️ Virtualization-specific Checks

### For VM Guests:
- **SLAT Support Check** - Verification of Second Level Address Translation
- **VM Tools Security** - Hypervisor-specific security features
- **Guest Integration** - Security-relevant integration services

### For Hypervisor Hosts:
- **Hyper-V Core Scheduler** - Intelligent OS version-aware SMT scheduler configuration
  - **Windows 10/Server 2016/2019 (Build < 20348)**: Manual activation required and included in recommendations
  - **Windows 11/Server 2022+ (Build 20348+)**: Automatically enabled by default, excluded from recommendations unless explicitly disabled
- **Nested Virtualization** - Security considerations for nested VMs
- **VM Isolation Policies** - Configuration for secure multi-tenant environments
- **Modern CVE Support** - CPU-specific mitigation based on manufacturer

## 🔧 Virtualization Requirements

### Hardware Requirements:
- **Intel**: VT-x with EPT, VT-d **or** **AMD**: AMD-V with RVI, AMD-Vi
- **IOMMU Support** for secure DMA isolation
- **TPM 2.0** for VBS/Credential Guard
- **UEFI Secure Boot** support

### Hypervisor-specific Requirements:

#### **Microsoft Hyper-V:**
- Windows Server 2019+ for Core Scheduler
- Generation 2 VMs for enhanced security
- VBS/HVCI enabled on host

#### **VMware vSphere:**
- ESXi 6.7 U2+ for Side-Channel Aware Scheduler
- VM Hardware Version 14+
- VMware Tools with security updates

## 🛡️ VMware Host Security Configuration

**Critical**: VMware hosts require specific ESXi configurations to protect VMs against side-channel vulnerabilities.

### **🔧 Essential ESXi Host Settings:**

#### **1. Side-Channel Aware Scheduler (SCAS)**
```bash
# Enable Side-Channel Aware Scheduler (ESXi 6.7 U2+)
esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigation -i true
esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigationIntraVM -i true

# Alternative: Disable Hyperthreading completely (more secure but performance impact)
esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingActive -i false
```

#### **2. L1 Terminal Fault (L1TF) Protection**
```bash
# Enable L1D cache flush for VMs
esxcli system settings advanced set -o /VMkernel/Boot/runToCompletionOnly -i true

# Disable non-VPID execution (VM configuration)
# Add to VM's .vmx file: vmx.allowNonVPID = FALSE
```

#### **3. MDS/TAA Microcode Mitigations**
```bash
# Enable CPU microcode updates
esxcli system settings advanced set -o /VMkernel/Boot/ignoreMsrLoad -i false

# Enable MDS mitigation
esxcli system settings advanced set -o /VMkernel/Boot/mitigateL1TF -i true
```

#### **4. Spectre/Meltdown Host Protection**
```bash
# Enable IBRS/IBPB support
esxcli system settings advanced set -o /VMkernel/Boot/disableSpeculativeExecution -i false

# Enable SSBD (Speculative Store Bypass Disable)
esxcli system settings advanced set -o /VMkernel/Boot/enableSSBD -i true
```

### **⚙️ VM-Level Configuration:**

#### **VM Hardware Settings:**
- **VM Hardware Version**: 14+ (required for CPU security features)
- **CPU Configuration**: Enable "Expose hardware assisted virtualization"
- **Memory**: Enable "Reserve all guest memory (All locked)"
- **Execution Policy**: Enable "Virtualize CPU performance counters"

#### **VM Advanced Parameters (.vmx file):**
```ini
# Disable vulnerable features
vmx.allowNonVPID = "FALSE"
vmx.allowVpid = "TRUE"
isolation.tools.unity.disable = "TRUE"
isolation.tools.unityActive.disable = "TRUE"

# Enable security features
vpmc.enable = "TRUE"
hypervisor.cpuid.v0 = "FALSE"
monitor.phys_bits_used = "40"

# CPU security flags
featMask.vm.hv.capable = "Min:1"
featMask.vm.hv.replay.capable = "Min:1"
```

### **🔍 VMware-Specific Security Verification:**

#### **Check ESXi Security Status:**
```bash
# Verify Side-Channel Aware Scheduler
esxcli system settings advanced list -o /VMkernel/Boot/hyperthreadingMitigation

# Check CPU security features
esxcli hardware cpu global get
esxcli hardware cpu feature get -f spectre-ctrl

# Verify L1TF protection
esxcli system settings advanced list -o /VMkernel/Boot/mitigateL1TF

# Check microcode version
esxcli hardware cpu global get | grep -i microcode
```

#### **VM Security Verification:**
```bash
# Check VM security settings
vim-cmd vmsvc/get.config <VMID> | grep -E "(vmx.allow|featMask|isolation)"

# Verify VMware Tools version (should be latest)
vmware-toolbox-cmd -v
```

### **📋 VMware Security Checklist:**

**Host Level (ESXi):**
- ✅ Update ESXi to 6.7 U2+ or 7.0+
- ✅ Apply latest CPU microcode updates
- ✅ Enable Side-Channel Aware Scheduler
- ✅ Configure L1TF protection
- ✅ Enable MDS/TAA mitigations
- ✅ Verify Spectre/Meltdown host protections

**VM Level:**
- ✅ Update to VM Hardware Version 14+
- ✅ Install latest VMware Tools
- ✅ Configure VM security parameters
- ✅ Enable CPU performance counter virtualization
- ✅ Reserve guest memory (for critical VMs)
- ✅ Apply guest OS mitigations (using this script)

**Network Security:**
- ✅ Isolate management network
- ✅ Use encrypted vMotion
- ✅ Enable VM communication encryption
- ✅ Configure distributed firewall rules

### **⚡ Performance Impact Considerations:**

| Mitigation | Performance Impact | Recommendation |
|------------|-------------------|----------------|
| **Side-Channel Aware Scheduler** | 2-5% | Enable for multi-tenant environments |
| **L1TF Protection** | 5-15% | Critical for untrusted VMs |
| **Full Hyperthreading Disable** | 20-40% | Only for highest security requirements |
| **MDS Mitigation** | 3-8% | Enable for Intel hosts |
| **VM Memory Reservation** | 0% (but uses more host memory) | For critical security workloads |

### **🔗 VMware Security Resources:**

- [VMware Security Advisories](https://www.vmware.com/security/advisories.html)
- [Side-Channel Attack Mitigations](https://kb.vmware.com/s/article/55636)
- [ESXi CPU Performance Monitoring](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.monitoring.doc/GUID-4D4AC9F1-2C67-4F2E-B9E9-E7B4442BB970.html)

#### **Linux KVM/QEMU:**
- Kernel 4.15+ with spec-ctrl support
- CPU flags: +spec-ctrl, +ibpb, +ssbd
- Intel EPT/AMD RVI enabled## ⚠️ Important Notes

### Before running `-Apply`:
- **Backup registry** or create system restore point
- **Test in non-production environment first**
- **Check application compatibility** - some protections may impact performance
- **Update CPU microcode** - Modern CVE mitigations require current microcode
- **Plan system restart** - Changes require reboot

### Interactive Mode Best Practices:
- **Use WhatIf first** - Always preview changes with `-Interactive -WhatIf`
- **Start with low-impact mitigations** - Apply hardware-dependent features first
- **Check CPU compatibility** - Some mitigations are vendor-specific (Intel vs AMD)
- **Review impact ratings** - Consider performance implications before applying
- **Apply incrementally** - Test a few mitigations at a time in production

### Modern CVE Mitigations (2018-2023):
- **CPU-specific validation** - Intel vs AMD specific mitigations
- **Microcode dependencies** - BHB, GDS, SRSO, RFDS require current CPU microcode
- **Vendor-specific** - SRSO only for AMD, GDS/RFDS primarily Intel
- **Performance analysis** - Modern mitigations have variable performance impacts

### OS Version-specific Considerations:
- **Core Scheduler** - Intelligent detection: automatically enabled in Windows 11/Server 2022+ (Build 20348+) and excluded from recommendations unless explicitly disabled
- **Legacy Support** - Windows 10/Server 2016/2019 (Build < 20348) require manual configuration and are included in recommendations when not configured
- **Build Detection** - Enhanced logic automatically detects OS capabilities and only recommends actions when actually needed

### Virtualization-specific Considerations:
- **Secure host system first** before configuring guests
- **Hypervisor updates** have priority over guest configuration
- **Nested Virtualization** increases attack surface - use carefully
- **VM Isolation** configure for multi-tenant environments

### Performance Considerations:
- Most classic protections have **minimal performance impact** on modern CPUs
- **Modern CVE mitigations** may have higher performance impacts
- **Intel TSX** deactivation can affect applications with Transactional Synchronization Extensions
- **Enhanced IBRS** requires sufficient physical memory
- **Hardware mitigations** vary by CPU generation
- **L1TF mitigations** have significant impact in virtualized environments

## 🖥️ Virtualization-specific Usage

### VM Guest System:
```powershell
# Basic check in VM guest
.\SideChannel_Check.ps1

# Detailed information with host recommendations
.\SideChannel_Check.ps1 -Detailed

# Apply guest-specific mitigations
.\SideChannel_Check.ps1 -Apply

# Apply guest mitigations interactively (recommended)
.\SideChannel_Check.ps1 -Apply -Interactive
```

### Hypervisor Host:
```powershell
# Host system analysis with virtualization checks
.\SideChannel_Check.ps1 -Detailed

# Host configuration for secure VM environment
.\SideChannel_Check.ps1 -Apply

# Host configuration with interactive selection (recommended)
.\SideChannel_Check.ps1 -Apply -Interactive

# Export for compliance documentation
.\SideChannel_Check.ps1 -ExportPath "C:\Reports\HostSecurityReport.csv"

# Revert specific mitigations causing performance issues
.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf
```

## 🔍 Troubleshooting

### Common Issues:

**"Access Denied" errors:**
- Ensure PowerShell is running as Administrator
- Check if Windows Defender or security software blocks registry access
- Verify user has SeBackupPrivilege and SeRestorePrivilege

**"Registry path not found" errors:**
- Some paths may not exist in all Windows versions
- The script creates missing registry paths when using `-Apply`
- Use `-Interactive -WhatIf` to preview which paths will be created

**Interactive mode issues:**
- If selection input fails, ensure clean input without extra spaces
- Range selections like "1-3" require no spaces around the dash
- Use 'all' (lowercase) to select all available mitigations

**WhatIf mode not working:**
- WhatIf requires `-Interactive` mode for security reasons
- Ensure both `-Apply -Interactive -WhatIf` switches are used together
- Some changes may require elevation verification

**Performance degradation after application:**
- Check which protections were applied using detailed mode
- Consider disabling specific mitigations for application issues
- Consult application vendor documentation for compatibility
- Use `-Interactive` mode to apply mitigations incrementally
- **Use `-Revert -Interactive -WhatIf` to safely remove problematic mitigations**

**Revert mode issues:**
- Revert mode requires `-Interactive` for safety - this is intentional
- Use `-WhatIf` to preview what would be reverted before making changes  
- Some mitigations cannot be reverted if they're OS/hardware enforced
- Always restart system after reverting mitigations for changes to take effect

**Virtualization-specific issues:**
- VM guests: Ensure host system is up to date
- Hypervisor hosts: Check hardware virtualization support
- Nested VMs: Verify ExposeVirtualizationExtensions settings

### Reverting Changes:
Individual mitigations can now be safely reverted using the new revert functionality:
```powershell
# Preview which mitigations can be reverted
.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf

# Safely revert specific mitigations
.\SideChannel_Check.ps1 -Revert -Interactive
```

**Legacy manual revert**: To manually reset specific protections, delete the registry values or set them to their original values. Always test in controlled environment.

## 📚 References

### Official Microsoft Documentation:
- [Microsoft KB4073119](https://support.microsoft.com/en-us/topic/kb4073119-windows-client-guidance-for-it-pros-to-protect-against-silicon-based-microarchitectural-and-speculative-execution-side-channel-vulnerabilities-35820a8a-ae13-1299-88cc-357f104f5b11) - Official Microsoft guidance
- [Microsoft SpeculationControl PowerShell Module](https://www.powershellgallery.com/packages/SpeculationControl) - Official Microsoft assessment tool
- [Microsoft VBS Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/introduction-to-device-guard-virtualization-based-security-and-windows-defender-application-control) - Virtualization Based Security
- [Hyper-V Security Guide](https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/hyper-v-security) - Hyper-V security guide

### Classic CVE References:
- [CVE-2017-5753](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5753) - Spectre Variant 1
- [CVE-2017-5715](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5715) - Spectre Variant 2  
- [CVE-2017-5754](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5754) - Meltdown
- [CVE-2018-3639](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3639) - Speculative Store Bypass

### Modern CVE References (2018-2023):
- [CVE-2018-3620](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3620) - L1 Terminal Fault (L1TF)
- [CVE-2022-0001](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0001) - Branch History Buffer (BHB) - Variant 1
- [CVE-2022-0002](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0002) - Branch History Buffer (BHB) - Variant 2
- [CVE-2022-40982](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40982) - Gather Data Sample (GDS)
- [CVE-2023-20569](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20569) - Speculative Return Stack Overflow (SRSO)
- [CVE-2023-28746](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28746) - Register File Data Sampling (RFDS)

## 🆘 Support

For issues or questions:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Consult the official Microsoft documentation
3. Create an issue in the repository
4. Contact your security team

## ⚖️ Disclaimer

This tool is provided "as is" without warranty. Always:
- Test in non-production environments first
- Have a rollback plan
- Consult security policies
- Understand the impact of each protection

The authors are not responsible for system issues that may arise from using this tool.

---

## 👤 Autor

**Jan Tiedemann**  
IT Security Specialist & PowerShell Developer

- 🔧 Spezialisiert auf Windows-Sicherheit und Virtualisierung
- 💼 Fokus auf Side-Channel-Vulnerability-Mitigationen
- 🛡️ Enterprise Security Consulting

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make changes
4. Add tests if applicable
5. Submit a pull request

### Areas for Contributions:
- Additional security checks
- Support for older Windows versions
- Performance analyses
- Integration with other security tools
- Hypervisor-specific extensions

---

---

**Version:** 2.4  
**Last Update:** November 2025  
**PowerShell Compatibility:** 5.1+ (Fully Compatible with Windows Server defaults)  
**CVE Coverage:** 2017-2023 (Complete compatibility with Microsoft SpeculationControl 1.0.19)  
**Enterprise Features:** Interactive Mode, WhatIf Preview, Granular Control, Mitigation Revert, Intelligent OS Detection  
**New in 2.4:** Enhanced Hyper-V Core Scheduler detection, improved registry path formatting, smarter recommendations  
**Compatibility:** Windows 10/11, Windows Server 2016/2019/2022/2025  
**Repository:** [GitHub - BetaHydri/side-channel-vulnerabilities-check](https://github.com/BetaHydri/side-channel-vulnerabilities-check)
