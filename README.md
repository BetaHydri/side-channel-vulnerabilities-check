# Side-Channel Vulnerability Configuration Checker

A comprehensive PowerShell tool for checking and configuring Windows side-channel vulnerability mitigations according to Microsoft's security guidance (KB4073119), enhanced with modern CVE support and **intelligent categorization system** for accurate security scoring.

## 🔒 Overview

This tool helps system administrators assess and configure their Windows systems against CPU-based side-channel attacks with **intelligent security categorization**, **full PowerShell 5.1+ compatibility** and **enterprise-grade interactive features**.

### 🎯 **NEW in v2.8: Intelligent Security Categorization**
The tool now separates security assessments into three distinct categories:
- **🛡️ Software Mitigations** (Primary Score): Registry-configurable protections that determine your main security score
- **🔐 Security Features**: Windows security services (VBS, HVCI, Credential Guard, etc.)
- **🔧 Hardware Prerequisites**: Platform readiness checks (UEFI, TPM, CPU virtualization)

This provides **more accurate and meaningful security assessments** by focusing the primary score on actionable configurations rather than hardware capabilities.

### 🛡️ Classic Vulnerabilities (2017-2018):
- **Spectre** (Variants 1, 2, and 4) - CVE-2017-5753, CVE-2017-5715
- **Meltdown** attacks - CVE-2017-5754
- **Intel TSX** vulnerabilities
- **Branch Target Injection** (BTI)
- **Speculative Store Bypass** (SSB) - CVE-2018-3639

### 🆕 Modern CVEs (2018-2023):
- **L1TF** (L1 Terminal Fault) - CVE-2018-3620, CVE-2018-3646
- **MDS** (Microarchitectural Data Sampling) - CVE-2018-11091, CVE-2018-12126, CVE-2018-12127, CVE-2018-12130
- **CVE-2019-11135** (Windows Kernel Information Disclosure)
- **SBDR/SBDS** (Shared Buffer Data) - CVE-2022-21123, CVE-2022-21125
- **SRBDS** (Special Register Buffer) - CVE-2022-21127
- **DRPW** (Device Register Partial Write) - CVE-2022-21166

⚠️ **PERFORMANCE IMPACT WARNING**: L1TF and MDS mitigations may require disabling hyperthreading/SMT on older systems

### 🎯 Enterprise Features:
- **🎯 Intelligent Security Categorization** - Separate scoring for software mitigations vs hardware readiness
- **🎮 Interactive Mode** - Choose specific mitigations with user-friendly interface
- **🔍 WhatIf Preview** - See changes before applying them
- **🎯 Granular Control** - Select individual, ranges, or all mitigations
- **🔄 Intelligent Revert** - Safely remove specific problematic mitigations
- **⚠️ Performance Impact Warnings** - Clear warnings about L1TF/MDS performance impacts
- **🖥️ PowerShell 5.1 Compatibility** - Works seamlessly on Windows Server default installations
- **🏢 KB4073119 + Extended CVE Support** - Core documented mitigations plus performance-critical CVEs

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
- **VMware Security Guide** - **NEW**: Complete ESXi host security configuration guide with `-ShowVMwareHostSecurity`

## 🖥️ Virtualization Support

**Enhanced support for virtualized environments:**

- ✅ **VM Detection** - Automatic identification of host/guest systems
- ✅ **Hypervisor-specific Checks** - Special checks for Hyper-V, VMware, KVM
- ✅ **Host Recommendations** - Security guidance for virtualization hosts
- ✅ **Guest Recommendations** - VM-specific security configuration
- ✅ **Hardware Requirements** - Detailed requirements for secure virtualization
- ✅ **VMware ESXi Integration** - Complete host security guide with `-ShowVMwareHostSecurity` switch

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
| **CVE Coverage** | ✅ KB4073119 + Performance-Critical CVEs | ✅ Complete (2017-2023) |
| **Virtualization** | ✅ Comprehensive VMware/Hyper-V | ❌ None |
| **Auto-Configuration** | ✅ `-Apply` Switch with Interactive Mode | ❌ Assessment only |
| **Revert Functionality** | ✅ **Interactive Revert with WhatIf** | ❌ None |
| **Performance Impact Warnings** | ✅ **Detailed L1TF/MDS/SMT warnings** | ⚠️ Basic |
| **Enterprise Features** | ✅ CSV Export, Tables, WhatIf, Interactive | ⚠️ Basic text |
| **OS Version-Awareness** | ✅ Automatic | ⚠️ Basic |
| **Hardware Analysis** | ⚠️ Registry-based + Hardware Detection | ✅ Native APIs |

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

### 📋 **Command Reference Table**

| Command | Purpose | Use Case |
|---------|---------|----------|
| `.\SideChannel_Check.ps1` | **Basic Security Assessment** | Full security analysis and assessment |
| `.\SideChannel_Check.ps1 -Detailed` | **Comprehensive Analysis** | Full security audit with registry paths and detailed explanations |
| `.\SideChannel_Check.ps1 -Apply -Interactive` | **Selective Configuration** | Choose specific mitigations to apply |
| `.\SideChannel_Check.ps1 -Revert -Interactive` | **Safe Mitigation Removal** | Remove problematic mitigations |
| `.\SideChannel_Check.ps1 -ShowVMwareHostSecurity` | **VMware Security Guide** | ESXi host security configuration |
| `.\SideChannel_Check.ps1 -ExportPath "report.csv"` | **Compliance Reporting** | Export results for documentation |

### 📊 **Parameter Comparison:**

| Parameter | Output Level | Content Differences |
|-----------|-------------|-------------------|
| **None (default)** | **Complete Assessment** | Full security analysis, detailed mitigations table, VBS analysis, hardware matrix, recommendations |
| `-Detailed` | **Extended Analysis** | Same as default + detailed registry paths and additional explanations |
| `-ShowVMwareHostSecurity` | **VMware Focus** | Default assessment + comprehensive ESXi host configuration guide |

### Basic Security Assessment
```powershell
.\SideChannel_Check.ps1
```
**Default behavior**: Shows a complete security assessment including all mitigations, VBS analysis, hardware mitigation matrix, and recommendations.

**Note**: There is no `-QuickCheck` parameter. The default command provides the full assessment.

### Detailed Information
```powershell
.\SideChannel_Check.ps1 -Detailed
```
Displays comprehensive details about each security check including registry paths and additional explanations beyond the default output.

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
**NEW**: Shows exactly what registry changes would be made without actually applying them. Must be combined with both `-Apply` and `-Interactive` for security.

### 🎮 **Combined Interactive WhatIf** (Enterprise Standard)
```powershell
.\SideChannel_Check.ps1 -Apply -Interactive -WhatIf
```
**🏢 ENTERPRISE WORKFLOW**: Select specific mitigations, see detailed registry changes, and apply only after careful review.

## 🏢 Enterprise Workflows

### 🖥️ **VMware Environment Security Workflow**
```powershell
# 1. Initial security assessment of Windows VM
.\SideChannel_Check.ps1 -Detailed

# 2. Get ESXi host configuration requirements
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity

# 3. Apply Windows guest-level mitigations
.\SideChannel_Check.ps1 -Apply -Interactive

# 4. Document complete environment security
.\SideChannel_Check.ps1 -Detailed -ShowVMwareHostSecurity -ExportPath "C:\Reports\VMware_Security_Complete.csv"

# 5. Verify configuration after ESXi host changes
.\SideChannel_Check.ps1
```

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

### 🏢 VMware Host Security Guide
```powershell
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity
```
**For VMware Administrators**: Displays comprehensive ESXi host security configuration guide with specific commands and settings for protecting VMs against side-channel attacks.

#### VMware Security Guide Features:
- **ESXi Host Configuration** - Complete command-line configuration guide
- **Side-Channel Aware Scheduler** - SCAS configuration for ESXi 6.7 U2+
- **VM-Level Security** - Hardware version and .vmx file settings
- **Security Verification** - Commands to verify ESXi security status
- **Performance Impact Analysis** - Impact assessment for each mitigation
- **Security Checklist** - Comprehensive host and VM security checklist

### 🔄 **Enterprise Revert System** - Safely Remove Mitigations
```powershell
.\SideChannel_Check.ps1 -Revert -Interactive
```
**🏢 ENTERPRISE FEATURE**: Intelligently remove specific side-channel mitigations causing performance issues. Particularly useful for L1TF/MDS mitigations that may require SMT disable. Interactive mode provides safety confirmations with detailed security impact analysis.

### 🔍 **Preview Revert Changes** - Risk-Free Planning
```powershell
.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf
```
**🎯 RECOMMENDED ENTERPRISE WORKFLOW**: Preview which mitigations would be reverted, their security implications, and registry changes before making any modifications. Essential for performance recovery in production environments.

## 🖥️ VMware Host Security Management

### 🎯 **VMware Security Guide Display**
```powershell
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity
```
**For VMware vSphere Administrators**: Displays a comprehensive security configuration guide specifically for ESXi hosts protecting against side-channel vulnerabilities.

#### Sample Output:
```
=== VMware ESXi Host Security Configuration Guide ===
Protecting VMs against Side-Channel Vulnerabilities

🔧 Essential ESXi Host Settings:

1. Side-Channel Aware Scheduler (SCAS)
   # Enable SCAS (ESXi 6.7 U2+)
   esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigation -i true
   esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigationIntraVM -i true

2. L1 Terminal Fault (L1TF) Protection
   # Enable L1D cache flush for VMs
   esxcli system settings advanced set -o /VMkernel/Boot/runToCompletionOnly -i true

3. MDS/TAA Microcode Mitigations
   # Enable CPU microcode updates
   esxcli system settings advanced set -o /VMkernel/Boot/ignoreMsrLoad -i false

4. VM Configuration Requirements
   # VM Hardware Version 14+ required
   # Add to VM .vmx file:
   vmx.allowNonVPID = "FALSE"
   featMask.vm.hv.capable = "Min:1"

📋 VMware Security Checklist:
  ✅ Update ESXi to 6.7 U2+ or 7.0+
  ✅ Enable Side-Channel Aware Scheduler
  ✅ Configure L1TF protection
  ✅ Apply latest CPU microcode
  ✅ Update VM Hardware Version to 14+
  ✅ Configure VM security parameters

⚡ Performance Impact Guide:
  SCAS: 2-5% impact (recommended for multi-tenant)
  L1TF: 5-15% impact (critical for untrusted VMs)
  Microcode: 3-8% impact (essential for Intel hosts)
```

**Key Features of VMware Security Guide:**
- **Ready-to-use ESXi commands** - Copy-paste configuration commands
- **VM Configuration templates** - .vmx file security parameters
- **Performance impact ratings** - Informed decision making
- **Security verification commands** - Validate configuration
- **Comprehensive checklists** - Ensure nothing is missed

### 🔗 **Combined VMware Assessment**
```powershell
# Complete VMware environment assessment
.\SideChannel_Check.ps1 -Detailed -ShowVMwareHostSecurity
```
Displays both Windows guest assessment AND ESXi host security guidance in a single comprehensive report.

### 📊 **VMware Security Documentation**
```powershell
# Export Windows assessment with VMware guidance
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity -ExportPath "C:\Reports\VMware_Security_Guide.csv"
```
Exports the security assessment along with VMware-specific recommendations for comprehensive documentation.

### 🎯 **VMware-Specific Use Cases**

#### **For VMware Infrastructure Teams:**
```powershell
# 1. Quick ESXi security reference during maintenance
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity

# 2. Combined guest and host security assessment
.\SideChannel_Check.ps1 -Detailed -ShowVMwareHostSecurity -ExportPath "VMware_Complete_Report.csv"

# 3. Pre-deployment security verification
.\SideChannel_Check.ps1
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity
```

#### **For Security Audits:**
```powershell
# Comprehensive VMware security audit
.\SideChannel_Check.ps1 -Detailed -ShowVMwareHostSecurity -ExportPath "Security_Audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

#### **For Troubleshooting Performance Issues:**
```powershell
# Check current mitigations that may impact VM performance
.\SideChannel_Check.ps1 -Detailed

# Get ESXi performance tuning guidance
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity

# Selectively disable problematic mitigations if needed
.\SideChannel_Check.ps1 -Revert -Interactive
```

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

## 🏢 VMware Security Management - Complete Command Reference

### 📋 **VMware Command Matrix**

| Command | Primary Use | VMware Benefit |
|---------|------------|----------------|
| `.\SideChannel_Check.ps1 -ShowVMwareHostSecurity` | **ESXi Configuration Guide** | Ready-to-use ESXi security commands |
| `.\SideChannel_Check.ps1 -Detailed -ShowVMwareHostSecurity` | **Complete Assessment** | Windows guest + ESXi host analysis |
| `.\SideChannel_Check.ps1 -ShowVMwareHostSecurity -ExportPath "report.csv"` | **Documentation** | Export VMware security guide for compliance |
| `.\SideChannel_Check.ps1 -Apply -Interactive` | **Guest Hardening** | Apply Windows mitigations inside VM |
| `.\SideChannel_Check.ps1` | **Post-Change Verification** | Verify security after ESXi changes |

### 🎯 **VMware-Specific Usage Scenarios**

#### **Scenario 1: New VM Deployment**
```powershell
# Step 1: Check baseline security
.\SideChannel_Check.ps1

# Step 2: Get ESXi host requirements
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity

# Step 3: Apply guest-level protections
.\SideChannel_Check.ps1 -Apply -Interactive

# Step 4: Document final configuration
.\SideChannel_Check.ps1 -Detailed -ExportPath "VM_Security_Baseline.csv"
```

#### **Scenario 2: Security Audit Preparation**
```powershell
# Generate comprehensive VMware security report
.\SideChannel_Check.ps1 -Detailed -ShowVMwareHostSecurity -ExportPath "Audit_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').csv"
```

#### **Scenario 3: Performance Troubleshooting**
```powershell
# Check current mitigations affecting performance
.\SideChannel_Check.ps1 -Detailed

# Get ESXi-level performance optimization guidance
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity

# Preview mitigation removal impact
.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf

# Apply selective revert if needed
.\SideChannel_Check.ps1 -Revert -Interactive
```

#### **Scenario 4: Maintenance Window Planning**
```powershell
# Before maintenance: Document current state
.\SideChannel_Check.ps1 -Detailed -ShowVMwareHostSecurity -ExportPath "Pre_Maintenance_$(Get-Date -Format 'yyyy-MM-dd').csv"

# During maintenance: Get configuration commands
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity

# After maintenance: Verify changes
.\SideChannel_Check.ps1 -QuickCheck
```

### 🔧 **Integration with VMware Tools**

#### **vSphere PowerCLI Integration**
```powershell
# Run security check across multiple VMs
$VMs = Get-VM | Where {$_.PowerState -eq "PoweredOn"}
foreach ($VM in $VMs) {
    # Connect to VM and run security check
    Invoke-VMScript -VM $VM -ScriptText ".\SideChannel_Check.ps1" -GuestUser $cred
}
```

#### **Automated Security Reporting**
```powershell
# Generate security reports for VM fleet
$Date = Get-Date -Format "yyyy-MM-dd"
.\SideChannel_Check.ps1 -Detailed -ShowVMwareHostSecurity -ExportPath "VMware_Security_Report_$Date.csv"

# Copy to vCenter server for centralized reporting
Copy-Item "VMware_Security_Report_$Date.csv" "\\vcenter\reports\"
```

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

### 🎯 New Emoji Categories:
- **🛡️ SOFTWARE MITIGATIONS**: Registry-configurable protections (primary score)
- **🔐 SECURITY FEATURES**: Windows security services status
- **🔧 HARDWARE PREREQUISITES**: Platform readiness indicators

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

Security Assessment Categories:
- Software Mitigations: 19/23 enabled
- Security Features: 4/5 enabled  
- Hardware Prerequisites: 3/4 ready

Security Status Overview:
=========================

🛡️  SOFTWARE MITIGATIONS (Primary Score):
[+] ENABLED:       19 / 23 mitigations  (GREEN - Good)
[-] NOT SET:       4 / 23 mitigations   (YELLOW - Review needed)
[-] DISABLED:      0 / 23 mitigations   (RED - Critical if present)

🔐 SECURITY FEATURES:
[+] ENABLED:       4 / 5 features        (GREEN - Good)

🔧 HARDWARE PREREQUISITES:
[+] READY:         3 / 4 components      (GREEN - Good)

Overall Mitigation Score: 82.6%          (GREEN - Good)
Mitigation Progress: [########--] 82.6%   (Visual progress indicator)

Score Explanation:
• Mitigation Score: Based on registry-configurable side-channel protections
• Security Features: Windows security services (VBS, HVCI, etc.)
• Hardware Prerequisites: Platform readiness for advanced security
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
Based on Microsoft KB4073119 - Core Documented Mitigations

IMPORTANT: This script checks only the core KB4073119 documented mitigations.
For comprehensive analysis including modern CVEs (2022-2023), also run:
   Install-Module SpeculationControl; Get-SpeculationControlSettings

*** PERFORMANCE IMPACT WARNING ***
Some mitigations may significantly impact system performance:
- L1TF & MDS Mitigations: May require disabling hyperthreading
- Older Hyper-V (pre-2016): Higher performance impact
- VBS/Credential Guard: Requires UEFI, Secure Boot, TPM 2.0
- Build servers/shared hosting: May need SMT disabled
Test performance impact in non-production first!

System Information:
CPU: 11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
OS: Microsoft Windows 11 Enterprise Build 26200
Architecture: 64-bit

Virtualization Environment:
Running in VM: No
Hyper-V Status: Enabled
VBS Status: Running
HVCI Status: Enforced
Nested Virtualization: Disabled

Checking Side-Channel Vulnerability Mitigations...

Speculative Store Bypass Disable              : [+] ENABLED (Value: 72)
SSBD Feature Mask                             : [+] ENABLED (Value: 3)
Branch Target Injection Mitigation            : [+] ENABLED (Value: 0)
Kernel VA Shadow (Meltdown Protection)        : [+] ENABLED (Value: 1)
Hardware Security Mitigations                 : [+] ENABLED (Value: 2305843009213694208)
Exception Chain Validation                    : [+] ENABLED (Value: 0)
Supervisor Mode Access Prevention             : [+] ENABLED (Value: 1)
Intel TSX Disable                             : [+] ENABLED (Value: 1)
Enhanced IBRS                                 : [+] ENABLED (Value: 1)

Checking Additional CVE Mitigations (Performance Impact Warning)...
L1TF Mitigation                               : [-] NOT SET
MDS Mitigation                                : [-] NOT SET
CVE-2019-11135 Mitigation                     : [+] ENABLED (Value: 1)
SBDR/SBDS Mitigation                          : [+] ENABLED (Value: 1)
SRBDS Update Mitigation                       : [+] ENABLED (Value: 1)
DRPW Mitigation                               : [+] ENABLED (Value: 1)

Checking Windows Security Features...

Checking Virtualization-Specific Security Features...

Status Legend:
[+] Enabled - Mitigation is active and properly configured
[-] Disabled - Mitigation is explicitly disabled
[-] Not Set - Registry value not configured (using defaults)
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

Security Assessment Categories:
- Software Mitigations: 19/23 enabled
- Security Features: 4/5 enabled
- Hardware Prerequisites: 3/4 ready

Security Status Overview:
=========================

🛡️  SOFTWARE MITIGATIONS (Primary Score):
[+] ENABLED:       19 / 23 mitigations
[-] NOT SET:       4 / 23 mitigations
[-] DISABLED:      0 / 23 mitigations

🔐 SECURITY FEATURES:
[+] ENABLED:       4 / 5 features

🔧 HARDWARE PREREQUISITES:
[+] READY:         3 / 4 components

Overall Mitigation Score: 82.6%
Mitigation Progress: [########--] 82.6%

Score Explanation:
• Mitigation Score: Based on registry-configurable side-channel protections
• Security Features: Windows security services (VBS, HVCI, etc.)
• Hardware Prerequisites: Platform readiness for advanced security

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

### Modern CVE Mitigations (2018-2023) - Performance Impact Focus:

| CVE | Mitigation | Target CPUs | Performance Impact | Description |
|-----|------------|-----------|-------------------|-------------|
| **CVE-2018-3620/3646** | L1TF Mitigation | Intel (Virtualization) | **HIGH** - May require SMT disable | L1 Terminal Fault protection |
| **CVE-2018-11091-12130** | MDS Mitigation | Intel (Affected) | **MODERATE-HIGH** - 3-8% impact | Microarchitectural Data Sampling |
| **CVE-2019-11135** | TAA/TSX Mitigation | Intel/AMD | **VARIABLE** - Application dependent | Windows Kernel Information Disclosure |
| **CVE-2022-21123/21125** | SBDR/SBDS Mitigation | Intel (Recent) | **LOW-MEDIUM** - CPU dependent | Shared Buffer Data protection |
| **CVE-2022-21127** | SRBDS Update Mitigation | Intel (Affected) | **LOW** - Minimal impact | Special Register Buffer protection |
| **CVE-2022-21166** | DRPW Mitigation | Intel (Components) | **LOW** - Typically minimal | Device Register Partial Write protection |

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

### ⚠️ **CRITICAL PERFORMANCE WARNING**:
- **L1TF & MDS Mitigations**: May require disabling hyperthreading/SMT
- **Older Hyper-V (pre-Windows Server 2016)**: Higher performance impact
- **VBS/Credential Guard**: Requires UEFI, Secure Boot, TPM 2.0
- **Build servers/shared hosting**: May need SMT disabled for security
- **TEST PERFORMANCE IMPACT IN NON-PRODUCTION FIRST!**

### Before running `-Apply`:
- **Backup registry** or create system restore point
- **Test in non-production environment first**
- **Check application compatibility** - some protections may impact performance
- **Update CPU microcode** - Modern CVE mitigations require current microcode
- **Plan system restart** - Changes require reboot
- **Review performance warnings** - Especially for L1TF and MDS mitigations

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

### 🏢 **VMware Environment Best Practices:**

#### **🎯 Security Implementation Priority:**
```
1. ESXi Host Security (Infrastructure Team)
   ↓
2. VM Configuration Security (VMware Admins)
   ↓
3. Windows Guest Security (VM Admins) ← This Tool
   ↓
4. Application Security (Dev/App Teams)
```

#### **📋 Coordination Between Teams:**

**Before Guest Hardening:**
```powershell
# VM Admin: Check host requirements first
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity

# Coordinate with Infrastructure team for:
# - ESXi host updates
# - CPU microcode updates  
# - SCAS configuration
```

**After Host Configuration:**
```powershell
# VM Admin: Apply guest-level security
.\SideChannel_Check.ps1 -Apply -Interactive

# Verify complete security stack
.\SideChannel_Check.ps1 -Detailed
```

#### **⚡ Performance Considerations for VMware VMs:**

**High-Performance VMs (Database, Application Servers):**
```powershell
# Apply low-impact mitigations first
.\SideChannel_Check.ps1 -Apply -Interactive
# Select: Low-impact options only

# Test performance before applying medium/high impact
```

**VDI/Terminal Server VMs:**
```powershell
# Balance security vs user experience
.\SideChannel_Check.ps1 -Apply -Interactive
# Consider: User density vs security requirements
```

**Development/Test VMs:**
```powershell
# Apply comprehensive security
.\SideChannel_Check.ps1 -Apply
# Full protection for development security
```

#### **🔍 Monitoring and Compliance:**

```powershell
# Regular security assessment scheduled task
$TaskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Tools\SideChannel_Check.ps1 -ExportPath C:\Reports\Daily_Security_Check.csv"
$TaskTrigger = New-ScheduledTaskTrigger -Daily -At "2:00AM"
Register-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -TaskName "VM Security Assessment"
```

### Performance Considerations:
- Most classic protections have **minimal performance impact** on modern CPUs
- **Modern CVE mitigations** may have higher performance impacts
- **Intel TSX** deactivation can affect applications with Transactional Synchronization Extensions
- **Enhanced IBRS** requires sufficient physical memory
- **Hardware mitigations** vary by CPU generation
- **L1TF mitigations** have significant impact in virtualized environments

## 🖥️ Virtualization-specific Usage

### 🏢 **Windows VMs on VMware Infrastructure** - **COMPREHENSIVE GUIDANCE**

#### **🎯 Where to Execute the Tool:**

**1. Inside Windows Guest VMs (Primary Usage):**
```powershell
# Run inside each Windows VM to assess guest-level security
.\SideChannel_Check.ps1                    # Quick guest assessment
.\SideChannel_Check.ps1 -Detailed          # Full guest analysis
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity  # Get ESXi requirements
```

**2. On VMware vCenter/Management Systems:**
```powershell
# Use PowerCLI for fleet-wide assessment
foreach ($VM in Get-VM) {
    Invoke-VMScript -VM $VM -ScriptText ".\SideChannel_Check.ps1"
}
```

**3. ESXi Host Level (Manual Configuration):**
- Use the tool's output to configure ESXi host settings
- ESXi hosts require direct SSH/console access for security configuration

#### **🔄 Complete VMware VM Security Workflow:**

##### **Phase 1: Assessment (Run in Windows VMs)**
```powershell
# Step 1: Baseline security assessment inside each Windows VM
.\SideChannel_Check.ps1 -Detailed -ExportPath "VM_Security_Assessment.csv"

# Step 2: Get ESXi host configuration requirements
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity
```

##### **Phase 2: Host Configuration (ESXi Administrator)**
```bash
# Apply ESXi host-level mitigations (run on ESXi host)
esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigation -i true
esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigationIntraVM -i true
```

##### **Phase 3: Guest Configuration (Run in Windows VMs)**
```powershell
# Step 3: Apply guest-level mitigations inside Windows VMs
.\SideChannel_Check.ps1 -Apply -Interactive

# Step 4: Verify complete security posture
.\SideChannel_Check.ps1
```

#### **👥 Administrator Role Responsibilities:**

**Windows VM Administrators:**
- ✅ Run the tool **inside** Windows guest VMs
- ✅ Apply Windows-specific mitigations using `-Apply -Interactive`
- ✅ Monitor guest-level security compliance
- ✅ Generate compliance reports with `-ExportPath`
- ✅ Coordinate with VMware administrators for host requirements

**VMware Infrastructure Administrators:**
- ✅ Configure ESXi hosts using guidance from `-ShowVMwareHostSecurity`
- ✅ Apply VM hardware security settings (Hardware Version 14+)
- ✅ Configure .vmx file security parameters
- ✅ Ensure CPU microcode updates on ESXi hosts
- ✅ Implement VM isolation policies

**Security Teams:**
- ✅ Review reports from both guest and host assessments
- ✅ Define security policies for VM environments
- ✅ Validate compliance across VMware infrastructure
- ✅ Coordinate remediation efforts between teams

#### **🎯 VMware Environment Security Layers:**

```
┌─────────────────────────────────────────────┐
│ Windows Guest VM Security (This Tool)      │
│ • Guest OS mitigations                     │
│ • Windows-specific protections             │
│ • Application compatibility                │
└─────────────────────────────────────────────┘
                    ↕ Coordination Required
┌─────────────────────────────────────────────┐
│ VM Configuration Security (VMware Admin)   │
│ • VM Hardware Version 14+                 │
│ • .vmx security parameters                 │
│ • CPU feature exposure                     │
└─────────────────────────────────────────────┘
                    ↕ Dependencies
┌─────────────────────────────────────────────┐
│ ESXi Host Security (Infrastructure Admin)  │
│ • Side-Channel Aware Scheduler             │
│ • CPU microcode updates                    │
│ • Hardware-level mitigations               │
└─────────────────────────────────────────────┘
```

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

### 🔧 **Practical VMware VM Administration Examples:**

#### **Large VM Fleet Management:**
```powershell
# PowerCLI script for multiple VMs
Connect-VIServer -Server vcenter.company.com

$VMs = Get-VM | Where-Object {$_.PowerState -eq "PoweredOn" -and $_.Guest.OSFullName -like "*Windows*"}

foreach ($VM in $VMs) {
    Write-Host "Assessing VM: $($VM.Name)"
    
    $ScriptPath = "C:\Tools\SideChannel_Check.ps1"
    $Result = Invoke-VMScript -VM $VM -ScriptText "& '$ScriptPath'" -GuestUser $GuestCred
    
    # Export results
    $Result.ScriptOutput | Out-File "Reports\$($VM.Name)_Security.txt"
}
```

#### **Automated Security Compliance Reporting:**
```powershell
# Scheduled task script for regular compliance checks
$Date = Get-Date -Format "yyyy-MM-dd"
$VMName = $env:COMPUTERNAME
$ReportPath = "\\FileServer\SecurityReports\VM_$VMName_$Date.csv"

# Run comprehensive assessment
.\SideChannel_Check.ps1 -Detailed -ShowVMwareHostSecurity -ExportPath $ReportPath

# Email notification to security team
Send-MailMessage -To "security@company.com" -Subject "VM Security Report - $VMName" -Body "Security assessment completed" -Attachments $ReportPath
```

#### **Pre-Production Security Validation:**
```powershell
# Golden image validation script
.\SideChannel_Check.ps1 -Apply -Interactive -WhatIf  # Preview changes
.\SideChannel_Check.ps1 -Apply -Interactive           # Apply mitigations
.\SideChannel_Check.ps1 -Detailed -ExportPath "GoldenImage_Security_Baseline.csv"
```

### 🚀 **Integration with VMware Automation:**

#### **vRealize Automation Integration:**
```powershell
# Post-deployment security hardening
# Add to vRA blueprint provisioning workflow
$SecurityScript = @"
    # Download and run security assessment
    Invoke-WebRequest -Uri "https://repo.company.com/SideChannel_Check.ps1" -OutFile "C:\Temp\SideChannel_Check.ps1"
    & "C:\Temp\SideChannel_Check.ps1" -Apply -Interactive
"@

Invoke-VMScript -VM $NewVM -ScriptText $SecurityScript -GuestUser $GuestCred
```

#### **VMware Horizon VDI Integration:**
```powershell
# VDI master image hardening
# Run during master image preparation
.\SideChannel_Check.ps1 -Apply -Interactive
.\SideChannel_Check.ps1 -ExportPath "VDI_Master_Security_Report.csv"

# Sysprep preparation with security validation
.\SideChannel_Check.ps1
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

**Version:** 2.8  
**Last Update:** November 2025  
**PowerShell Compatibility:** 5.1+ (Fully Compatible with Windows Server defaults)  
**CVE Coverage:** KB4073119 + Performance-Critical CVEs (2018-2022)  
**Enterprise Features:** **Intelligent Security Categorization**, Interactive Mode, WhatIf Preview, Granular Control, Mitigation Revert, Performance Impact Warnings, Hardware Requirements Detection  
**New in 2.8:** **Intelligent Security Categorization System** - Separates software mitigations, security features, and hardware prerequisites for accurate scoring; Extended CVE Support with L1TF, MDS, CVE-2019-11135, SBDR/SBDS, SRBDS, DRPW mitigations  
**Previous in 2.7:** Enhanced revert functionality, CPU filtering, performance impact assessment  
**Focus:** Enterprise deployment with **meaningful security scoring** and performance consideration for production systems  
**Compatibility:** Windows 10/11, Windows Server 2016/2019/2022/2025  
**Repository:** [GitHub - BetaHydri/side-channel-vulnerabilities-check](https://github.com/BetaHydri/side-channel-vulnerabilities-check)
