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

## 🖥️ Virtualization Support

**NEW**: Enhanced support for virtualized environments:

- ✅ **VM Detection** - Automatic identification of host/guest systems
- ✅ **Hypervisor-specific Checks** - Special checks for Hyper-V, VMware, KVM
- ✅ **Host Recommendations** - Security guidance for virtualization hosts
- ✅ **Guest Recommendations** - VM-specific security configuration
- ✅ **Hardware Requirements** - Detailed requirements for secure virtualization

## 🚀 Enterprise Features

- ✅ **Comprehensive Security Assessment** - Checks 21+ critical security mitigations including modern CVEs (2018-2023)
- 🎮 **Interactive Mode** - **NEW**: Choose specific mitigations to apply with numbered selection interface
- 🔍 **WhatIf Preview** - **NEW**: See registry changes before applying them
- 🎯 **Granular Control** - **NEW**: Apply individual mitigations, ranges (1-3), or all at once
- ✅ **Extended CVE Support** - Based on Microsoft's SpeculationControl tool analysis
- ✅ **Virtualization-Aware** - Detects VM/host environment and provides specific recommendations
- 🧠 **OS Version-Aware** - Automatic adaptation to Windows version (Core Scheduler Detection)
- 🔍 **Hardware Mitigation Matrix** - Decodes MitigationOptions registry values in `-Detailed` mode
- 📊 **Professional Table Display** - Formatted output with visual status indicators
- ⚙️ **Automated Configuration** - One-click application of security settings with `-Apply`
- 🔬 **CPU-specific Validation** - Intel vs AMD specific mitigation recommendations
- 📈 **Enterprise Reporting** - Export results as CSV for documentation and compliance
- 🎯 **Safe Operation** - Read-only by default, only modifies system on explicit request
- 🖥️ **System Information** - Shows CPU and OS details relevant for vulnerabilities
- 🔄 **VBS/HVCI Support** - Checks virtualization-based security features
- 🛡️ **PowerShell 5.1+ Compatible** - **Full compatibility** with Windows Server default PowerShell

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
| **Enterprise Features** | ✅ CSV Export, Tables | ⚠️ Basic text |
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

### 🎮 Combined Interactive WhatIf (Recommended)
```powershell
.\SideChannel_Check.ps1 -Apply -Interactive -WhatIf
```
**Enterprise Workflow**: Select specific mitigations, see detailed registry changes, and apply only after careful review.

### Export Results
```powershell
.\SideChannel_Check.ps1 -ExportPath "C:\Reports\SecurityReport.csv"
```
Exports detailed results to CSV file for documentation and compliance reporting.

### Combined Usage
```powershell
.\SideChannel_Check.ps1 -Detailed -ExportPath "C:\Reports\DetailedReport.csv"
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
Intel TSX Disable                       [-] Disabled             0                 1    May affect applications that rely on TSX
BHB Mitigation                          [?] Not Set          Not Set                 1    Minimal performance impact on recent CPUs
GDS Mitigation                          [?] Not Set          Not Set                 1    Performance impact varies by workload
SRSO Mitigation                         [?] Not Set          Not Set                 1    Minor performance impact on AMD Zen
Windows Defender Exploit Guard ASLR     [?] Not Set          Not Set                 1    Improves resistance to memory corruption
Virtualization Based Security (VBS)     [+] Enabled                1                 1    Requires UEFI, Secure Boot
Hypervisor-protected Code Integrity     [+] Enabled                1                 1    May cause compatibility issues

Status Legend:
[+] Enabled - Mitigation is active and properly configured
[-] Disabled - Mitigation is explicitly disabled  
[?] Not Set - Registry value not configured (using defaults)

=== SECURITY CONFIGURATION SUMMARY ===

Security Status Overview:
=========================
[+] ENABLED:       8 / 21 mitigations
[?] NOT SET:       12 / 21 mitigations
[-] DISABLED:      1 / 21 mitigations

Overall Security Level: 38.1%
Security Bar:     [####------] 38.1%

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
- **Hyper-V Core Scheduler** - OS version-aware SMT scheduler configuration
  - **Windows 10/Server 2016/2019**: Manual activation required
  - **Windows 11/Server 2022+**: Automatically enabled (Build 20348+)
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
- **Core Scheduler** - Automatic in Windows 11/Server 2022+ (Build 20348+)
- **Legacy Support** - Windows 10/Server 2016/2019 need manual configuration
- **Build Detection** - Tool automatically detects required vs. already active features

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

**Virtualization-specific issues:**
- VM guests: Ensure host system is up to date
- Hypervisor hosts: Check hardware virtualization support
- Nested VMs: Verify ExposeVirtualizationExtensions settings

### Reverting Changes:
To manually reset specific protections, delete the registry values or set them to their original values. Always test in controlled environment.

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

**Version:** 2.2  
**Last Update:** November 2025  
**PowerShell Compatibility:** 5.1+ (Fully Compatible with Windows Server defaults)  
**CVE Coverage:** 2017-2023 (Complete compatibility with Microsoft SpeculationControl 1.0.19)  
**Enterprise Features:** Interactive Mode, WhatIf Preview, Granular Control  
**Compatibility:** Windows 10/11, Windows Server 2016/2019/2022/2025  
**Repository:** [GitHub - BetaHydri/side-channel-vulnerabilities-check](https://github.com/BetaHydri/side-channel-vulnerabilities-check)
