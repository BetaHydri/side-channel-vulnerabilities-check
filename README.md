# Side-Channel Vulnerability Configuration Checker

A comprehensive PowerShell tool for checking and configuring Windows side-channel vulnerability mitigations according to Microsoft's security guidance (KB4073119).

## 🔒 Overview

This tool helps system administrators assess and configure their Windows systems against CPU-based side-channel attacks, including:

### Classic Vulnerabilities:
- **Spectre** (Variants 1, 2, and 4)
- **Meltdown** attacks
- **Intel TSX** vulnerabilities
- **Branch Target Injection** (BTI)
- **Speculative Store Bypass** (SSB)

### Modern CVEs (2018-2023):
- **L1TF** (L1 Terminal Fault) - CVE-2018-3620
- **BHB** (Branch History Buffer) - CVE-2022-0001/0002
- **GDS** (Gather Data Sample) - CVE-2022-40982
- **SRSO** (Speculative Return Stack Overflow) - CVE-2023-20569
- **RFDS** (Register File Data Sampling) - CVE-2023-28746
- **MDS** (Microarchitectural Data Sampling) mitigation

## 🖥️ Virtualization Support

**NEW**: Enhanced support for virtualized environments:

- ✅ **VM Detection** - Automatic identification of host/guest systems
- ✅ **Hypervisor-specific Checks** - Special checks for Hyper-V, VMware, KVM
- ✅ **Host Recommendations** - Security guidance for virtualization hosts
- ✅ **Guest Recommendations** - VM-specific security configuration
- ✅ **Hardware Requirements** - Detailed requirements for secure virtualization

## 🚀 Features

- ✅ **Comprehensive Security Assessment** - Checks 21+ critical security mitigations including modern CVEs (2018-2023)
- ✅ **Extended CVE Support** - Based on Microsoft's SpeculationControl tool analysis
- ✅ **Virtualization-Aware** - Detects VM/host environment and provides specific recommendations
- 🧠 **OS Version-Aware** - Automatic adaptation to Windows version (Core Scheduler Detection)
- 🔍 **Hardware Mitigation Matrix** - **NEW**: Decodes MitigationOptions registry values in `-Detailed` mode
- 📊 **Clear Table Display** - Professionally formatted output with visual status indicators
- ⚙️ **Automated Configuration** - One-click application of security settings with `-Apply`
- 🔬 **CPU-specific Validation** - Intel vs AMD specific mitigation recommendations
- 📈 **Detailed Reporting** - Export results as CSV for documentation
- 🎯 **Safe Operation** - Read-only by default, only modifies system on explicit request
- 🖥️ **System Information** - Shows CPU and OS details relevant for vulnerabilities
- 🔄 **VBS/HVCI Support** - Checks virtualization-based security features

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

### Export Results
```powershell
.\SideChannel_Check.ps1 -ExportPath "C:\Reports\SecurityReport.csv"
```
Exports detailed results to CSV file for documentation and compliance reporting.

### Combined Usage
```powershell
.\SideChannel_Check.ps1 -Detailed -ExportPath "C:\Reports\DetailedReport.csv"
```

## 🔍 Hardware Security Mitigation Value Matrix

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
Decimal: 2305843009213694208
Hex:     0x2000000000000100
Enabled: 2 of 25 known flags
```

### Benefits for Administrators:
- **🔍 Decode Hex Values**: Understand what `2305843009213694208` means
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
=== Side-Channel Vulnerability Mitigation Status ===

Mitigation Name                        Status      Current Value   Expected Value
---------------                        ------      -------------   --------------
Speculative Store Bypass Disable      [+] Enabled             72               72
SSBD Feature Mask                     [+] Enabled              3                3
Branch Target Injection Mitigation    [?] Not Set        Not Set                0
Hardware Security Mitigations         [?] Not Set        Not Set  2000000000000000
Intel TSX Disable                     [-] Disabled             0                1

Overall Security Level: 85.7%
Security Bar:     [########--] 85.7%

Status Legend:
[+] Enabled  - Mitigation is active and properly configured
[-] Disabled - Mitigation is explicitly disabled  
[?] Not Set  - Registry value not configured (using defaults)
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
```

### Hypervisor Host:
```powershell
# Host system analysis with virtualization checks
.\SideChannel_Check.ps1 -Detailed

# Host configuration for secure VM environment
.\SideChannel_Check.ps1 -Apply

# Export for compliance documentation
.\SideChannel_Check.ps1 -ExportPath "C:\Reports\HostSecurityReport.csv"
```

## 🔍 Troubleshooting

### Common Issues:

**"Access Denied" errors:**
- Ensure PowerShell is running as Administrator
- Check if Windows Defender or security software blocks registry access

**"Registry path not found" errors:**
- Some paths may not exist in all Windows versions
- The script creates missing registry paths when using `-Apply`

**Performance degradation after application:**
- Check which protections were applied
- Consider disabling specific mitigations for application issues
- Consult application vendor documentation for compatibility

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

**Version:** 2.1  
**Last Update:** November 2025  
**PowerShell Compatibility:** 5.1+ (Fully Compatible)  
**CVE Coverage:** 2017-2023 (Fully compatible with Microsoft SpeculationControl 1.0.19)  
**Compatibility:** Windows 10/11, Windows Server 2016+  
**Repository:** [GitHub - BetaHydri/side-channel-vulnerabilities-check](https://github.com/BetaHydri/side-channel-vulnerabilities-check)