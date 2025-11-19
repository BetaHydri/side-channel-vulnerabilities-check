# Side-Channel Vulnerability Configuration Checker

A comprehensive PowerShell tool for checking and configuring Windows side-channel vulnerability mitigations according to Microsoft's security guidance (KB4073119).

## 🔒 Overview

This tool helps system administrators assess and configure their Windows systems against CPU-based side-channel attacks including:

- **Spectre** (Variants 1, 2, and 4)
- **Meltdown** attacks
- **Intel TSX** vulnerabilities
- **Branch Target Injection** (BTI)
- **Speculative Store Bypass** (SSB)

## 🚀 Features

- ✅ **Comprehensive Security Assessment** - Checks 11+ critical security mitigations
- 📊 **Clear Table Display** - Professional formatted output with visual status indicators
- ⚙️ **Automated Configuration** - One-click application of security settings with `-Apply` switch
- 📈 **Detailed Reporting** - Export results to CSV for documentation
- 🎯 **Safe Operation** - Read-only by default, only modifies system when explicitly requested
- 🖥️ **System Information** - Shows CPU and OS details relevant to vulnerabilities

## 📋 Requirements

- **Windows**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **Privileges**: Administrator rights required
- **Architecture**: x64 systems (Intel/AMD processors)

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

## 📊 Example Output

```
=== Side-Channel Vulnerability Mitigation Status ===

Mitigation Name                        Status      Current Value   Expected Value
---------------                        ------      -------------   --------------
Speculative Store Bypass Disable      ✓ Enabled               72               72
SSBD Feature Mask                     ✓ Enabled                3                3
Branch Target Injection Mitigation    ○ Not Set          Not Set                0
Hardware Security Mitigations         ○ Not Set          Not Set  2000000000000000
Intel TSX Disable                     ✗ Disabled               0                1

Status Legend:
✓ Enabled  - Mitigation is active and properly configured
✗ Disabled - Mitigation is explicitly disabled
○ Not Set  - Registry value not configured (using defaults)
```

## 🛡️ Security Mitigations Checked

| Mitigation | Description | Registry Path | Impact |
|------------|-------------|---------------|---------|
| **Speculative Store Bypass Disable (SSBD)** | Mitigates Spectre Variant 4 | `HKLM:\SYSTEM\...\Memory Management` | Minimal |
| **Branch Target Injection (BTI)** | Mitigates Spectre Variant 2 | `HKLM:\SYSTEM\...\kernel` | Low-Medium |
| **Kernel VA Shadow (KVAS)** | Meltdown protection | `HKLM:\SYSTEM\...\Memory Management` | Medium |
| **Enhanced IBRS** | Intel hardware mitigation | `HKLM:\SYSTEM\...\Memory Management` | Low |
| **Intel TSX Disable** | Prevents TSX-based attacks | `HKLM:\SYSTEM\...\kernel` | Application-dependent |
| **Hardware Mitigations** | CPU-level protections | `HKLM:\SYSTEM\...\kernel` | Hardware-dependent |

## ⚠️ Important Notes

### Before Running `-Apply`:
- **Backup your registry** or create a system restore point
- **Test in a non-production environment** first
- **Review your application compatibility** - some mitigations may impact performance
- **Plan for system restart** - changes require reboot to take effect

### Performance Considerations:
- Most mitigations have **minimal performance impact** on modern CPUs
- **Intel TSX** disable may affect applications using Transactional Synchronization Extensions
- **Enhanced IBRS** requires sufficient physical memory
- **Hardware mitigations** performance varies by CPU generation

## 🔍 Troubleshooting

### Common Issues:

**"Access Denied" errors:**
- Ensure PowerShell is running as Administrator
- Check if Windows Defender or security software is blocking registry access

**"Cannot find registry path" errors:**
- Some paths may not exist on all Windows versions
- The script will create missing registry paths when using `-Apply`

**Performance impact after applying:**
- Review which mitigations were applied
- Consider disabling specific mitigations if applications are affected
- Consult application vendor documentation for compatibility

### Reverting Changes:
To manually revert specific mitigations, delete the registry values or set them to their original values. Always test in a controlled environment.

## 📚 References

- [Microsoft KB4073119](https://support.microsoft.com/en-us/topic/kb4073119-windows-client-guidance-for-it-pros-to-protect-against-silicon-based-microarchitectural-and-speculative-execution-side-channel-vulnerabilities-35820a8a-ae13-1299-88cc-357f104f5b11) - Official Microsoft guidance
- [CVE-2017-5753](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5753) - Spectre Variant 1
- [CVE-2017-5715](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5715) - Spectre Variant 2  
- [CVE-2017-5754](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5754) - Meltdown
- [CVE-2018-3639](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3639) - Speculative Store Bypass

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Areas for contribution:
- Additional security checks
- Support for older Windows versions
- Performance impact analysis
- Integration with other security tools

## 🆘 Support

If you encounter issues or have questions:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Review Microsoft's official documentation
3. Create an issue in the repository
4. Consult your organization's security team

## ⚖️ Disclaimer

This tool is provided "as-is" without warranty. Always:
- Test in non-production environments first
- Have a rollback plan
- Consult your security policies
- Understand the implications of each mitigation

The authors are not responsible for any system issues that may arise from using this tool.

---

**Version:** 1.0  
**Last Updated:** November 2025  
**Compatibility:** Windows 10/11, Windows Server 2016+