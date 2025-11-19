# Side-Channel Vulnerability Configuration Checker

Ein umfassendes PowerShell-Tool zur Überprüfung und Konfiguration von Windows-Schutzmaßnahmen gegen Side-Channel-Vulnerabilities gemäß Microsoft-Sicherheitsleitlinien (KB4073119).

## 🔒 Überblick

Dieses Tool hilft Systemadministratoren bei der Bewertung und Konfiguration ihrer Windows-Systeme gegen CPU-basierte Side-Channel-Angriffe, einschließlich:

- **Spectre** (Varianten 1, 2 und 4)
- **Meltdown** Angriffe
- **Intel TSX** Vulnerabilities
- **Branch Target Injection** (BTI)
- **Speculative Store Bypass** (SSB)

## 🖥️ Virtualisierungs-Support

**NEU**: Erweiterte Unterstützung für virtualisierte Umgebungen:

- ✅ **VM-Erkennung** - Automatische Identifikation von Host/Guest-Systemen
- ✅ **Hypervisor-spezifische Prüfungen** - Spezielle Checks für Hyper-V, VMware, KVM
- ✅ **Host-Empfehlungen** - Sicherheitshinweise für Virtualisierungs-Hosts
- ✅ **Guest-Empfehlungen** - VM-spezifische Sicherheitskonfiguration
- ✅ **Hardware-Voraussetzungen** - Detaillierte Anforderungen für sichere Virtualisierung

## 🚀 Features

- ✅ **Umfassende Sicherheitsbewertung** - Prüft 15+ kritische Sicherheitsmitigationen
- ✅ **Virtualisierungs-Aware** - Erkennt VM/Host-Umgebung und gibt spezifische Empfehlungen
- 📊 **Klare Tabellendarstellung** - Professionell formatierte Ausgabe mit visuellen Statusindikatoren
- ⚙️ **Automatisierte Konfiguration** - Ein-Klick-Anwendung von Sicherheitseinstellungen mit `-Apply`
- 📈 **Detailliertes Reporting** - Export der Ergebnisse als CSV für Dokumentation
- 🎯 **Sicherer Betrieb** - Standardmäßig nur lesend, modifiziert System nur auf explizite Anfrage
- 🖥️ **Systeminformationen** - Zeigt CPU- und OS-Details relevant für Vulnerabilities
- 🔄 **VBS/HVCI-Support** - Prüfung virtualisierungsbasierter Sicherheitsfeatures

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

## 🛡️ Überprüfte Sicherheitsmaßnahmen

| Schutzmaßnahme | Beschreibung | Registry-Pfad | Auswirkung |
|----------------|--------------|---------------|------------|
| **Speculative Store Bypass Disable (SSBD)** | Schutz vor Spectre Variante 4 | `HKLM:\SYSTEM\...\Memory Management` | Minimal |
| **Branch Target Injection (BTI)** | Schutz vor Spectre Variante 2 | `HKLM:\SYSTEM\...\kernel` | Niedrig-Mittel |
| **Kernel VA Shadow (KVAS)** | Meltdown-Schutz | `HKLM:\SYSTEM\...\Memory Management` | Mittel |
| **Enhanced IBRS** | Intel Hardware-Mitigation | `HKLM:\SYSTEM\...\Memory Management` | Niedrig |
| **Intel TSX Disable** | Verhindert TSX-basierte Angriffe | `HKLM:\SYSTEM\...\kernel` | Anwendungsabhängig |
| **Hardware Mitigations** | CPU-Level-Schutz | `HKLM:\SYSTEM\...\kernel` | Hardware-abhängig |
| **VBS (Virtualization Based Security)** | Hardware-basierte Sicherheit | `HKLM:\SYSTEM\...\DeviceGuard` | Erfordert UEFI/TPM |
| **HVCI (Hypervisor Code Integrity)** | Hypervisor-geschützte Code-Integrität | `HKLM:\SYSTEM\...\HypervisorEnforcedCodeIntegrity` | Treiber-Kompatibilität |
| **Credential Guard** | Schutz vor Credential-Diebstahl | `HKLM:\SYSTEM\...\Lsa` | VBS erforderlich |

## 🖥️ Virtualisierungs-spezifische Prüfungen

### Für VM-Gäste:
- **SLAT-Support-Prüfung** - Überprüfung der Second Level Address Translation
- **VM-Tools-Sicherheit** - Hypervisor-spezifische Sicherheitsfeatures
- **Guest-Integration** - Sicherheitsrelevante Integrationsservices

### Für Hypervisor-Hosts:
- **Hyper-V Core Scheduler** - SMT-bewusste Scheduler für VM-Isolation
- **Nested Virtualization** - Sicherheitsüberlegungen für verschachtelte VMs
- **VM-Isolations-Richtlinien** - Konfiguration für sichere Multi-Tenant-Umgebungen

## 🔧 Virtualisierungs-Voraussetzungen

### Hardware-Anforderungen:
- **Intel**: VT-x mit EPT, VT-d **oder** **AMD**: AMD-V mit RVI, AMD-Vi
- **IOMMU-Support** für sichere DMA-Isolation
- **TPM 2.0** für VBS/Credential Guard
- **UEFI Secure Boot** Unterstützung

### Hypervisor-spezifische Anforderungen:

#### **Microsoft Hyper-V:**
- Windows Server 2019+ für Core Scheduler
- Generation 2 VMs für erweiterte Sicherheit
- VBS/HVCI auf Host aktiviert

#### **VMware vSphere:**
- ESXi 6.7 U2+ für Side-Channel Aware Scheduler
- VM Hardware Version 14+ 
- VMware Tools mit Sicherheits-Updates

#### **Linux KVM/QEMU:**
- Kernel 4.15+ mit spec-ctrl Unterstützung
- CPU-Flags: +spec-ctrl, +ibpb, +ssbd
- Intel EPT/AMD RVI aktiviert

## ⚠️ Wichtige Hinweise

### Vor der Ausführung von `-Apply`:
- **Registry sichern** oder Systemwiederherstellungspunkt erstellen
- **Zuerst in Nicht-Produktionsumgebung testen**
- **Anwendungskompatibilität prüfen** - einige Schutzmaßnahmen können die Leistung beeinträchtigen
- **Systemneustart einplanen** - Änderungen erfordern Neustart

### Virtualisierungs-spezifische Überlegungen:
- **Host-System zuerst absichern** vor Konfiguration der Gäste
- **Hypervisor-Updates** haben Priorität vor Guest-Konfiguration
- **Nested Virtualization** erhöht Angriffsfläche - vorsichtig verwenden
- **VM-Isolation** konfigurieren für Multi-Tenant-Umgebungen

### Leistungsüberlegungen:
- Die meisten Schutzmaßnahmen haben **minimale Leistungseinbußen** auf modernen CPUs
- **Intel TSX**-Deaktivierung kann Anwendungen mit Transactional Synchronization Extensions betreffen
- **Enhanced IBRS** erfordert ausreichend physischen Speicher
- **Hardware-Mitigationen** variieren je nach CPU-Generation
- **Core Scheduler** reduziert VM-Performance bei SMT-Systemen

## 🖥️ Virtualisierungs-spezifische Verwendung

### VM-Gast-System:
```powershell
# Grundlegende Überprüfung im VM-Gast
.\SideChannel_Check.ps1

# Detaillierte Informationen mit Host-Empfehlungen
.\SideChannel_Check.ps1 -Detailed

# Anwendung von Guest-spezifischen Mitigationen
.\SideChannel_Check.ps1 -Apply
```

### Hypervisor-Host:
```powershell
# Host-System-Analyse mit Virtualisierungs-Checks
.\SideChannel_Check.ps1 -Detailed

# Host-Konfiguration für sichere VM-Umgebung
.\SideChannel_Check.ps1 -Apply

# Export für Compliance-Dokumentation
.\SideChannel_Check.ps1 -ExportPath "C:\Reports\HostSecurityReport.csv"
```

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