# Side-Channel Vulnerability Configuration Checker
*Konfigurationsprüfer für Side-Channel-Schwachstellen*

Ein umfassendes PowerShell-Tool zur Überprüfung und Konfiguration von Windows-Schutzmaßnahmen gegen Side-Channel-Vulnerabilities gemäß Microsoft-Sicherheitsleitlinien (KB4073119).

*A comprehensive PowerShell tool for checking and configuring Windows side-channel vulnerability mitigations according to Microsoft's security guidance (KB4073119).*

## 🔒 Überblick

Dieses Tool hilft Systemadministratoren bei der Bewertung und Konfiguration ihrer Windows-Systeme gegen CPU-basierte Side-Channel-Angriffe, einschließlich:

### Klassische Vulnerabilities:
- **Spectre** (Varianten 1, 2 und 4)
- **Meltdown** Angriffe
- **Intel TSX** Vulnerabilities
- **Branch Target Injection** (BTI)
- **Speculative Store Bypass** (SSB)

### Moderne CVEs (2018-2023):
- **L1TF** (L1 Terminal Fault) - CVE-2018-3620
- **BHB** (Branch History Buffer) - CVE-2022-0001/0002
- **GDS** (Gather Data Sample) - CVE-2022-40982
- **SRSO** (Speculative Return Stack Overflow) - CVE-2023-20569
- **RFDS** (Register File Data Sampling) - CVE-2023-28746
- **MDS** (Microarchitectural Data Sampling) mitigation

## 🖥️ Virtualisierungs-Support

**NEU**: Erweiterte Unterstützung für virtualisierte Umgebungen:

- ✅ **VM-Erkennung** - Automatische Identifikation von Host/Guest-Systemen
- ✅ **Hypervisor-spezifische Prüfungen** - Spezielle Checks für Hyper-V, VMware, KVM
- ✅ **Host-Empfehlungen** - Sicherheitshinweise für Virtualisierungs-Hosts
- ✅ **Guest-Empfehlungen** - VM-spezifische Sicherheitskonfiguration
- ✅ **Hardware-Voraussetzungen** - Detaillierte Anforderungen für sichere Virtualisierung

## 🚀 Features

- ✅ **Umfassende Sicherheitsbewertung** - Prüft 21+ kritische Sicherheitsmitigationen inkl. moderner CVEs (2018-2023)
- ✅ **Erweiterte CVE-Unterstützung** - Basiert auf Microsoft's SpeculationControl tool Analyse
- ✅ **Virtualisierungs-Aware** - Erkennt VM/Host-Umgebung und gibt spezifische Empfehlungen
- 🧠 **OS-Version-bewusst** - Automatische Anpassung an Windows-Version (Core Scheduler Detection)
- 🔍 **Hardware Mitigation Matrix** - **NEU**: Entschlüsselt MitigationOptions Registry-Werte im `-Detailed` Modus
- 📊 **Klare Tabellendarstellung** - Professionell formatierte Ausgabe mit visuellen Statusindikatoren
- ⚙️ **Automatisierte Konfiguration** - Ein-Klick-Anwendung von Sicherheitseinstellungen mit `-Apply`
- 🔬 **CPU-spezifische Validierung** - Intel vs AMD spezifische Mitigationsempfehlungen
- 📈 **Detailliertes Reporting** - Export der Ergebnisse als CSV für Dokumentation
- 🎯 **Sicherer Betrieb** - Standardmäßig nur lesend, modifiziert System nur auf explizite Anfrage
- 🖥️ **Systeminformationen** - Zeigt CPU- und OS-Details relevant für Vulnerabilities
- 🔄 **VBS/HVCI-Support** - Prüfung virtualisierungsbasierter Sicherheitsfeatures

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

## 🔄 Kompatibilität mit Microsoft Tools

Dieses Tool wurde **erweitert basierend auf Microsoft's offizieller SpeculationControl Modul Analyse**:

```powershell
# Für umfassende Bewertung beide Tools verwenden:
.\SideChannel_Check.ps1                    # Dieses erweiterte Enterprise-Tool
Install-Module SpeculationControl          # Microsoft's offizielle Bewertung
Get-SpeculationControlSettings             # Hardware-Level-Analyse
```

### Vergleich der Tools:
| Feature | Dieses Tool | Microsoft SpeculationControl |
|---------|-------------|------------------------------|
| **CVE-Abdeckung** | ✅ Vollständig (2017-2023) | ✅ Vollständig (2017-2023) |
| **Virtualisierung** | ✅ Umfassend | ❌ Keine |
| **Auto-Konfiguration** | ✅ `-Apply` Switch | ❌ Nur Bewertung |
| **Enterprise Features** | ✅ CSV Export, Tabellen | ⚠️ Basis-Text |
| **OS-Version-Bewusstsein** | ✅ Automatisch | ⚠️ Basis |
| **Hardware-Analyse** | ⚠️ Registry-basiert | ✅ Native APIs |

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

**NEU in Version 2.0**: Der `-Detailed` Modus enthält jetzt eine umfassende **Hardware Security Mitigation Value Matrix**, die die kryptischen MitigationOptions Registry-Werte entschlüsselt.

### Was die Matrix zeigt:
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

### Nutzen für Administratoren:
- **🔍 Hex-Werte entschlüsseln**: Verstehen Sie was `2305843009213694208` bedeutet
- **🛡️ Sicherheits-Audit**: Klare Übersicht über aktive Hardware-Mitigationen
- **📋 Compliance**: Einfache Überprüfung spezifischer Sicherheits-Flags
- **🔧 Troubleshooting**: Identifikation fehlender Sicherheitskonfigurationen
- **🎓 Bildung**: Lernen Sie die Windows-Sicherheitsarchitektur kennen

### Verfügbare Hardware-Mitigationen:
- **CFG** (Control Flow Guard) - ROP/JOP-Angriffsprävention
- **DEP** (Data Execution Prevention) - Code-Execution in Datenbereichen verhindern
- **ASLR** (Address Space Layout Randomization) - Speicher-Layout-Randomisierung
- **CET** (Intel Control-flow Enforcement Technology) - Hardware-assistierte CFI
- **Core Hardware Security Features** - Essentielle CPU-Sicherheitsmitigationen
- **25+ weitere Flags** - Vollständige Liste in der detaillierten Ausgabe

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

## 🛡️ Überprüfte Sicherheitsmaßnahmen

### Klassische Side-Channel Mitigationen:

| Schutzmaßnahme | Beschreibung | Registry-Pfad | Auswirkung |
|----------------|--------------|---------------|------------|
| **Speculative Store Bypass Disable (SSBD)** | Schutz vor Spectre Variante 4 | `HKLM:\SYSTEM\...\Memory Management` | Minimal |
| **Branch Target Injection (BTI)** | Schutz vor Spectre Variante 2 | `HKLM:\SYSTEM\...\kernel` | Niedrig-Mittel |
| **Kernel VA Shadow (KVAS)** | Meltdown-Schutz | `HKLM:\SYSTEM\...\Memory Management` | Mittel |
| **Enhanced IBRS** | Intel Hardware-Mitigation | `HKLM:\SYSTEM\...\Memory Management` | Niedrig |
| **Intel TSX Disable** | Verhindert TSX-basierte Angriffe | `HKLM:\SYSTEM\...\kernel` | Anwendungsabhängig |
| **Hardware Mitigations** | CPU-Level-Schutz | `HKLM:\SYSTEM\...\kernel` | Hardware-abhängig |

### Moderne CVE-Mitigationen (2018-2023):

| CVE | Mitigation | Ziel-CPUs | Beschreibung |
|-----|------------|-----------|-------------|
| **CVE-2018-3620** | L1TF Mitigation | Intel (Virtualisierung) | L1 Terminal Fault Schutz |
| **CVE-2022-0001/0002** | BHB Mitigation | Intel/AMD (Modern) | Branch History Buffer |
| **CVE-2022-40982** | GDS Mitigation | Intel (Server/Datacenter) | Gather Data Sample |
| **CVE-2023-20569** | SRSO Mitigation | AMD Zen | Speculative Return Stack Overflow |
| **CVE-2023-28746** | RFDS Mitigation | Intel (Modern) | Register File Data Sampling |
| **MDS** | MDS Mitigation | Intel (Affected) | Microarchitectural Data Sampling |

### Windows-Sicherheitsfeatures:

| Schutzmaßnahme | Beschreibung | Registry-Pfad | Auswirkung |
|----------------|--------------|---------------|------------|
| **VBS (Virtualization Based Security)** | Hardware-basierte Sicherheit | `HKLM:\SYSTEM\...\DeviceGuard` | Erfordert UEFI/TPM |
| **HVCI (Hypervisor Code Integrity)** | Hypervisor-geschützte Code-Integrität | `HKLM:\SYSTEM\...\HypervisorEnforcedCodeIntegrity` | Treiber-Kompatibilität |
| **Credential Guard** | Schutz vor Credential-Diebstahl | `HKLM:\SYSTEM\...\Lsa` | VBS erforderlich |
| **Windows Defender ASLR** | Address Space Layout Randomization | Windows Defender Exploit Guard | Anwendungskompatibilität |

## 🖥️ Virtualisierungs-spezifische Prüfungen

### Für VM-Gäste:
- **SLAT-Support-Prüfung** - Überprüfung der Second Level Address Translation
- **VM-Tools-Sicherheit** - Hypervisor-spezifische Sicherheitsfeatures
- **Guest-Integration** - Sicherheitsrelevante Integrationsservices

### Für Hypervisor-Hosts:
- **Hyper-V Core Scheduler** - OS-version-bewusste SMT-Scheduler-Konfiguration
  - **Windows 10/Server 2016/2019**: Manuelle Aktivierung erforderlich
  - **Windows 11/Server 2022+**: Automatisch aktiviert (Build 20348+)
- **Nested Virtualization** - Sicherheitsüberlegungen für verschachtelte VMs
- **VM-Isolations-Richtlinien** - Konfiguration für sichere Multi-Tenant-Umgebungen
- **Modern CVE Support** - CPU-spezifische Mitigation basierend auf Hersteller

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
- **CPU-Mikrocode aktualisieren** - Moderne CVE-Mitigationen erfordern aktuelle Microcode
- **Systemneustart einplanen** - Änderungen erfordern Neustart

### Moderne CVE-Mitigationen (2018-2023):
- **CPU-spezifische Validierung** - Intel vs AMD spezifische Mitigationen
- **Mikrocode-Abhängigkeiten** - BHB, GDS, SRSO, RFDS erfordern aktuelle CPU-Mikrocode
- **Hersteller-spezifisch** - SRSO nur für AMD, GDS/RFDS primär Intel
- **Leistungsanalyse** - Moderne Mitigationen haben variable Performance-Auswirkungen

### OS-Version-spezifische Überlegungen:
- **Core Scheduler** - Automatisch in Windows 11/Server 2022+ (Build 20348+)
- **Legacy-Support** - Windows 10/Server 2016/2019 benötigen manuelle Konfiguration
- **Build-Erkennung** - Tool erkennt automatisch erforderliche vs. bereits aktive Features

### Virtualisierungs-spezifische Überlegungen:
- **Host-System zuerst absichern** vor Konfiguration der Gäste
- **Hypervisor-Updates** haben Priorität vor Guest-Konfiguration
- **Nested Virtualization** erhöht Angriffsfläche - vorsichtig verwenden
- **VM-Isolation** konfigurieren für Multi-Tenant-Umgebungen

### Leistungsüberlegungen:
- Die meisten klassischen Schutzmaßnahmen haben **minimale Leistungseinbußen** auf modernen CPUs
- **Moderne CVE-Mitigationen** können höhere Performance-Auswirkungen haben
- **Intel TSX**-Deaktivierung kann Anwendungen mit Transactional Synchronization Extensions betreffen
- **Enhanced IBRS** erfordert ausreichend physischen Speicher
- **Hardware-Mitigationen** variieren je nach CPU-Generation
- **L1TF-Mitigationen** haben signifikante Auswirkungen in virtualisierten Umgebungen

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

## 🔍 Problembehandlung

### Häufige Probleme:

**"Zugriff verweigert" Fehler:**
- Stellen Sie sicher, dass PowerShell als Administrator läuft
- Prüfen Sie, ob Windows Defender oder Sicherheitssoftware Registry-Zugriff blockiert

**"Registry-Pfad nicht gefunden" Fehler:**
- Einige Pfade existieren möglicherweise nicht in allen Windows-Versionen
- Das Skript erstellt fehlende Registry-Pfade bei Verwendung von `-Apply`

**Leistungseinbußen nach Anwendung:**
- Überprüfen Sie, welche Schutzmaßnahmen angewendet wurden
- Erwägen Sie die Deaktivierung spezifischer Mitigationen bei Anwendungsproblemen
- Konsultieren Sie die Anwendungsherstellerdokumentation für Kompatibilität

**Virtualisierungs-spezifische Probleme:**
- VM-Gäste: Stellen Sie sicher, dass Host-System aktuell ist
- Hypervisor-Hosts: Prüfen Sie Hardware-Virtualisierungsunterstützung
- Nested VMs: Überprüfen Sie ExposeVirtualizationExtensions-Einstellungen

### Änderungen rückgängig machen:
Um spezifische Schutzmaßnahmen manuell zurückzusetzen, löschen Sie die Registry-Werte oder setzen Sie sie auf ihre ursprünglichen Werte. Testen Sie immer in kontrollierter Umgebung.

## 📚 Referenzen

### Offizielle Microsoft-Dokumentation:
- [Microsoft KB4073119](https://support.microsoft.com/en-us/topic/kb4073119-windows-client-guidance-for-it-pros-to-protect-against-silicon-based-microarchitectural-and-speculative-execution-side-channel-vulnerabilities-35820a8a-ae13-1299-88cc-357f104f5b11) - Offizielle Microsoft-Anleitung
- [Microsoft SpeculationControl PowerShell Module](https://www.powershellgallery.com/packages/SpeculationControl) - Offizielles Microsoft Assessment Tool
- [Microsoft VBS Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/introduction-to-device-guard-virtualization-based-security-and-windows-defender-application-control) - Virtualization Based Security
- [Hyper-V Security Guide](https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/hyper-v-security) - Hyper-V Sicherheitsleitfaden

### Klassische CVE-Referenzen:
- [CVE-2017-5753](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5753) - Spectre Variante 1
- [CVE-2017-5715](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5715) - Spectre Variante 2  
- [CVE-2017-5754](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5754) - Meltdown
- [CVE-2018-3639](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3639) - Speculative Store Bypass

### Moderne CVE-Referenzen (2018-2023):
- [CVE-2018-3620](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3620) - L1 Terminal Fault (L1TF)
- [CVE-2022-0001](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0001) - Branch History Buffer (BHB) - Variant 1
- [CVE-2022-0002](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0002) - Branch History Buffer (BHB) - Variant 2
- [CVE-2022-40982](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40982) - Gather Data Sample (GDS)
- [CVE-2023-20569](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20569) - Speculative Return Stack Overflow (SRSO)
- [CVE-2023-28746](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28746) - Register File Data Sampling (RFDS)

## 🆘 Support

Bei Problemen oder Fragen:

1. Prüfen Sie den [Troubleshooting](#-troubleshooting) Abschnitt
2. Konsultieren Sie die offizielle Microsoft-Dokumentation
3. Erstellen Sie ein Issue im Repository
4. Wenden Sie sich an Ihr Sicherheitsteam

## ⚖️ Haftungsausschluss

Dieses Tool wird "wie besehen" ohne Gewährleistung bereitgestellt. Immer:
- Zuerst in Nicht-Produktionsumgebungen testen
- Rollback-Plan haben
- Sicherheitsrichtlinien konsultieren
- Auswirkungen jeder Schutzmaßnahme verstehen

Die Autoren sind nicht verantwortlich für Systemprobleme, die durch die Verwendung dieses Tools entstehen können.

---

## 👤 Autor

**Jan Tiedemann**  
IT Security Specialist & PowerShell Developer

- 🔧 Spezialisiert auf Windows-Sicherheit und Virtualisierung
- 💼 Fokus auf Side-Channel-Vulnerability-Mitigationen
- 🛡️ Enterprise Security Consulting

## 🤝 Mitwirken

Beiträge sind willkommen! Bitte:

1. Repository forken
2. Feature-Branch erstellen
3. Änderungen vornehmen
4. Tests hinzufügen falls zutreffend
5. Pull Request einreichen

### Bereiche für Beiträge:
- Zusätzliche Sicherheitsprüfungen
- Support für ältere Windows-Versionen
- Leistungsanalysen
- Integration mit anderen Sicherheitstools
- Hypervisor-spezifische Erweiterungen

---

---

**Version:** 2.1  
**Letztes Update:** November 2025  
**PowerShell Compatibility:** 5.1+ (Fully Compatible)  
**CVE-Abdeckung:** 2017-2023 (Vollständig kompatibel mit Microsoft SpeculationControl 1.0.19)  
**Kompatibilität:** Windows 10/11, Windows Server 2016+  
**Repository:** [GitHub - BetaHydri/side-channel-vulnerabilities-check](https://github.com/BetaHydri/side-channel-vulnerabilities-check)