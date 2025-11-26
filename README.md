# Side-Channel Vulnerability Mitigation Tool

Enterprise-grade PowerShell tool for assessing and managing Windows side-channel vulnerability mitigations (Spectre, Meltdown, L1TF, MDS, and related CVEs).

## 📦 Available Versions

### Version 2.1.0 (Latest - Recommended)
**Location:** [`v2/`](v2/)

Modern redesign with enhanced features:
- ✨ **Simplified Mode Structure** - 5 dedicated modes (Assess, ApplyInteractive, RevertInteractive, Backup, Restore)
- 🎯 **Selective Apply & Restore** - Choose [R]ecommended or [A]ll mitigations; restore [A]ll or [S]elective items
- 🛡️ **Comprehensive Coverage** - 24 mitigations + 5 hardware prerequisites
- 🔍 **Hardware Detection** - Automatic UEFI, Secure Boot, TPM 2.0, VT-x, IOMMU detection
- 📊 **Intelligent Scoring** - Visual security score bar (█░) with smart filtering
- 🎯 **WhatIf Support** - Preview all changes before applying
- 🔄 **Backup & Restore** - JSON-based configuration management with selective restoration
- 📋 **Interactive Modes** - User-friendly selection interface with detailed educational output
- 🖥️ **PS 5.1 & 7.x Compatible** - Runtime Unicode generation for cross-version support
- 🧪 **Automated Testing** - Comprehensive test suite included

**Quick Start:**
```powershell
cd v2
.\SideChannel_Check_v2.ps1
```

[📖 Full v2 Documentation](v2/README.md)

---

### Version 1.x (Legacy - Stable)
**Location:** [`v1/`](v1/)

Original production-tested version:
- ✅ Battle-tested in production environments
- ✅ Simple command-line interface
- ✅ Core side-channel mitigations
- ✅ Basic assessment and remediation

**Quick Start:**
```powershell
cd v1
.\SideChannel_Check.ps1
```

[📖 Full v1 Documentation](v1/README.md)

---

## 🚀 Which Version Should I Use?

| Scenario | Recommended Version |
|----------|-------------------|
| **New Deployments** | v2.1.0 - Modern features, better UX |
| **Production Environments** | v2.1.0 - Thoroughly tested, WhatIf support |
| **Testing/Preview** | v2.1.0 - Use `-WhatIf` for safe testing |
| **Legacy Compatibility** | v1.x - If you have existing v1 workflows |
| **Enterprise Rollout** | v2.1.0 - Automated testing, better logging |

---

## 📋 Feature Comparison

| Feature | v1.x | v2.1.0 |
|---------|------|--------|
| **Core Mitigations** | 19 | 24 |
| **Hardware Prerequisites** | ❌ | ✅ 5 checks |
| **Interactive Apply** | ❌ | ✅ [R]ecommended/[A]ll modes |
| **Selective Restore** | ❌ | ✅ [A]ll/[S]elect options |
| **WhatIf Preview** | ❌ | ✅ All modes |
| **Backup/Restore** | ❌ | ✅ JSON-based |
| **Detailed View** | ❌ | ✅ CVEs, Impact, Recommendations |
| **Automated Tests** | ❌ | ✅ Full suite |
| **Visual Security Score** | ❌ | ✅ Block characters (█░) |
| **Intelligent Filtering** | ❌ | ✅ Platform-aware |
| **Hardware-only Filtering** | ❌ | ✅ Auto-skips TPM/CPU/IOMMU |
| **Detailed Logging** | Basic | Advanced |
| **PowerShell Support** | 5.1 | 5.1 & 7.x optimized |
| **Unicode Rendering** | BOM-dependent | ✅ Runtime generation |

---

## 🔒 Security Features

Both versions assess and remediate:
- **Spectre** (CVE-2017-5715, CVE-2017-5753)
- **Meltdown** (CVE-2017-5754)
- **L1TF/Foreshadow** (CVE-2018-3620)
- **MDS/ZombieLoad** (CVE-2018-12130)
- **TAA** (CVE-2019-11135)
- **SBDR/SBDS** (CVE-2022-21123, CVE-2022-21125)
- **SRBDS** (CVE-2022-21127)
- **DRPW** (CVE-2022-21166)
- And more...

---

## 📥 Installation

```powershell
# Clone repository
git clone https://github.com/BetaHydri/side-channel-vulnerabilities-check.git
cd side-channel-vulnerabilities-check

# For v2 (recommended)
cd v2
.\SideChannel_Check_v2.ps1

# For v1 (legacy)
cd v1
.\SideChannel_Check.ps1
```

---

## ⚡ Quick Examples

### v2.1.0 - Modern Interface

```powershell
# Basic assessment
.\SideChannel_Check_v2.ps1

# Detailed educational view (CVEs, descriptions, impacts)
.\SideChannel_Check_v2.ps1 -ShowDetails

# Preview changes (safe - no modifications made)
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf

# Interactive apply with selective hardening
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive
# Choose [R]ecommended (quick) or [A]ll (selective after review)

# Create backup only
.\SideChannel_Check_v2.ps1 -Mode Backup

# Restore from backup with options
.\SideChannel_Check_v2.ps1 -Mode Restore
# Choose [A]ll (complete) or [S]elect (individual mitigations)

# Revert to most recent backup
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive

# Export to CSV
.\SideChannel_Check_v2.ps1 -ExportPath "report.csv"

# Run automated tests
.\Test-SideChannelTool.ps1
```

### v1.x - Classic Interface

```powershell
# Basic assessment
.\SideChannel_Check.ps1

# Apply mitigations
.\SideChannel_Check.ps1 -Apply

# Export results
.\SideChannel_Check.ps1 -ExportPath "report.csv"
```

---

## 📝 Requirements

- **PowerShell:** 5.1 or higher (v2 supports 7.x)
- **Privileges:** Administrator
- **Platform:** Windows 10/11, Windows Server 2016+
- **CPU:** Intel or AMD (platform-specific mitigations auto-detected)

---

## 🤝 Migration from v1 to v2

v2 is designed for easy migration:

1. **Export v1 state:** `.\SideChannel_Check.ps1 -ExportPath "v1_state.csv"`
2. **Run v2 assessment:** `.\SideChannel_Check_v2.ps1 -ExportPath "v2_state.csv"`
3. **Compare reports** and use v2's WhatIf mode to preview changes
4. **Apply incrementally** using v2's interactive mode

---

## 🐛 Support

- **Issues:** [GitHub Issues](https://github.com/BetaHydri/side-channel-vulnerabilities-check/issues)
- **Pull Requests:** Welcome!
- **Documentation:** See version-specific READMEs in `v1/` and `v2/` folders

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file

---

## 👤 Author

**Jan Tiedemann**
- GitHub: [@BetaHydri](https://github.com/BetaHydri)

---

**Current Versions:**
- v1.x: Stable (Legacy)
- v2.1.0: Latest (Recommended) - 2025-11-26
