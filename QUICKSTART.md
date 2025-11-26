# Quick Start Guide - v2.1.0

> **Note:** v2.1.0 is now the main version in the repository root. Legacy v1 has been archived to `archive/v1/`.

---

## 🚀 Getting Started

### Basic Assessment (Default)
```powershell
# Run from repository root
.\SideChannel_Check_v2.ps1
```

### Detailed Educational View
```powershell
# Show CVEs, descriptions, impacts, and recommendations
.\SideChannel_Check_v2.ps1 -ShowDetails
```

---

## 📋 Available Modes

### 1️⃣ **Assess** (Default)
Evaluate security posture without making changes.

```powershell
# Standard assessment
.\SideChannel_Check_v2.ps1

# With detailed educational output
.\SideChannel_Check_v2.ps1 -ShowDetails

# Export to CSV
.\SideChannel_Check_v2.ps1 -ExportPath "security_report.csv"
```

---

### 2️⃣ **ApplyInteractive**
Selectively apply mitigations with two view modes.

```powershell
# Preview changes first (RECOMMENDED)
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf

# Interactive application
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive
```

**Selection Modes:**
- **[R] Recommended** - Shows only actionable mitigations (quick hardening)
- **[A] All Mitigations** - Shows all 24+ mitigations (selective hardening after review)

**Recommended Workflow:**
1. `.\SideChannel_Check_v2.ps1 -ShowDetails` - Review CVEs and impacts
2. `.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive` - Choose [A] mode
3. Select specific mitigations based on your requirements

---

### 3️⃣ **RevertInteractive**
Revert to most recent backup quickly.

```powershell
# Preview revert
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive -WhatIf

# Revert to latest backup
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive
```

---

### 4️⃣ **Backup**
Create configuration backup manually.

```powershell
# Preview backup
.\SideChannel_Check_v2.ps1 -Mode Backup -WhatIf

# Create backup
.\SideChannel_Check_v2.ps1 -Mode Backup
```

**Note:** Backups are created automatically before ApplyInteractive mode.

---

### 5️⃣ **Restore**
Browse and restore from any available backup with selective options.

```powershell
# Interactive restore
.\SideChannel_Check_v2.ps1 -Mode Restore
```

**Restore Options:**
- **[A] All** - Restore complete backup (all settings)
- **[S] Select** - Choose individual mitigations to restore
- **[Q] Cancel** - Exit without changes

---

## 🔧 Common Workflows

### Quick Security Audit
```powershell
# Assess and export report
.\SideChannel_Check_v2.ps1 -ExportPath "audit_$(Get-Date -Format 'yyyyMMdd').csv"
```

### Safe Testing
```powershell
# Create backup first
.\SideChannel_Check_v2.ps1 -Mode Backup

# Apply with preview
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf

# Apply if satisfied
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive

# Revert if needed
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive
```

### Educational Review
```powershell
# Review all details with CVEs, impacts, recommendations
.\SideChannel_Check_v2.ps1 -ShowDetails

# Then apply selectively
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive
# Choose [A] for all mitigations view
```

### Run Automated Tests
```powershell
.\Test-SideChannelTool.ps1
```

---

## 📦 Legacy Version (Archived)

The original v1.x version is available in `archive/v1/` for reference:

```powershell
cd archive\v1
.\SideChannel_Check.ps1
```

**Note:** v1 is no longer actively maintained. Please use v2.1.0 for latest features and support.

---

## 💡 Key Features

- ✅ **5 Dedicated Modes** - Assess, ApplyInteractive, RevertInteractive, Backup, Restore
- ✅ **Selective Apply & Restore** - Choose [R]ecommended/[A]ll or [A]ll/[S]elect options
- ✅ **WhatIf Support** - Preview all changes before applying
- ✅ **Educational View** - CVEs, descriptions, impacts, recommendations
- ✅ **PowerShell 5.1 & 7.x** - Full compatibility with runtime Unicode generation
- ✅ **Hardware Detection** - UEFI, Secure Boot, TPM 2.0, VT-x, IOMMU
- ✅ **Intelligent Scoring** - Visual progress bar excludes N/A items

---

## ⚠️ Important Notes

- **Always run as Administrator** - Required for registry access
- **System restart required** - After applying mitigations
- **Use -WhatIf first** - Preview changes safely before applying
- **Backups are automatic** - Created before ApplyInteractive mode
- **Hardware-only items** - TPM, CPU Virtualization, IOMMU are auto-skipped in restore (firmware settings)

---

## 🆘 Need Help?

1. **Full Documentation:** [README.md](README.md)
2. **GitHub Issues:** https://github.com/BetaHydri/side-channel-vulnerabilities-check/issues
3. **Test Suite:** `.\Test-SideChannelTool.ps1`
4. **Parameter Help:** `Get-Help .\SideChannel_Check_v2.ps1 -Detailed`

---

## 📝 Parameter Reference

| Parameter | Values | Description |
|-----------|--------|-------------|
| `-Mode` | Assess, ApplyInteractive, RevertInteractive, Backup, Restore | Operation mode (default: Assess) |
| `-ShowDetails` | Switch | Show CVEs, descriptions, impacts, recommendations |
| `-WhatIf` | Switch | Preview changes without applying |
| `-ExportPath` | Path | Export assessment to CSV file |
| `-LogPath` | Path | Custom log file location |
