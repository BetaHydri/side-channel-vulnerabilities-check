# Quick Start Guide - v2.1.1

> **Note:** v2.1.1 is now the main version in the repository root. Legacy v1 has been archived to `archive/v1/`.

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
- **[A] All Mitigations** - Shows all 30+ mitigations (selective hardening after review)

**Recommended Workflow:**
1. `.\SideChannel_Check_v2.ps1 -ShowDetails` - Review CVEs and impacts
2. `.\SideChannel_Check_v2.ps1 -Mode Backup` - Create manual backup (recommended before remediation)
3. `.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive` - Choose [A] mode
4. Select specific mitigations based on your requirements
5. Restart system to activate changes
6. If needed, restore: `.\SideChannel_Check_v2.ps1 -Mode RevertInteractive` or `-Mode Restore`
6. If needed, restore: `.\SideChannel_Check_v2.ps1 -Mode RevertInteractive` or `-Mode Restore`

---

### 3️⃣ **RevertInteractive**
**Quick undo:** Instantly revert to your most recent backup.

```powershell
# Preview revert
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive -WhatIf

# Revert to latest backup
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive
```

**When to use:**
- ✅ You just applied changes and want to undo them quickly
- ✅ System is unstable after applying mitigations
- ✅ Simple one-step rollback to last known good state

**What it does:** Automatically finds and restores your most recent backup (complete restore only).

---

### 4️⃣ **Backup**
**Manual snapshot:** Create a backup before making changes or for safekeeping.

```powershell
# Preview backup
.\SideChannel_Check_v2.ps1 -Mode Backup -WhatIf

# Create backup
.\SideChannel_Check_v2.ps1 -Mode Backup
```

**When to use:**
- ✅ Before testing changes in production
- ✅ Creating a checkpoint before major configuration updates
- ✅ Scheduled backups for compliance/audit purposes

**Note:** ApplyInteractive mode **automatically creates a backup** before applying changes, so manual backup is optional in that workflow.

---

### 5️⃣ **Restore**
**Advanced recovery:** Browse all backups and choose what to restore (selective or complete).

```powershell
# Interactive restore
.\SideChannel_Check_v2.ps1 -Mode Restore
```

**When to use:**
- ✅ Need to restore from an older backup (not just the latest)
- ✅ Want to restore only specific mitigations, not everything
- ✅ Comparing multiple backups before deciding which to restore
- ✅ Recovering from older configuration states

**Restore Options:**
- **[A] All** - Restore complete backup (all settings)
- **[S] Select** - Choose individual mitigations to restore (granular recovery)
- **[Q] Cancel** - Exit without changes

**Difference from RevertInteractive:**
- **RevertInteractive** = Quick undo to latest backup (one command, no choices)
- **Restore** = Browse all backups, choose which one, choose what to restore (flexible)

---

## 🔄 Mode Comparison Quick Reference

| Mode | Purpose | Backup Selection | Restore Options | Use Case |
|------|---------|------------------|-----------------|----------|
| **RevertInteractive** | Quick undo | Latest only (automatic) | Complete only | "Oops, undo that!" |
| **Restore** | Advanced recovery | Choose any backup | Complete or Selective | "I need that setting from 3 days ago" |
| **Backup** | Create snapshot | N/A | N/A | "Checkpoint before changes" |
| **ApplyInteractive** | Apply mitigations | Auto-creates backup | N/A | "Harden my system" |

**Decision Tree:**
- Need to **undo recent changes**? → Use **RevertInteractive** (fastest)
- Need **older backup** or **specific settings**? → Use **Restore** (flexible)
- About to **test something risky**? → Use **Backup** first (safety net)
- Want to **harden system**? → Use **ApplyInteractive** (auto-backup included)

---

## 🔧 Common Workflows

### Quick Security Audit
```powershell
# Assess and export report
.\SideChannel_Check_v2.ps1 -ExportPath "audit_$(Get-Date -Format 'yyyyMMdd').csv"
```

### Safe Hardening (Recommended)
```powershell
# Step 1: Review what needs fixing
.\SideChannel_Check_v2.ps1 -ShowDetails

# Step 2: Preview what will change
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf

# Step 3: Apply changes (automatic backup created)
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive

# Step 4 (if problems): Quick undo
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive
```

### Manual Backup Before Changes
```powershell
# Optional: Create named checkpoint first
.\SideChannel_Check_v2.ps1 -Mode Backup

# Apply changes (creates another backup automatically)
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive

# If needed: Restore from specific backup
.\SideChannel_Check_v2.ps1 -Mode Restore
```

### Selective Recovery
```powershell
# Browse all backups and restore only specific mitigations
.\SideChannel_Check_v2.ps1 -Mode Restore
# Choose backup, then select [S] for selective restore
```

### Educational Review
```powershell
# Review all details with CVEs, impacts, recommendations
.\SideChannel_Check_v2.ps1 -ShowDetails

# Then apply selectively
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive
# Choose [A] for all mitigations view
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
- ✅ **Enhanced Runtime Status Guide** - 5 comprehensive states (Active, Inactive, Not Needed, Supported, N/A)
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
3. **Parameter Help:** `Get-Help .\SideChannel_Check_v2.ps1 -Detailed`

---

## 📝 Parameter Reference

| Parameter | Values | Description |
|-----------|--------|-------------|
| `-Mode` | Assess, ApplyInteractive, RevertInteractive, Backup, Restore | Operation mode (default: Assess) |
| `-ShowDetails` | Switch | Show CVEs, descriptions, impacts, recommendations |
| `-WhatIf` | Switch | Preview changes without applying |
| `-ExportPath` | Path | **Export assessment results** to CSV (mitigation status table) |
| `-LogPath` | Path | Optional: Custom execution log location (default: `.\Logs\`) |

**CSV Export vs Log File:**
- **`-ExportPath`** → Your security assessment data (CSV table for reporting/analysis)
- **`-LogPath`** → Execution log (troubleshooting/audit trail of what the script did)
- For most users, only `-ExportPath` is needed
