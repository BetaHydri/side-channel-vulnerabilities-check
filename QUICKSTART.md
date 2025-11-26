# Quick Start Guide

## 🚀 Choose Your Version

### For New Users (Recommended)
```powershell
cd v2
.\SideChannel_Check_v2.ps1
```

### For Legacy Users
```powershell
cd v1
.\SideChannel_Check.ps1
```

---

## 📋 Common Tasks

### v2.1.0 - Modern Version

**Check Your System:**
```powershell
cd v2
.\SideChannel_Check_v2.ps1
```

**Preview Changes (No Risk):**
```powershell
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf
```

**Apply Mitigations:**
```powershell
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive
```

**Create Backup:**
```powershell
.\SideChannel_Check_v2.ps1 -Mode Backup
```

**Restore from Backup:**
```powershell
.\SideChannel_Check_v2.ps1 -Mode Restore
```

**Export Report:**
```powershell
.\SideChannel_Check_v2.ps1 -ExportPath "report.csv"
```

**Run Tests:**
```powershell
.\Test-SideChannelTool.ps1
```

---

### v1.x - Classic Version

**Check Your System:**
```powershell
cd v1
.\SideChannel_Check.ps1
```

**Apply Mitigations:**
```powershell
.\SideChannel_Check.ps1 -Apply
```

**Export Report:**
```powershell
.\SideChannel_Check.ps1 -ExportPath "report.csv"
```

---

## 📖 Full Documentation

- **v2 Documentation:** [v2/README.md](v2/README.md)
- **v1 Documentation:** [v1/README.md](v1/README.md)
- **Main README:** [README.md](README.md)

---

## ⚠️ Important Notes

- **Always run as Administrator**
- **System restart required** after applying mitigations
- **Use `-WhatIf` in v2** to preview changes safely
- **Backups are automatic** in v2's ApplyInteractive mode

---

## 🆘 Need Help?

1. Read the version-specific README: `v1/README.md` or `v2/README.md`
2. Check GitHub Issues: https://github.com/BetaHydri/side-channel-vulnerabilities-check/issues
3. Use `-WhatIf` mode in v2 to understand what will change
