# Side-Channel Vulnerability Mitigation Tool v2.1.0

Enterprise-grade PowerShell tool for assessing and managing Windows side-channel vulnerability mitigations (Spectre, Meltdown, L1TF, MDS, and related CVEs) with comprehensive hardware detection and intelligent scoring.

## 🎯 What's New in v2.1.0

### Major Enhancements
- **✨ Simplified Mode Structure** - Dedicated modes replace parameter combinations
- **🛡️ Comprehensive Coverage** - 24 mitigations (100% parity with v1)
- **🔍 Hardware Detection** - Automatic detection of UEFI, Secure Boot, TPM 2.0, VT-x, IOMMU
- **📊 Intelligent Scoring** - Excludes prerequisites and N/A items from security score
- **💾 Advanced Backup System** - Dedicated Backup and Restore modes
- **👁️ WhatIf Support** - Preview all changes before applying
- **🎨 Visual Progress Bar** - Color-coded security score visualization
- **🖥️ Platform-Aware** - Automatically adapts to Physical/Hyper-V/VMware environments

### Version Comparison

| Feature | v1 (Legacy) | v2.1.0 (Current) |
|---------|-------------|------------------|
| Mitigations Covered | 28 checks | 24 checks (streamlined) |
| Architecture | Monolithic | Modular functions |
| Hardware Detection | Basic | Comprehensive (5 prerequisites) |
| Scoring | All-inclusive | Intelligent (excludes N/A) |
| Modes | Assess/Apply/Revert | 5 dedicated modes |
| Backup System | Auto-backup only | Dedicated management |
| WhatIf Support | ❌ No | ✅ Yes |
| PowerShell Support | 5.1+ | 5.1 & 7.x |

## 🚀 Quick Start

### Prerequisites
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or higher
- Administrator privileges
- Execution policy allowing script execution

```powershell
# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Basic Usage

```powershell
# 1. Assessment (default mode)
.\SideChannel_Check_v2.ps1

# 2. Apply mitigations interactively
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive

# 3. Preview changes first (recommended)
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf

# 4. Revert to most recent backup
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive

# 5. Restore from specific backup
.\SideChannel_Check_v2.ps1 -Mode Restore
```

## 📋 Available Modes

### 1. **Assess** (Default)
Evaluate current security posture without making changes.

```powershell
# Standard assessment
.\SideChannel_Check_v2.ps1

# With detailed output
.\SideChannel_Check_v2.ps1 -ShowDetails

# Export results
.\SideChannel_Check_v2.ps1 -ExportPath "security_assessment.csv"
```

**Output:**
- Platform Information (CPU, OS, Hypervisor status)
- Hardware Prerequisites Status (5 checks)
- Security Mitigations Status (19 mitigations)
- Visual Security Score Bar
- Categorized Recommendations

### 2. **ApplyInteractive**
Interactively select and apply security mitigations.

```powershell
# Interactive application
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive

# Preview changes first (recommended)
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf
```

**Features:**
- ✅ Automatic backup creation before changes
- ✅ Interactive selection (individual, ranges, or all)
- ✅ WhatIf preview support
- ✅ Impact warnings
- ✅ System restart notification

**Selection Syntax:**
- `1,3,5` - Apply specific mitigations
- `1-4` - Apply range of mitigations
- `all` - Apply all recommended
- `critical` - Apply only critical mitigations

### 3. **RevertInteractive**
Restore most recent backup configuration.

```powershell
# Revert to last backup
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive

# Preview revert operation
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive -WhatIf
```

**Features:**
- ✅ Shows backup metadata (timestamp, computer, user)
- ✅ Confirmation prompt before reverting
- ✅ WhatIf preview of changes
- ✅ Detailed restore summary

### 4. **Backup**
Create a backup of current mitigation settings.

```powershell
# Create backup
.\SideChannel_Check_v2.ps1 -Mode Backup

# Preview backup operation
.\SideChannel_Check_v2.ps1 -Mode Backup -WhatIf
```

**Backup Contents:**
- Timestamp (ISO 8601 format)
- Computer name
- User name
- All mitigation registry values (24 settings)

**Backup Location:** `.\Backups\Backup_YYYYMMDD_HHMMSS.json`

### 5. **Restore**
Browse and restore from any available backup.

```powershell
# Interactive restore
.\SideChannel_Check_v2.ps1 -Mode Restore
```

**Features:**
- ✅ Lists all available backups with age
- ✅ Shows backup metadata (computer, user, timestamp)
- ✅ Interactive selection
- ✅ Detailed restore preview

---

## 🔍 Comprehensive Assessment Output

### Sample Output - v2.1.0

```
================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.0
================================================================================

--- Platform Information ---
Type:        HyperVHost
CPU:         11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
OS:          Microsoft Windows 11 Enterprise (Build 26200)

--- Security Assessment Summary ---
Total Mitigations Evaluated:  19
Protected:                    19 (100.0%)

Security Score: [========================================] 100%
Security Level: Excellent

--- Hardware Prerequisites ---
Prerequisites Enabled: 5 / 5

--- Mitigation Status ---
Mitigation                                    Status               Action Needed             Impact
--------------------------------------------  -------------------  ------------------------  ---------
Speculative Store Bypass Disable             Protected            No                        Low
SSBD Feature Mask                            Protected            No                        Low
Branch Target Injection Mitigation           Protected            No                        Low
Kernel VA Shadow (Meltdown Protection)       Protected            No                        Medium
Enhanced IBRS                                Protected            No                        Low
Intel TSX Disable                            Protected            No                        Low
L1 Terminal Fault Mitigation                 Not Applicable       No                        High
MDS Mitigation (ZombieLoad)                  Protected            No                        Medium
TSX Asynchronous Abort Mitigation            Protected            No                        Medium
Hardware Security Mitigations                Protected            No                        Low
SBDR/SBDS Mitigation                         Protected            No                        Low
SRBDS Update Mitigation                      Protected            No                        Low
DRPW Mitigation                              Protected            No                        Low
Exception Chain Validation                   Protected            No                        Low
Supervisor Mode Access Prevention            Protected            No                        Low
Virtualization Based Security                Not Applicable       No                        Low
Hypervisor-protected Code Integrity          Not Applicable       No                        Low
Credential Guard                             Not Applicable       No                        Low
Hyper-V Core Scheduler                       Protected            No                        Medium

✓ All critical mitigations are properly configured!
```

### Detailed Status Explanation

**Mitigation Status Values:**
- **Protected** - Mitigation is properly configured and active
- **Vulnerable** - Mitigation is not configured or disabled
- **Not Applicable** - Hardware doesn't support this mitigation
- **Unknown** - Status cannot be determined

**Prerequisite Status Values:**
- **Protected** - Feature is enabled and active (Secure Boot, TPM, VT-x, IOMMU)
- **Active** - Feature is present and working (UEFI)
- **Vulnerable** - Feature is supported but not enabled (e.g., Secure Boot capable but disabled)
- **Missing** - Feature is not available on this hardware

### Sample Output - ApplyInteractive Mode

```
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive

=== Interactive Mitigation Application ===
Select mitigations to apply (or 'all' for recommended, 'critical' for critical only)

[1] L1 Terminal Fault Mitigation
    High performance impact; primarily for multi-tenant virtualization environments
    Impact: High | CVE: CVE-2018-3620

[2] MDS Mitigation (ZombieLoad)
    Protects against MDS attacks
    Impact: Medium | CVE: CVE-2018-12130

Enter selections (e.g., '1,2,5' or '1-3' or 'all' or 'critical'): 2

You have selected 1 mitigation(s):
  • MDS Mitigation (ZombieLoad)

A backup will be created before applying changes.
Do you want to proceed? (Y/N): Y

[INFO] Creating configuration backup...
[SUCCESS] Backup created: C:\...\Backups\Backup_20251126_153045.json

Applying mitigations...
[INFO] Applying: MDS Mitigation (ZombieLoad)
[SUCCESS] Applied: MDS Mitigation (ZombieLoad)

=== Summary ===
Successfully applied: 1
Backup saved: C:\...\Backups\Backup_20251126_153045.json

⚠ A system restart is required for changes to take effect.
```

### Sample Output - WhatIf Mode

```
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf

=== Interactive Mitigation Application ===
[WhatIf Mode] Changes will be previewed but not applied

Select mitigations to apply (or 'all' for recommended, 'critical' for critical only)

[1] MDS Mitigation (ZombieLoad)
    Protects against MDS attacks
    Impact: Medium | CVE: CVE-2018-12130

Enter selections (e.g., '1,2,5' or '1-3' or 'all' or 'critical'): 1

You have selected 1 mitigation(s):
  • MDS Mitigation (ZombieLoad)

=== WhatIf: Changes Preview ===
The following changes would be made:

[MDS] MDS Mitigation (ZombieLoad)
  Registry Path: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel
  Registry Name: MDSMitigationLevel
  New Value: 1
  Impact: Medium

WhatIf Summary:
Total changes that would be made: 1
Backup would be created: Yes
System restart would be required: Yes
```

### Sample Output - Backup Mode

```
.\SideChannel_Check_v2.ps1 -Mode Backup

================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.0
================================================================================

--- Platform Information ---
Type:        HyperVHost
CPU:         11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
OS:          Microsoft Windows 11 Enterprise (Build 26200)

[INFO] Creating configuration backup...
[SUCCESS] Backup created: C:\...\Backups\Backup_20251126_153622.json

Backup Details:
  Computer: WORKSTATION01
  User: Administrator
  Timestamp: 2025-11-26T15:36:22
  Mitigations: 19 settings backed up
```

### Sample Output - Restore Mode

```
.\SideChannel_Check_v2.ps1 -Mode Restore

================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.0
================================================================================

--- Platform Information ---
Type:        HyperVHost
CPU:         11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
OS:          Microsoft Windows 11 Enterprise (Build 26200)

=== Available Backups ===

[1] Backup_20251126_153622.json
    Computer: WORKSTATION01
    User: Administrator
    Created: 2025-11-26 15:36:22 (5m ago)
    Mitigations: 19

[2] Backup_20251126_143022.json
    Computer: WORKSTATION01
    User: Administrator
    Created: 2025-11-26 14:30:22 (1h ago)
    Mitigations: 19

Enter backup number to restore (or 'q' to quit): 1

=== Restore Preview ===
This will restore configuration from: 2025-11-26 15:36:22

Changes that will be made:
  [+] Restore: SSBD - Value: 72
  [+] Restore: SSBD Mask - Value: 3
  [+] Restore: BTI - Value: 0
  ... (16 more changes)

Total changes: 19
System restart required: Yes

Do you want to proceed? (Y/N): Y

[INFO] Restoring configuration from 2025-11-26T15:36:22...
[INFO] Restored: Speculative Store Bypass Disable
[INFO] Restored: SSBD Feature Mask
... (17 more)

=== Restore Summary ===
Successfully restored: 19

⚠ A system restart is required for changes to take effect.
```

### Sample Output - RevertInteractive Mode

```
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive

================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.0
================================================================================

--- Platform Information ---
Type:        HyperVHost
CPU:         11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
OS:          Microsoft Windows 11 Enterprise (Build 26200)

=== Configuration Revert (Most Recent Backup) ===

Latest backup found:
  File: Backup_20251126_153622.json
  Created: 2025-11-26 15:36:22 (8m ago)
  Computer: WORKSTATION01
  User: Administrator
  Mitigations: 19

This will restore all mitigation settings to their state at backup time.

Do you want to proceed? (Y/N): Y

[INFO] Restoring configuration from 2025-11-26T15:36:22...
[SUCCESS] Restored: Speculative Store Bypass Disable
[SUCCESS] Restored: SSBD Feature Mask
... (17 more)

=== Restore Summary ===
Successfully restored: 19

⚠ A system restart is required for changes to take effect.
```

### Sample Output - CSV Export

```
.\SideChannel_Check_v2.ps1 -ExportPath "security_assessment.csv"

================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.0
================================================================================

[Assessment runs normally...]

✓ Assessment exported successfully to: security_assessment.csv
```

**CSV Content Preview:**
```csv
Id,Name,CVE,Category,RegistryStatus,RuntimeStatus,OverallStatus,ActionNeeded,Impact,Description,Recommendation
SSBD,"Speculative Store Bypass Disable",CVE-2018-3639,Critical,Enabled,Active,Protected,No,Low,"Prevents Speculative Store Bypass attacks","Enable to protect against speculative execution vulnerabilities"
KVAS,"Kernel VA Shadow (Meltdown Protection)",CVE-2017-5754,Critical,Enabled,Active,Protected,No,Medium,"Page table isolation to prevent Meltdown attacks","Critical for Meltdown protection; modern CPUs have hardware immunity"
...
```

---

## 🛡️ Mitigation Coverage

### Critical Mitigations (6)
- **SSBD** (Speculative Store Bypass Disable) - CVE-2018-3639
- **SSBD Mask** (Required companion setting)
- **BTI** (Branch Target Injection) - CVE-2017-5715 (Spectre v2)
- **KVAS** (Kernel VA Shadow) - CVE-2017-5754 (Meltdown)
- **Enhanced IBRS** - Hardware Spectre v2 protection
- **Hardware Security Mitigations** - Core CPU protections

### Recommended Mitigations (8)
- **TSX Disable** - Prevents TAA vulnerabilities
- **MDS** (Microarchitectural Data Sampling) - CVE-2018-12130
- **TAA** (TSX Asynchronous Abort) - CVE-2019-11135
- **SBDR/SBDS** - CVE-2022-21123, CVE-2022-21125
- **SRBDS** - CVE-2022-21127
- **DRPW** - CVE-2022-21166
- **Exception Chain Validation** - SEH protection
- **SMAP** (Supervisor Mode Access Prevention)

### Optional Mitigations (5)
- **L1TF** (L1 Terminal Fault) - High performance impact
- **VBS** (Virtualization Based Security) - Requires hardware
- **HVCI** (Hypervisor-protected Code Integrity) - Requires VBS
- **Credential Guard** - Requires VBS + TPM
- **Hyper-V Core Scheduler** - For Hyper-V hosts

### Hardware Prerequisites (5)
- **UEFI Firmware** - Required for modern security
- **Secure Boot** - Boot integrity protection
- **TPM 2.0** - Hardware cryptographic security
- **CPU Virtualization (VT-x/AMD-V)** - For Hyper-V and VBS
- **IOMMU/VT-d** - DMA protection and HVCI optimization

---

## 🧪 Testing & Validation

### Automated Test Script

Save as `Test-SideChannelTool.ps1`:

```powershell
#Requires -RunAsAdministrator

Write-Host "=== Side-Channel Tool v2 Test Suite ===" -ForegroundColor Cyan

# Test 1: Basic Assessment
Write-Host "`n[Test 1] Basic Assessment..." -ForegroundColor Yellow
try {
    $result = & ".\SideChannel_Check_v2.ps1" 2>&1
    Write-Host "✅ PASS: Assessment completed" -ForegroundColor Green
} catch {
    Write-Host "❌ FAIL: Assessment failed - $_" -ForegroundColor Red
}

# Test 2: WhatIf Mode
Write-Host "`n[Test 2] WhatIf Mode..." -ForegroundColor Yellow
try {
    $result = & ".\SideChannel_Check_v2.ps1" -Mode ApplyInteractive -WhatIf 2>&1
    if ($result -match "WhatIf") {
        Write-Host "✅ PASS: WhatIf mode working" -ForegroundColor Green
    } else {
        Write-Host "⚠️  WARN: WhatIf indicator not found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ FAIL: WhatIf test failed - $_" -ForegroundColor Red
}

# Test 3: Backup Creation
Write-Host "`n[Test 3] Backup Creation..." -ForegroundColor Yellow
try {
    $backupsBefore = @(Get-ChildItem ".\Backups\Backup_*.json" -ErrorAction SilentlyContinue).Count
    & ".\SideChannel_Check_v2.ps1" -Mode Backup | Out-Null
    $backupsAfter = @(Get-ChildItem ".\Backups\Backup_*.json" -ErrorAction SilentlyContinue).Count
    
    if ($backupsAfter -gt $backupsBefore) {
        Write-Host "✅ PASS: Backup created successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ FAIL: Backup not created" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ FAIL: Backup test failed - $_" -ForegroundColor Red
}

# Test 4: CSV Export
Write-Host "`n[Test 4] CSV Export..." -ForegroundColor Yellow
$testCsvPath = ".\test_export.csv"
try {
    & ".\SideChannel_Check_v2.ps1" -ExportPath $testCsvPath | Out-Null
    
    if (Test-Path $testCsvPath) {
        $csv = Import-Csv $testCsvPath
        if ($csv.Count -gt 0) {
            Write-Host "✅ PASS: CSV export successful ($($csv.Count) rows)" -ForegroundColor Green
        } else {
            Write-Host "❌ FAIL: CSV is empty" -ForegroundColor Red
        }
        Remove-Item $testCsvPath -Force
    } else {
        Write-Host "❌ FAIL: CSV file not created" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ FAIL: CSV export test failed - $_" -ForegroundColor Red
}

# Test 5: WhatIf - No Changes Made
Write-Host "`n[Test 5] WhatIf Safety Check..." -ForegroundColor Yellow
try {
    $backupsBefore = @(Get-ChildItem ".\Backups\*.json" -ErrorAction SilentlyContinue).Count
    & ".\SideChannel_Check_v2.ps1" -Mode Backup -WhatIf | Out-Null
    $backupsAfter = @(Get-ChildItem ".\Backups\*.json" -ErrorAction SilentlyContinue).Count
    
    if ($backupsAfter -eq $backupsBefore) {
        Write-Host "✅ PASS: WhatIf prevented changes" -ForegroundColor Green
    } else {
        Write-Host "❌ FAIL: WhatIf did not prevent changes" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ FAIL: WhatIf safety test failed - $_" -ForegroundColor Red
}

# Test 6: Restore Mode Browse
Write-Host "`n[Test 6] Restore Mode..." -ForegroundColor Yellow
try {
    # Create a test backup first
    & ".\SideChannel_Check_v2.ps1" -Mode Backup | Out-Null
    
    # Attempt to browse (won't actually restore without selection)
    $result = & ".\SideChannel_Check_v2.ps1" -Mode Restore 2>&1
    
    if ($result -match "available backup") {
        Write-Host "✅ PASS: Restore mode lists backups" -ForegroundColor Green
    } else {
        Write-Host "⚠️  WARN: No backups found or unexpected output" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ FAIL: Restore mode test failed - $_" -ForegroundColor Red
}

Write-Host "`n=== Test Suite Complete ===" -ForegroundColor Cyan
```

### Manual Test Scenarios

#### Test 1: Basic Assessment
```powershell
.\SideChannel_Check_v2.ps1

# Expected: 
# ✅ No errors or exceptions
# ✅ Security score displayed (0-100%)
# ✅ All mitigations evaluated
# ✅ Prerequisites shown separately
```

#### Test 2: WhatIf Preview
```powershell
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf

# Expected:
# ✅ No registry changes made
# ✅ Preview of all selected changes displayed
# ✅ "WhatIf Mode" clearly indicated
```

#### Test 3: Interactive Apply
```powershell
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive
# Select: 1,2

# Expected:
# ✅ Backup created before changes
# ✅ Only selected mitigations applied
# ✅ Success/failure count displayed
# ✅ System restart warning shown
```

#### Test 4: Backup & Restore
```powershell
# Create backup
.\SideChannel_Check_v2.ps1 -Mode Backup

# Browse backups
.\SideChannel_Check_v2.ps1 -Mode Restore

# Expected:
# ✅ Backup file created in .\Backups\
# ✅ All backups listed with timestamps
# ✅ Age calculation correct (e.g., "2h ago")
```

#### Test 5: WhatIf with Revert
```powershell
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive -WhatIf

# Expected:
# ✅ Lists latest backup
# ✅ Shows all changes that would be made
# ✅ No actual restore performed
```

---

## 📊 Performance Considerations

### Low Impact (<5% performance loss)
- SSBD, BTI, Enhanced IBRS, TSX Disable
- SBDR/SBDS, SRBDS, DRPW
- Exception Chain Validation, SMAP

### Medium Impact (5-15% performance loss)
- KVAS (Kernel VA Shadow / Meltdown)
- MDS (Microarchitectural Data Sampling)
- TAA (TSX Asynchronous Abort)
- Hyper-V Core Scheduler

### High Impact (15%+ performance loss)
- L1TF (L1 Terminal Fault)
- **⚠️ Test in non-production first!**

---

## 🔒 Security Best Practices

### Recommended Workflow

1. **Assessment** → `.\SideChannel_Check_v2.ps1`
2. **Planning** → `.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf`
3. **Backup** → `.\SideChannel_Check_v2.ps1 -Mode Backup`
4. **Apply** → `.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive`
5. **Validate** → Restart system, re-run assessment
6. **Rollback** → `.\SideChannel_Check_v2.ps1 -Mode RevertInteractive` (if issues)

### Enterprise Deployment

```powershell
# Assess multiple systems
$computers = @("SERVER01", "SERVER02")
$computers | ForEach-Object {
    Invoke-Command -ComputerName $_ -ScriptBlock {
        & "C:\Scripts\SideChannel_Check_v2.ps1" -ExportPath "C:\Reports\$env:COMPUTERNAME.csv"
    }
}
```

---

## 🐛 Troubleshooting

### Access Denied
```powershell
# Solution: Run as Administrator
Start-Process powershell -Verb RunAs
```

### Backups not found
```powershell
# Check backup directory
Test-Path ".\Backups\"
Get-ChildItem ".\Backups\Backup_*.json"
```

### Export fails
```powershell
# Create export directory
$exportDir = Split-Path $ExportPath -Parent
New-Item -ItemType Directory -Path $exportDir -Force
```

### WhatIf not working
```powershell
# Verify PowerShell supports ShouldProcess
Get-Help about_Functions_CmdletBindingAttribute
```

---

## ⚠️ Important Warnings

- ⚠️ **Always use -WhatIf first**
- ⚠️ **System restart required** after changes
- ⚠️ **Create backups** before modifications
- ⚠️ **Test in non-production** first

---

## 📝 Changelog

### v2.1.0 (2025-11-26)
- ✨ Simplified mode structure (5 dedicated modes)
- ✨ Removed standalone -Interactive switch (ApplyInteractive/RevertInteractive modes)
- ✨ WhatIf support for all modification modes (ApplyInteractive, RevertInteractive, Backup)
- ✨ Get-AllBackups function for Restore mode
- ✨ Comprehensive hardware detection (5 prerequisites)
- ✨ Intelligent scoring system (excludes N/A and prerequisites)
- ✨ Visual security score bar
- ✨ Dedicated Backup and Restore modes

### v2.0.0 (2025-11-20)
- 🎉 Initial v2 release
- Modular function-based architecture
- PowerShell 5.1 & 7.x compatibility
- Runtime kernel detection
- Interactive modes
- Automatic backup creation
- JSON-based restore system

---

## 📄 License

MIT License

---

## 👤 Author

**Jan Tiedemann**
- GitHub: [@BetaHydri](https://github.com/BetaHydri)

---

**Version:** 2.1.0  
**Last Updated:** 2025-11-26  
**PowerShell:** 5.1, 7.x  
**Platform:** Windows 10/11, Server 2016+
